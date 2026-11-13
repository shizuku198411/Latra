package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/sdk"
	"go.yaml.in/yaml/v3"
)

const maxDefinitionBytes int64 = 1 << 20

var workshopNamePattern = regexp.MustCompile(`^[a-z](?:-?[a-z0-9])*$`)

type projectDefinition struct {
	Name        string            `yaml:"name"`
	Base        string            `yaml:"base"`
	Runtime     string            `yaml:"runtime,omitempty"`
	SDKs        []sdkDeclaration  `yaml:"sdks,omitempty"`
	Connections []connection      `yaml:"connections,omitempty"`
	Actions     map[string]string `yaml:"actions,omitempty"`
}

type sdkDeclaration struct {
	Name    string         `yaml:"name"`
	Channel string         `yaml:"channel,omitempty"`
	Plugs   map[string]any `yaml:"plugs,omitempty"`
	Slots   map[string]any `yaml:"slots,omitempty"`
}

type connection struct {
	Plug string `yaml:"plug"`
	Slot string `yaml:"slot"`
}

func readProject(ctx context.Context, projectPath string, limits sdk.Limits, resolver StoreResolver, includeUnsupported bool) (*Result, error) {
	root, err := os.OpenRoot(projectPath)
	if err != nil {
		return nil, fmt.Errorf("open project: %w", err)
	}
	defer root.Close()

	entries, err := fs.ReadDir(root.FS(), ".workshop")
	if err != nil {
		return nil, fmt.Errorf("read .workshop: %w", err)
	}
	definitionNames := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || path.Ext(entry.Name()) != ".yaml" {
			continue
		}
		definitionNames = append(definitionNames, entry.Name())
	}
	sort.Strings(definitionNames)
	if len(definitionNames) == 0 {
		return nil, fmt.Errorf("no Workshop definitions found under .workshop")
	}

	result := &Result{Kind: InputProject, Root: projectPath}
	index := make(map[string]int)
	for _, definitionName := range definitionNames {
		relative := path.Join(".workshop", definitionName)
		content, err := readBounded(root, relative, maxDefinitionBytes)
		if err != nil {
			return nil, err
		}
		definition, err := decodeProjectDefinition(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", relative, err)
		}
		if err := validateProjectDefinition(definition); err != nil {
			return nil, fmt.Errorf("%s: %w", relative, err)
		}

		result.Workshops = append(result.Workshops, Workshop{
			Name:       definition.Name,
			Base:       definition.Base,
			Runtime:    definition.Runtime,
			Definition: relative,
		})
		configuration := Configuration{Name: definition.Name, Definition: relative}
		for i, declaration := range definition.SDKs {
			configuration.SDKs = append(configuration.SDKs, ConfigurationSDK{Name: declaration.Name, Order: i, Plugs: declaration.Plugs, Slots: declaration.Slots})
		}
		for i, connection := range definition.Connections {
			configuration.Connections = append(configuration.Connections, Connection{Plug: connection.Plug, Slot: connection.Slot, Order: i})
		}
		result.Configurations = append(result.Configurations, configuration)

		seen := make(map[string]bool)
		for declarationOrder, declaration := range definition.SDKs {
			name, sourceType, err := classifyDeclaration(declaration.Name)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", relative, err)
			}
			if !includeInInventory(sourceType, includeUnsupported) {
				continue
			}
			if seen[name] {
				return nil, fmt.Errorf("%s: SDK %q must only be included once", relative, name)
			}
			seen[name] = true
			if declaration.Channel != "" {
				if err := sdk.ValidateChannel(declaration.Channel); err != nil {
					return nil, fmt.Errorf("%s: SDK %q: %w", relative, name, err)
				}
			}

			usage := sdk.Declaration{
				Definition: relative,
				Workshop:   definition.Name,
				Order:      declarationOrder,
				Base:       definition.Base,
				Channel:    declaration.Channel,
				Plugs:      declaration.Plugs,
				Slots:      declaration.Slots,
			}
			resolvedChannel := declaration.Channel
			if sourceType == sdk.SourceStore && resolvedChannel == "" {
				resolvedChannel = "stable"
			}
			key := string(sourceType) + "\x00" + name + "\x00" + resolvedChannel + "\x00" + definition.Base
			if sourceType == sdk.SourceProject {
				key = string(sourceType) + "\x00" + name
			}
			if position, exists := index[key]; exists {
				resolved := &result.SDKs[position]
				if resolved.Metadata != nil && resolved.Metadata.Base != "" && resolved.Metadata.Base != definition.Base {
					return nil, fmt.Errorf("%s: SDK %q targets %q, required %q", relative, name, resolved.Metadata.Base, definition.Base)
				}
				resolved.Declarations = append(resolved.Declarations, usage)
				continue
			}

			var resolved *sdk.SDK
			if sourceType == sdk.SourceProject {
				sdkRelative := path.Join(".workshop", name)
				sdkRoot, err := root.OpenRoot(sdkRelative)
				if err != nil {
					return nil, &sdk.Error{Code: sdk.CodeUnsafePath, Path: sdkRelative, Err: fmt.Errorf("resolve project SDK %q: %w", name, err)}
				}
				resolved, err = sdk.ReadRoot(sdkRoot, filepath.Join(projectPath, filepath.FromSlash(sdkRelative)), name, limits)
				closeErr := sdkRoot.Close()
				if err != nil {
					return nil, err
				}
				if closeErr != nil {
					return nil, closeErr
				}
				if resolved.Metadata.Base != "" && resolved.Metadata.Base != definition.Base {
					return nil, fmt.Errorf("%s: SDK %q targets %q, required %q", relative, name, resolved.Metadata.Base, definition.Base)
				}
			} else if sourceType == sdk.SourceStore && resolver != nil {
				resolved, err = resolver.Resolve(ctx, StoreRequest{
					Name: name, Channel: resolvedChannel, Base: definition.Base,
				}, limits)
				if err != nil {
					state := sdk.StateNotResolved
					diagnostic := sdk.Diagnostic{
						Code: "store-resolution-failed", Severity: sdk.SeverityError,
						Phase: "resolve", Message: err.Error(),
					}
					var resolutionError *ResolutionError
					if errors.As(err, &resolutionError) {
						state = resolutionError.State
						diagnostic = resolutionError.Diagnostic
					}
					resolved = &sdk.SDK{
						Name: name, Source: sdk.SourceStore, State: state,
						Channel: resolvedChannel, Diagnostics: []sdk.Diagnostic{diagnostic},
					}
				}
			} else {
				resolved = &sdk.SDK{
					Name:    name,
					Source:  sourceType,
					State:   sdk.StateNotResolved,
					Channel: resolvedChannel,
				}
			}
			resolved.Declarations = []sdk.Declaration{usage}
			index[key] = len(result.SDKs)
			result.SDKs = append(result.SDKs, *resolved)
		}
	}

	sort.Slice(result.SDKs, func(i, j int) bool {
		if result.SDKs[i].Source != result.SDKs[j].Source {
			return result.SDKs[i].Source < result.SDKs[j].Source
		}
		if result.SDKs[i].Name != result.SDKs[j].Name {
			return result.SDKs[i].Name < result.SDKs[j].Name
		}
		return result.SDKs[i].Channel < result.SDKs[j].Channel
	})
	return result, nil
}

func decodeProjectDefinition(content []byte) (*projectDefinition, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	decoder.KnownFields(true)
	var definition projectDefinition
	if err := decoder.Decode(&definition); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("multiple YAML documents are not supported")
		}
		return nil, err
	}
	return &definition, nil
}

func validateProjectDefinition(definition *projectDefinition) error {
	if !workshopNamePattern.MatchString(definition.Name) {
		return fmt.Errorf("invalid Workshop name %q", definition.Name)
	}
	if !slicesContains([]string{"ubuntu@20.04", "ubuntu@22.04", "ubuntu@24.04", "ubuntu@26.04"}, definition.Base) {
		return fmt.Errorf("unsupported Workshop base %q", definition.Base)
	}
	if definition.Runtime != "" && definition.Runtime != "lxd-container" && definition.Runtime != "lxd-vm" {
		return fmt.Errorf("unsupported Workshop runtime %q", definition.Runtime)
	}
	return nil
}

// includeInInventory centralizes the Workshop special-SDK policy for both
// scanning and Explorer discovery. Unsupported SDKs remain visible only in
// Explorer; built-in/reserved entries are never shown or analyzed.
func includeInInventory(sourceType sdk.Source, includeUnsupported bool) bool {
	switch sourceType {
	case sdk.SourceSystem, sdk.SourceAgent:
		return false
	case sdk.SourceTry, sdk.SourceSketch:
		return includeUnsupported
	default:
		return true
	}
}

func classifyDeclaration(raw string) (string, sdk.Source, error) {
	switch raw {
	case "system":
		return raw, sdk.SourceSystem, nil
	case "sketch":
		return raw, sdk.SourceSketch, nil
	case "agent":
		return raw, sdk.SourceAgent, nil
	}
	if suffix, ok := strings.CutPrefix(raw, "project-"); ok {
		if err := sdk.ValidateName(suffix); err != nil {
			return "", "", err
		}
		return suffix, sdk.SourceProject, nil
	}
	if suffix, ok := strings.CutPrefix(raw, "try-"); ok {
		if err := sdk.ValidateName(suffix); err != nil {
			return "", "", err
		}
		return suffix, sdk.SourceTry, nil
	}
	if err := sdk.ValidateName(raw); err != nil {
		return "", "", err
	}
	return raw, sdk.SourceStore, nil
}

func readBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Stat(name)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", name)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", name, limit)
	}
	return content, nil
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
