package source

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/sdk"
)

// SDKReference identifies one SDK declaration in a Workshop project without
// resolving or downloading the SDK artifact.
type SDKReference struct {
	Name        string
	Source      sdk.Source
	Channel     string
	Definitions []string
}

// ResolveSDKReference resolves an SDK name against all Workshop definitions in
// a project. It rejects declarations that disagree on source or channel.
func ResolveSDKReference(projectPath, name string) (SDKReference, error) {
	if err := sdk.ValidateName(name); err != nil {
		return SDKReference{}, err
	}
	root, err := os.OpenRoot(projectPath)
	if err != nil {
		return SDKReference{}, fmt.Errorf("open project: %w", err)
	}
	defer root.Close()

	entries, err := fs.ReadDir(root.FS(), ".workshop")
	if err != nil {
		return SDKReference{}, fmt.Errorf("read .workshop: %w", err)
	}
	definitionNames := make([]string, 0)
	for _, entry := range entries {
		if !entry.IsDir() && path.Ext(entry.Name()) == ".yaml" {
			definitionNames = append(definitionNames, entry.Name())
		}
	}
	sort.Strings(definitionNames)

	references := make(map[string]*SDKReference)
	for _, definitionName := range definitionNames {
		relative := path.Join(".workshop", definitionName)
		content, err := readBounded(root, relative, maxDefinitionBytes)
		if err != nil {
			return SDKReference{}, err
		}
		definition, err := decodeProjectDefinition(content)
		if err != nil {
			return SDKReference{}, fmt.Errorf("%s: %w", relative, err)
		}
		if err := validateProjectDefinition(definition); err != nil {
			return SDKReference{}, fmt.Errorf("%s: %w", relative, err)
		}
		for _, declaration := range definition.SDKs {
			declaredName, sourceType, err := classifyDeclaration(declaration.Name)
			if err != nil {
				return SDKReference{}, fmt.Errorf("%s: %w", relative, err)
			}
			if declaredName != name {
				continue
			}
			channel := declaration.Channel
			if sourceType == sdk.SourceStore && channel == "" {
				channel = "stable"
			}
			if channel != "" {
				if err := sdk.ValidateChannel(channel); err != nil {
					return SDKReference{}, fmt.Errorf("%s: SDK %q: %w", relative, name, err)
				}
			}
			key := string(sourceType) + "\x00" + channel
			reference := references[key]
			if reference == nil {
				reference = &SDKReference{Name: name, Source: sourceType, Channel: channel}
				references[key] = reference
			}
			reference.Definitions = append(reference.Definitions, relative)
		}
	}
	if len(references) == 0 {
		return SDKReference{}, fmt.Errorf("%w: SDK %q is not declared by this Workshop project", fs.ErrNotExist, name)
	}
	if len(references) > 1 {
		variants := make([]string, 0, len(references))
		for _, reference := range references {
			variant := string(reference.Source)
			if reference.Channel != "" {
				variant += " channel " + reference.Channel
			}
			variants = append(variants, variant+" in "+strings.Join(reference.Definitions, ", "))
		}
		sort.Strings(variants)
		return SDKReference{}, fmt.Errorf("SDK %q has conflicting Workshop declarations: %s", name, strings.Join(variants, "; "))
	}
	for _, reference := range references {
		sort.Strings(reference.Definitions)
		return *reference, nil
	}
	panic("unreachable")
}
