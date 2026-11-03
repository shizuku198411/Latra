package knowledge

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"
)

type Query struct {
	Entity     string
	Name       string
	Capability string
	Command    string
	Verbose    bool
}

func Select(catalog Catalog, query Query) (Catalog, error) {
	if query.Command != "" && !containsCommand(catalog.Commands, query.Command) {
		return Catalog{}, fmt.Errorf("command %q not found", query.Command)
	}
	if query.Capability != "" && !containsCapability(catalog.Capabilities, query.Capability) {
		return Catalog{}, fmt.Errorf("capability %q not found", query.Capability)
	}
	result := catalog
	result.Capabilities = []Capability{}
	result.Commands = []Command{}
	switch query.Entity {
	case "":
		return result, nil
	case "capabilities":
		for _, capability := range catalog.Capabilities {
			if query.Name != "" && capability.Name != query.Name {
				continue
			}
			if query.Command != "" && !hasAssociationCommand(capability.Associations, query.Command) {
				continue
			}
			if !query.Verbose && query.Name == "" {
				capability.Associations = nil
			}
			result.Capabilities = append(result.Capabilities, capability)
		}
		if query.Name != "" && len(result.Capabilities) == 0 {
			return Catalog{}, fmt.Errorf("capability %q not found", query.Name)
		}
	case "commands":
		for _, command := range catalog.Commands {
			if query.Name != "" && command.Name != query.Name {
				continue
			}
			if query.Capability != "" && !hasAssociationCapability(command.Associations, query.Capability) {
				continue
			}
			if !query.Verbose && query.Name == "" {
				command.Associations = nil
			}
			result.Commands = append(result.Commands, command)
		}
		if query.Name != "" && len(result.Commands) == 0 {
			return Catalog{}, fmt.Errorf("command %q not found", query.Name)
		}
	default:
		return Catalog{}, fmt.Errorf("unknown database entity %q", query.Entity)
	}
	return result, nil
}

func Write(writer io.Writer, format Format, catalog Catalog, query Query) error {
	selected, err := Select(catalog, query)
	if err != nil {
		return err
	}
	if format == FormatJSON {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		return encoder.Encode(selected)
	}
	if format != FormatText {
		return fmt.Errorf("unsupported database format %q", format)
	}
	return writeText(writer, selected, query)
}

func WriteFile(path string, format Format, catalog Catalog, query Query) (returnErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".latra-db-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := Write(temporary, format, catalog, query); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil
	return os.Rename(temporaryPath, path)
}

func writeText(writer io.Writer, catalog Catalog, query Query) error {
	if query.Entity == "" {
		_, err := fmt.Fprintf(writer, "Latra Embedded DB\n\nSource: %s\nSchema Version: %s\nCapabilities: %d\nCommands: %d\nRules: %d\n", catalog.Source, catalog.DatabaseSchema, catalog.Summary.Capabilities, catalog.Summary.Commands, catalog.Summary.Rules)
		return err
	}
	if query.Entity == "capabilities" {
		if _, err := fmt.Fprintf(writer, "Capabilities: %d\n", len(catalog.Capabilities)); err != nil {
			return err
		}
		for _, capability := range catalog.Capabilities {
			if _, err := fmt.Fprintf(writer, "\n%s\n  %s\n", capability.Name, capability.Description); err != nil {
				return err
			}
			if len(capability.Associations) > 0 {
				if err := writeAssociations(writer, capability.Associations, false); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if _, err := fmt.Fprintf(writer, "Commands: %d\n", len(catalog.Commands)); err != nil {
		return err
	}
	for _, command := range catalog.Commands {
		if _, err := fmt.Fprintf(writer, "\n%s\n", command.Name); err != nil {
			return err
		}
		if len(command.Associations) > 0 {
			if err := writeAssociations(writer, command.Associations, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeAssociations(writer io.Writer, associations []Association, commandView bool) error {
	for _, association := range associations {
		label := association.Command
		if commandView {
			label = association.Capability
		}
		if label == "" {
			label = "(no command)"
		}
		if _, err := fmt.Fprintf(writer, "  %s [%s]\n    Rules: %s\n", label, association.Type, strings.Join(association.RuleIDs, ", ")); err != nil {
			return err
		}
	}
	return nil
}

func hasAssociationCommand(items []Association, command string) bool {
	for _, item := range items {
		if item.Command == command {
			return true
		}
	}
	return false
}
func hasAssociationCapability(items []Association, capability string) bool {
	for _, item := range items {
		if item.Capability == capability {
			return true
		}
	}
	return false
}

func containsCommand(items []Command, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return true
		}
	}
	return false
}
func containsCapability(items []Capability, name string) bool {
	for _, item := range items {
		if item.Name == name {
			return true
		}
	}
	return false
}
