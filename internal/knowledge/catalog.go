// Package knowledge exposes a stable, read-only catalog derived from Latra's
// embedded capability configuration.
package knowledge

import (
	"reflect"
	"sort"

	"github.com/shizuku198411/Latra/internal/capabilityconfig"
)

const SchemaVersion = "1"

type Catalog struct {
	SchemaVersion  string       `json:"schemaVersion"`
	Kind           string       `json:"kind"`
	Source         string       `json:"source"`
	DatabaseSchema string       `json:"databaseSchemaVersion"`
	Summary        Summary      `json:"summary"`
	Capabilities   []Capability `json:"capabilities"`
	Commands       []Command    `json:"commands"`
}

type Summary struct {
	Capabilities int `json:"capabilities"`
	Commands     int `json:"commands"`
	Rules        int `json:"rules"`
}

type Capability struct {
	Name         string        `json:"name"`
	Description  string        `json:"description"`
	Associations []Association `json:"associations,omitempty"`
}

type Command struct {
	Name         string        `json:"name"`
	Category     string        `json:"category,omitempty"`
	Description  string        `json:"description,omitempty"`
	Associations []Association `json:"associations,omitempty"`
}

type Association struct {
	Capability string   `json:"capability"`
	Command    string   `json:"command,omitempty"`
	Type       string   `json:"type"`
	RuleIDs    []string `json:"ruleIds"`
}

func Default() Catalog { return Build(capabilityconfig.MustDefault()) }

func Build(config *capabilityconfig.Config) Catalog {
	capabilities := make(map[string]*Capability, len(config.CapabilityDefinitions))
	commands := make(map[string]*Command)
	for name, definition := range config.CapabilityDefinitions {
		capabilities[name] = &Capability{Name: name, Description: definition.Description, Associations: []Association{}}
	}
	for name, definition := range config.CommandDefinitions {
		commands[name] = &Command{Name: name, Category: definition.Category, Description: definition.Description, Associations: []Association{}}
	}
	add := func(command, capability, associationType string, ruleIDs ...string) {
		association := Association{Capability: capability, Command: command, Type: associationType, RuleIDs: sortedUnique(ruleIDs)}
		if entry := capabilities[capability]; entry != nil {
			entry.Associations = appendUniqueAssociation(entry.Associations, association)
		}
		if command != "" {
			entry := commands[command]
			if entry == nil {
				entry = &Command{Name: command, Associations: []Association{}}
				commands[command] = entry
			}
			entry.Associations = appendUniqueAssociation(entry.Associations, association)
		}
	}
	for _, rule := range config.CommandRules {
		kind := "conditional"
		if reflect.DeepEqual(rule.Match, capabilityconfig.CommandMatch{}) {
			kind = "direct"
		}
		for _, command := range rule.Commands {
			for _, capability := range rule.Capabilities {
				add(command, capability, kind, rule.ID)
			}
		}
	}
	for _, rule := range config.WrapperRules {
		for _, command := range rule.Wrappers {
			for _, capability := range rule.Capabilities {
				add(command, capability, "wrapper", rule.ID)
			}
		}
	}
	for _, rule := range config.TargetRules {
		for _, command := range rule.Commands {
			for _, capability := range rule.Capabilities {
				add(command, capability, "conditional", rule.ID)
			}
		}
	}
	for _, rule := range config.Interpreters {
		for _, command := range rule.Commands {
			add(command, rule.Capability, "conditional", rule.ID)
		}
	}
	for _, rule := range config.UploadRules {
		for _, command := range rule.Commands {
			add(command, rule.Capability, "conditional", rule.ID)
		}
	}
	for _, rule := range config.OperationRules {
		for _, capability := range rule.Capabilities {
			add("", capability, "operation", rule.ID)
		}
	}
	for class, mapping := range config.PathCapabilities {
		for _, pathRule := range []*capabilityconfig.CapabilityRule{mapping.Read, mapping.Write} {
			if pathRule != nil {
				add("", pathRule.Capability, "path-dependent", pathRule.ID)
			}
		}
		_ = class
	}
	for _, fileRule := range config.FileCommandRules {
		accesses := make(map[string]bool)
		for _, operand := range fileRule.Operands {
			accesses[operand.Access] = true
		}
		for _, operand := range fileRule.OptionOperands {
			accesses[operand.Access] = true
		}
		for _, command := range fileRule.Commands {
			for _, mapping := range config.PathCapabilities {
				if (accesses["read"] || accesses["read-write"]) && mapping.Read != nil {
					add(command, mapping.Read.Capability, "path-dependent", fileRule.ID, mapping.Read.ID)
				}
				if (accesses["write"] || accesses["read-write"]) && mapping.Write != nil {
					add(command, mapping.Write.Capability, "path-dependent", fileRule.ID, mapping.Write.ID)
				}
			}
		}
	}
	catalog := Catalog{SchemaVersion: SchemaVersion, Kind: "capability-catalog", Source: capabilityconfig.SourceEmbeddedDefault, DatabaseSchema: config.SchemaVersion}
	for _, entry := range capabilities {
		sortAssociations(entry.Associations)
		catalog.Capabilities = append(catalog.Capabilities, *entry)
	}
	for _, entry := range commands {
		sortAssociations(entry.Associations)
		catalog.Commands = append(catalog.Commands, *entry)
	}
	sort.Slice(catalog.Capabilities, func(i, j int) bool { return catalog.Capabilities[i].Name < catalog.Capabilities[j].Name })
	sort.Slice(catalog.Commands, func(i, j int) bool { return catalog.Commands[i].Name < catalog.Commands[j].Name })
	catalog.Summary = Summary{Capabilities: len(catalog.Capabilities), Commands: len(catalog.Commands), Rules: countRules(config)}
	return catalog
}

func countRules(config *capabilityconfig.Config) int {
	count := len(config.CommandRules) + len(config.WrapperRules) + len(config.FileCommandRules) + len(config.TargetRules) + len(config.Interpreters) + len(config.UploadRules) + len(config.OperationRules)
	for _, mapping := range config.PathCapabilities {
		if mapping.Read != nil {
			count++
		}
		if mapping.Write != nil {
			count++
		}
	}
	return count
}

func appendUniqueAssociation(items []Association, candidate Association) []Association {
	for index, item := range items {
		if item.Capability == candidate.Capability && item.Command == candidate.Command && item.Type == candidate.Type && reflect.DeepEqual(item.RuleIDs, candidate.RuleIDs) {
			return items
		}
		if item.Capability == candidate.Capability && item.Command == candidate.Command && item.Type == candidate.Type {
			items[index].RuleIDs = sortedUnique(append(items[index].RuleIDs, candidate.RuleIDs...))
			return items
		}
	}
	return append(items, candidate)
}

func sortAssociations(items []Association) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Capability != items[j].Capability {
			return items[i].Capability < items[j].Capability
		}
		if items[i].Command != items[j].Command {
			return items[i].Command < items[j].Command
		}
		if items[i].Type != items[j].Type {
			return items[i].Type < items[j].Type
		}
		return items[i].RuleIDs[0] < items[j].RuleIDs[0]
	})
}
func sortedUnique(items []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	sort.Strings(result)
	return result
}
