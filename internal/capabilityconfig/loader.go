package capabilityconfig

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

const SourceEmbeddedDefault = "embedded-default"

//go:embed default/*.yaml
var defaultFiles embed.FS

var (
	defaultOnce   sync.Once
	defaultConfig *Config
	defaultError  error
)

// Default returns the validated configuration embedded at build time.
func Default() (*Config, error) {
	defaultOnce.Do(func() { defaultConfig, defaultError = loadDefault() })
	return defaultConfig, defaultError
}

// MustDefault returns Default and panics only when the build-time configuration is invalid.
func MustDefault() *Config {
	config, err := Default()
	if err != nil {
		panic(fmt.Sprintf("invalid embedded capability configuration: %v", err))
	}
	return config
}

// Parse strictly decodes and validates configuration bytes.
func Parse(content []byte) (*Config, error) {
	config, err := decode(content)
	if err != nil {
		return nil, err
	}
	if err := validate(config); err != nil {
		return nil, err
	}
	return config, nil
}

func decode(content []byte) (*Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode capability configuration: %w", err)
	}
	return &config, nil
}

func loadDefault() (*Config, error) {
	paths, err := fs.Glob(defaultFiles, "default/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("list embedded capability configuration: %w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("embedded capability configuration is empty")
	}
	merged := &Config{}
	for _, path := range paths {
		content, readErr := defaultFiles.ReadFile(path)
		if readErr != nil {
			return nil, fmt.Errorf("read embedded capability configuration %q: %w", path, readErr)
		}
		fragment, decodeErr := decode(content)
		if decodeErr != nil {
			return nil, fmt.Errorf("%s: %w", path, decodeErr)
		}
		if mergeErr := mergeConfig(merged, fragment, path); mergeErr != nil {
			return nil, mergeErr
		}
	}
	if err := validate(merged); err != nil {
		return nil, err
	}
	return merged, nil
}

func mergeConfig(target, fragment *Config, source string) error {
	if fragment.SchemaVersion != "" {
		if target.SchemaVersion != "" {
			return fmt.Errorf("%s: duplicate schema version", source)
		}
		target.SchemaVersion = fragment.SchemaVersion
	}
	if target.CapabilityDefinitions == nil {
		target.CapabilityDefinitions = make(map[string]CapabilityDefinition)
	}
	if target.CommandDefinitions == nil {
		target.CommandDefinitions = make(map[string]CommandDefinition)
	}
	if target.PathClasses == nil {
		target.PathClasses = make(map[string]PathClass)
	}
	if target.PathCapabilities == nil {
		target.PathCapabilities = make(map[string]PathCapability)
	}
	for key, value := range fragment.CapabilityDefinitions {
		if _, exists := target.CapabilityDefinitions[key]; exists {
			return fmt.Errorf("%s: duplicate capability definition %q", source, key)
		}
		target.CapabilityDefinitions[key] = value
	}
	for key, value := range fragment.CommandDefinitions {
		if _, exists := target.CommandDefinitions[key]; exists {
			return fmt.Errorf("%s: duplicate command definition %q", source, key)
		}
		target.CommandDefinitions[key] = value
	}
	for key, value := range fragment.PathClasses {
		if _, exists := target.PathClasses[key]; exists {
			return fmt.Errorf("%s: duplicate path class %q", source, key)
		}
		target.PathClasses[key] = value
	}
	for key, value := range fragment.PathCapabilities {
		if _, exists := target.PathCapabilities[key]; exists {
			return fmt.Errorf("%s: duplicate path capability %q", source, key)
		}
		target.PathCapabilities[key] = value
	}
	target.CommandRules = append(target.CommandRules, fragment.CommandRules...)
	target.WrapperRules = append(target.WrapperRules, fragment.WrapperRules...)
	target.FileCommandRules = append(target.FileCommandRules, fragment.FileCommandRules...)
	target.TargetRules = append(target.TargetRules, fragment.TargetRules...)
	target.Interpreters = append(target.Interpreters, fragment.Interpreters...)
	target.UploadRules = append(target.UploadRules, fragment.UploadRules...)
	target.OperationRules = append(target.OperationRules, fragment.OperationRules...)
	return nil
}

var identifierPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

func validate(config *Config) error {
	if config.SchemaVersion != "2" {
		return fmt.Errorf("unsupported capability configuration schema version %q", config.SchemaVersion)
	}
	ids := make(map[string]bool)
	if len(config.CapabilityDefinitions) == 0 {
		return fmt.Errorf("capability definitions are empty")
	}
	for name, definition := range config.CapabilityDefinitions {
		if !identifierPattern.MatchString(name) || strings.TrimSpace(definition.Description) == "" {
			return fmt.Errorf("invalid capability definition %q", name)
		}
	}
	for name, definition := range config.CommandDefinitions {
		if strings.TrimSpace(name) == "" || !identifierPattern.MatchString(definition.Category) || strings.TrimSpace(definition.Description) == "" {
			return fmt.Errorf("invalid command definition %q", name)
		}
	}
	validateCapabilities := func(ruleID string, capabilities []string) error {
		for _, capability := range capabilities {
			if _, ok := config.CapabilityDefinitions[capability]; !ok {
				return fmt.Errorf("rule %q references undefined capability %q", ruleID, capability)
			}
		}
		return nil
	}
	validateRule := func(id string, values ...[]string) error {
		if !identifierPattern.MatchString(id) {
			return fmt.Errorf("invalid or empty rule ID %q", id)
		}
		if ids[id] {
			return fmt.Errorf("duplicate rule ID %q", id)
		}
		ids[id] = true
		for _, items := range values {
			if len(items) == 0 {
				return fmt.Errorf("rule %q contains an empty required list", id)
			}
			for _, item := range items {
				if item == "" {
					return fmt.Errorf("rule %q contains an empty value", id)
				}
			}
		}
		return nil
	}
	for _, rule := range config.CommandRules {
		if err := validateRule(rule.ID, rule.Commands, rule.Capabilities); err != nil {
			return err
		}
		if err := validateCommandMatch(rule.ID, rule.Match); err != nil {
			return err
		}
		if err := validateCapabilities(rule.ID, rule.Capabilities); err != nil {
			return err
		}
	}
	for _, rule := range config.WrapperRules {
		if err := validateRule(rule.ID, rule.Wrappers, rule.Capabilities); err != nil {
			return err
		}
		if err := validateCapabilities(rule.ID, rule.Capabilities); err != nil {
			return err
		}
	}
	for _, rule := range config.FileCommandRules {
		if err := validateRule(rule.ID, rule.Commands); err != nil {
			return err
		}
		if err := validateCommandMatch(rule.ID, rule.Match); err != nil {
			return err
		}
		if len(rule.Options) > 0 {
			if err := validateOptions(rule.ID, rule.Options); err != nil {
				return err
			}
		}
		if len(rule.Operands) == 0 && len(rule.OptionOperands) == 0 {
			return fmt.Errorf("rule %q has no operands", rule.ID)
		}
		for _, operand := range rule.Operands {
			if !containsString([]string{"all", "first", "last", "all-but-first", "all-but-last", "position-2"}, operand.Selector) {
				return fmt.Errorf("rule %q has invalid operand selector %q", rule.ID, operand.Selector)
			}
			if err := validateAccess(rule.ID, operand.Access); err != nil {
				return err
			}
		}
		for _, operand := range rule.OptionOperands {
			if err := validateOptions(rule.ID, operand.Options); err != nil {
				return err
			}
			if err := validateAccess(rule.ID, operand.Access); err != nil {
				return err
			}
			if strings.ContainsAny(operand.PathMarker, "\r\n\x00") {
				return fmt.Errorf("rule %q has invalid path marker", rule.ID)
			}
		}
	}
	for _, rule := range config.TargetRules {
		if err := validateRule(rule.ID, rule.Commands, rule.Prefixes, rule.PathClasses, rule.Capabilities); err != nil {
			return err
		}
		for _, class := range rule.PathClasses {
			if _, ok := config.PathClasses[class]; !ok {
				return fmt.Errorf("rule %q references unknown path class %q", rule.ID, class)
			}
		}
		if err := validateCapabilities(rule.ID, rule.Capabilities); err != nil {
			return err
		}
	}
	for _, rule := range config.Interpreters {
		if err := validateRule(rule.ID, rule.Commands, []string{rule.Capability}); err != nil {
			return err
		}
		if err := validateOptions(rule.ID, rule.Options); err != nil {
			return err
		}
		if err := validateCapabilities(rule.ID, []string{rule.Capability}); err != nil {
			return err
		}
	}
	for _, rule := range config.UploadRules {
		if err := validateRule(rule.ID, rule.Commands, []string{rule.Capability}); err != nil {
			return err
		}
		if err := validateOptions(rule.ID, rule.Options); err != nil {
			return err
		}
		if err := validateCapabilities(rule.ID, []string{rule.Capability}); err != nil {
			return err
		}
	}
	for _, rule := range config.OperationRules {
		if rule.CommandResolution != "" && rule.CommandResolution != "unresolved" {
			return fmt.Errorf("rule %q has unsupported command resolution %q", rule.ID, rule.CommandResolution)
		}
		if err := validateRule(rule.ID, rule.OperationKinds, rule.Capabilities); err != nil {
			return err
		}
		if err := validateCapabilities(rule.ID, rule.Capabilities); err != nil {
			return err
		}
	}
	for class, mapping := range config.PathCapabilities {
		if _, ok := config.PathClasses[class]; !ok {
			return fmt.Errorf("path capability references unknown class %q", class)
		}
		if mapping.Read == nil && mapping.Write == nil {
			return fmt.Errorf("path class %q has no capability", class)
		}
		for _, rule := range []*CapabilityRule{mapping.Read, mapping.Write} {
			if rule == nil {
				continue
			}
			capabilities := append([]string{rule.Capability}, rule.AdditionalCapabilities...)
			if err := validateRule(rule.ID, capabilities); err != nil {
				return err
			}
			if err := validateCapabilities(rule.ID, capabilities); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateAccess(ruleID, access string) error {
	if !containsString([]string{"read", "write", "read-write"}, access) {
		return fmt.Errorf("rule %q has invalid operand access %q", ruleID, access)
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func validateCommandMatch(ruleID string, match CommandMatch) error {
	for _, items := range [][]string{
		match.Subcommands, match.ExcludedSubcommands, match.OptionsConsumingNext,
		match.AnyArgumentPrefixes, match.ExcludedArgumentPrefixes, match.ShortFlagSet,
		match.AnyShortFlags, match.ExcludedShortFlags,
	} {
		for _, item := range items {
			if item == "" {
				return fmt.Errorf("rule %q contains an empty match value", ruleID)
			}
		}
	}
	for _, paths := range [][][]string{match.SubcommandPaths, match.ExcludedSubcommandPaths} {
		for _, path := range paths {
			if len(path) == 0 {
				return fmt.Errorf("rule %q contains an empty subcommand path", ruleID)
			}
			for _, part := range path {
				if part == "" {
					return fmt.Errorf("rule %q contains an empty subcommand path value", ruleID)
				}
			}
		}
	}
	for _, flag := range append(append(append([]string{}, match.ShortFlagSet...), match.AnyShortFlags...), match.ExcludedShortFlags...) {
		if len(flag) != 2 || flag[0] != '-' || flag[1] == '-' {
			return fmt.Errorf("rule %q has invalid short flag %q", ruleID, flag)
		}
	}
	for _, flag := range append(append([]string{}, match.AnyShortFlags...), match.ExcludedShortFlags...) {
		if !containsString(match.ShortFlagSet, flag) {
			return fmt.Errorf("rule %q uses short flag %q outside its flag set", ruleID, flag)
		}
	}
	for _, option := range match.OptionsConsumingNext {
		if !strings.HasPrefix(option, "-") {
			return fmt.Errorf("rule %q has invalid consuming option %q", ruleID, option)
		}
	}
	for _, subcommand := range match.Subcommands {
		if containsString(match.ExcludedSubcommands, subcommand) {
			return fmt.Errorf("rule %q both includes and excludes subcommand %q", ruleID, subcommand)
		}
	}
	for _, included := range match.SubcommandPaths {
		for _, excluded := range match.ExcludedSubcommandPaths {
			if equalStrings(included, excluded) {
				return fmt.Errorf("rule %q both includes and excludes subcommand path %q", ruleID, strings.Join(included, " "))
			}
		}
	}
	if len(match.AnyOptions) > 0 {
		if err := validateOptions(ruleID, match.AnyOptions); err != nil {
			return err
		}
	}
	if len(match.ExcludedOptions) > 0 {
		if err := validateOptions(ruleID, match.ExcludedOptions); err != nil {
			return err
		}
	}
	for _, included := range match.AnyOptions {
		for _, excluded := range match.ExcludedOptions {
			if included.Name == excluded.Name {
				return fmt.Errorf("rule %q both includes and excludes option %q", ruleID, included.Name)
			}
		}
	}
	for field, value := range map[string]string{"source": match.Source, "destination": match.Destination} {
		if value != "" && value != "remote" && value != "local" {
			return fmt.Errorf("rule %q has invalid %s %q", ruleID, field, value)
		}
	}
	if match.RemoteOperands != "" && match.RemoteOperands != "any" && match.RemoteOperands != "none" {
		return fmt.Errorf("rule %q has invalid remote operands mode %q", ruleID, match.RemoteOperands)
	}
	if match.ArgumentCondition != nil {
		if len(match.ArgumentCondition.AnyClasses) == 0 {
			return fmt.Errorf("rule %q has an empty argument condition", ruleID)
		}
		for _, class := range match.ArgumentCondition.AnyClasses {
			if !containsString([]string{"non-local-artifact", "non-local-package-source", "build-source", "any-resolved", "unresolved", "network-address", "executable-address", "local-data-address", "none"}, class) {
				return fmt.Errorf("rule %q has invalid argument class %q", ruleID, class)
			}
		}
	}
	if match.ArgumentAt != nil {
		if match.ArgumentAt.Position < 0 || len(match.ArgumentAt.Values) == 0 {
			return fmt.Errorf("rule %q has invalid positional argument match", ruleID)
		}
		for _, value := range match.ArgumentAt.Values {
			if value == "" {
				return fmt.Errorf("rule %q has an empty positional argument value", ruleID)
			}
		}
	}
	for _, class := range append(append([]string{}, match.SourceClasses...), match.DestinationClasses...) {
		if !containsString([]string{"network-address", "executable-address", "local-data-address"}, class) {
			return fmt.Errorf("rule %q has invalid endpoint class %q", ruleID, class)
		}
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func validateOptions(ruleID string, options []OptionSpec) error {
	if len(options) == 0 {
		return fmt.Errorf("rule %q contains no options", ruleID)
	}
	allowed := map[string]bool{"next": true, "attached": true, "equals": true, "none": true}
	names := make(map[string]bool)
	for _, option := range options {
		if option.Name == "" || option.Name[0] != '-' {
			return fmt.Errorf("rule %q has invalid option %q", ruleID, option.Name)
		}
		if len(option.ValueStyles) == 0 {
			return fmt.Errorf("rule %q option %q has no value styles", ruleID, option.Name)
		}
		for _, value := range option.Values {
			if value == "" {
				return fmt.Errorf("rule %q option %q contains an empty allowed value", ruleID, option.Name)
			}
		}
		if names[option.Name] {
			return fmt.Errorf("rule %q contains duplicate option %q", ruleID, option.Name)
		}
		names[option.Name] = true
		styles := make(map[string]bool)
		for _, style := range option.ValueStyles {
			if !allowed[style] {
				return fmt.Errorf("rule %q option %q has invalid value style %q", ruleID, option.Name, style)
			}
			if style == "attached" && strings.HasPrefix(option.Name, "--") {
				return fmt.Errorf("rule %q long option %q cannot use attached value style", ruleID, option.Name)
			}
			if styles[style] {
				return fmt.Errorf("rule %q option %q contains duplicate value style %q", ruleID, option.Name, style)
			}
			styles[style] = true
		}
	}
	return nil
}
