// Package capabilityconfig loads and validates declarative Capability knowledge.
package capabilityconfig

type Config struct {
	SchemaVersion         string                          `yaml:"schema-version"`
	CapabilityDefinitions map[string]CapabilityDefinition `yaml:"capability-definitions"`
	CommandRules          []CommandRule                   `yaml:"command-rules"`
	WrapperRules          []WrapperRule                   `yaml:"wrapper-rules"`
	FileCommandRules      []FileCommandRule               `yaml:"file-command-rules"`
	TargetRules           []TargetRule                    `yaml:"target-rules"`
	Interpreters          []InterpreterRule               `yaml:"interpreters"`
	UploadRules           []UploadRule                    `yaml:"upload-rules"`
	OperationRules        []OperationRule                 `yaml:"operation-rules"`
	PathClasses           map[string]PathClass            `yaml:"path-classes"`
	PathCapabilities      map[string]PathCapability       `yaml:"path-capabilities"`
}

type WrapperRule struct {
	ID           string   `yaml:"id"`
	Wrappers     []string `yaml:"wrappers"`
	Capabilities []string `yaml:"capabilities"`
}

type CapabilityDefinition struct {
	Description string `yaml:"description"`
}

type CommandRule struct {
	ID           string       `yaml:"id"`
	Commands     []string     `yaml:"commands"`
	Match        CommandMatch `yaml:"match,omitempty"`
	Capabilities []string     `yaml:"capabilities"`
}

type CommandMatch struct {
	Subcommands              []string           `yaml:"subcommands,omitempty"`
	ExcludedSubcommands      []string           `yaml:"excluded-subcommands,omitempty"`
	SubcommandPaths          [][]string         `yaml:"subcommand-paths,omitempty"`
	ExcludedSubcommandPaths  [][]string         `yaml:"excluded-subcommand-paths,omitempty"`
	AnyOptions               []OptionSpec       `yaml:"any-options,omitempty"`
	ExcludedOptions          []OptionSpec       `yaml:"excluded-options,omitempty"`
	ShortFlagSet             []string           `yaml:"short-flag-set,omitempty"`
	AnyShortFlags            []string           `yaml:"any-short-flags,omitempty"`
	ExcludedShortFlags       []string           `yaml:"excluded-short-flags,omitempty"`
	OptionsConsumingNext     []string           `yaml:"options-consuming-next,omitempty"`
	AnyArgumentPrefixes      []string           `yaml:"any-argument-prefixes,omitempty"`
	ExcludedArgumentPrefixes []string           `yaml:"excluded-argument-prefixes,omitempty"`
	ArgumentCondition        *ArgumentCondition `yaml:"argument-condition,omitempty"`
	ArgumentAt               *ArgumentAt        `yaml:"argument-at,omitempty"`
	SourceClasses            []string           `yaml:"source-classes,omitempty"`
	DestinationClasses       []string           `yaml:"destination-classes,omitempty"`
	Source                   string             `yaml:"source,omitempty"`
	Destination              string             `yaml:"destination,omitempty"`
	RemoteOperands           string             `yaml:"remote-operands,omitempty"`
}

type ArgumentCondition struct {
	AfterSubcommand bool     `yaml:"after-subcommand,omitempty"`
	StartPosition   int      `yaml:"start-position,omitempty"`
	AnyClasses      []string `yaml:"any-classes"`
}

type ArgumentAt struct {
	Position int      `yaml:"position"`
	Values   []string `yaml:"values"`
}

type FileCommandRule struct {
	ID             string              `yaml:"id"`
	Commands       []string            `yaml:"commands"`
	Match          CommandMatch        `yaml:"match,omitempty"`
	Options        []OptionSpec        `yaml:"options,omitempty"`
	Operands       []OperandRule       `yaml:"operands,omitempty"`
	OptionOperands []OptionOperandRule `yaml:"option-operands,omitempty"`
}

type OperandRule struct {
	Selector string `yaml:"selector"`
	Access   string `yaml:"access"`
}

type OptionOperandRule struct {
	Options []OptionSpec `yaml:"options"`
	Access  string       `yaml:"access"`
}

type TargetRule struct {
	ID           string   `yaml:"id"`
	Commands     []string `yaml:"commands"`
	Prefixes     []string `yaml:"prefixes"`
	PathClasses  []string `yaml:"path-classes"`
	Capabilities []string `yaml:"capabilities"`
}

type InterpreterRule struct {
	ID         string       `yaml:"id"`
	Commands   []string     `yaml:"commands"`
	Options    []OptionSpec `yaml:"options"`
	Capability string       `yaml:"capability"`
}

type UploadRule struct {
	ID         string       `yaml:"id"`
	Commands   []string     `yaml:"commands"`
	Options    []OptionSpec `yaml:"options"`
	Capability string       `yaml:"capability"`
}

type OptionSpec struct {
	Name        string   `yaml:"name"`
	ValueStyles []string `yaml:"value-styles"`
	Values      []string `yaml:"values,omitempty"`
}

type OperationRule struct {
	ID                string   `yaml:"id"`
	OperationKinds    []string `yaml:"operation-kinds"`
	CommandResolution string   `yaml:"command-resolution,omitempty"`
	Capabilities      []string `yaml:"capabilities"`
}

type PathClass struct {
	VariableNames           []string `yaml:"variable-names,omitempty"`
	Exact                   []string `yaml:"exact,omitempty"`
	Prefixes                []string `yaml:"prefixes,omitempty"`
	Contains                []string `yaml:"contains,omitempty"`
	CaseInsensitiveContains []string `yaml:"case-insensitive-contains,omitempty"`
	Suffixes                []string `yaml:"suffixes,omitempty"`
}

type PathCapability struct {
	Read  *CapabilityRule `yaml:"read,omitempty"`
	Write *CapabilityRule `yaml:"write,omitempty"`
}

type CapabilityRule struct {
	ID         string `yaml:"id"`
	Capability string `yaml:"capability"`
}
