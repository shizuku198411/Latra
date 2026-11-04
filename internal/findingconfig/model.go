// Package findingconfig loads and validates Latra's embedded finding rules.
package findingconfig

type Config struct {
	SchemaVersion  string `yaml:"schema-version"`
	ContentVersion string `yaml:"content-version"`
	Rules          []Rule `yaml:"finding-rules"`
}

type Rule struct {
	ID              string   `yaml:"id"`
	Kind            string   `yaml:"kind"`
	Family          string   `yaml:"family"`
	Title           string   `yaml:"title"`
	Severity        string   `yaml:"severity,omitempty"`
	Strength        string   `yaml:"strength,omitempty"`
	Confidence      string   `yaml:"confidence"`
	Weight          int      `yaml:"weight"`
	Matcher         Matcher  `yaml:"match"`
	Message         string   `yaml:"message"`
	Remediation     string   `yaml:"remediation,omitempty"`
	ProtectsAgainst []string `yaml:"protects-against,omitempty"`
	Limitations     []string `yaml:"limitations,omitempty"`
}

type Matcher struct {
	Type                      string   `yaml:"type"`
	Capabilities              []string `yaml:"capabilities,omitempty"`
	HookNames                 []string `yaml:"hook-names,omitempty"`
	RunAsRoot                 *bool    `yaml:"run-as-root,omitempty"`
	ProjectMounted            *bool    `yaml:"project-mounted,omitempty"`
	InterfacesActive          *bool    `yaml:"interfaces-active,omitempty"`
	StateMounted              *bool    `yaml:"state-mounted,omitempty"`
	ContextDependent          *bool    `yaml:"context-dependent,omitempty"`
	ParseStatuses             []string `yaml:"parse-statuses,omitempty"`
	DiagnosticCodes           []string `yaml:"diagnostic-codes,omitempty"`
	DiagnosticMessageContains []string `yaml:"diagnostic-message-contains,omitempty"`
	RelationKinds             []string `yaml:"relation-kinds,omitempty"`
	SourceCapability          string   `yaml:"source-capability,omitempty"`
	SinkCommands              []string `yaml:"sink-commands,omitempty"`
	PathClasses               []string `yaml:"path-classes,omitempty"`
}
