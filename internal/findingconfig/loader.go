package findingconfig

import (
	"bytes"
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"

	"go.yaml.in/yaml/v3"
)

const SourceEmbeddedDefault = "embedded-default"

//go:embed default/*.yaml
var defaultFiles embed.FS

var defaultOnce sync.Once
var defaultConfig *Config
var defaultError error

func Default() (*Config, error) {
	defaultOnce.Do(func() { defaultConfig, defaultError = loadDefault() })
	return defaultConfig, defaultError
}

func MustDefault() *Config {
	config, err := Default()
	if err != nil {
		panic(fmt.Sprintf("invalid embedded finding configuration: %v", err))
	}
	return config
}

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

func loadDefault() (*Config, error) {
	paths, err := fs.Glob(defaultFiles, "default/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("list embedded finding configuration: %w", err)
	}
	sort.Strings(paths)
	merged := &Config{}
	for _, path := range paths {
		content, err := defaultFiles.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %q: %w", path, err)
		}
		fragment, err := decode(content)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if fragment.SchemaVersion != "" {
			if merged.SchemaVersion != "" {
				return nil, fmt.Errorf("%s: duplicate schema version", path)
			}
			merged.SchemaVersion = fragment.SchemaVersion
			merged.ContentVersion = fragment.ContentVersion
		}
		merged.Rules = append(merged.Rules, fragment.Rules...)
	}
	if err := validate(merged); err != nil {
		return nil, err
	}
	return merged, nil
}

func decode(content []byte) (*Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(content))
	decoder.KnownFields(true)
	var config Config
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode finding configuration: %w", err)
	}
	return &config, nil
}

var identifierPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)

func validate(config *Config) error {
	if config.SchemaVersion != "2" || strings.TrimSpace(config.ContentVersion) == "" {
		return fmt.Errorf("unsupported or incomplete finding configuration version %q", config.SchemaVersion)
	}
	if len(config.Rules) == 0 {
		return fmt.Errorf("finding rules are empty")
	}
	seen := make(map[string]bool)
	validMatchers := map[string]bool{
		"capability": true, "unknown-command": true, "parse-status": true,
		"sdk-unresolved": true, "sdk-diagnostic": true, "all-hooks-parsed": true,
		"all-commands-known": true, "absence-capability": true, "archive-digest": true,
		"complete-file-inventory": true, "read-only-health-check": true,
		"relation-flow": true, "path-write": true,
	}
	for _, rule := range config.Rules {
		if !identifierPattern.MatchString(rule.ID) || seen[rule.ID] {
			return fmt.Errorf("invalid or duplicate finding rule ID %q", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Kind != "risk" && rule.Kind != "assurance" {
			return fmt.Errorf("rule %q has invalid kind %q", rule.ID, rule.Kind)
		}
		if !identifierPattern.MatchString(rule.Family) || strings.TrimSpace(rule.Title) == "" || strings.TrimSpace(rule.Message) == "" {
			return fmt.Errorf("rule %q has incomplete metadata", rule.ID)
		}
		if rule.Kind == "risk" && !contains([]string{"info", "low", "medium", "high", "critical"}, rule.Severity) {
			return fmt.Errorf("rule %q has invalid severity %q", rule.ID, rule.Severity)
		}
		if rule.Kind == "assurance" && !contains([]string{"info", "low", "medium", "high"}, rule.Strength) {
			return fmt.Errorf("rule %q has invalid strength %q", rule.ID, rule.Strength)
		}
		if !contains([]string{"low", "medium", "high"}, rule.Confidence) || rule.Weight < 0 || rule.Weight > 100 {
			return fmt.Errorf("rule %q has invalid confidence or weight", rule.ID)
		}
		if !validMatchers[rule.Matcher.Type] {
			return fmt.Errorf("rule %q has invalid matcher %q", rule.ID, rule.Matcher.Type)
		}
		if err := validateMatcherContext(rule); err != nil {
			return err
		}
	}
	return nil
}

func validateMatcherContext(rule Rule) error {
	for _, name := range rule.Matcher.HookNames {
		if !contains([]string{"setup-base", "setup-project", "check-health", "save-state", "restore-state"}, name) {
			return fmt.Errorf("rule %q has invalid hook name %q", rule.ID, name)
		}
	}
	hasContext := rule.Matcher.RunAsRoot != nil || rule.Matcher.ProjectMounted != nil ||
		rule.Matcher.InterfacesActive != nil || rule.Matcher.StateMounted != nil || rule.Matcher.ContextDependent != nil
	if !hasContext && len(rule.Matcher.HookNames) == 0 {
		return nil
	}
	sdkMatchers := []string{"sdk-unresolved", "sdk-diagnostic", "all-hooks-parsed", "all-commands-known", "archive-digest", "complete-file-inventory"}
	if contains(sdkMatchers, rule.Matcher.Type) {
		return fmt.Errorf("rule %q applies hook context to SDK-level matcher %q", rule.ID, rule.Matcher.Type)
	}
	return nil
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}
