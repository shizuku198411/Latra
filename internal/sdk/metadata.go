package sdk

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

const maxSDKNameLength = 40

var sdkNamePattern = regexp.MustCompile(`^(?:[a-z0-9]-?)*[a-z](?:-?[a-z0-9])*$`)

var allowedBases = []string{"ubuntu@20.04", "ubuntu@22.04", "ubuntu@24.04", "ubuntu@26.04"}

var allowedArchitectures = []string{
	"all", "amd64", "arm64", "armhf", "i386", "powerpc", "ppc64", "ppc64el", "riscv64", "s390x",
}

// UnmarshalYAML accepts either one string or a sequence of strings.
func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var value string
		if err := node.Decode(&value); err != nil {
			return err
		}
		*s = StringList{value}
		return nil
	case yaml.SequenceNode:
		var values []string
		if err := node.Decode(&values); err != nil {
			return err
		}
		*s = values
		return nil
	default:
		return fmt.Errorf("must be a string or a sequence of strings")
	}
}

func decodeMetadata(content []byte) (*Metadata, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	decoder.KnownFields(true)

	var metadata Metadata
	if err := decoder.Decode(&metadata); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, fmt.Errorf("multiple YAML documents are not supported")
		}
		return nil, err
	}
	if err := validateMetadata(&metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func validateMetadata(metadata *Metadata) error {
	if err := ValidateName(metadata.Name); err != nil {
		return err
	}
	if metadata.Base != "" && !slices.Contains(allowedBases, metadata.Base) {
		return fmt.Errorf("invalid SDK base %q", metadata.Base)
	}
	if metadata.Architecture != "" && !slices.Contains(allowedArchitectures, metadata.Architecture) {
		return fmt.Errorf("invalid SDK architecture %q", metadata.Architecture)
	}
	if metadata.Type != "" && metadata.Type != "regular" {
		return fmt.Errorf("invalid SDK type %q", metadata.Type)
	}
	if metadata.BuiltAt != "" {
		if _, err := time.Parse(time.RFC3339Nano, metadata.BuiltAt); err != nil {
			return fmt.Errorf("invalid sdkcraft-started-at: %w", err)
		}
	}
	return nil
}

// ValidateName applies the SDK name rules used by Workshop v0.9.9.
func ValidateName(name string) error {
	if name == "agent" || name == "system" || name == "sketch" || strings.HasPrefix(name, "try-") || strings.HasPrefix(name, "project-") {
		return fmt.Errorf("%q is a reserved SDK name", name)
	}
	if !sdkNamePattern.MatchString(name) {
		return fmt.Errorf("invalid SDK name %q", name)
	}
	if len(name) > maxSDKNameLength {
		return fmt.Errorf("SDK name %q too long", name)
	}
	return nil
}
