package findingconfig_test

import (
	"testing"

	"github.com/shizuku198411/Latra/internal/findingconfig"
)

func TestDefaultIsValidAndSplitAcrossKinds(t *testing.T) {
	t.Parallel()
	config, err := findingconfig.Default()
	if err != nil {
		t.Fatal(err)
	}
	if config.SchemaVersion != "1" || config.ContentVersion == "" {
		t.Fatalf("versions = %q, %q", config.SchemaVersion, config.ContentVersion)
	}
	kinds := map[string]int{}
	for _, rule := range config.Rules {
		kinds[rule.Kind]++
	}
	if kinds["risk"] == 0 || kinds["assurance"] == 0 {
		t.Fatalf("rule kinds = %#v", kinds)
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	t.Parallel()
	_, err := findingconfig.Parse([]byte("schema-version: '1'\ncontent-version: test\nunknown: true\n"))
	if err == nil {
		t.Fatal("expected strict decoding error")
	}
}
