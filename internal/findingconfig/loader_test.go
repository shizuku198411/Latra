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
	if config.SchemaVersion != "2" || config.ContentVersion == "" {
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
	_, err := findingconfig.Parse([]byte("schema-version: '2'\ncontent-version: test\nunknown: true\n"))
	if err == nil {
		t.Fatal("expected strict decoding error")
	}
}

func TestParseAcceptsHookContextConstraints(t *testing.T) {
	t.Parallel()
	config, err := findingconfig.Parse([]byte(`
schema-version: "2"
content-version: test
finding-rules:
  - id: risk.context-test
    kind: risk
    family: lifecycle-misuse
    title: Context test
    severity: high
    confidence: high
    weight: 50
    match:
      type: capability
      capabilities:
        - project-write
      hook-names:
        - check-health
      run-as-root: true
      project-mounted: true
      interfaces-active: true
      state-mounted: false
      context-dependent: false
    message: Context is matched.
`))
	if err != nil {
		t.Fatal(err)
	}
	matcher := config.Rules[0].Matcher
	if matcher.RunAsRoot == nil || !*matcher.RunAsRoot || matcher.ProjectMounted == nil || !*matcher.ProjectMounted || matcher.StateMounted == nil || *matcher.StateMounted {
		t.Fatalf("matcher = %#v", matcher)
	}
}

func TestParseRejectsHookContextOnSDKMatcher(t *testing.T) {
	t.Parallel()
	_, err := findingconfig.Parse([]byte(`
schema-version: "2"
content-version: test
finding-rules:
  - id: risk.invalid-context
    kind: risk
    family: analysis-gap
    title: Invalid context
    severity: high
    confidence: high
    weight: 50
    match:
      type: sdk-unresolved
      project-mounted: true
    message: Invalid SDK matcher context.
`))
	if err == nil {
		t.Fatal("expected SDK-level matcher context to be rejected")
	}
}
