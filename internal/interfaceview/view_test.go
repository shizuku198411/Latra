package interfaceview

import (
	"github.com/shizuku198411/Latra/internal/sdk"
	"strings"
	"testing"
)

func TestEntriesPreserveDeclarations(t *testing.T) {
	metadata := &sdk.Metadata{Plugs: map[string]any{"key": map[string]any{"interface": "secret"}}}
	declarations := []sdk.Declaration{{Workshop: "dev", Definition: ".workshop/dev.yaml", Plugs: map[string]any{"key": "mount", "camera": nil, "bound": map[string]any{"bind": "other:plug"}, "invalid": 42}}}
	entries := Entries(metadata, "sdk.yaml", declarations)
	if len(entries) != 5 {
		t.Fatalf("entries: %+v", entries)
	}
	found := map[string]Entry{}
	for _, e := range entries {
		found[e.Source+":"+e.Name] = e
	}
	if found["SDK:key"].Type != "secret" || found["Workshop:key"].Type != "mount" || found["Workshop:camera"].Type != "camera" || found["Workshop:bound"].Form != "binding" || found["Workshop:invalid"].Form != "uninterpreted" {
		t.Fatalf("entries: %+v", entries)
	}
	if strings.Contains(Safe("x\x1b\n"), "\x1b") {
		t.Fatal("escape retained")
	}
}
