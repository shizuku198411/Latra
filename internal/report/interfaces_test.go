package report

import (
	"bytes"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
	"strings"
	"testing"
)

func TestInterfaceDeclarationsInTextForUnresolvedSDK(t *testing.T) {
	result := &source.Result{Kind: source.InputProject, SDKs: []sdk.SDK{{Name: "remote", Source: sdk.SourceStore, State: sdk.StateNotResolved, Declarations: []sdk.Declaration{{Workshop: "dev", Definition: ".workshop/dev.yaml", Plugs: map[string]any{"camera": nil}}}}}}
	for _, write := range []func(*bytes.Buffer) error{func(b *bytes.Buffer) error { return WriteTextSummary(b, result) }, func(b *bytes.Buffer) error { return WriteText(b, result) }} {
		var b bytes.Buffer
		if err := write(&b); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"SDK declarations: unavailable", "camera", "Workshop: dev", "connection not inspected"} {
			if !strings.Contains(strings.ToLower(b.String()), strings.ToLower(want)) {
				t.Fatalf("missing %q in %s", want, b.String())
			}
		}
	}
}
