package interfacegraph

import (
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
	"testing"
)

func TestBuildSeparatesWorkshopsAndReportsUncertainty(t *testing.T) {
	c := source.Configuration{Name: "dev", Definition: ".workshop/dev.yaml", SDKs: []source.ConfigurationSDK{
		{Name: "app", Order: 0, Plugs: map[string]any{"alias": map[string]any{"bind": "provider:mount"}}},
		{Name: "provider", Order: 1}, {Name: "system", Order: 2, Slots: map[string]any{"key": map[string]any{"interface": "secret"}}},
	}, Connections: []source.Connection{{Plug: "app:data", Slot: "provider:data"}, {Plug: "app:key", Slot: ":key", Order: 1}, {Plug: "missing:x", Slot: "provider:data", Order: 2}}}
	items := []sdk.SDK{
		{Metadata: &sdk.Metadata{Plugs: map[string]any{"data": map[string]any{"interface": "mount"}, "key": map[string]any{"interface": "secret"}, "alias": map[string]any{"interface": "mount"}}}, Declarations: []sdk.Declaration{{Definition: c.Definition, Order: 0}}},
		{Metadata: &sdk.Metadata{Plugs: map[string]any{"mount": map[string]any{"interface": "mount"}}, Slots: map[string]any{"data": map[string]any{"interface": "mount"}}}, Declarations: []sdk.Declaration{{Definition: c.Definition, Order: 1}}},
	}
	g := Build(c, items)
	if len(g.Edges) != 4 {
		t.Fatalf("edges: %+v", g.Edges)
	}
	states := map[string]string{}
	for _, e := range g.Edges {
		states[e.From.Reference] = e.State
	}
	if states["app:alias"] != "Bound" || states["app:data"] != "Configured" || states["app:key"] != "Configured" || states["missing:x"] != "Invalid" {
		t.Fatalf("states: %+v", states)
	}
	c.Definition = ".workshop/other.yaml"
	g = Build(c, items)
	for _, e := range g.Edges {
		if e.From.Reference == "app:data" && e.State != "Unresolved" {
			t.Fatalf("cross-workshop metadata used: %+v", e)
		}
	}
}

func TestBindingConflictAndChain(t *testing.T) {
	c := source.Configuration{SDKs: []source.ConfigurationSDK{{Name: "a", Plugs: map[string]any{"x": map[string]any{"bind": "a:y"}, "y": map[string]any{"bind": "a:x"}}}}, Connections: []source.Connection{{Plug: "a:x", Slot: ":mount"}}}
	g := Build(c, nil)
	if len(g.Edges) != 3 {
		t.Fatal(g)
	}
	for _, e := range g.Edges {
		if e.State != "Invalid" {
			t.Fatalf("expected invalid: %+v", e)
		}
	}
}
