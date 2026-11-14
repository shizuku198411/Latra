package interfaceexposure

import (
	"github.com/shizuku198411/Latra/internal/interfacegraph"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
	"testing"
)

func TestReviewRetainsWorkshopAndUncertainty(t *testing.T) {
	c := source.Configuration{Name: "dev", Definition: ".workshop/dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "project-a", Order: 0, Plugs: map[string]any{"new": map[string]any{"interface": "tunnel", "endpoint": "[::1]:80"}}}, {Name: "unknown", Order: 1}}}
	items := []sdk.SDK{{Metadata: &sdk.Metadata{Plugs: map[string]any{"secret": map[string]any{"interface": "secret"}, "cache": map[string]any{"interface": "mount", "read-only": true}}}, Declarations: []sdk.Declaration{{Definition: c.Definition, Order: 0}}}}
	graph := interfacegraph.Graph{Edges: []interfacegraph.Edge{{State: "Unresolved", From: interfacegraph.Endpoint{SDK: "project-a", Name: "secret", Kind: "plug"}}}}
	r := Build(c, items, graph)
	if len(r.Items) != 3 || !r.Incomplete {
		t.Fatalf("review: %+v", r)
	}
	for _, i := range r.Items {
		if i.Workshop != "dev" || i.State != "declared" {
			t.Fatalf("item: %+v", i)
		}
		if i.Name == "secret" && len(i.Related) != 1 {
			t.Fatalf("missing edge: %+v", i)
		}
	}
	c.Definition = ".workshop/other.yaml"
	r = Build(c, items, graph)
	if !r.Incomplete || len(r.Items) != 1 {
		t.Fatalf("cross-workshop metadata: %+v", r)
	}
}
func TestUnknownAndEmpty(t *testing.T) {
	c := source.Configuration{SDKs: []source.ConfigurationSDK{{Name: "system", Slots: map[string]any{"mystery": 42}}}}
	r := Build(c, nil, interfacegraph.Graph{})
	if !r.Incomplete || len(r.Items) != 1 || r.Items[0].State != "not evaluated" {
		t.Fatal(r)
	}
	r = Build(source.Configuration{}, nil, interfacegraph.Graph{})
	if r.Incomplete || len(r.Items) != 0 {
		t.Fatal(r)
	}
}

func TestStartupCandidatesAcrossDeclarations(t *testing.T) {
	c := source.Configuration{Name: "dev", Definition: "dev.yaml", SDKs: []source.ConfigurationSDK{
		{Name: "project-app", Order: 0},
		{Name: "system", Order: 1, Slots: map[string]any{"key": map[string]any{"interface": "secret"}}},
	}}
	sdks := []sdk.SDK{{Metadata: &sdk.Metadata{Plugs: map[string]any{
		"cache": map[string]any{"interface": "mount", "workshop-target": "/cache"},
		"token": map[string]any{"interface": "secret"},
	}}, Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 0}}}}
	r := Build(c, sdks, interfacegraph.Build(c, sdks))
	items := map[string]Item{}
	for _, item := range r.Items {
		items[item.Name] = item
	}
	if items["cache"].Startup != "Auto-connect candidate" || items["cache"].Target != "system:mount" {
		t.Fatalf("cache: %+v", items["cache"])
	}
	if items["token"].Startup != "Manual required" || items["token"].Target != "system:key" || items["token"].Basis != "Declared slots (not selected)" {
		t.Fatalf("secret: %+v", items["token"])
	}
}

func TestBuiltInManualSlotsSharedInReview(t *testing.T) {
	config := source.Configuration{Name: "dev", Definition: "dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "project-app", Order: 0}}}
	items := []sdk.SDK{{Metadata: &sdk.Metadata{Plugs: map[string]any{"camera": map[string]any{"interface": "camera"}, "token": map[string]any{"interface": "secret"}}}, Declarations: []sdk.Declaration{{Definition: "dev.yaml", Order: 0}}}}
	review := Build(config, items, interfacegraph.Graph{})
	var camera, slot bool
	for _, item := range review.Items {
		if item.Kind == "Plug" && item.Name == "camera" {
			camera = item.Target == "system:camera" && item.Basis == BasisSystemSlot && item.Startup == StartupManual
		}
		if item.Kind == "Slot" && item.SDK == "system" && item.Name == "camera" {
			slot = item.Source == "System-provided"
		}
		if item.Kind == "Slot" && item.Type == "secret" {
			t.Fatal("secret slot must not be invented")
		}
	}
	if !camera || !slot {
		t.Fatalf("missing built-in candidate: %+v", review.Items)
	}
	if len(WithBuiltInManualSlots(review).Items) != len(review.Items) {
		t.Fatal("builtin slot augmentation must be idempotent")
	}
}
