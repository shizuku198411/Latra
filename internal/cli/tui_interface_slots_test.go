package cli

import (
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/interfaceexposure"
)

func TestInterfaceSlotsGroupCandidatesAndUnresolved(t *testing.T) {
	review := interfaceexposure.Review{Items: []interfaceexposure.Item{
		{Kind: "Slot", SDK: "provider", Name: "data", Type: "mount", Source: "SDK"},
		{Kind: "Slot", SDK: "provider", Name: "metrics", Type: "tunnel", Source: "SDK"},
		{Kind: "Plug", SDK: "app", Name: "cache", Type: "mount", Startup: "Auto-connect candidate", Target: "system:mount", Basis: "Default auto-connect policy"},
		{Kind: "Plug", SDK: "other", Name: "cache", Type: "mount", Startup: "Auto-connect candidate", Target: "system:mount", Basis: "Default auto-connect policy"},
		{Kind: "Plug", SDK: "app", Name: "unknown", Type: "mount", Startup: "Unknown", Target: "provider:data"},
	}}
	nodes := tuiInterfaceSlotNodes(review)
	var names []string
	for _, n := range nodes {
		names = append(names, n.Name)
	}
	view := strings.Join(names, "\n")
	if strings.Count(view, "system:mount") != 1 || !strings.Contains(view, "app:cache") || !strings.Contains(view, "other:cache") || !strings.Contains(view, "No known plug candidate") || !strings.Contains(view, "[Plugs without a resolved slot]") || !strings.Contains(view, "app:unknown") {
		t.Fatalf("unexpected tree:\n%s", view)
	}
	for _, n := range nodes {
		if n.Review != nil && n.Review.Name == "unknown" && n.SlotRef != "" {
			t.Fatal("unknown plug attached to slot")
		}
	}
}

func TestInterfaceSlotsManualCandidatesAreNotSelected(t *testing.T) {
	review := interfaceexposure.Review{Items: []interfaceexposure.Item{
		{Kind: "Slot", SDK: "system", Name: "one", Type: "secret", Source: "Workshop"},
		{Kind: "Slot", SDK: "system", Name: "two", Type: "secret", Source: "Workshop"},
		{Kind: "Plug", SDK: "app", Name: "key", Type: "secret", Startup: "Manual required", Target: "system:one, system:two", Basis: "Declared slots (not selected)"},
	}}
	nodes := tuiInterfaceSlotNodes(review)
	count := 0
	for _, node := range nodes {
		if node.Review != nil && node.Review.Name == "key" {
			count++
			if !strings.Contains(node.Name, "not selected") {
				t.Fatalf("misleading candidate: %+v", node)
			}
		}
	}
	if count != 2 {
		t.Fatalf("expected two possible slots, got %d", count)
	}
}
