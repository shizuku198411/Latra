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

func TestInterfaceTunnelEndpoints(t *testing.T) {
	review := interfaceexposure.Review{Items: []interfaceexposure.Item{
		{Kind: "Slot", SDK: "provider", Name: "gdb", Type: "tunnel", Source: "SDK", Value: `{"interface":"tunnel","endpoint":"[::1]:1234/udp"}`},
		{Kind: "Plug", SDK: "system", Name: "gdb", Type: "tunnel", Startup: "Auto-connect candidate", Target: "provider:gdb", Value: `{"interface":"tunnel","endpoint":"/tmp/gdb.sock"}`},
		{Kind: "Plug", SDK: "system", Name: "other", Type: "tunnel", Startup: "Manual required", Value: `{"interface":"tunnel"}`},
		{Kind: "Slot", SDK: "provider", Name: "invalid", Type: "tunnel", Source: "SDK", Value: `{"endpoint":123}`},
		{Kind: "Slot", SDK: "provider", Name: "control", Type: "tunnel", Source: "SDK", Value: `{"endpoint":"127.0.0.1:1234\u001b[31m"}`},
		{Kind: "Slot", SDK: "provider", Name: "mount", Type: "mount", Source: "SDK", Value: `{"endpoint":"ignore"}`},
	}}
	var names []string
	for _, node := range tuiInterfaceSlotNodes(review) {
		names = append(names, node.Name)
	}
	view := strings.Join(names, "\n")
	for _, want := range []string{"provider:gdb  [SDK]  endpoint: [::1]:1234/udp", "system:gdb  [Auto-connect candidate]  endpoint: /tmp/gdb.sock", "system:other  [Manual required]  endpoint: not specified", "provider:invalid  [SDK]  endpoint: unavailable"} {
		if !strings.Contains(view, want) {
			t.Errorf("missing %q in:\n%s", want, view)
		}
	}
	if strings.Contains(view, "\x1b") || strings.Contains(view, "endpoint: ignore") {
		t.Fatalf("unsafe or non-tunnel endpoint in:\n%s", view)
	}
}
