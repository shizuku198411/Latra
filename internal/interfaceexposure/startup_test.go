package interfaceexposure

import (
	"github.com/shizuku198411/Latra/internal/interfacegraph"
	"testing"
)

func TestStartupPolicy(t *testing.T) {
	tests := []struct {
		name         string
		item         Item
		edges        []interfacegraph.Edge
		want, target string
	}{
		{"mount default", Item{SDK: "app", Kind: "Plug", Name: "cache", Type: "mount", State: "declared", Value: `{"workshop-target":"/cache"}`}, nil, "Auto-connect candidate", "system:mount"},
		{"secret explicit", Item{SDK: "app", Kind: "Plug", Name: "key", Type: "secret", State: "declared"}, []interfacegraph.Edge{{Kind: "connection", State: "Configured", From: interfacegraph.Endpoint{SDK: "app", Name: "key"}, To: interfacegraph.Endpoint{SDK: "system", Reference: ":key"}}}, "Manual required", ":key"},
		{"unsupported tunnel", Item{SDK: "app", Kind: "Plug", Name: "api", Type: "tunnel", State: "declared"}, []interfacegraph.Edge{{Kind: "connection", State: "Configured", From: interfacegraph.Endpoint{SDK: "app", Name: "api"}, To: interfacegraph.Endpoint{SDK: "provider", Reference: "provider:api"}}}, "Invalid", "provider:api"},
		{"external tunnel", Item{SDK: "system", Kind: "Plug", Name: "api", Type: "tunnel", State: "declared", Value: `{"endpoint":"0.0.0.0:8080"}`}, []interfacegraph.Edge{{Kind: "connection", State: "Configured", From: interfacegraph.Endpoint{SDK: "system", Name: "api"}, To: interfacegraph.Endpoint{SDK: "provider", Reference: "provider:api"}}}, "Manual required", "provider:api"},
		{"unresolved", Item{SDK: "app", Kind: "Plug", Name: "x", Type: "mount", State: "declared", Value: `{"workshop-target":"/x"}`}, []interfacegraph.Edge{{Kind: "connection", State: "Unresolved", From: interfacegraph.Endpoint{SDK: "app", Name: "x"}, To: interfacegraph.Endpoint{Reference: "missing:x"}}}, "Unknown", "missing:x"},
		{"binding", Item{SDK: "app", Kind: "Plug", Name: "x", Type: "mount", State: "declared", Value: `{"workshop-target":"/x"}`}, []interfacegraph.Edge{{Kind: "binding", State: "Bound", From: interfacegraph.Endpoint{SDK: "app", Name: "x"}, To: interfacegraph.Endpoint{Reference: "other:x"}}}, "Delegated", "other:x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.item.Related = tc.edges
			evaluate(&tc.item, nil, interfacegraph.Graph{}, false)
			if tc.item.Startup != tc.want || tc.item.Target != tc.target {
				t.Fatalf("got %+v", tc.item)
			}
		})
	}
}

func TestTunnelEndpointPolicy(t *testing.T) {
	for _, tc := range []struct {
		raw            string
		allowed, known bool
	}{{`{}`, true, true}, {`{"endpoint":"127.0.0.1:80"}`, true, true}, {`{"endpoint":"[::1]:80"}`, true, true}, {`{"endpoint":"/tmp/a"}`, true, true}, {`{"endpoint":"0.0.0.0:80"}`, false, true}, {`{"endpoint":"$DYNAMIC"}`, false, false}, {`{"endpoint":123}`, false, false}} {
		allowed, known := loopbackEndpoint(tc.raw)
		if allowed != tc.allowed || known != tc.known {
			t.Errorf("%s: %v %v", tc.raw, allowed, known)
		}
	}
}

func TestBindingShowsTargetPlugOutcome(t *testing.T) {
	items := []Item{
		{SDK: "app", Kind: "Plug", Name: "shared", Startup: "Delegated", Related: []interfacegraph.Edge{{Kind: "binding", State: "Bound", From: interfacegraph.Endpoint{SDK: "app", Name: "shared"}, To: interfacegraph.Endpoint{SDK: "provider", Name: "cache"}}}},
		{SDK: "provider", Kind: "Plug", Name: "cache", Startup: "Auto-connect candidate", Target: "system:mount", Basis: "Default auto-connect policy", Reason: "Default slot"},
	}
	resolveBindings(items)
	if items[0].ViaTarget != "system:mount" || items[0].ViaStartup != "Auto-connect candidate" {
		t.Fatalf("binding: %+v", items[0])
	}
	items[1].Startup = "Manual required"
	items[1].Target = "system:key"
	items[1].Basis = "Declared slots (not selected)"
	resolveBindings(items)
	if items[0].ViaStartup != "Manual required" || items[0].ViaTarget != "" {
		t.Fatalf("unselected slot presented as target: %+v", items[0])
	}
	resolveBindings(items[:1])
	if items[0].ViaStartup != "Unknown" {
		t.Fatalf("missing target: %+v", items[0])
	}
}
