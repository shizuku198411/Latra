// Package interfaceexposure produces unscored reviews of static declarations.
package interfaceexposure

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/interfacegraph"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
)

// Startup and basis values are shared by analysis and presentation.
const (
	StartupAuto          = "Auto-connect candidate"
	StartupManual        = "Manual required"
	StartupDelegated     = "Delegated"
	BasisUnselectedSlots = "Declared slots (not selected)"
	BasisSystemSlot      = "System-provided slot (not selected)"
)

type Item struct {
	ID, Workshop, Definition, SDK, Kind, Name, Source, Type, State, Fact, Value, Limitation string
	Target, Startup, Basis, Reason                                                          string
	ViaTarget, ViaStartup, ViaReason                                                        string
	Related                                                                                 []interfacegraph.Edge
}
type Review struct {
	Workshop, Definition string
	Items                []Item
	Incomplete           bool
}

// EdgePolicy returns the static startup classification for an explicit connection.
func EdgePolicy(reviews []Review, definition string, edge interfacegraph.Edge) (string, string) {
	if edge.Kind != "connection" {
		return "", ""
	}
	for _, review := range reviews {
		if review.Definition != definition {
			continue
		}
		for _, item := range review.Items {
			if item.Kind == "Plug" && item.SDK == edge.From.SDK && item.Name == edge.From.Name {
				return item.Startup, item.Reason
			}
		}
	}
	return "Unknown", "Plug declaration is unavailable"
}

// Build reviews only declared facts; it never inspects runtime state or scores.
func Build(config source.Configuration, sdks []sdk.SDK, graph interfacegraph.Graph) Review {
	out := Review{Workshop: config.Name, Definition: config.Definition, Items: []Item{}, Incomplete: graph.Incomplete}
	for _, edge := range graph.Edges {
		if edge.State == "Unresolved" || edge.State == "Invalid" {
			out.Incomplete = true
		}
	}
	for _, decl := range config.SDKs {
		var item *sdk.SDK
		for i := range sdks {
			for _, usage := range sdks[i].Declarations {
				if usage.Definition == config.Definition && usage.Order == decl.Order {
					item = &sdks[i]
					break
				}
			}
			if item != nil {
				break
			}
		}
		if decl.Name != "system" && (item == nil || item.Metadata == nil) {
			out.Incomplete = true
		}
		if item != nil && item.Metadata != nil {
			add(&out, decl.Name, "SDK", "Plug", item.Metadata.Plugs, graph)
			add(&out, decl.Name, "SDK", "Slot", item.Metadata.Slots, graph)
		}
		add(&out, decl.Name, "Workshop", "Plug", decl.Plugs, graph)
		add(&out, decl.Name, "Workshop", "Slot", decl.Slots, graph)
	}
	for i := range out.Items {
		evaluate(&out.Items[i], out.Items, graph, out.Incomplete)
	}
	out = WithBuiltInManualSlots(out)
	resolveBindings(out.Items)
	sort.SliceStable(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
	return out
}

// WithBuiltInManualSlots adds known system-provided manual targets to a review.
// It is idempotent and does not claim that any candidate is connected.
func WithBuiltInManualSlots(review Review) Review {
	items := append([]Item(nil), review.Items...)
	known := make(map[string]bool)
	for _, item := range items {
		if item.SDK == "system" && item.Kind == "Slot" {
			known[item.Name] = true
		}
	}
	for i := range items {
		item := &items[i]
		if item.Kind != "Plug" || item.SDK == "system" || item.State != "declared" || item.Startup != StartupManual || item.Target != "" {
			continue
		}
		switch item.Type {
		case "camera", "desktop", "ssh-agent":
			if item.Name != item.Type {
				continue
			}
		case "custom-device":
		default:
			continue
		}
		name := item.Type
		item.Target, item.Basis = "system:"+name, BasisSystemSlot
		if !known[name] {
			known[name] = true
			items = append(items, Item{ID: strings.Join([]string{review.Definition, "system", "Slot", name, "System-provided"}, "\x00"), Workshop: review.Workshop, Definition: review.Definition, SDK: "system", Kind: "Slot", Name: name, Type: name, Source: "System-provided", State: "declared", Startup: "Provider declaration", Fact: "Built-in system slot", Limitation: "Runtime connection and per-plug host resources are not inspected"})
		}
	}
	review.Items = items
	return review
}

// Standalone reviews an SDK without inventing Workshop configuration.
func Standalone(item sdk.SDK) Review {
	out := Review{Items: []Item{}, Incomplete: item.Metadata == nil}
	if item.Metadata != nil {
		add(&out, item.Name, "SDK", "Plug", item.Metadata.Plugs, interfacegraph.Graph{})
		add(&out, item.Name, "SDK", "Slot", item.Metadata.Slots, interfacegraph.Graph{})
	}
	for i := range out.Items {
		out.Items[i].Startup = "Not evaluated"
		out.Items[i].Reason = "No Workshop configuration is available"
	}
	sort.SliceStable(out.Items, func(i, j int) bool { return out.Items[i].ID < out.Items[j].ID })
	return out
}

func add(out *Review, owner, origin, kind string, declarations map[string]any, graph interfacegraph.Graph) {
	for name, raw := range declarations {
		typ, state := interpret(name, raw)
		if state == "binding" {
			continue
		} // The SDK plug carries the declaration; the graph retains the binding.
		fact, limitation := description(typ, kind)
		if state != "declared" || fact == "" {
			state = "not evaluated"
			fact = "Interface declaration could not be evaluated"
			limitation = "Interface type or declaration is unknown; runtime state is not inspected"
			out.Incomplete = true
		}
		value, err := json.Marshal(raw)
		if err != nil {
			value = []byte("<uninterpreted>")
			state = "not evaluated"
			out.Incomplete = true
		}
		if len(value) > 8192 {
			value = append(value[:8192], []byte("… (truncated)")...)
		}
		id := strings.Join([]string{out.Definition, owner, kind, name, origin}, "\x00")
		entry := Item{ID: id, Workshop: out.Workshop, Definition: out.Definition, SDK: owner, Kind: kind, Name: name, Source: origin, Type: typ, State: state, Fact: fact, Value: string(value), Limitation: limitation, Related: []interfacegraph.Edge{}}
		for _, edge := range graph.Edges {
			if (edge.From.SDK == owner && edge.From.Name == name && strings.EqualFold(edge.From.Kind, kind)) || (edge.To.SDK == owner && edge.To.Name == name && strings.EqualFold(edge.To.Kind, kind)) {
				entry.Related = append(entry.Related, edge)
			}
		}
		out.Items = append(out.Items, entry)
	}
}
func interpret(name string, raw any) (string, string) {
	switch v := raw.(type) {
	case nil:
		return name, "declared"
	case string:
		if v != "" {
			return v, "declared"
		}
	case map[string]any:
		if _, ok := v["bind"]; ok {
			if len(v) == 1 {
				if _, ok := v["bind"].(string); ok {
					return "", "binding"
				}
			}
			return "", "unknown"
		}
		if t, ok := v["interface"].(string); ok && t != "" {
			return t, "declared"
		}
	}
	return "", "unknown"
}
func description(typ, kind string) (string, string) {
	switch typ {
	case "secret":
		return fmt.Sprintf("Secret %s declared", strings.ToLower(kind)), "Keyring value, access and runtime connection are not inspected"
	case "ssh-agent":
		return "SSH agent interface declared", "Runtime connection and signing operations are not inspected"
	case "mount":
		return "Mount interface declared", "Effective mount, permissions and runtime connection are not inspected; omitted attributes are Workshop-managed"
	case "tunnel":
		return "Tunnel interface declared", "Listening, external exposure and runtime connection are not inspected; omitted endpoint is Workshop-managed"
	case "custom-device", "camera", "gpu", "desktop":
		return fmt.Sprintf("%s interface declared", typ), "Device access and runtime connection are not inspected"
	}
	return "", ""
}
