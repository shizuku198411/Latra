package interfaceexposure

import (
	"encoding/json"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/shizuku198411/Latra/internal/interfacegraph"
)

// resolveBindings attaches the target plug's independently evaluated outcome.
// Invalid or ambiguous bindings are left unresolved; no recursive chain is followed.
func resolveBindings(items []Item) {
	for i := range items {
		item := &items[i]
		if item.Kind != "Plug" || item.Startup != StartupDelegated {
			continue
		}
		item.ViaTarget, item.ViaStartup, item.ViaReason = "", "", ""
		var target *Item
		matches := 0
		for _, edge := range item.Related {
			if edge.Kind != "binding" || edge.State != "Bound" || edge.From.SDK != item.SDK || edge.From.Name != item.Name {
				continue
			}
			for j := range items {
				candidate := &items[j]
				if candidate.Kind == "Plug" && candidate.SDK == edge.To.SDK && candidate.Name == edge.To.Name {
					matches++
					target = candidate
				}
			}
		}
		if matches != 1 {
			item.ViaStartup = "Unknown"
			item.ViaReason = "Target plug declaration is unavailable or ambiguous"
			continue
		}
		item.ViaStartup, item.ViaReason = target.Startup, target.Reason
		if target.Basis != BasisUnselectedSlots && target.Basis != BasisSystemSlot {
			item.ViaTarget = target.Target
		}
	}
}

// evaluate classifies policy candidates, never actual runtime connections.
func evaluate(item *Item, items []Item, graph interfacegraph.Graph, incomplete bool) {
	if item.Kind != "Plug" {
		item.Startup = "Provider declaration"
		item.Reason = "Slot is available as a connection endpoint; runtime state is not inspected"
		return
	}
	item.Startup = "Unknown"
	item.Reason = "Policy or declaration could not be evaluated"
	if item.State != "declared" {
		return
	}
	for _, other := range items {
		if other.ID != item.ID && other.SDK == item.SDK && other.Name == item.Name && other.Kind == item.Kind {
			item.Reason = "Multiple declarations for this endpoint require resolution"
			return
		}
	}
	if item.Type == "mount" {
		var attrs map[string]any
		if json.Unmarshal([]byte(item.Value), &attrs) != nil {
			item.Reason = "Mount attributes could not be evaluated"
			return
		}
		target, ok := attrs["workshop-target"].(string)
		if !ok || target == "" {
			item.Startup = "Invalid"
			item.Reason = "Mount plug requires workshop-target"
			return
		}
	}
	if (item.Type == "gpu" || item.Type == "camera" || item.Type == "desktop" || item.Type == "ssh-agent") && item.Name != item.Type {
		item.Startup = "Invalid"
		item.Reason = "Plug name does not match the required interface name"
		return
	}
	var connections, bindings []interfacegraph.Edge
	for _, edge := range item.Related {
		if edge.From.SDK != item.SDK || edge.From.Name != item.Name {
			continue
		}
		switch edge.Kind {
		case "connection":
			connections = append(connections, edge)
		case "binding":
			bindings = append(bindings, edge)
		}
	}
	if len(bindings) > 0 {
		item.Target, item.Basis = bindings[0].To.Reference, "Binding"
		if len(bindings) > 1 || bindings[0].State == "Invalid" {
			item.Startup = "Invalid"
			item.Reason = "Binding is invalid or conflicts with a connection"
			return
		}
		if bindings[0].State != "Bound" {
			item.Reason = "Binding target could not be resolved"
			return
		}
		item.Startup = StartupDelegated
		item.Reason = "This plug follows the target plug; binding is not a slot connection"
		return
	}
	if len(connections) > 1 {
		item.Target = "Multiple configured targets"
		item.Basis = "Explicit connection"
		item.Reason = "Multiple configured targets require review"
		return
	}
	if len(connections) == 1 {
		e := connections[0]
		item.Target = e.To.Reference
		item.Basis = "Explicit connection"
		if e.State == "Invalid" {
			item.Startup = "Invalid"
			item.Reason = "Configured connection is invalid"
			return
		}
		if e.State != "Configured" {
			item.Reason = "Configured endpoints could not be resolved"
			return
		}
		if item.Type == "secret" || item.Type == "ssh-agent" || item.Type == "camera" || item.Type == "custom-device" || item.Type == "desktop" {
			item.Startup = StartupManual
			item.Reason = "Interface policy does not permit automatic connection"
			return
		}
		if item.Type == "tunnel" && item.SDK != "system" && e.To.SDK != "system" {
			item.Startup = "Invalid"
			item.Reason = "Tunnel connections between regular SDKs are unsupported"
			return
		}
		if item.Type == "tunnel" && item.SDK == "system" && e.To.SDK == "system" {
			item.Startup = "Invalid"
			item.Reason = "Tunnel connections within system SDK are unsupported"
			return
		}
		if item.Type == "tunnel" {
			if item.SDK != "system" {
				item.Startup = StartupManual
				item.Reason = "Automatic tunnel connection requires a system plug"
				return
			}
			allowed, known := loopbackEndpoint(item.Value)
			if !known {
				item.Reason = "Tunnel endpoint could not be evaluated"
				return
			}
			if !allowed {
				item.Startup = StartupManual
				item.Reason = "Tunnel plug endpoint is not loopback or a Unix socket"
				return
			}
		}
		if item.Type == "mount" || item.Type == "gpu" || item.Type == "tunnel" {
			item.Startup = StartupAuto
			item.Reason = "Explicit pairing is eligible for further Workshop policy and endpoint validation"
			return
		}
		return
	}
	switch item.Type {
	case "secret", "ssh-agent", "camera", "custom-device", "desktop":
		item.Startup = StartupManual
		item.Basis = "Interface policy"
		item.Reason = "Interface policy does not permit automatic connection"
		var slots []string
		for _, other := range items {
			if other.Kind == "Slot" && other.Type == item.Type && other.State == "declared" {
				slots = append(slots, other.SDK+":"+other.Name)
			}
		}
		sort.Strings(slots)
		if len(slots) > 0 {
			item.Target = strings.Join(slots, ", ")
			item.Basis = BasisUnselectedSlots
		}
	case "mount":
		if item.SDK == "system" {
			item.Startup = "Invalid"
			item.Reason = "System SDK cannot own a mount plug"
			return
		}
		item.Target = "system:mount"
		item.Basis = "Default auto-connect policy"
		item.Startup = StartupAuto
		item.Reason = "Default system mount slot; Workshop validates the declaration at launch"
	case "gpu":
		if item.SDK == "system" {
			item.Startup = "Invalid"
			item.Reason = "System SDK cannot own a GPU plug"
			return
		}
		item.Target = "system:gpu"
		item.Basis = "Default auto-connect policy"
		item.Startup = StartupAuto
		item.Reason = "Default system GPU slot; Workshop validates the declaration at launch"
	case "tunnel":
		item.Basis = "Auto-connect policy"
		if item.SDK != "system" {
			item.Startup = StartupManual
			item.Reason = "Automatic tunnel connection requires a system plug"
			return
		}
		allowed, known := loopbackEndpoint(item.Value)
		if !known {
			item.Reason = "Tunnel endpoint could not be evaluated"
			return
		}
		if !allowed {
			item.Startup = StartupManual
			item.Reason = "Tunnel plug endpoint is not loopback or a Unix socket"
			return
		}
		var candidates []string
		for _, other := range items {
			if other.SDK != "system" && other.Kind == "Slot" && other.Name == item.Name && other.Type == "tunnel" && other.State == "declared" {
				candidates = append(candidates, other.SDK+":"+other.Name)
			}
		}
		if len(candidates) == 1 && !incomplete {
			item.Target = candidates[0]
			item.Startup = StartupAuto
			item.Reason = "Matching tunnel slot; Workshop validates endpoints at launch"
			return
		}
		if len(candidates) > 1 {
			item.Target = strings.Join(candidates, ", ")
			item.Reason = "Multiple matching slots; selection is not determined"
			return
		}
		if incomplete {
			item.Reason = "SDK inventory or configuration is incomplete"
			return
		}
		item.Startup = "No matching slot"
		item.Reason = "No same-name tunnel slot was declared"
	}
}

// Values come from JSON-encoded YAML; reject unexpected types and dynamic addresses.
func loopbackEndpoint(raw string) (bool, bool) {
	var data map[string]any
	if raw == "null" || raw == `"tunnel"` {
		return true, true
	}
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		return false, false
	}
	value, exists := data["endpoint"]
	if !exists {
		return true, true
	}
	s, ok := value.(string)
	if !ok || s == "" {
		return false, false
	}
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "@") || strings.HasPrefix(s, "$HOME/") || strings.HasPrefix(s, "$XDG_RUNTIME_DIR/") {
		return true, true
	}
	address := strings.SplitN(s, "/", 2)[0]
	if address == "tcp" || address == "udp" {
		return true, true
	}
	if port, err := strconv.Atoi(address); err == nil && port >= 1 && port <= 65535 {
		return true, true
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	if host == "localhost" || host == "ip6-localhost" || host == "ip6-loopback" {
		return true, true
	}
	ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false, false
	}
	return ip.IsLoopback(), true
}
