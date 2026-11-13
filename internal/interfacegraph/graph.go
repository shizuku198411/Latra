// Package interfacegraph resolves explicitly configured interface relationships.
package interfacegraph

import (
	"fmt"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
	"regexp"
	"sort"
	"strings"
)

type Endpoint struct {
	Reference string `json:"reference"`
	SDK       string `json:"sdk,omitempty"`
	Name      string `json:"name,omitempty"`
	Kind      string `json:"kind"`
	Type      string `json:"type,omitempty"`
	Origin    string `json:"origin,omitempty"`
}
type Edge struct {
	Kind        string   `json:"kind"`
	From        Endpoint `json:"from"`
	To          Endpoint `json:"to"`
	State       string   `json:"state"`
	Diagnostics []string `json:"diagnostics"`
	Order       int      `json:"order"`
	Policy      string   `json:"policy"`
}
type Graph struct {
	Workshop   string `json:"workshop"`
	Definition string `json:"definition"`
	Edges      []Edge `json:"edges"`
	Incomplete bool   `json:"incomplete"`
}

const limit = 10000

var referencePart = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

type resolver struct {
	config      source.Configuration
	sdks        []sdk.SDK
	bindings    map[string]any
	connections map[string]bool
}

func Build(config source.Configuration, sdks []sdk.SDK) Graph {
	g := Graph{Workshop: config.Name, Definition: config.Definition, Edges: []Edge{}}
	r := resolver{config: config, sdks: sdks, bindings: map[string]any{}, connections: map[string]bool{}}
	for _, c := range config.Connections {
		from, _, ok := parse(c.Plug)
		if ok {
			r.connections[from] = true
		}
	}
	for _, d := range config.SDKs {
		for name, raw := range d.Plugs {
			if m, ok := raw.(map[string]any); ok {
				if v, exists := m["bind"]; exists {
					r.bindings[d.Name+":"+name] = v
				}
			}
		}
	}
	for _, c := range config.Connections {
		if len(g.Edges) >= limit {
			g.Incomplete = true
			break
		}
		e := Edge{Kind: "connection", State: "Configured", From: Endpoint{Reference: c.Plug, Kind: "plug"}, To: Endpoint{Reference: c.Slot, Kind: "slot"}, Order: c.Order, Policy: "not evaluated", Diagnostics: []string{}}
		r.resolve(&e, false)
		if key, _, ok := parse(c.Plug); ok {
			if _, found := r.bindings[key]; found {
				invalid(&e, "plug has both binding and connection")
			}
		}
		g.Edges = append(g.Edges, e)
	}
	for _, d := range config.SDKs {
		names := make([]string, 0, len(d.Plugs))
		for n := range d.Plugs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			raw, ok := d.Plugs[name].(map[string]any)
			if !ok {
				continue
			}
			target, exists := raw["bind"]
			if !exists {
				continue
			}
			if len(g.Edges) >= limit {
				g.Incomplete = true
				break
			}
			value, valid := target.(string)
			e := Edge{Kind: "binding", State: "Bound", From: Endpoint{Reference: d.Name + ":" + name, Kind: "plug"}, To: Endpoint{Reference: value, Kind: "plug"}, Order: d.Order, Policy: "not evaluated", Diagnostics: []string{}}
			if !valid {
				invalid(&e, "binding target must be a string")
			}
			if len(raw) != 1 {
				invalid(&e, "binding has additional attributes")
			}
			if d.Name == "system" {
				invalid(&e, "system plug cannot be bound")
			}
			r.resolve(&e, true)
			if key, _, ok := parse(value); ok {
				if strings.HasPrefix(key, "system:") {
					invalid(&e, "binding target cannot be system")
				}
				if _, found := r.bindings[key]; found {
					invalid(&e, "binding target is itself bound")
				}
			}
			if r.connections[d.Name+":"+name] {
				invalid(&e, "plug has both binding and connection")
			}
			g.Edges = append(g.Edges, e)
		}
	}
	sort.SliceStable(g.Edges, func(i, j int) bool {
		a, b := g.Edges[i], g.Edges[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.From.Reference != b.From.Reference {
			return a.From.Reference < b.From.Reference
		}
		if a.To.Reference != b.To.Reference {
			return a.To.Reference < b.To.Reference
		}
		return a.Order < b.Order
	})
	return g
}

func parse(ref string) (string, string, bool) {
	s, n, ok := strings.Cut(ref, ":")
	if !ok || !referencePart.MatchString(n) || (s != "" && !referencePart.MatchString(s)) {
		return "", "", false
	}
	if s == "" {
		s = "system"
	}
	return s + ":" + n, n, true
}
func invalid(e *Edge, message string) {
	e.State = "Invalid"
	e.Diagnostics = append(e.Diagnostics, message)
}
func unresolved(e *Edge, message string) {
	if e.State != "Invalid" {
		e.State = "Unresolved"
	}
	e.Diagnostics = append(e.Diagnostics, message)
}
func (r resolver) resolve(e *Edge, binding bool) {
	for _, p := range []*Endpoint{&e.From, &e.To} {
		key, name, ok := parse(p.Reference)
		if !ok {
			invalid(e, "invalid "+p.Kind+" reference")
			continue
		}
		p.Name = name
		p.SDK = strings.TrimSuffix(key, ":"+name)
		typ, origin, state := r.lookup(p.SDK, name, p.Kind, binding && p == &e.From)
		p.Type, p.Origin = typ, origin
		if state == "missing" {
			invalid(e, fmt.Sprintf("%s %s does not exist", p.Kind, key))
		}
		if state == "unknown" {
			unresolved(e, fmt.Sprintf("%s %s could not be verified", p.Kind, key))
		}
		if state == "ambiguous" {
			unresolved(e, fmt.Sprintf("%s %s has ambiguous declarations", p.Kind, key))
		}
	}
	if e.From.Type != "" && e.To.Type != "" && e.From.Type != e.To.Type {
		invalid(e, "interface types do not match")
	}
}
func interfaceType(name string, raw any) string {
	switch v := raw.(type) {
	case nil:
		return name
	case string:
		return v
	case map[string]any:
		t, _ := v["interface"].(string)
		return t
	}
	return ""
}
func (r resolver) lookup(owner, name, kind string, bindingSource bool) (string, string, string) {
	var declaration *source.ConfigurationSDK
	for i := range r.config.SDKs {
		if r.config.SDKs[i].Name == owner {
			declaration = &r.config.SDKs[i]
			break
		}
	}
	if declaration == nil {
		if owner == "system" || owner == "sketch" {
			return "", "", "unknown"
		}
		return "", "", "missing"
	}
	var values map[string]any
	if kind == "plug" {
		values = declaration.Plugs
	} else {
		values = declaration.Slots
	}
	raw, has := values[name]
	if bindingSource {
		has = false
	}
	var item *sdk.SDK
	for i := range r.sdks {
		for _, d := range r.sdks[i].Declarations {
			if d.Definition == r.config.Definition && d.Order == declaration.Order {
				item = &r.sdks[i]
				break
			}
		}
		if item != nil {
			break
		}
	}
	var sdkRaw any
	sdkHas := false
	if item != nil && item.Metadata != nil {
		if kind == "plug" {
			sdkRaw, sdkHas = item.Metadata.Plugs[name]
		} else {
			sdkRaw, sdkHas = item.Metadata.Slots[name]
		}
	}
	if has && sdkHas {
		return "", "", "ambiguous"
	}
	if has {
		t := interfaceType(name, raw)
		if t == "" {
			return "", "Workshop", "unknown"
		}
		return t, "Workshop", ""
	}
	if sdkHas {
		t := interfaceType(name, sdkRaw)
		if t == "" {
			return "", "SDK", "unknown"
		}
		return t, "SDK", ""
	}
	if item == nil || item.Metadata == nil {
		return "", "", "unknown"
	}
	return "", "", "missing"
}
