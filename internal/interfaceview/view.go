// Package interfaceview describes static interface declarations for display.
package interfaceview

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/shizuku198411/Latra/internal/sdk"
)

type Entry struct{ Kind, Name, Type, Source, Workshop, Definition, MetadataPath, Form, Value string }

// Safe removes terminal controls from untrusted text.
func Safe(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '�'
		}
		return r
	}, s)
}

// Entries preserves SDK and Workshop declarations separately.
func Entries(metadata *sdk.Metadata, metadataPath string, declarations []sdk.Declaration) []Entry {
	var entries []Entry
	add := func(kind, source, workshop, definition string, values map[string]any) {
		for name, raw := range values {
			e := Entry{Kind: kind, Name: name, Source: source, Workshop: workshop, Definition: definition, MetadataPath: metadataPath, Form: "uninterpreted"}
			switch v := raw.(type) {
			case nil:
				if source == "Workshop" {
					e.Type, e.Form = name, "inline"
				}
			case string:
				if source == "Workshop" {
					e.Type, e.Form = v, "inline"
				}
			case map[string]any:
				if binding, ok := v["bind"].(string); ok && kind == "Plug" && source == "Workshop" && len(v) == 1 {
					e.Type, e.Form = binding, "binding"
				} else if t, ok := v["interface"].(string); ok && t != "" {
					if _, binding := v["bind"]; !binding {
						e.Type, e.Form = t, "inline"
					}
				}
			}
			b, err := json.Marshal(raw)
			if err != nil {
				e.Value = fmt.Sprintf("<uninterpreted %T>", raw)
			} else {
				e.Value = string(b)
			}
			if len(e.Value) > 8192 {
				e.Value = e.Value[:8192] + "… (truncated)"
			}
			entries = append(entries, e)
		}
	}
	if metadata != nil {
		add("Plug", "SDK", "", "", metadata.Plugs)
		add("Slot", "SDK", "", "", metadata.Slots)
	}
	for _, d := range declarations {
		add("Plug", "Workshop", d.Workshop, d.Definition, d.Plugs)
		add("Slot", "Workshop", d.Workshop, d.Definition, d.Slots)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		a, b := entries[i], entries[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Workshop != b.Workshop {
			return a.Workshop < b.Workshop
		}
		return a.Definition < b.Definition
	})
	return entries
}
func (e Entry) Label() string {
	t := e.Type
	if e.Form == "binding" {
		t = "bind → " + t
	}
	if e.Form == "uninterpreted" {
		t = "uninterpreted"
	}
	origin := e.Source
	if e.Workshop != "" {
		origin += ": " + e.Workshop
	}
	return Safe(fmt.Sprintf("%s  %s  [%s]", e.Name, t, origin))
}
func (e Entry) Details() []string {
	origin := e.Source
	if e.Source == "SDK" {
		origin += " (" + e.MetadataPath + ")"
	} else {
		origin += ": " + e.Workshop + " (" + e.Definition + ")"
	}
	return []string{Safe("Interface: " + e.Name), Safe("Kind: " + e.Kind), Safe("Type: " + e.Type), Safe("Declared by: " + origin), Safe("Form: " + e.Form), Safe("Declared value: " + e.Value), "Connection: Not inspected (static view)"}
}
