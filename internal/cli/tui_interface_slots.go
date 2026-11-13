package cli

import (
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/interfaceexposure"
	"github.com/shizuku198411/Latra/internal/interfaceview"
)

type tuiSlotGroup struct {
	ref, kind string
	slot      interfaceexposure.Item
	plugs     []tuiNode
}

// tuiInterfaceSlotNodes groups static candidates; it does not inspect runtime state.
func tuiInterfaceSlotNodes(review interfaceexposure.Review) []tuiNode {
	var groups []tuiSlotGroup
	indices := map[string][]int{}
	addSlot := func(item interfaceexposure.Item) {
		ref := item.SDK + ":" + item.Name
		indices[ref] = append(indices[ref], len(groups))
		groups = append(groups, tuiSlotGroup{ref: ref, kind: item.Type, slot: item})
	}
	for _, item := range review.Items {
		if item.Kind == "Slot" {
			addSlot(item)
		}
	}
	var unassigned []tuiNode
	for _, item := range review.Items {
		if item.Kind != "Plug" {
			continue
		}
		state, target, basis := item.Startup, item.Target, item.Basis
		if state == "Delegated" {
			state, target, basis = item.ViaStartup, item.ViaTarget, "Binding via "+item.Target
		}
		if state != "Auto-connect candidate" && state != "Manual required" {
			target = ""
		}
		var targets []string
		if target != "" {
			if basis == "Declared slots (not selected)" {
				targets = strings.Split(target, ", ")
			} else {
				targets = []string{target}
			}
		}
		attached := false
		for _, raw := range targets {
			ref := raw
			if strings.HasPrefix(ref, ":") {
				ref = "system" + ref
			}
			if len(indices[ref]) == 0 && (ref == "system:mount" || ref == "system:gpu") {
				typ := strings.TrimPrefix(ref, "system:")
				addSlot(interfaceexposure.Item{SDK: "system", Name: typ, Kind: "Slot", Type: typ, Source: "System-provided", Fact: "Built-in system slot", Limitation: "Runtime connection and per-plug host resources are not inspected"})
			}
			// Ambiguous slot declarations cannot identify a unique destination.
			if len(indices[ref]) != 1 {
				continue
			}
			index := indices[ref][0]
			if groups[index].kind != item.Type {
				continue
			}
			label := item.SDK + ":" + item.Name + "  [" + state + "]"
			if item.Startup == "Delegated" {
				label += " via " + item.Target
			}
			if basis == "Declared slots (not selected)" {
				label += " · possible, not selected"
			}
			entry := item
			groups[index].plugs = append(groups[index].plugs, tuiNode{Kind: "exposure-review", Depth: 1, Name: interfaceview.Safe("└─ " + label), Review: &entry, SlotRef: ref, SlotBasis: basis})
			attached = true
		}
		if !attached {
			entry := item
			label := item.SDK + ":" + item.Name + "  [" + item.Startup + "]"
			if item.Startup == "Delegated" {
				label += " via " + item.Target + " [" + item.ViaStartup + "]"
			}
			unassigned = append(unassigned, tuiNode{Kind: "exposure-review", Name: interfaceview.Safe(label), Review: &entry})
		}
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].kind != groups[j].kind {
			return groups[i].kind < groups[j].kind
		}
		return groups[i].ref < groups[j].ref
	})
	nodes := []tuiNode{}
	if review.Incomplete {
		nodes = append(nodes, tuiNode{Header: true, Name: "Some interface information could not be evaluated"})
	}
	lastKind := ""
	for _, group := range groups {
		kind := group.kind
		if kind == "" {
			kind = "Unknown interface"
		}
		if kind != lastKind {
			nodes = append(nodes, tuiNode{Header: true, Name: "[" + interfaceview.Safe(kind) + "]"})
			lastKind = kind
		}
		slot := group.slot
		children := []tuiNode{{Kind: "exposure-review", Depth: 1, Name: "Slot details", Review: &slot}}
		children = append(children, group.plugs...)
		if len(group.plugs) == 0 {
			message := "No known plug candidate"
			if review.Incomplete {
				message += " (inventory incomplete)"
			}
			children = append(children, tuiNode{Header: true, Depth: 1, Name: message})
		}
		label := group.ref + "  [" + slot.Source + "]"
		node := tuiNode{Kind: "slot-group", Directory: true, Expanded: true, Name: interfaceview.Safe(label), Children: children}
		nodes = append(nodes, node)
		nodes = append(nodes, children...)
	}
	if len(unassigned) > 0 {
		nodes = append(nodes, tuiNode{Header: true, Name: "[Plugs without a resolved slot]"})
		nodes = append(nodes, unassigned...)
	}
	if len(groups) == 0 && len(unassigned) == 0 && !review.Incomplete {
		nodes = append(nodes, tuiNode{Header: true, Name: "No interfaces declared"})
	}
	return nodes
}
