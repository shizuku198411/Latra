package cli

import (
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/interfaceexposure"
	"github.com/shizuku198411/Latra/internal/interfaceview"
)

// tuiVisualPage reuses the text view's resolved relationships and detail nodes.
type tuiVisualPage struct {
	Slot       *tuiNode
	Items      []tuiNode
	State      string
	Incomplete bool
}

func buildTUIVisualPages(nodes []tuiNode) []tuiVisualPage {
	var pages []tuiVisualPage
	incomplete := false
	for _, node := range nodes {
		if node.Header && strings.Contains(node.Name, "could not be evaluated") {
			incomplete = true
		}
		if node.Kind == "slot-group" && len(node.Children) > 0 && node.Children[0].Review != nil {
			slot := node.Children[0]
			byState := map[string][]tuiNode{}
			for _, child := range node.Children[1:] {
				if child.Review == nil {
					continue
				}
				state := child.Review.Startup
				if state == interfaceexposure.StartupDelegated {
					state = child.Review.ViaStartup
				}
				byState[state] = append(byState[state], child)
			}
			if len(byState) == 0 {
				pages = append(pages, tuiVisualPage{Slot: &slot, Items: []tuiNode{slot}, Incomplete: incomplete})
			}
			for _, state := range []string{interfaceexposure.StartupAuto, interfaceexposure.StartupManual} {
				if plugs := byState[state]; len(plugs) > 0 {
					items := append([]tuiNode{slot}, plugs...)
					pages = append(pages, tuiVisualPage{Slot: &slot, Items: items, State: state, Incomplete: incomplete})
				}
			}
		} else if node.Kind == "exposure-review" && node.Depth == 0 || node.Kind == "topology-edge" {
			pages = append(pages, tuiVisualPage{Items: []tuiNode{node}, Incomplete: incomplete})
		}
	}
	sort.SliceStable(pages, func(i, j int) bool { return visualPageType(pages[i]) < visualPageType(pages[j]) })
	return pages
}

func visualPageType(page tuiVisualPage) string {
	if page.Slot != nil && page.Slot.Review != nil {
		return page.Slot.Review.Type
	}
	if len(page.Items) > 0 && page.Items[0].Review != nil {
		return page.Items[0].Review.Type
	}
	return "~unresolved"
}

// visualSelectionOrder follows the displayed rows from left to right.
func visualSelectionOrder(page tuiVisualPage) []int {
	order := make([]int, 0, len(page.Items))
	if page.Slot != nil && len(page.Items) > 1 && page.Slot.Review.SDK != "system" {
		// The plug is on the left of the slot for HOST → WORKSHOP and
		// same-side relationships. Remaining plugs occupy subsequent rows.
		order = append(order, 1, 0)
		for i := 2; i < len(page.Items); i++ {
			order = append(order, i)
		}
	} else {
		for i := range page.Items {
			order = append(order, i)
		}
	}
	return order
}

func (m *tuiExplorer) moveVisual(delta int) {
	if len(m.VisualPages) == 0 || delta == 0 {
		return
	}
	order := visualSelectionOrder(m.VisualPages[m.VisualPage])
	position := 0
	for i, selection := range order {
		if selection == m.VisualSelection {
			position = i
			break
		}
	}
	next := position + delta
	if next < 0 && m.VisualPage > 0 {
		m.VisualPage--
		previous := visualSelectionOrder(m.VisualPages[m.VisualPage])
		m.VisualSelection = previous[len(previous)-1]
	} else if next >= len(order) && m.VisualPage+1 < len(m.VisualPages) {
		m.VisualPage++
		m.VisualSelection = visualSelectionOrder(m.VisualPages[m.VisualPage])[0]
	} else if next >= 0 && next < len(order) {
		m.VisualSelection = order[next]
	}
	m.VisualScroll = 0
	m.Message = ""
}

func sameTUIInterfaceNode(a, b tuiNode) bool {
	if a.Review != nil && b.Review != nil {
		return a.Review.SDK == b.Review.SDK && a.Review.Name == b.Review.Name && a.Review.Kind == b.Review.Kind && a.Review.Source == b.Review.Source && a.Review.Definition == b.Review.Definition && (a.SlotRef == b.SlotRef || a.Review.Kind == "Slot")
	}
	return a.Edge != nil && b.Edge != nil && a.Edge.Kind == b.Edge.Kind && a.Edge.Order == b.Edge.Order && a.Edge.From.Reference == b.Edge.From.Reference && a.Edge.To.Reference == b.Edge.To.Reference
}

func (m *tuiExplorer) toggleInterfaceView() {
	if !m.InterfacesActive || m.Preview != nil {
		return
	}
	m.VisualScroll = 0
	if m.VisualInterfaces {
		if len(m.VisualPages) > 0 {
			selected := m.VisualPages[m.VisualPage].Items[m.VisualSelection]
			for i, node := range m.Nodes {
				if node.Kind == "slot-group" && !node.Expanded {
					for j, child := range node.Children {
						if sameTUIInterfaceNode(child, selected) && selected.Review != nil && selected.Review.Kind == "Plug" {
							children := append([]tuiNode(nil), node.Children...)
							m.Nodes = append(m.Nodes[:i+1], append(children, m.Nodes[i+1:]...)...)
							m.Nodes[i].Expanded = true
							m.SelectedNode = i + 1 + j
							m.VisualInterfaces = false
							return
						}
					}
				}
				if sameTUIInterfaceNode(node, selected) {
					m.SelectedNode = i
					break
				}
				if node.Kind == "slot-group" && len(node.Children) > 0 && sameTUIInterfaceNode(node.Children[0], selected) {
					m.SelectedNode = i
					break
				}
			}
		}
	} else if len(m.Nodes) > 0 {
		selected := m.Nodes[m.SelectedNode]
		if selected.Kind == "slot-group" && len(selected.Children) > 0 {
			selected = selected.Children[0]
		}
		for i, page := range m.VisualPages {
			for j, item := range page.Items {
				if sameTUIInterfaceNode(item, selected) {
					m.VisualPage, m.VisualSelection = i, j
					m.VisualInterfaces = true
					return
				}
			}
		}
	}
	m.VisualInterfaces = !m.VisualInterfaces
}

func visualItemName(node tuiNode) string {
	if node.Review != nil {
		return interfaceview.Safe(node.Review.SDK + ":" + node.Review.Name)
	}
	return interfaceview.Safe(node.Name)
}

type tuiVisualRow struct {
	text     string
	selected bool
}

// visualRows lays out the complete inventory and scrolls to the selected item.
func (m *tuiExplorer) visualRows(width, height int) []string {
	if len(m.VisualPages) == 0 {
		message := "No interfaces declared"
		for _, node := range m.Nodes {
			if node.Header && node.Name != "" {
				message = node.Name
				break
			}
		}
		return []string{interfaceview.Safe(message), "Static configuration; runtime not inspected"}
	}
	lines, wide, header := m.visualContent(width)
	return visualViewport(lines, width, height, wide, header, &m.VisualScroll)
}

// visualContent builds logical display rows without applying viewport scrolling.
func (m *tuiExplorer) visualContent(width int) ([]tuiVisualRow, bool, string) {
	var lines []tuiVisualRow
	add := func(text string, selected bool) { lines = append(lines, tuiVisualRow{text, selected}) }
	leftWidth, rightWidth := visualWidths(m.VisualPages)
	wide := leftWidth+rightWidth+11 <= width-1
	box := func(left, bridge, right string) string {
		return "| " + visualPad(left, leftWidth) + " |" + bridge + "| " + visualPad(right, rightWidth) + " |"
	}
	connect := func(left, leftEnd, bridge, rightStart, right string) string {
		return "| " + visualPad(left, leftWidth+1-len([]rune(leftEnd))) + leftEnd + "|" + bridge + "|" + rightStart + visualPad(" "+right, rightWidth+1-len([]rune(rightStart))) + " |"
	}
	frame := func(title string, n int) string {
		return "+-- " + title + " " + strings.Repeat("-", max(0, n-len(title)-4)) + "+"
	}
	header := "HOST / WORKSHOP (static)"
	if wide {
		header = frame("HOST", leftWidth+2) + "   " + frame("WORKSHOP", rightWidth+2)
	}
	if m.VisualPages[0].Incomplete {
		add("Inventory incomplete; some information unavailable", false)
	}
	lastType := ""
	for pi, page := range m.VisualPages {
		typ := visualPageType(page)
		if typ == "" {
			typ = "unknown"
		}
		if typ == "~unresolved" {
			typ = "Unresolved configuration"
		}
		if typ != lastType {
			if lastType != "" {
				if wide {
					add(box("", "   ", ""), false)
				} else {
					add("", false)
				}
			}
			if wide {
				add(box("["+interfaceview.Safe(typ)+"]", "   ", ""), false)
			} else {
				add("["+interfaceview.Safe(typ)+"]", false)
			}
			lastType = typ
		}
		if page.Slot == nil {
			node := page.Items[0]
			selected := pi == m.VisualPage && m.VisualSelection == 0
			label, state, symbol := visualMarker(selected)+"(p) "+visualItemName(node), "Unknown", "?"
			if node.Review != nil && node.Review.Startup != "" {
				state = node.Review.Startup
			}
			if node.Edge != nil {
				label = visualMarker(selected) + visualItemName(node)
				state = node.Edge.State
			}
			if state == "Invalid" {
				symbol = "✕"
			}
			if wide && node.Review != nil && node.Review.SDK == "system" {
				add(box(label, "   ", symbol+" "+interfaceview.Safe(state)), selected)
			} else if wide {
				add(box(symbol+" "+interfaceview.Safe(state), "   ", label), selected)
			} else {
				add(label+"  "+symbol+" "+interfaceview.Safe(state), selected)
			}
			if endpoint := visualEndpoint(node); endpoint != "" {
				if wide && node.Review != nil && node.Review.SDK == "system" {
					add(box(visualIndent(endpoint, 6), "   ", ""), false)
				} else if wide {
					add(box("", "   ", visualIndent(endpoint, 6)), false)
				} else {
					add("      "+endpoint, false)
				}
			}
			continue
		}
		slot := *page.Slot
		slotHost := slot.Review.SDK == "system"
		slotSelected := pi == m.VisualPage && m.VisualSelection == 0
		slotLabel := visualMarker(slotSelected) + "(s) " + visualItemName(slot)
		if len(page.Items) == 1 {
			if wide && slotHost {
				add(box(slotLabel+" [ ]", "   ", "No known plug candidate"), slotSelected)
			} else if wide {
				add(box("No known plug candidate", "   ", "[ ] "+slotLabel), slotSelected)
			} else {
				add(slotLabel+" [ ]  No known plug candidate", slotSelected)
			}
			if endpoint := visualEndpoint(slot); endpoint != "" {
				if wide && slotHost {
					add(box(visualIndent(endpoint, 6), "   ", ""), false)
				} else if wide {
					add(box("", "   ", visualIndent(endpoint, 10)), false)
				} else {
					add("      "+endpoint, false)
				}
			}
			continue
		}
		for i, plug := range page.Items[1:] {
			plugSelected := pi == m.VisualPage && m.VisualSelection == i+1
			plugLabel := visualMarker(plugSelected) + "(p) " + visualItemName(plug)
			manual := page.State == interfaceexposure.StartupManual
			bridge := "───"
			if manual {
				bridge = " · "
			}
			if wide && slotHost && plug.Review.SDK != "system" {
				leftEnd, rightStart := "[ ]◀──", "──●"
				if manual {
					leftEnd, rightStart = "[ ]◁ ·", "· ·●"
				}
				if len(page.Items) > 2 && i == 0 {
					rightStart = "──┬──●"
					if manual {
						rightStart = "· ┬··●"
					}
				}
				if i == 0 {
					labelIndent := "   "
					if len(page.Items) > 2 {
						labelIndent = ""
					}
					add(connect(slotLabel, leftEnd, bridge, rightStart, labelIndent+plugLabel), slotSelected || plugSelected)
				} else {
					add(box("", "   ", " │"), false)
					junction := " ├──● "
					if i == len(page.Items)-2 {
						junction = " └──● "
					}
					add(box("", "   ", junction+plugLabel), plugSelected)
				}
			} else if wide && !slotHost && plug.Review.SDK == "system" {
				leftEnd, rightStart := "●──", "──▶[ ]"
				if manual {
					leftEnd, rightStart = "●· ·", "· ▷[ ]"
				}
				if len(page.Items) > 2 && i == 0 {
					leftEnd = "●──┬──"
					if manual {
						leftEnd = "●··┬··"
					}
				}
				if i == 0 {
					add(connect(plugLabel, leftEnd, bridge, rightStart, slotLabel), slotSelected || plugSelected)
				} else {
					add(box(visualIndent("│", leftWidth-2), "   ", ""), false)
					junction := "├──●"
					if i == len(page.Items)-2 {
						junction = "└──●"
					}
					add(box(visualPad(plugLabel, leftWidth-len([]rune(junction)))+junction, "   ", ""), plugSelected)
				}
			} else if wide {
				// Same-side relationships require two lines in the Workshop box.
				if i == 0 {
					arrow := "   └──▶[ ] "
					if manual {
						arrow = "   └ · ▷[ ] "
					}
					add(box("", "   ", "●──┐ "+plugLabel), plugSelected)
					add(box("", "   ", arrow+slotLabel), slotSelected)
				} else {
					add(box("", "   ", "●──  "+plugLabel), plugSelected)
					add(box("", "   ", "     candidate: "+visualItemName(slot)), false)
				}
			} else {
				// Compact view wraps complete names rather than clipping them.
				if slotHost && i == 0 {
					add(slotLabel+" [ ]", slotSelected)
				}
				arrow := "●──▶"
				if manual {
					arrow = "● · ▷"
				}
				add(plugLabel+" "+arrow, plugSelected)
				if !slotHost && i == 0 {
					add("    [ ] "+slotLabel, slotSelected)
				} else if i > 0 || slotHost {
					add("    candidate slot: "+visualItemName(slot), false)
				}
			}
			if plug.CandidateUnselected {
				if wide && slotHost && plug.Review.SDK != "system" {
					indent := 12
					if manual && len(page.Items) == 2 {
						indent++
					}
					possible := visualIndent("Possible; not selected", indent)
					if len(page.Items) > 2 && i < len(page.Items)-2 {
						possible = " │" + string([]rune(possible)[2:])
					}
					add(box("", "   ", possible), false)
				} else if wide && plug.Review.SDK == "system" {
					add(box(visualIndent("Possible; not selected", 6), "   ", ""), false)
				} else if wide {
					add(box("", "   ", visualIndent("Possible; not selected", 11)), false)
				} else {
					add(visualIndent("Possible; not selected", 6), false)
				}
			}
			plugEndpoint, slotEndpoint := visualEndpoint(plug), ""
			if i == 0 {
				slotEndpoint = visualEndpoint(slot)
			}
			if plugEndpoint != "" || slotEndpoint != "" {
				if wide && slotHost && plug.Review.SDK != "system" {
					indent := 12
					if manual {
						indent++
					}
					rightEndpoint := visualIndent(plugEndpoint, indent)
					if len(page.Items) > 2 && i < len(page.Items)-2 {
						if rightEndpoint == "" {
							rightEndpoint = " │"
						} else if len([]rune(rightEndpoint)) > 1 {
							rightEndpoint = " │" + string([]rune(rightEndpoint)[2:])
						}
					}
					add(box(visualIndent(slotEndpoint, 6), "   ", rightEndpoint), false)
				} else if wide && !slotHost && plug.Review.SDK == "system" {
					add(box(visualIndent(plugEndpoint, 6), "   ", visualIndent(slotEndpoint, 12)), false)
				} else {
					if plugEndpoint != "" {
						add("    plug: "+plugEndpoint, false)
					}
					if slotEndpoint != "" {
						add("    slot: "+slotEndpoint, false)
					}
				}
			}
		}
	}
	if wide {
		add("+"+strings.Repeat("-", leftWidth+2)+"+   +"+strings.Repeat("-", rightWidth+2)+"+", false)
	}
	return lines, wide, header
}

// visualWidths includes selection markers, connector margins, and endpoints.
func visualWidths(pages []tuiVisualPage) (int, int) {
	leftWidth, rightWidth := 20, 20
	for _, page := range pages {
		for _, item := range page.Items {
			if item.Review == nil {
				continue
			}
			needed := max(len([]rune(visualItemName(item)))+18, len([]rune(visualEndpoint(item)))+14)
			if item.CandidateUnselected {
				needed = max(needed, len("Possible; not selected")+13)
			}
			if item.Review.SDK == "system" {
				leftWidth = max(leftWidth, needed)
			} else {
				rightWidth = max(rightWidth, needed)
			}
		}
	}
	return leftWidth, rightWidth
}

// visualViewport wraps the compact layout and scrolls its rows independently
// from selection. The offset resets when the selected interface changes.
func visualViewport(lines []tuiVisualRow, width, height int, wide bool, header string, offset *int) []string {
	if !wide {
		var wrapped []tuiVisualRow
		limit := max(1, width-1)
		for _, line := range lines {
			r := []rune(line.text)
			if len(r) == 0 {
				wrapped = append(wrapped, line)
				continue
			}
			for len(r) > limit {
				wrapped = append(wrapped, tuiVisualRow{string(r[:limit]), line.selected})
				r = r[limit:]
			}
			wrapped = append(wrapped, tuiVisualRow{string(r), line.selected})
		}
		lines = wrapped
	}
	selected := 0
	for i, line := range lines {
		if line.selected {
			selected = i
			break
		}
	}
	legend := "▶ auto ▷ manual ? unknown ✕ invalid"
	available := max(1, height-2)
	start := max(0, selected-available+1)
	if available > 1 && selected+1 < len(lines) && selected+1 >= start+available {
		start++
	}
	base := start
	start = max(0, min(max(0, len(lines)-available), start+*offset))
	*offset = start - base
	end := min(len(lines), start+available)
	result := []string{legend, header}
	for _, line := range lines[start:end] {
		result = append(result, line.text)
	}
	return result
}

func visualPad(value string, width int) string {
	return value + strings.Repeat(" ", max(0, width-len([]rune(value))))
}

func visualMarker(selected bool) string {
	if selected {
		return "❯ "
	}
	return "  "
}

func visualEndpoint(node tuiNode) string {
	if node.Review == nil || node.Review.Type != "tunnel" {
		return ""
	}
	return interfaceview.Safe(tunnelEndpointValue(*node.Review))
}

func visualIndent(value string, spaces int) string {
	if value == "" {
		return ""
	}
	return strings.Repeat(" ", spaces) + value
}
