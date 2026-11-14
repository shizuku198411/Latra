package cli

import (
	"strings"
	"testing"

	"github.com/shizuku198411/Latra/internal/interfaceexposure"
	"github.com/shizuku198411/Latra/internal/interfacegraph"
	"github.com/shizuku198411/Latra/internal/source"
)

func TestVisualInterfaceNavigationAndToggle(t *testing.T) {
	review := interfaceexposure.Review{Definition: "dev.yaml", Items: []interfaceexposure.Item{
		{Kind: "Slot", SDK: "system", Name: "mount", Type: "mount", Source: "Workshop"},
		{Kind: "Plug", SDK: "app", Name: "cache", Type: "mount", Startup: "Auto-connect candidate", Target: "system:mount", Value: `{"endpoint":"unused"}`},
		{Kind: "Plug", SDK: "other", Name: "cache", Type: "mount", Startup: "Auto-connect candidate", Target: "system:mount"},
	}}
	m := tuiExplorer{Configurations: []source.Configuration{{Name: "dev", Definition: "dev.yaml"}}, Reviews: []interfaceexposure.Review{review}}
	m.openTopology()
	m.enter()
	selectTUIKind(t, &m, "workshop-interfaces")
	m.enter()
	if !m.VisualInterfaces || len(m.VisualPages) != 1 || len(m.VisualPages[0].Items) != 3 {
		t.Fatalf("visual pages: %+v", m.VisualPages)
	}
	m.move(1)
	if m.VisualPages[0].Items[m.VisualSelection].Review.SDK != "app" {
		t.Fatal("plug selection failed")
	}
	m.enter()
	if m.Preview == nil || !strings.Contains(strings.Join(m.Preview.Lines, " "), "SDK: app") {
		t.Fatalf("wrong detail: %+v", m.Preview)
	}
	m.back()
	m.toggleInterfaceView()
	if m.VisualInterfaces || m.Nodes[m.SelectedNode].Review == nil || m.Nodes[m.SelectedNode].Review.SDK != "app" {
		t.Fatal("text selection not preserved")
	}
	m.toggleInterfaceView()
	if !m.VisualInterfaces || m.VisualPages[m.VisualPage].Items[m.VisualSelection].Review.SDK != "app" {
		t.Fatal("visual selection not preserved")
	}
	m.back()
	if m.InterfacesActive || m.Nodes[m.SelectedNode].Kind != "workshop-interfaces" {
		t.Fatal("return to workshop failed")
	}
}

func TestVisualInterfaceStatesAndCompactLayout(t *testing.T) {
	review := interfaceexposure.Review{Items: []interfaceexposure.Item{
		{Kind: "Slot", SDK: "system", Name: "one", Type: "secret", Source: "Workshop"},
		{Kind: "Slot", SDK: "system", Name: "two", Type: "secret", Source: "Workshop"},
		{Kind: "Plug", SDK: "app", Name: "key", Type: "secret", Startup: "Manual required", Target: "system:one, system:two", Basis: "Declared slots (not selected)"},
		{Kind: "Plug", SDK: "app", Name: "unresolved", Type: "tunnel", Startup: "Unknown", Reason: "Could not determine endpoint", Value: `{"endpoint":"$DYNAMIC"}`},
	}}
	pages := buildTUIVisualPages(tuiInterfaceSlotNodes(review))
	if len(pages) != 3 {
		t.Fatalf("pages=%+v", pages)
	}
	m := tuiExplorer{VisualPages: pages}
	rows := strings.Join(m.visualRows(120, 40), "\n")
	if strings.Count(rows, "not selected") != 2 || !strings.Contains(rows, "◁") || !strings.Contains(rows, "Unknown") || !strings.Contains(rows, "$DYNAMIC") {
		t.Fatalf("all interface states must remain visible: %s", rows)
	}
	compact := strings.Join(m.visualRows(40, 40), "\n")
	if !strings.Contains(compact, "▷") || !strings.Contains(compact, "not selected") || !strings.Contains(compact, "Unknown") {
		t.Fatalf("compact interface states: %s", compact)
	}
}

func TestVisualInterfaceShowsTypesAndEndpointsTogether(t *testing.T) {
	review := interfaceexposure.Review{Items: []interfaceexposure.Item{
		{Kind: "Slot", SDK: "app", Name: "web", Type: "tunnel", Source: "SDK", Value: `{"endpoint":"localhost:8888"}`},
		{Kind: "Plug", SDK: "system", Name: "web", Type: "tunnel", Startup: "Auto-connect candidate", Target: "app:web", Value: `{"endpoint":"127.0.0.1:8888"}`},
		{Kind: "Plug", SDK: "app", Name: "cache", Type: "mount", Startup: "Auto-connect candidate", Target: "system:mount"},
	}}
	m := tuiExplorer{VisualPages: buildTUIVisualPages(tuiInterfaceSlotNodes(review))}
	rows := strings.Join(m.visualRows(100, 30), "\n")
	for _, want := range []string{"[mount]", "[tunnel]", "system:mount", "app:cache", "system:web", "app:web", "127.0.0.1:8888", "localhost:8888"} {
		if !strings.Contains(rows, want) {
			t.Fatalf("missing %q: %s", want, rows)
		}
	}
	if strings.Count(rows, "+-- HOST ") != 1 || strings.Contains(rows, " / ") {
		t.Fatalf("diagram must be one frame: %s", rows)
	}
	m.VisualPage = 1
	m.VisualSelection = 1
	scrolled := strings.Join(m.visualRows(100, 5), "\n")
	if !strings.Contains(scrolled, "❯ (p) system:web") {
		t.Fatalf("selected row not visible: %s", scrolled)
	}
}

func TestVisualConnectorsStayAtBoxBoundaries(t *testing.T) {
	for _, tc := range []struct {
		slotHost    bool
		state, want string
	}{
		{true, "Auto-connect candidate", "[ ]◀──|───|──●"},
		{false, "Auto-connect candidate", "●──|───|──▶[ ]"},
		{true, "Manual required", "[ ]◁ ·| · |· ·●"},
		{false, "Manual required", "●· ·| · |· ▷[ ]"},
	} {
		slot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "system", Name: "slot", Type: "tunnel"}}
		plug := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "plug", Type: "tunnel"}}
		if !tc.slotHost {
			slot.Review.SDK, plug.Review.SDK = "app", "system"
		}
		m := tuiExplorer{VisualPages: []tuiVisualPage{{Slot: &slot, Items: []tuiNode{slot, plug}, State: tc.state}}}
		rows := strings.Join(m.visualRows(120, 30), "\n")
		if !strings.Contains(rows, tc.want) {
			t.Fatalf("missing %q in %s", tc.want, rows)
		}
	}
}

func TestVisualTunnelEndpointAlignment(t *testing.T) {
	for _, hostSlot := range []bool{true, false} {
		for _, state := range []string{"Auto-connect candidate", "Manual required"} {
			slot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "system", Name: "slot", Type: "tunnel", Value: `{"endpoint":"SLOT"}`}}
			plug := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "plug", Type: "tunnel", Value: `{"endpoint":"PLUG"}`}}
			if !hostSlot {
				slot.Review.SDK, plug.Review.SDK = "app", "system"
			}
			m := tuiExplorer{VisualPages: []tuiVisualPage{{Slot: &slot, Items: []tuiNode{slot, plug}, State: state}}}
			rows := m.visualRows(100, 20)
			var labels, endpoints string
			for _, line := range rows {
				if strings.Contains(line, "(s)") && strings.Contains(line, "(p)") {
					labels = line
				}
				if strings.Contains(line, "SLOT") && strings.Contains(line, "PLUG") {
					endpoints = line
				}
			}
			column := func(line, value string) int {
				i := strings.Index(line, value)
				if i < 0 {
					return -1
				}
				return len([]rune(line[:i]))
			}
			if column(labels, "system:") != column(endpoints, map[bool]string{true: "SLOT", false: "PLUG"}[hostSlot]) || column(labels, "app:") != column(endpoints, map[bool]string{true: "PLUG", false: "SLOT"}[hostSlot]) || strings.Contains(endpoints, "endpoint:") {
				t.Fatalf("hostSlot=%v state=%s labels=%q endpoints=%q", hostSlot, state, labels, endpoints)
			}
		}
	}
}

func TestVisualNavigationFollowsHostThenWorkshop(t *testing.T) {
	hostPlug := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "system", Name: "web"}}
	workshopSlot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "app", Name: "web"}}
	hostSlot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "system", Name: "mount"}}
	appPlug := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "cache"}}
	otherPlug := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "other", Name: "cache"}}
	m := tuiExplorer{VisualPages: []tuiVisualPage{{Slot: &workshopSlot, Items: []tuiNode{workshopSlot, hostPlug}}, {Slot: &hostSlot, Items: []tuiNode{hostSlot, appPlug, otherPlug}}}, VisualSelection: 1}
	for i, want := range []string{"system:web", "app:web", "system:mount", "app:cache", "other:cache"} {
		got := visualItemName(m.VisualPages[m.VisualPage].Items[m.VisualSelection])
		if got != want {
			t.Fatalf("step %d: got %s, want %s", i, got, want)
		}
		if i < 4 {
			m.moveVisual(1)
		}
	}
	for _, want := range []string{"app:cache", "system:mount", "app:web", "system:web"} {
		m.moveVisual(-1)
		if got := visualItemName(m.VisualPages[m.VisualPage].Items[m.VisualSelection]); got != want {
			t.Fatalf("reverse got %s, want %s", got, want)
		}
	}
}

func TestVisualLongNamesAndEndpointsAreNotTruncated(t *testing.T) {
	name := "project-consumer-with-a-very-long-name"
	endpoint := "/home/workshop/a-very-long-directory-name/service.sock"
	slot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "system", Name: "mount", Type: "tunnel", Value: `{"endpoint":"` + endpoint + `"}`}}
	plug := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: name, Name: "server", Type: "tunnel", Value: `{"endpoint":"short"}`}}
	m := tuiExplorer{VisualPages: []tuiVisualPage{{Slot: &slot, Items: []tuiNode{slot, plug}, State: "Auto-connect candidate"}}}
	for _, width := range []int{220, 40} {
		rows := m.visualRows(width, 100)
		joined := strings.Join(rows, "")
		if !strings.Contains(joined, name+":server") || !strings.Contains(joined, endpoint) || strings.Contains(joined, "…") {
			t.Fatalf("width %d: %q", width, joined)
		}
		for _, line := range rows {
			if len([]rune(line)) > width-1 {
				t.Fatalf("width %d overflow: %q", width, line)
			}
		}
	}
}

func TestVisualMultiplePlugsShareOneSlot(t *testing.T) {
	slot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "system", Name: "mount", Type: "mount"}}
	a := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "a", Type: "mount"}}
	b := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "b", Type: "mount"}}
	m := tuiExplorer{VisualPages: []tuiVisualPage{{Slot: &slot, Items: []tuiNode{slot, a, b}, State: "Auto-connect candidate"}}}
	rows := strings.Join(m.visualRows(120, 30), "\n")
	for _, want := range []string{"system:mount", "app:a", "app:b", "┬", "│", "└"} {
		if !strings.Contains(rows, want) {
			t.Fatalf("missing %q: %s", want, rows)
		}
	}
	if strings.Count(rows, "[ ]") != 1 {
		t.Fatalf("expected one slot: %s", rows)
	}
	var positions []int
	for _, line := range strings.Split(rows, "\n") {
		if i := strings.Index(line, "(p)"); i >= 0 {
			positions = append(positions, len([]rune(line[:i])))
		}
	}
	if len(positions) != 2 || positions[0] != positions[1] {
		t.Fatalf("plug labels are not aligned: %s", rows)
	}
}

func TestVisualLegendAndFrameAlignment(t *testing.T) {
	slot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "system", Name: "mount", Type: "mount"}}
	plug := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "cache", Type: "mount"}}
	m := tuiExplorer{VisualPages: []tuiVisualPage{{Slot: &slot, Items: []tuiNode{slot, plug}, State: "Auto-connect candidate"}}}
	rows := m.visualRows(120, 30)
	if !strings.HasPrefix(rows[0], "▶ auto") {
		t.Fatalf("legend must appear first: %q", rows[0])
	}
	header := []rune(rows[1])
	var box string
	for _, row := range rows {
		if strings.Contains(row, "(s)") && strings.Contains(row, "(p)") {
			box = row
			break
		}
	}
	var headerColumns, boxColumns []int
	for i, ch := range header {
		if ch == '+' {
			headerColumns = append(headerColumns, i)
		}
	}
	for i, ch := range []rune(box) {
		if ch == '|' {
			boxColumns = append(boxColumns, i)
		}
	}
	if len(headerColumns) != len(boxColumns) {
		t.Fatalf("header=%q row=%q", rows[1], box)
	}
	for i := range headerColumns {
		if headerColumns[i] != boxColumns[i] {
			t.Fatalf("misaligned header=%q row=%q", rows[1], box)
		}
	}
}

func TestVisualManualCandidateLabelsAlignAcrossBranches(t *testing.T) {
	slot := tuiNode{Review: &interfaceexposure.Item{Kind: "Slot", SDK: "system", Name: "key", Type: "secret"}}
	a := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "one", Type: "secret"}, SlotBasis: "Declared slots (not selected)", CandidateUnselected: true}
	b := tuiNode{Review: &interfaceexposure.Item{Kind: "Plug", SDK: "app", Name: "two", Type: "secret"}, SlotBasis: "Declared slots (not selected)", CandidateUnselected: true}
	m := tuiExplorer{VisualPages: []tuiVisualPage{{Slot: &slot, Items: []tuiNode{slot, a, b}, State: "Manual required"}}}
	var nameColumns, candidateColumns []int
	for _, line := range m.visualRows(120, 30) {
		if index := strings.Index(line, "app:"); index >= 0 {
			nameColumns = append(nameColumns, len([]rune(line[:index])))
		}
		if index := strings.Index(line, "Possible; not selected"); index >= 0 {
			candidateColumns = append(candidateColumns, len([]rune(line[:index])))
		}
	}
	if len(nameColumns) != 2 || len(candidateColumns) != 2 || nameColumns[0] != candidateColumns[0] || nameColumns[1] != candidateColumns[1] {
		t.Fatalf("name columns %v, candidate columns %v", nameColumns, candidateColumns)
	}
}

func TestVisualUnresolvedEdgeKeepsKindAndInvalidState(t *testing.T) {
	edge := interfacegraph.Edge{Kind: "binding", State: "Invalid", From: interfacegraph.Endpoint{Reference: "app:source"}, To: interfacegraph.Endpoint{Reference: "app:target"}}
	m := tuiExplorer{VisualPages: []tuiVisualPage{{Items: []tuiNode{{Kind: "topology-edge", Name: "binding app:source → app:target [Invalid]", Edge: &edge}}}}}
	rows := strings.Join(m.visualRows(120, 20), "\n")
	if !strings.Contains(rows, "✕ Invalid") || !strings.Contains(rows, "binding app:source") || strings.Contains(rows, "(p)") {
		t.Fatalf("wrong edge display: %s", rows)
	}
}

func TestVisualViewportScrollsWrappedSelection(t *testing.T) {
	long := tuiVisualRow{text: "abcdefghijklmnop", selected: true}
	firstOffset, nextOffset := 0, 2
	first := visualViewport([]tuiVisualRow{long}, 5, 4, false, "head", &firstOffset)
	next := visualViewport([]tuiVisualRow{long}, 5, 4, false, "head", &nextOffset)
	if !strings.Contains(strings.Join(first, ""), "abcdefgh") || !strings.Contains(strings.Join(next, ""), "ijklmnop") {
		t.Fatalf("first=%q next=%q", first, next)
	}
}
