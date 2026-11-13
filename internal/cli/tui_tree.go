package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/interfaceexposure"
	"github.com/shizuku198411/Latra/internal/interfacegraph"
	"github.com/shizuku198411/Latra/internal/interfaceview"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/sdkcache"
	"github.com/shizuku198411/Latra/internal/source"
)

type tuiNode struct {
	Name, Path       string
	Depth            int
	Directory        bool
	Symlink          bool
	Expanded         bool
	Header           bool
	Group            string
	Kind             string
	Interface        *interfaceview.Entry
	Children         []tuiNode
	Edge             *interfacegraph.Edge
	Review           *interfaceexposure.Item
	Index            int
	DeclarationOrder int
}

type tuiFrame struct {
	Nodes                     []tuiNode
	SelectedNode, SelectedSDK int
	InTree, InTopology        bool
	Title                     string
}

type tuiExplorer struct {
	SDKs            []tuiSDK
	SelectedSDK     int
	InTree          bool
	SelectedNode    int
	Nodes           []tuiNode
	Message         string
	ScanStatus      string
	Preview         *tuiPreview
	Scan            *report.Document
	Scanning        bool
	Topology        []interfacegraph.Graph
	Reviews         []interfaceexposure.Review
	InTopology      bool
	Configurations  []source.Configuration
	Workshops       []source.Workshop
	CurrentWorkshop int
	Title           string
	History         []tuiFrame
	DiscoveryError  string
}

func (m *tuiExplorer) enter() {
	if m.Preview != nil {
		return
	}
	if !m.InTree {
		if len(m.SDKs) == 0 {
			return
		}
		if len(m.History) > 0 {
			m.push()
		}
		m.openSDK()
		if !m.InTree && len(m.History) > 1 {
			m.pop()
		}
		return
	}
	if len(m.Nodes) == 0 {
		return
	}
	node := m.Nodes[m.SelectedNode]
	switch node.Kind {
	case "workshop":
		m.openWorkshop(node.Index)
		return
	case "workshop-sdk":
		m.push()
		m.SelectedSDK = node.Index
		m.InTree = false
		m.openSDK()
		if !m.InTree {
			m.pop()
		}
		return
	case "workshop-system":
		m.openSystem(node.Index)
		return
	case "workshop-interfaces":
		m.openWorkshopInterfaces()
		return
	case "workshop-reviews":
		m.openWorkshopReviews()
		return
	case "workshop-assessment":
		m.openAssessment()
		return
	}
	if node.Kind == "exposure-review" {
		i := node.Review
		lines := []string{i.Fact, "SDK: " + i.SDK, "Interface: " + i.Kind + " " + i.Name, "Declared by: " + i.Source, "Workshop: " + i.Workshop + " (" + i.Definition + ")", "State: " + i.State, "Declared value: " + i.Value, "Limitation: " + i.Limitation}
		for _, e := range i.Related {
			lines = append(lines, e.Kind+": "+e.From.Reference+" → "+e.To.Reference+" ["+e.State+"]")
		}
		for n := range lines {
			lines[n] = interfaceview.Safe(lines[n])
		}
		m.Preview = &tuiPreview{Path: "Exposure review", Status: "Static review (unscored)", Lines: lines, Interface: true}
		return
	}
	if node.Kind == "topology-edge" {
		e := node.Edge
		lines := []string{"Kind: " + e.Kind, "From: " + e.From.Reference, "To: " + e.To.Reference, "State: " + e.State, "From type: " + e.From.Type + " (" + e.From.Origin + ")", "To type: " + e.To.Type + " (" + e.To.Origin + ")", "Policy: " + e.Policy, "Runtime: Not inspected"}
		if m.CurrentWorkshop < len(m.Configurations) {
			lines = append(lines, "Definition: "+m.Configurations[m.CurrentWorkshop].Definition)
		}
		lines = append(lines, e.Diagnostics...)
		for i := range lines {
			lines[i] = interfaceview.Safe(lines[i])
		}
		m.Preview = &tuiPreview{Path: "Configured interface", Status: "Static configuration (read-only)", Lines: lines, Interface: true}
		return
	}
	if node.Kind == "interface" {
		lines := node.Interface.Details()
		for _, review := range m.Reviews {
			for _, entry := range review.Items {
				if m.InTopology || len(m.SDKs) == 0 {
					continue
				}
				owner := strings.TrimPrefix(strings.TrimPrefix(entry.SDK, "project-"), "try-")
				matches := false
				for _, d := range m.SDKs[m.SelectedSDK].Declarations {
					if d.Definition == entry.Definition {
						matches = true
						break
					}
				}
				if matches && owner == m.SDKs[m.SelectedSDK].Name && entry.Kind == node.Interface.Kind && entry.Name == node.Interface.Name && entry.Source == node.Interface.Source && (entry.Source != "Workshop" || entry.Definition == node.Interface.Definition) {
					lines = append(lines, interfaceview.Safe("Review ("+entry.Workshop+"): "+entry.Fact+" — "+entry.State), interfaceview.Safe("Limitation: "+entry.Limitation))
				}
			}
		}
		m.Preview = &tuiPreview{Path: node.Interface.Name, Status: "Interface declaration (read-only)", Lines: lines, Interface: true}
		m.Message = ""
		return
	}
	if node.Header {
		return
	}
	if node.Symlink {
		m.Message = "Symlink preview is disabled"
		return
	}
	if !node.Directory {
		preview, err := loadTUIPreview(m.SDKs[m.SelectedSDK].Entry, node.Path)
		if err != nil {
			m.Message = err.Error()
			return
		}
		m.Preview, m.Message = &preview, ""
		return
	}
	if node.Expanded {
		next := m.SelectedNode + 1
		for next < len(m.Nodes) && m.Nodes[next].Depth > node.Depth {
			next++
		}
		m.Nodes = append(m.Nodes[:m.SelectedNode+1], m.Nodes[next:]...)
		m.Nodes[m.SelectedNode].Expanded = false
		m.Message = ""
		return
	}
	if node.Kind == "interface-group" {
		i := m.SelectedNode
		m.Nodes = append(m.Nodes[:i+1], append(append([]tuiNode{}, node.Children...), m.Nodes[i+1:]...)...)
		m.Nodes[i].Expanded = true
		return
	}
	children, err := readTUINodes(m.SDKs[m.SelectedSDK].Entry, node.Path, node.Depth+1)
	if err == nil {
		children = filterTUIGroup(children, node.Group)
		for j := range children {
			children[j].Group = node.Group
		}
	}
	if err != nil {
		m.Message = err.Error()
		return
	}
	i := m.SelectedNode
	m.Nodes = append(m.Nodes[:i+1], append(children, m.Nodes[i+1:]...)...)
	m.Nodes[i].Expanded = true
	m.Message = ""
}

func (m *tuiExplorer) back() {
	if m.Preview != nil {
		m.Preview = nil
		m.Message = ""
		return
	}
	if m.InTree || len(m.History) > 0 {
		if !m.pop() {
			m.InTree, m.InTopology, m.Nodes, m.SelectedNode, m.Title = false, false, nil, 0, ""
		}
		m.Message = ""
	}
}

func (m *tuiExplorer) push() {
	m.History = append(m.History, tuiFrame{Nodes: m.Nodes, SelectedNode: m.SelectedNode, SelectedSDK: m.SelectedSDK, InTree: m.InTree, InTopology: m.InTopology, Title: m.Title})
}
func (m *tuiExplorer) pop() bool {
	if len(m.History) == 0 {
		return false
	}
	n := len(m.History) - 1
	f := m.History[n]
	m.History = m.History[:n]
	m.Nodes, m.SelectedNode, m.SelectedSDK, m.InTree, m.InTopology, m.Title = f.Nodes, f.SelectedNode, f.SelectedSDK, f.InTree, f.InTopology, f.Title
	return true
}
func (m *tuiExplorer) show(nodes []tuiNode, title string) {
	m.push()
	m.Nodes = nodes
	m.SelectedNode = firstTUISelectable(nodes)
	m.InTree = true
	m.InTopology = true
	m.Title = title
	m.Message = ""
}
func (m *tuiExplorer) openSDK() {
	item := m.SDKs[m.SelectedSDK]
	var children []tuiNode
	if item.Status == "local" || item.Status == "cached" {
		var err error
		children, err = readTUIGroupedNodes(item.Entry)
		if err != nil {
			m.Message = err.Error()
			return
		}
	}
	interfaces := interfaceNodes(item)
	insert := len(children)
	for i, node := range children {
		if node.Header && node.Name == "[Files]" {
			insert = i
			break
		}
	}
	children = append(children[:insert], append(interfaces, children[insert:]...)...)
	m.Nodes, m.SelectedNode, m.InTree, m.InTopology, m.Message = children, firstTUISelectable(children), true, false, ""
	m.Title = " SDK: " + interfaceview.Safe(item.Name) + "  (read-only tree)"
	if len(m.History) > 0 && m.History[len(m.History)-1].InTopology && m.CurrentWorkshop < len(m.Configurations) {
		m.Title = " Workshop: " + interfaceview.Safe(m.Configurations[m.CurrentWorkshop].Name) + "  ›  SDK: " + interfaceview.Safe(item.Name)
	}
}

// openSDKList switches from the root Workshop list to the existing SDK list.
func (m *tuiExplorer) openSDKList() {
	if !m.InTree || !m.InTopology || len(m.History) != 0 || m.Preview != nil {
		return
	}
	m.push()
	m.InTree, m.InTopology, m.Nodes, m.Title, m.Message = false, false, nil, "", ""
}
func (m *tuiExplorer) openTopology() {
	if m.InTree || m.Preview != nil {
		return
	}
	nodes := []tuiNode{}
	nameWidth := 0
	for _, c := range m.Configurations {
		nameWidth = max(nameWidth, len([]rune(interfaceview.Safe(c.Name))))
	}
	for i, c := range m.Configurations {
		name := interfaceview.Safe(c.Name)
		label := name + strings.Repeat(" ", nameWidth-len([]rune(name))+3) + interfaceview.Safe(c.Definition)
		nodes = append(nodes, tuiNode{Kind: "workshop", Index: i, Name: label})
	}
	if len(nodes) == 0 {
		message := "No Workshop definitions"
		if m.DiscoveryError != "" {
			message = "Workshop discovery failed: " + interfaceview.Safe(m.DiscoveryError)
		}
		nodes = append(nodes, tuiNode{Header: true, Name: message})
	}
	m.show(nodes, fmt.Sprintf(" Workshops: %d", len(m.Configurations)))
}
func (m *tuiExplorer) openWorkshop(index int) {
	m.CurrentWorkshop = index
	c := m.Configurations[index]
	nodes := []tuiNode{{Header: true, Name: "[SDKs]"}}
	type sdkRow struct {
		node                          tuiNode
		name, source, status, channel string
	}
	var rows []sdkRow
	for _, d := range c.SDKs {
		if d.Name == "system" {
			rows = append(rows, sdkRow{node: tuiNode{Kind: "workshop-system", Index: d.Order}, name: "system", source: "built-in", status: "configuration"})
			continue
		}
		found := -1
		for i, item := range m.SDKs {
			for _, usage := range item.Declarations {
				if usage.Definition == c.Definition && usage.Order == d.Order {
					found = i
					break
				}
			}
			if found >= 0 {
				break
			}
		}
		if found >= 0 {
			item := m.SDKs[found]
			rows = append(rows, sdkRow{node: tuiNode{Kind: "workshop-sdk", Index: found, DeclarationOrder: d.Order}, name: item.Name, source: item.Source, status: item.Status, channel: item.Channel})
		} else {
			rows = append(rows, sdkRow{node: tuiNode{Header: true}, name: d.Name, status: "unavailable"})
		}
	}
	var nameWidth, sourceWidth, statusWidth int
	for i := range rows {
		row := &rows[i]
		row.name, row.source, row.status, row.channel = interfaceview.Safe(row.name), interfaceview.Safe(row.source), interfaceview.Safe(row.status), interfaceview.Safe(row.channel)
		nameWidth = max(nameWidth, len([]rune(row.name)))
		sourceWidth = max(sourceWidth, len([]rune(row.source)))
		statusWidth = max(statusWidth, len([]rune(row.status)))
	}
	for _, row := range rows {
		row.node.Name = row.name + strings.Repeat(" ", nameWidth-len([]rune(row.name))+3) + row.source + strings.Repeat(" ", sourceWidth-len([]rune(row.source))+3) + row.status
		if row.channel != "" {
			row.node.Name += strings.Repeat(" ", statusWidth-len([]rune(row.status))+3) + row.channel
		}
		nodes = append(nodes, row.node)
	}
	if len(c.SDKs) == 0 {
		nodes = append(nodes, tuiNode{Header: true, Name: "No SDKs declared"})
	}
	nodes = append(nodes, tuiNode{Header: true, Name: "[Configuration]"}, tuiNode{Kind: "workshop-interfaces", Name: "Interfaces  ›"}, tuiNode{Header: true, Name: "[Scan results]"}, tuiNode{Kind: "workshop-assessment", Name: "SDK assessment  ›"}, tuiNode{Kind: "workshop-reviews", Name: "Interface exposure review  ›"})
	base := ""
	for _, w := range m.Workshops {
		if w.Definition == c.Definition {
			base = w.Base
			break
		}
	}
	m.show(nodes, interfaceview.Safe(" Workshop: "+c.Name+"  ("+c.Definition+")  "+base))
}
func (m *tuiExplorer) openSystem(order int) {
	c := m.Configurations[m.CurrentWorkshop]
	for _, d := range c.SDKs {
		if d.Order != order {
			continue
		}
		item := tuiSDK{Declarations: []sdk.Declaration{{Workshop: c.Name, Definition: c.Definition, Plugs: d.Plugs, Slots: d.Slots}}}
		nodes := interfaceNodes(item)
		nodes = append(nodes[:1], nodes[2:]...)
		m.show(nodes, interfaceview.Safe(" Workshop: "+c.Name+"  ›  system configuration"))
		return
	}
}
func (m *tuiExplorer) openWorkshopInterfaces() {
	c := m.Configurations[m.CurrentWorkshop]
	nodes := []tuiNode{}
	for _, kind := range []string{"binding", "connection"} {
		nodes = append(nodes, tuiNode{Header: true, Name: "[" + strings.ToUpper(kind[:1]) + kind[1:] + "s]"})
		count := 0
		for _, g := range m.Topology {
			if g.Definition != c.Definition {
				continue
			}
			if g.Incomplete {
				nodes = append(nodes, tuiNode{Header: true, Name: "Configuration incomplete"})
			}
			for _, edge := range g.Edges {
				if edge.Kind != kind {
					continue
				}
				e := edge
				count++
				nodes = append(nodes, tuiNode{Kind: "topology-edge", Name: interfaceview.Safe(e.From.Reference + " → " + e.To.Reference + " [" + e.State + "]"), Edge: &e})
			}
		}
		if count == 0 {
			nodes = append(nodes, tuiNode{Header: true, Name: "None configured"})
		}
	}
	m.show(nodes, interfaceview.Safe(" Workshop: "+c.Name+"  ›  Interfaces (static configuration)"))
}
func (m *tuiExplorer) openWorkshopReviews() {
	c := m.Configurations[m.CurrentWorkshop]
	nodes := []tuiNode{}
	for _, review := range m.Reviews {
		if review.Definition != c.Definition {
			continue
		}
		if review.Incomplete {
			nodes = append(nodes, tuiNode{Header: true, Name: "Not evaluated: incomplete declarations"})
		}
		for _, entry := range review.Items {
			item := entry
			nodes = append(nodes, tuiNode{Kind: "exposure-review", Name: interfaceview.Safe(item.Kind + " " + item.SDK + ":" + item.Name + " — " + item.Fact), Review: &item})
		}
	}
	if len(nodes) == 0 {
		nodes = append(nodes, tuiNode{Header: true, Name: "No review items"})
	}
	m.show(nodes, interfaceview.Safe(" Workshop: "+c.Name+"  ›  Exposure review (unscored)"))
}

func (m *tuiExplorer) openAssessment() {
	if m.Scan == nil {
		if m.Scanning {
			m.Message = "Scan in progress"
		} else {
			m.Message = "Scan result unavailable"
		}
		return
	}
	var output bytes.Buffer
	assessment := m.Scan.Assessment
	workshop := m.InTopology && m.CurrentWorkshop >= 0 && m.CurrentWorkshop < len(m.Configurations)
	if workshop {
		config := m.Configurations[m.CurrentWorkshop]
		orders := make(map[int]bool, len(config.SDKs))
		for _, declaration := range config.SDKs {
			orders[declaration.Order] = true
		}
		assessment.BySDK = nil
		for _, item := range m.Scan.Assessment.BySDK {
			for _, declaration := range item.Declarations {
				if declaration.Definition == config.Definition && orders[declaration.Order] {
					assessment.BySDK = append(assessment.BySDK, item)
					break
				}
			}
		}
	}
	assessment, err := safeTUIAssessment(assessment)
	if err != nil {
		m.Message = "Cannot display assessment: " + err.Error()
		return
	}
	color := os.Getenv("NO_COLOR") == ""
	if workshop {
		err = report.WriteSDKAssessmentsWithOptions(&output, assessment.BySDK, report.TextOptions{Color: color})
	} else {
		err = report.WriteAssessmentWithOptions(&output, assessment, report.TextOptions{Color: color})
	}
	if err != nil {
		m.Message = "Cannot display assessment: " + err.Error()
		return
	}
	lines := strings.Split(strings.Trim(output.String(), "\n"), "\n")
	status := "Project-wide scan assessment (all Workshops)"
	if workshop {
		status = "SDK assessments for this Workshop"
	}
	m.Preview = &tuiPreview{Path: "SDK assessment", Status: status, Lines: lines, Interface: true, Colored: color}
}

// Sanitize untrusted evidence before the report renderer adds its own ANSI colors.
func safeTUIAssessment(assessment finding.Assessment) (finding.Assessment, error) {
	encoded, err := json.Marshal(assessment)
	if err != nil {
		return finding.Assessment{}, err
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		return finding.Assessment{}, err
	}
	var clean func(any) any
	clean = func(v any) any {
		switch x := v.(type) {
		case string:
			return interfaceview.Safe(x)
		case []any:
			for i := range x {
				x[i] = clean(x[i])
			}
		case map[string]any:
			for k, item := range x {
				x[k] = clean(item)
			}
		}
		return v
	}
	encoded, err = json.Marshal(clean(value))
	if err != nil {
		return finding.Assessment{}, err
	}
	var result finding.Assessment
	err = json.Unmarshal(encoded, &result)
	return result, err
}

func (m *tuiExplorer) move(delta int) {
	if delta == 0 {
		return
	}
	if m.Preview != nil {
		m.Preview.Scroll = max(0, min(max(0, len(m.Preview.Lines)-1), m.Preview.Scroll+delta))
		return
	}
	count := len(m.SDKs)
	if m.InTree {
		count = len(m.Nodes)
	}
	if count == 0 {
		return
	}
	if m.InTree {
		next := max(0, min(count-1, m.SelectedNode+delta))
		for next >= 0 && next < count && m.Nodes[next].Header {
			next += signTUI(delta)
		}
		if next >= 0 && next < count {
			m.SelectedNode = next
		}
	} else {
		m.SelectedSDK = max(0, min(count-1, m.SelectedSDK+delta))
	}
	m.Message = ""
}

func readTUINodes(entry sdkcache.Entry, directory string, depth int) ([]tuiNode, error) {
	children, err := sdkcache.ReadDir(entry, directory)
	if err != nil {
		return nil, err
	}
	sort.Slice(children, func(i, j int) bool {
		a, b := children[i], children[j]
		if a.IsDir() != b.IsDir() {
			return a.IsDir()
		}
		return a.Name() < b.Name()
	})
	nodes := make([]tuiNode, 0, len(children))
	for _, child := range children {
		// The cache manifest is Latra metadata, not SDK content.
		if directory == "." && child.Name() == sdkcache.ManifestPath {
			continue
		}
		// Symlinks are displayed but never traversed, even if they point inside the SDK.
		symlink := child.Type()&fs.ModeSymlink != 0
		nodes = append(nodes, tuiNode{
			Name: child.Name(), Path: path.Join(directory, child.Name()), Depth: depth,
			Directory: child.IsDir(), Symlink: symlink,
		})
	}
	return nodes, nil
}

// readTUIGroupedNodes divides the SDK tree into semantic sections, without
// opening file contents or walking the full (potentially large) SDK tree.
func readTUIGroupedNodes(entry sdkcache.Entry) ([]tuiNode, error) {
	roots, err := readTUINodes(entry, ".", 0)
	if err != nil {
		return nil, err
	}
	var metadata, hooks, files []tuiNode
	for _, node := range roots {
		switch {
		case node.Path == "sdk.yaml" || (node.Path == "meta" && node.Directory):
			node.Group = "metadata"
			metadata = append(metadata, node)
		case node.Path == "hooks" && node.Directory:
			node.Group = "hooks"
			hooks = append(hooks, node)
		case node.Path == "sdk" && node.Directory:
			children, err := readTUINodes(entry, "sdk", 1)
			if err != nil {
				return nil, err
			}
			hasHooks, hasFiles := false, false
			for _, child := range children {
				if child.Name == "hooks" && child.Directory {
					hasHooks = true
				} else {
					hasFiles = true
				}
			}
			if hasHooks {
				hookNode := node
				hookNode.Group = "hooks"
				hooks = append(hooks, hookNode)
			}
			if hasFiles {
				fileNode := node
				fileNode.Group = "files"
				files = append(files, fileNode)
			}
			if !hasHooks && !hasFiles {
				node.Group = "files"
				files = append(files, node)
			}
		default:
			node.Group = "files"
			files = append(files, node)
		}
	}
	result := make([]tuiNode, 0, len(roots)+4)
	for _, section := range []struct {
		title string
		nodes []tuiNode
	}{
		{"SDK Metadata", metadata}, {"Hooks", hooks}, {"Files", files},
	} {
		result = append(result, tuiNode{Name: "[" + section.title + "]", Header: true, Depth: 0})
		result = append(result, section.nodes...)
	}
	return result, nil
}

func filterTUIGroup(nodes []tuiNode, group string) []tuiNode {
	if group != "files" && group != "hooks" {
		return nodes
	}
	result := nodes[:0]
	for _, node := range nodes {
		if node.Path == "sdk/hooks" && group == "files" {
			continue
		}
		if node.Path != "sdk/hooks" && path.Dir(node.Path) == "sdk" && group == "hooks" {
			continue
		}
		result = append(result, node)
	}
	return result
}

func firstTUISelectable(nodes []tuiNode) int {
	for i, node := range nodes {
		if !node.Header {
			return i
		}
	}
	return 0
}

func signTUI(n int) int {
	if n < 0 {
		return -1
	}
	return 1
}
