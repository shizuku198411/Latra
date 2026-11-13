package cli

import (
	"io/fs"
	"path"
	"sort"

	"github.com/shizuku198411/Latra/internal/interfaceview"
	"github.com/shizuku198411/Latra/internal/report"
	"github.com/shizuku198411/Latra/internal/sdkcache"
)

type tuiNode struct {
	Name, Path string
	Depth      int
	Directory  bool
	Symlink    bool
	Expanded   bool
	Header     bool
	Group      string
	Kind       string
	Interface  *interfaceview.Entry
	Children   []tuiNode
}

type tuiExplorer struct {
	SDKs         []tuiSDK
	SelectedSDK  int
	InTree       bool
	SelectedNode int
	Nodes        []tuiNode
	Message      string
	ScanStatus   string
	Preview      *tuiPreview
	Scan         *report.Document
	Scanning     bool
}

func (m *tuiExplorer) enter() {
	if m.Preview != nil {
		return
	}
	if !m.InTree {
		if len(m.SDKs) == 0 {
			return
		}
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
		m.Nodes, m.SelectedNode, m.InTree, m.Message = children, firstTUISelectable(children), true, ""
		return
	}
	if len(m.Nodes) == 0 {
		return
	}
	node := m.Nodes[m.SelectedNode]
	if node.Kind == "interface" {
		m.Preview = &tuiPreview{Path: node.Interface.Name, Status: "Interface declaration (read-only)", Lines: node.Interface.Details(), Interface: true}
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
	if m.InTree {
		m.InTree, m.Nodes, m.SelectedNode, m.Message = false, nil, 0, ""
	}
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
