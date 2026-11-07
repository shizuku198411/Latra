package cli

import (
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/shizuku198411/Latra/internal/sdkcache"
)

type tuiNode struct {
	Name, Path string
	Depth      int
	Directory  bool
	Symlink    bool
	Expanded   bool
}

type tuiExplorer struct {
	SDKs         []tuiSDK
	SelectedSDK  int
	InTree       bool
	SelectedNode int
	Nodes        []tuiNode
	Message      string
	Preview      *tuiPreview
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
		if item.Status != "local" && item.Status != "cached" {
			m.Message = fmt.Sprintf("%s: %s", item.Name, item.Status)
			if item.Error != "" {
				m.Message += ": " + item.Error
			}
			return
		}
		children, err := readTUINodes(item.Entry, ".", 0)
		if err != nil {
			m.Message = err.Error()
			return
		}
		m.Nodes, m.SelectedNode, m.InTree, m.Message = children, 0, true, ""
		return
	}
	if len(m.Nodes) == 0 {
		return
	}
	node := m.Nodes[m.SelectedNode]
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
	children, err := readTUINodes(m.SDKs[m.SelectedSDK].Entry, node.Path, node.Depth+1)
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
		m.SelectedNode = max(0, min(count-1, m.SelectedNode+delta))
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
