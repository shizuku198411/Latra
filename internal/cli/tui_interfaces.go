package cli

import (
	"fmt"
	"github.com/shizuku198411/Latra/internal/interfaceview"
)

func interfaceNodes(item tuiSDK) []tuiNode {
	nodes := []tuiNode{{Name: "[Interfaces]", Header: true}}
	if item.Metadata == nil {
		nodes = append(nodes, tuiNode{Name: "SDK declarations: unavailable", Header: true})
		if item.MetadataError != "" {
			nodes = append(nodes, tuiNode{Name: "Reason: " + interfaceview.Safe(item.MetadataError), Header: true})
		}
	}
	entries := interfaceview.Entries(item.Metadata, item.MetadataPath, item.Declarations)
	for _, kind := range []string{"Plug", "Slot"} {
		var children []tuiNode
		for _, e := range entries {
			if e.Kind == kind {
				entry := e
				children = append(children, tuiNode{Name: e.Label(), Depth: 1, Kind: "interface", Interface: &entry})
			}
		}
		nodes = append(nodes, tuiNode{Name: fmt.Sprintf("%ss (%d)", kind, len(children)), Directory: true, Kind: "interface-group", Children: children})
	}
	return nodes
}
