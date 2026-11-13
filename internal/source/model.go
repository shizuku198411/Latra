// Package source resolves SDK declarations from Workshop projects.
package source

import "github.com/shizuku198411/Latra/internal/sdk"

// InputKind describes what the scan path resolved to.
type InputKind string

const (
	InputProject    InputKind = "project"
	InputProjectSDK InputKind = "project-sdk"
)

// Workshop is a parsed Workshop definition.
type Workshop struct {
	Name       string `json:"name"`
	Base       string `json:"base"`
	Runtime    string `json:"runtime,omitempty"`
	Definition string `json:"definition"`
}

// Result is the resolved SDK source inventory returned before shell analysis.
type Result struct {
	Kind           InputKind       `json:"kind"`
	Root           string          `json:"root"`
	Workshops      []Workshop      `json:"workshops,omitempty"`
	SDKs           []sdk.SDK       `json:"sdks"`
	Configurations []Configuration `json:"-"`
}

// Configuration retains declarations independently of the scan SDK inventory.
type Configuration struct {
	Name        string
	Definition  string
	SDKs        []ConfigurationSDK
	Connections []Connection
}
type ConfigurationSDK struct {
	Name  string
	Order int
	Plugs map[string]any
	Slots map[string]any
}
type Connection struct {
	Plug, Slot string
	Order      int
}
