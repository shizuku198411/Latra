// Package shell parses Bash source without executing it.
package shell

import "mvdan.cc/sh/v3/syntax"

// ParseStatus describes the completeness of a parsed shell program.
type ParseStatus string

const (
	StatusParsed    ParseStatus = "Parsed"
	StatusRecovered ParseStatus = "Recovered"
	StatusFailed    ParseStatus = "Failed"
)

// Severity classifies parser diagnostics independently from later risk findings.
type Severity string

const (
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Location uses one-based line and column values. End is exclusive.
type Location struct {
	Path        string `json:"path"`
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn"`
}

// Diagnostic records a parser issue without conflating it with a risk finding.
type Diagnostic struct {
	Code       string   `json:"code"`
	Severity   Severity `json:"severity"`
	Message    string   `json:"message"`
	Location   Location `json:"location"`
	Incomplete bool     `json:"incomplete,omitempty"`
}

// Result contains the AST and parse metadata for one hook.
type Result struct {
	Path        string         `json:"path"`
	Status      ParseStatus    `json:"status"`
	Recovered   bool           `json:"recovered"`
	Diagnostics []Diagnostic   `json:"diagnostics,omitempty"`
	NodeTypes   map[string]int `json:"nodeTypes,omitempty"`
	Source      []byte         `json:"-"`
	Program     *syntax.File   `json:"-"`
}
