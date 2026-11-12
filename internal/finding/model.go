// Package finding evaluates explainable findings from an SDK inventory.
package finding

import (
	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

type Kind string

const (
	KindRisk        Kind = "risk"
	KindAssurance   Kind = "assurance"
	KindObservation Kind = "observation"
)

type Database struct {
	SchemaVersion  string `json:"schemaVersion"`
	ContentVersion string `json:"contentVersion"`
	Source         string `json:"source"`
}

type Scope struct {
	SDK  string       `json:"sdk"`
	Hook sdk.HookName `json:"hook,omitempty"`
}

type Context struct {
	RunAsRoot        bool `json:"runAsRoot"`
	ProjectMounted   bool `json:"projectMounted"`
	InterfacesActive bool `json:"interfacesActive"`
	StateMounted     bool `json:"stateMounted"`
}

// EvidenceDerivation describes how directly static inventory supports an
// evidence item. It is separate from Resolution: derivation describes the
// reasoning step, while resolution describes value certainty.
type EvidenceDerivation string

const (
	EvidenceDirect     EvidenceDerivation = "direct"
	EvidenceInferred   EvidenceDerivation = "inferred"
	EvidenceUnresolved EvidenceDerivation = "unresolved"
)

type Evidence struct {
	SDK                  string              `json:"sdk,omitempty"`
	Type                 string              `json:"type"`
	ID                   string              `json:"id,omitempty"`
	OperationID          string              `json:"operationId,omitempty"`
	FromOperationID      string              `json:"fromOperationId,omitempty"`
	ToOperationID        string              `json:"toOperationId,omitempty"`
	Value                string              `json:"value,omitempty"`
	Expression           string              `json:"expression,omitempty"`
	NormalizedValue      string              `json:"normalizedValue,omitempty"`
	NormalizedCandidates []string            `json:"normalizedCandidates,omitempty"`
	Resolution           analysis.Resolution `json:"resolution,omitempty"`
	Derivation           EvidenceDerivation  `json:"derivation,omitempty"`
	Relations            []analysis.Relation `json:"relations,omitempty"`
	Location             *shell.Location     `json:"location,omitempty"`
	ValueLocation        *shell.Location     `json:"valueLocation,omitempty"`
}

// CompositionRelation connects behavior across ordered SDK declarations in a
// single Workshop definition and lifecycle window.
type CompositionRelation struct {
	Kind            string              `json:"kind"`
	Workshop        string              `json:"workshop"`
	Definition      string              `json:"definition"`
	Hook            sdk.HookName        `json:"hook"`
	FromSDK         string              `json:"fromSdk"`
	ToSDK           string              `json:"toSdk"`
	FromOrder       int                 `json:"fromOrder"`
	ToOrder         int                 `json:"toOrder"`
	FromOperationID string              `json:"fromOperationId"`
	ToOperationID   string              `json:"toOperationId"`
	Artifact        analysis.Value      `json:"artifact"`
	Resolution      analysis.Resolution `json:"resolution"`
}

type Finding struct {
	ID              string     `json:"id"`
	Kind            Kind       `json:"kind"`
	Family          string     `json:"family"`
	Title           string     `json:"title"`
	Severity        string     `json:"severity,omitempty"`
	Strength        string     `json:"strength,omitempty"`
	Confidence      string     `json:"confidence"`
	Weight          int        `json:"weight"`
	Scope           Scope      `json:"scope"`
	Context         *Context   `json:"context,omitempty"`
	Evidence        []Evidence `json:"evidence"`
	Message         string     `json:"message"`
	Remediation     string     `json:"remediation,omitempty"`
	ProtectsAgainst []string   `json:"protectsAgainst,omitempty"`
	Limitations     []string   `json:"limitations,omitempty"`
}
