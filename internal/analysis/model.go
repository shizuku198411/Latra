// Package analysis converts Bash syntax trees into Latra's parser-independent
// operation and capability inventory.
package analysis

import "github.com/shizuku198411/Latra/internal/shell"

// Resolution describes how completely a value or operation was resolved.
type Resolution string

const (
	Resolved          Resolution = "Resolved"
	PartiallyResolved Resolution = "PartiallyResolved"
	Unknown           Resolution = "Unknown"
)

// ValuePartKind identifies one component of a shell word.
type ValuePartKind string

const (
	PartLiteral             ValuePartKind = "literal"
	PartQuotedLiteral       ValuePartKind = "quoted-literal"
	PartVariableReference   ValuePartKind = "variable-reference"
	PartCommandSubstitution ValuePartKind = "command-substitution"
	PartArithmeticExpansion ValuePartKind = "arithmetic-expansion"
	PartGlob                ValuePartKind = "glob"
	PartUnknownExpansion    ValuePartKind = "unknown-expansion"
)

// Value preserves shell word structure instead of flattening it prematurely.
type Value struct {
	Parts      []ValuePart `json:"parts,omitempty"`
	Resolution Resolution  `json:"resolution"`
	Literal    string      `json:"literal,omitempty"`
	Candidates []string    `json:"candidates,omitempty"`
}

// ValuePart is a source-level component of a Value.
type ValuePart struct {
	Kind ValuePartKind `json:"kind"`
	Text string        `json:"text,omitempty"`
	Name string        `json:"name,omitempty"`
}

// OperationKind identifies a normalized shell operation.
type OperationKind string

const (
	OperationCommand             OperationKind = "command-invocation"
	OperationAssignment          OperationKind = "assignment"
	OperationPipeline            OperationKind = "pipeline"
	OperationRedirectRead        OperationKind = "redirect-read"
	OperationRedirectWrite       OperationKind = "redirect-write"
	OperationCommandSubstitution OperationKind = "command-substitution"
	OperationProcessSubstitution OperationKind = "process-substitution"
	OperationFunctionDeclaration OperationKind = "function-declaration"
	OperationFunctionInvocation  OperationKind = "function-invocation"
	OperationSource              OperationKind = "source"
	OperationEval                OperationKind = "eval"
	OperationControlFlow         OperationKind = "control-flow"
)

// DataReference records a basic input or output edge.
type DataReference struct {
	Kind  string `json:"kind"`
	Value Value  `json:"value"`
}

// RelationKind identifies a structural or data-flow edge between operations.
type RelationKind string

const (
	RelationContains         RelationKind = "contains"
	RelationSequence         RelationKind = "sequence"
	RelationPipeline         RelationKind = "pipeline"
	RelationSubstitutionFlow RelationKind = "substitution-flow"
	RelationVariableFlow     RelationKind = "variable-flow"
)

// Relation connects two operations in the per-hook analysis graph.
type Relation struct {
	Kind            RelationKind `json:"kind"`
	FromOperationID string       `json:"fromOperationId"`
	ToOperationID   string       `json:"toOperationId"`
	Name            string       `json:"name,omitempty"`
	Resolution      Resolution   `json:"resolution"`
}

// Operation is Latra's parser-independent representation of shell behavior.
type Operation struct {
	ID         string          `json:"id,omitempty"`
	ParentID   string          `json:"parentId,omitempty"`
	Sequence   int             `json:"sequence"`
	Kind       OperationKind   `json:"kind"`
	Command    Value           `json:"command,omitzero"`
	Name       string          `json:"name,omitempty"`
	Wrappers   []string        `json:"wrappers,omitempty"`
	Arguments  []Value         `json:"arguments,omitempty"`
	Inputs     []DataReference `json:"inputs,omitempty"`
	Outputs    []DataReference `json:"outputs,omitempty"`
	Resolution Resolution      `json:"resolution"`
	Location   shell.Location  `json:"location"`
	Children   []Operation     `json:"children,omitempty"`

	pipelineBoundary int
}

// HookContext describes Workshop's execution environment for a lifecycle hook.
type HookContext struct {
	Name             string `json:"name"`
	RunAsRoot        bool   `json:"runAsRoot"`
	ProjectMounted   bool   `json:"projectMounted"`
	InterfacesActive bool   `json:"interfacesActive"`
	StateMounted     bool   `json:"stateMounted"`
	ContextDependent bool   `json:"contextDependent,omitempty"`
}

// Capability is an observable behavior inferred from an Operation.
type Capability struct {
	Kind        string         `json:"kind"`
	RuleID      string         `json:"ruleId"`
	RuleSource  string         `json:"ruleSource"`
	Operation   OperationKind  `json:"operation"`
	OperationID string         `json:"operationId,omitempty"`
	Target      Value          `json:"target,omitzero"`
	Resolution  Resolution     `json:"resolution"`
	Location    shell.Location `json:"location"`
}

// Result contains the normalized inventory for one hook.
type Result struct {
	Context      HookContext  `json:"context"`
	Operations   []Operation  `json:"operations,omitempty"`
	Relations    []Relation   `json:"relations,omitempty"`
	Capabilities []Capability `json:"capabilities,omitempty"`
}
