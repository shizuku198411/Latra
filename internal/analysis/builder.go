package analysis

import (
	"bytes"
	"path/filepath"
	"strings"

	"github.com/shizuku198411/Latra/internal/shell"
	"mvdan.cc/sh/v3/syntax"
)

const candidateLimit = 8

type builder struct {
	sourceName string
	variables  map[string]Value
	functions  map[string]bool
}

// Analyze converts a parsed hook into operations and capabilities.
func Analyze(hook string, parsed *shell.Result) Result {
	result := Result{Context: ContextFor(hook)}
	if parsed == nil || parsed.Program == nil {
		return result
	}
	b := &builder{
		sourceName: parsed.Path,
		variables:  make(map[string]Value),
		functions:  make(map[string]bool),
	}
	result.Operations = b.statements(parsed.Program.Stmts)
	result.Capabilities = ExtractCapabilities(result.Operations, result.Context)
	return result
}

func (b *builder) statements(statements []*syntax.Stmt) []Operation {
	var operations []Operation
	for _, statement := range statements {
		operations = append(operations, b.statement(statement)...)
	}
	return operations
}

func (b *builder) statement(statement *syntax.Stmt) []Operation {
	if statement == nil || statement.Cmd == nil {
		return nil
	}
	var operations []Operation
	switch command := statement.Cmd.(type) {
	case *syntax.CallExpr:
		operations = append(operations, b.call(command)...)
	case *syntax.DeclClause:
		for _, assignment := range command.Args {
			operations = append(operations, b.assignment(assignment))
		}
	case *syntax.BinaryCmd:
		operation := Operation{
			Kind:       OperationControlFlow,
			Name:       command.Op.String(),
			Resolution: Resolved,
			Location:   shell.LocationOf(b.sourceName, command),
		}
		if command.Op == syntax.Pipe || command.Op == syntax.PipeAll {
			operation.Kind = OperationPipeline
		}
		operation.Children = append(operation.Children, b.statement(command.X)...)
		operation.Children = append(operation.Children, b.statement(command.Y)...)
		if operation.Kind == OperationPipeline && len(operation.Children) > 1 {
			stream := literalValue("stdout")
			operation.Children[0].Outputs = append(operation.Children[0].Outputs, DataReference{Kind: "pipeline", Value: stream})
			operation.Children[1].Inputs = append(operation.Children[1].Inputs, DataReference{Kind: "pipeline", Value: literalValue("stdin")})
		}
		operations = append(operations, operation)
	case *syntax.FuncDecl:
		name := ""
		if command.Name != nil {
			name = command.Name.Value
			b.functions[name] = true
		}
		child := b.child().statement(command.Body)
		operations = append(operations, Operation{
			Kind: OperationFunctionDeclaration, Name: name, Resolution: resolutionForName(name),
			Location: shell.LocationOf(b.sourceName, command), Children: child,
		})
	case *syntax.IfClause:
		operations = append(operations, b.ifClause(command))
	case *syntax.WhileClause:
		child := b.child()
		children := child.statements(command.Cond)
		children = append(children, child.statements(command.Do)...)
		operations = append(operations, Operation{Kind: OperationControlFlow, Name: "loop", Resolution: PartiallyResolved,
			Location: shell.LocationOf(b.sourceName, command), Children: children})
	case *syntax.ForClause:
		child := b.child()
		operations = append(operations, Operation{Kind: OperationControlFlow, Name: "loop", Resolution: PartiallyResolved,
			Location: shell.LocationOf(b.sourceName, command), Children: child.statements(command.Do)})
	case *syntax.CaseClause:
		var children []Operation
		for _, item := range command.Items {
			children = append(children, b.child().statements(item.Stmts)...)
		}
		operations = append(operations, Operation{Kind: OperationControlFlow, Name: "case", Resolution: PartiallyResolved,
			Location: shell.LocationOf(b.sourceName, command), Children: children})
	case *syntax.Subshell:
		operations = append(operations, b.child().statements(command.Stmts)...)
	case *syntax.Block:
		operations = append(operations, b.statements(command.Stmts)...)
	}

	for _, redirect := range statement.Redirs {
		operation := b.redirect(redirect)
		operations = append(operations, operation)
	}
	return operations
}

func (b *builder) call(call *syntax.CallExpr) []Operation {
	var operations []Operation
	for _, assignment := range call.Assigns {
		operation := b.assignment(assignment)
		operations = append(operations, operation)
	}
	if len(call.Args) == 0 {
		return operations
	}

	words := make([]Value, 0, len(call.Args))
	for _, word := range call.Args {
		words = append(words, b.value(word))
	}
	command, arguments, wrappers := normalizeCommand(words)
	kind := OperationCommand
	if command.Resolution != Resolved {
		kind = OperationCommand
	} else if b.functions[command.Literal] {
		kind = OperationFunctionInvocation
	} else if command.Literal == "eval" {
		kind = OperationEval
	} else if command.Literal == "source" || command.Literal == "." {
		kind = OperationSource
	}
	operation := Operation{
		Kind: kind, Command: command, Arguments: arguments, Wrappers: wrappers,
		Resolution: command.Resolution, Location: shell.LocationOf(b.sourceName, call),
	}
	for _, word := range call.Args {
		operation.Children = append(operation.Children, b.substitutions(word)...)
	}
	operations = append(operations, operation)
	return operations
}

func (b *builder) assignment(assignment *syntax.Assign) Operation {
	name := ""
	if assignment.Name != nil {
		name = assignment.Name.Value
	}
	value := b.value(assignment.Value)
	if name != "" && assignment.Index == nil && assignment.Array == nil && !assignment.Append {
		b.variables[name] = value
	}
	return Operation{Kind: OperationAssignment, Name: name, Arguments: []Value{value},
		Resolution: value.Resolution, Location: shell.LocationOf(b.sourceName, assignment),
		Children: b.substitutions(assignment.Value)}
}

func (b *builder) redirect(redirect *syntax.Redirect) Operation {
	value := b.value(redirect.Word)
	kind := OperationRedirectWrite
	referenceKind := "file-write"
	switch redirect.Op {
	case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn, syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		kind = OperationRedirectRead
		referenceKind = "file-read"
	}
	operation := Operation{Kind: kind, Arguments: []Value{value}, Resolution: value.Resolution,
		Location: shell.LocationOf(b.sourceName, redirect)}
	reference := DataReference{Kind: referenceKind, Value: value}
	if kind == OperationRedirectRead {
		operation.Inputs = []DataReference{reference}
	} else {
		operation.Outputs = []DataReference{reference}
	}
	return operation
}

func (b *builder) ifClause(clause *syntax.IfClause) Operation {
	before := cloneValues(b.variables)
	thenBuilder := b.child()
	children := thenBuilder.statements(clause.Cond)
	children = append(children, thenBuilder.statements(clause.Then)...)
	branches := []map[string]Value{thenBuilder.variables}
	if clause.Else != nil {
		elseBuilder := b.child()
		children = append(children, elseBuilder.ifBranch(clause.Else)...)
		branches = append(branches, elseBuilder.variables)
	} else {
		branches = append(branches, before)
	}
	b.variables = mergeValues(branches)
	return Operation{Kind: OperationControlFlow, Name: "if", Resolution: PartiallyResolved,
		Location: shell.LocationOf(b.sourceName, clause), Children: children}
}

func (b *builder) ifBranch(clause *syntax.IfClause) []Operation {
	children := b.statements(clause.Cond)
	children = append(children, b.statements(clause.Then)...)
	if clause.Else != nil {
		children = append(children, b.ifBranch(clause.Else)...)
	}
	return children
}

func (b *builder) value(word *syntax.Word) Value {
	if word == nil {
		return literalValue("")
	}
	if len(word.Parts) == 1 {
		return b.wordPart(word.Parts[0], false)
	}
	value := Value{Resolution: Resolved}
	var rendered strings.Builder
	for _, part := range word.Parts {
		partValue := b.wordPart(part, false)
		value.Parts = append(value.Parts, partValue.Parts...)
		if partValue.Resolution == Unknown {
			value.Resolution = Unknown
		} else if partValue.Resolution == PartiallyResolved && value.Resolution == Resolved {
			value.Resolution = PartiallyResolved
		}
		if partValue.Resolution == Resolved {
			rendered.WriteString(partValue.Literal)
		}
	}
	if value.Resolution == Resolved {
		value.Literal = rendered.String()
	}
	return value
}

func (b *builder) wordPart(part syntax.WordPart, quoted bool) Value {
	switch part := part.(type) {
	case *syntax.Lit:
		kind := PartLiteral
		if quoted {
			kind = PartQuotedLiteral
		}
		resolution := Resolved
		if !quoted && hasGlob(part.Value) {
			kind = PartGlob
			resolution = PartiallyResolved
		}
		return Value{Parts: []ValuePart{{Kind: kind, Text: part.Value}}, Resolution: resolution, Literal: part.Value}
	case *syntax.SglQuoted:
		return Value{Parts: []ValuePart{{Kind: PartQuotedLiteral, Text: part.Value}}, Resolution: Resolved, Literal: part.Value}
	case *syntax.DblQuoted:
		return b.parts(part.Parts, true)
	case *syntax.ParamExp:
		name := ""
		if part.Param != nil {
			name = part.Param.Value
		}
		piece := ValuePart{Kind: PartVariableReference, Name: name}
		if known, ok := b.variables[name]; ok && !part.Excl && !part.Length && part.Index == nil && part.Exp == nil && part.Repl == nil {
			known.Parts = []ValuePart{piece}
			return known
		}
		return Value{Parts: []ValuePart{piece}, Resolution: Unknown}
	case *syntax.CmdSubst:
		return Value{Parts: []ValuePart{{Kind: PartCommandSubstitution}}, Resolution: Unknown}
	case *syntax.ArithmExp:
		return Value{Parts: []ValuePart{{Kind: PartArithmeticExpansion, Text: render(part)}}, Resolution: PartiallyResolved}
	case *syntax.ProcSubst:
		return Value{Parts: []ValuePart{{Kind: PartUnknownExpansion, Text: render(part)}}, Resolution: Unknown}
	default:
		return Value{Parts: []ValuePart{{Kind: PartUnknownExpansion, Text: render(part)}}, Resolution: Unknown}
	}
}

func (b *builder) parts(parts []syntax.WordPart, quoted bool) Value {
	if len(parts) == 1 {
		return b.wordPart(parts[0], quoted)
	}
	value := Value{Resolution: Resolved}
	var literal strings.Builder
	for _, part := range parts {
		piece := b.wordPart(part, quoted)
		value.Parts = append(value.Parts, piece.Parts...)
		if piece.Resolution == Unknown {
			value.Resolution = Unknown
		} else if piece.Resolution == PartiallyResolved && value.Resolution == Resolved {
			value.Resolution = PartiallyResolved
		}
		if piece.Resolution == Resolved {
			literal.WriteString(piece.Literal)
		}
	}
	if value.Resolution == Resolved {
		value.Literal = literal.String()
	}
	return value
}

func (b *builder) substitutions(word *syntax.Word) []Operation {
	var operations []Operation
	if word == nil {
		return nil
	}
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CmdSubst:
			operations = append(operations, Operation{Kind: OperationCommandSubstitution, Resolution: Unknown,
				Location: shell.LocationOf(b.sourceName, node), Children: b.child().statements(node.Stmts)})
			return false
		case *syntax.ProcSubst:
			operations = append(operations, Operation{Kind: OperationProcessSubstitution, Resolution: Unknown,
				Location: shell.LocationOf(b.sourceName, node), Children: b.child().statements(node.Stmts)})
			return false
		}
		return true
	})
	return operations
}

func normalizeCommand(words []Value) (Value, []Value, []string) {
	command := words[0]
	arguments := words[1:]
	var wrappers []string
	for command.Resolution == Resolved {
		name := filepath.Base(command.Literal)
		if !isCommandWrapper(name) {
			command.Literal = name
			break
		}
		wrappers = append(wrappers, name)
		index := wrappedCommandIndex(name, arguments)
		if index >= len(arguments) {
			return Value{Resolution: Unknown}, nil, wrappers
		}
		command = arguments[index]
		arguments = arguments[index+1:]
	}
	return command, arguments, wrappers
}

func isCommandWrapper(name string) bool {
	switch name {
	case "command", "builtin", "sudo", "runuser", "pkexec", "env", "timeout", "nice", "nohup", "setsid", "chroot", "unshare", "nsenter", "setpriv":
		return true
	default:
		return false
	}
}

func wrappedCommandIndex(name string, arguments []Value) int {
	index := 0
	consumeOptions := func(optionsWithValue map[string]bool) {
		for index < len(arguments) {
			argument := arguments[index]
			if argument.Resolution != Resolved || argument.Literal == "--" {
				if argument.Literal == "--" {
					index++
				}
				return
			}
			if !strings.HasPrefix(argument.Literal, "-") || argument.Literal == "-" {
				return
			}
			option := argument.Literal
			index++
			if optionsWithValue[option] && index < len(arguments) {
				index++
			}
		}
	}
	switch name {
	case "command", "builtin", "nohup", "setsid":
		consumeOptions(nil)
	case "sudo":
		consumeOptions(map[string]bool{"-u": true, "--user": true, "-g": true, "--group": true, "-h": true, "--host": true, "-C": true, "--close-from": true, "-R": true, "--chroot": true, "-D": true, "--chdir": true, "-T": true, "--command-timeout": true})
	case "runuser":
		consumeOptions(map[string]bool{"-u": true, "--user": true, "-g": true, "--group": true, "-G": true, "--supp-group": true})
	case "pkexec":
		consumeOptions(map[string]bool{"-u": true, "--user": true})
	case "env":
		consumeOptions(map[string]bool{"-u": true, "--unset": true, "-C": true, "--chdir": true, "-S": true, "--split-string": true})
		for index < len(arguments) && arguments[index].Resolution == Resolved && strings.Contains(arguments[index].Literal, "=") {
			index++
		}
	case "timeout":
		consumeOptions(map[string]bool{"-k": true, "--kill-after": true, "-s": true, "--signal": true})
		if index < len(arguments) {
			index++
		}
	case "nice":
		consumeOptions(map[string]bool{"-n": true, "--adjustment": true})
	case "chroot":
		consumeOptions(map[string]bool{"--userspec": true, "--groups": true})
		if index < len(arguments) {
			index++
		}
	case "unshare":
		consumeOptions(map[string]bool{"--fork": false, "--map-user": true, "--map-group": true, "--map-users": true, "--map-groups": true, "--root": true, "--wd": true, "--mount-proc": false, "--propagation": true, "--kill-child": false, "--setgroups": true, "--keep-caps": false, "--monotonic": true, "--boottime": true})
	case "nsenter":
		consumeOptions(map[string]bool{"-t": true, "--target": true, "-m": false, "--mount": false, "-u": false, "--uts": false, "-i": false, "--ipc": false, "-n": false, "--net": false, "-p": false, "--pid": false, "-C": false, "--cgroup": false, "-U": false, "--user": false, "-T": false, "--time": false, "-r": false, "--root": false, "-w": false, "--wd": false, "-S": true, "--setuid": true, "-G": true, "--setgid": true})
	case "setpriv":
		consumeOptions(map[string]bool{"--reuid": true, "--regid": true, "--ruid": true, "--euid": true, "--rgid": true, "--egid": true, "--clear-groups": false, "--keep-groups": false, "--init-groups": false, "--groups": true, "--bounding-set": true, "--inh-caps": true, "--ambient-caps": true, "--securebits": true, "--pdeathsig": true, "--selinux-label": true, "--apparmor-profile": true, "--landlock-access": true})
	}
	return index
}

func (b *builder) child() *builder {
	return &builder{
		sourceName: b.sourceName,
		variables:  cloneValues(b.variables),
		functions:  cloneSet(b.functions),
	}
}

func cloneValues(values map[string]Value) map[string]Value {
	clone := make(map[string]Value, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func cloneSet(values map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(values))
	for key, value := range values {
		clone[key] = value
	}
	return clone
}

func mergeValues(branches []map[string]Value) map[string]Value {
	merged := make(map[string]Value)
	keys := make(map[string]bool)
	for _, branch := range branches {
		for key := range branch {
			keys[key] = true
		}
	}
	for key := range keys {
		var candidates []string
		allResolved := true
		for _, branch := range branches {
			value, ok := branch[key]
			if !ok || value.Resolution != Resolved {
				allResolved = false
				continue
			}
			if !contains(candidates, value.Literal) {
				candidates = append(candidates, value.Literal)
			}
		}
		if !allResolved || len(candidates) == 0 || len(candidates) > candidateLimit {
			merged[key] = Value{Resolution: Unknown}
		} else if len(candidates) == 1 {
			merged[key] = literalValue(candidates[0])
		} else {
			merged[key] = Value{Resolution: PartiallyResolved, Candidates: candidates}
		}
	}
	return merged
}

func render(node syntax.Node) string {
	var buffer bytes.Buffer
	if err := syntax.NewPrinter(syntax.Minify(true)).Print(&buffer, node); err != nil {
		return ""
	}
	return buffer.String()
}

func literalValue(value string) Value {
	return Value{Parts: []ValuePart{{Kind: PartLiteral, Text: value}}, Resolution: Resolved, Literal: value}
}

func resolutionForName(name string) Resolution {
	if name == "" {
		return Unknown
	}
	return Resolved
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hasGlob(value string) bool {
	if strings.ContainsAny(value, "*?") {
		return true
	}
	left := strings.IndexByte(value, '[')
	return left >= 0 && strings.IndexByte(value[left+1:], ']') >= 0
}
