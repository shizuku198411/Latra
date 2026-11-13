package analysis

import (
	"bytes"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/shell"
	"mvdan.cc/sh/v3/syntax"
)

const candidateLimit = 8
const maxFunctionExpansionDepth = 8

type builder struct {
	sourceName         string
	variables          map[string]Value
	functions          map[string]*syntax.FuncDecl
	functionDepth      int
	workingDirectory   Value
	nextStatementGroup *int
}

// Analyze converts a parsed hook into operations and capabilities.
func Analyze(hook string, parsed *shell.Result) Result {
	result := Result{Context: ContextFor(hook)}
	if parsed == nil || parsed.Program == nil {
		return result
	}
	nextStatementGroup := 1
	b := &builder{
		sourceName:         parsed.Path,
		variables:          make(map[string]Value),
		functions:          make(map[string]*syntax.FuncDecl),
		workingDirectory:   initialWorkingDirectory(hook),
		nextStatementGroup: &nextStatementGroup,
	}
	result.Operations = b.statements(parsed.Program.Stmts)
	BuildRelations(result.Operations) // Assign stable IDs before alias edges are created.
	aliases := ResolvePathAliases(result.Operations)
	result.Relations = append(BuildRelations(result.Operations), aliases...)
	result.Capabilities = ExtractCapabilities(result.Operations, result.Context)
	return result
}

// Rebuild refreshes IDs, relations, and capabilities after a trusted caller
// attaches statically resolved operations such as SDK-local includes.
func Rebuild(result *Result) {
	if result == nil {
		return
	}
	aliases := filterAliasRelations(result.Relations)
	if len(aliases) == 0 {
		BuildRelations(result.Operations)
		aliases = ResolvePathAliases(result.Operations)
	}
	result.Relations = append(BuildRelations(result.Operations), aliases...)
	result.Capabilities = ExtractCapabilities(result.Operations, result.Context)
}

func filterAliasRelations(relations []Relation) []Relation {
	var aliases []Relation
	for _, relation := range relations {
		if relation.Kind == RelationAlias {
			aliases = append(aliases, relation)
		}
	}
	return aliases
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
	statementGroup := *b.nextStatementGroup
	*b.nextStatementGroup = *b.nextStatementGroup + 1
	statementWorkingDirectory := b.workingDirectory
	switch command := statement.Cmd.(type) {
	case *syntax.CallExpr:
		operations = append(operations, b.call(command)...)
	case *syntax.DeclClause:
		for _, assignment := range command.Args {
			operations = append(operations, b.assignment(assignment))
		}
	case *syntax.BinaryCmd:
		operations = append(operations, b.binary(command))
	case *syntax.FuncDecl:
		name := ""
		if command.Name != nil {
			name = command.Name.Value
			b.functions[name] = command
		}
		child := b.child().statement(command.Body)
		operations = append(operations, Operation{
			Kind: OperationFunctionDeclaration, Name: name, Resolution: resolutionForName(name),
			Location: shell.LocationOf(b.sourceName, command), Children: child,
		})
	case *syntax.IfClause:
		operations = append(operations, b.ifClause(command))
	case *syntax.WhileClause:
		operations = append(operations, b.whileClause(command))
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
		operation.workingDirectory = statementWorkingDirectory
		operations = append(operations, operation)
	}
	for index := range operations {
		if operations[index].statementGroup == 0 {
			operations[index].statementGroup = statementGroup
		}
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
	} else if b.functions[command.Literal] != nil {
		kind = OperationFunctionInvocation
	} else if command.Literal == "eval" {
		kind = OperationEval
	} else if command.Literal == "source" || command.Literal == "." {
		kind = OperationSource
	}
	operation := Operation{
		Kind: kind, Command: command, Arguments: arguments, Wrappers: wrappers,
		Resolution: command.Resolution, Location: shell.LocationOf(b.sourceName, call),
		workingDirectory: b.workingDirectory,
	}
	if kind == OperationSource && len(arguments) > 0 {
		operation.Inputs = append(operation.Inputs, DataReference{Kind: "file-read", Value: arguments[0]})
	}
	for _, word := range call.Args {
		operation.Children = append(operation.Children, b.substitutions(word)...)
	}
	if kind == OperationFunctionInvocation && b.functionDepth < maxFunctionExpansionDepth {
		if declaration := b.functions[command.Literal]; declaration != nil {
			callee := b.child()
			callee.functionDepth++
			for index, argument := range arguments {
				if index >= 9 {
					break
				}
				callee.variables[fmt.Sprint(index+1)] = argument
			}
			callee.variables["@"] = positionalArgumentsValue(arguments)
			callee.variables["*"] = positionalArgumentsValue(arguments)
			operation.Children = append(operation.Children, callee.statement(declaration.Body)...)
		}
	}
	operations = append(operations, operation)
	if command.Resolution == Resolved && filepath.Base(command.Literal) == "cd" {
		b.workingDirectory = resolveChangedDirectory(arguments, b.workingDirectory)
	}
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
		Children: b.substitutions(assignment.Value), workingDirectory: b.workingDirectory}
}

func (b *builder) redirect(redirect *syntax.Redirect) Operation {
	value := b.value(redirect.Word)
	kind := OperationRedirectWrite
	referenceKind := "file-write"
	heredoc := false
	switch redirect.Op {
	case syntax.RdrIn, syntax.RdrInOut, syntax.DplIn:
		kind = OperationRedirectRead
		referenceKind = "file-read"
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
		kind = OperationRedirectRead
		heredoc = true
		value = b.value(redirect.Hdoc)
	}
	operation := Operation{Kind: kind, Arguments: []Value{value}, Resolution: value.Resolution,
		Location: shell.LocationOf(b.sourceName, redirect)}
	if heredoc {
		operation.Name = "heredoc"
		return operation
	}
	reference := DataReference{Kind: referenceKind, Value: value}
	if kind == OperationRedirectRead {
		operation.Inputs = []DataReference{reference}
	} else {
		operation.Outputs = []DataReference{reference}
	}
	return operation
}

type conditionTruth uint8

const (
	truthUnknown conditionTruth = iota
	truthFalse
	truthTrue
)

func (b *builder) binary(command *syntax.BinaryCmd) Operation {
	operation := Operation{
		Kind: OperationControlFlow, Name: command.Op.String(), Resolution: Resolved,
		Location: shell.LocationOf(b.sourceName, command),
	}
	left := b.statement(command.X)
	operation.Children = append(operation.Children, left...)
	operation.pipelineBoundary = len(operation.Children)

	if command.Op == syntax.Pipe || command.Op == syntax.PipeAll {
		operation.Kind = OperationPipeline
		operation.Children = append(operation.Children, b.statement(command.Y)...)
		if len(operation.Children) > 1 {
			stream := literalValue("stdout")
			operation.Children[0].Outputs = append(operation.Children[0].Outputs, DataReference{Kind: "pipeline", Value: stream})
			operation.Children[operation.pipelineBoundary].Inputs = append(operation.Children[operation.pipelineBoundary].Inputs, DataReference{Kind: "pipeline", Value: literalValue("stdin")})
		}
		return operation
	}

	if command.Op != syntax.AndStmt && command.Op != syntax.OrStmt {
		operation.Children = append(operation.Children, b.statement(command.Y)...)
		return operation
	}

	leftTruth := staticStatement(command.X)
	executeRight := leftTruth == truthTrue
	if command.Op == syntax.OrStmt {
		executeRight = leftTruth == truthFalse
	}
	switch {
	case leftTruth == truthUnknown:
		rightBuilder := b.child()
		right := rightBuilder.statement(command.Y)
		markReachability(right, ReachUnknown)
		operation.Children = append(operation.Children, right...)
		operation.Resolution = PartiallyResolved
		b.variables = mergeValues([]map[string]Value{b.variables, rightBuilder.variables})
		b.workingDirectory = mergePathValues([]Value{b.workingDirectory, rightBuilder.workingDirectory})
	case executeRight:
		operation.Children = append(operation.Children, b.statement(command.Y)...)
	default:
		right := b.child().statement(command.Y)
		markReachability(right, Unreachable)
		operation.Children = append(operation.Children, right...)
	}
	return operation
}

func (b *builder) whileClause(clause *syntax.WhileClause) Operation {
	child := b.child()
	condition := child.statements(clause.Cond)
	truth := staticCondition(clause.Cond)
	if clause.Until {
		truth = negateTruth(truth)
	}
	bodyBuilder := child.child()
	body := bodyBuilder.statements(clause.Do)
	resolution := Resolved
	switch truth {
	case truthFalse:
		markReachability(body, Unreachable)
		b.variables = child.variables
		b.workingDirectory = child.workingDirectory
	case truthTrue:
		// The body is reachable, but a statically true loop may not exit, so its
		// resulting state is not propagated to following statements.
	default:
		resolution = PartiallyResolved
		markReachability(body, ReachUnknown)
		b.variables = mergeValues([]map[string]Value{child.variables, bodyBuilder.variables})
		b.workingDirectory = mergePathValues([]Value{child.workingDirectory, bodyBuilder.workingDirectory})
	}
	return Operation{Kind: OperationControlFlow, Name: "loop", Resolution: resolution,
		Location: shell.LocationOf(b.sourceName, clause), Children: append(condition, body...)}
}

func staticCondition(statements []*syntax.Stmt) conditionTruth {
	if len(statements) != 1 {
		return truthUnknown
	}
	return staticStatement(statements[0])
}

func staticStatement(statement *syntax.Stmt) conditionTruth {
	if statement == nil || statement.Cmd == nil || statement.Background || len(statement.Redirs) > 0 {
		return truthUnknown
	}
	var truth conditionTruth
	switch command := statement.Cmd.(type) {
	case *syntax.CallExpr:
		if len(command.Assigns) != 0 || len(command.Args) != 1 {
			return truthUnknown
		}
		word := command.Args[0]
		if word == nil || len(word.Parts) != 1 {
			return truthUnknown
		}
		literal, ok := word.Parts[0].(*syntax.Lit)
		if !ok {
			return truthUnknown
		}
		switch literal.Value {
		case "true", ":":
			truth = truthTrue
		case "false":
			truth = truthFalse
		default:
			truth = truthUnknown
		}
	case *syntax.BinaryCmd:
		left := staticStatement(command.X)
		right := staticStatement(command.Y)
		switch command.Op {
		case syntax.AndStmt:
			truth = andTruth(left, right)
		case syntax.OrStmt:
			truth = orTruth(left, right)
		default:
			truth = truthUnknown
		}
	default:
		truth = truthUnknown
	}
	if statement.Negated {
		return negateTruth(truth)
	}
	return truth
}

func andTruth(left, right conditionTruth) conditionTruth {
	if left == truthFalse || right == truthFalse {
		return truthFalse
	}
	if left == truthTrue && right == truthTrue {
		return truthTrue
	}
	return truthUnknown
}

func orTruth(left, right conditionTruth) conditionTruth {
	if left == truthTrue || right == truthTrue {
		return truthTrue
	}
	if left == truthFalse && right == truthFalse {
		return truthFalse
	}
	return truthUnknown
}

func negateTruth(truth conditionTruth) conditionTruth {
	switch truth {
	case truthTrue:
		return truthFalse
	case truthFalse:
		return truthTrue
	default:
		return truthUnknown
	}
}

func markReachability(operations []Operation, reachability Reachability) {
	for index := range operations {
		operation := &operations[index]
		if reachability == Unreachable || operation.Reachability == Reachable {
			operation.Reachability = reachability
		}
		markReachability(operation.Children, reachability)
	}
}

func (b *builder) ifClause(clause *syntax.IfClause) Operation {
	beforeWorkingDirectory := b.workingDirectory
	conditionBuilder := b.child()
	children := conditionBuilder.statements(clause.Cond)
	truth := staticCondition(clause.Cond)

	thenBuilder := conditionBuilder.child()
	thenOperations := thenBuilder.statements(clause.Then)

	elseBuilder := conditionBuilder.child()
	var elseOperations []Operation
	if clause.Else != nil {
		if len(clause.Else.Cond) == 0 {
			elseOperations = elseBuilder.statements(clause.Else.Then)
		} else {
			elseOperations = []Operation{elseBuilder.ifClause(clause.Else)}
		}
	}
	resolution := Resolved
	switch truth {
	case truthTrue:
		markReachability(elseOperations, Unreachable)
		b.variables = thenBuilder.variables
		b.workingDirectory = thenBuilder.workingDirectory
	case truthFalse:
		markReachability(thenOperations, Unreachable)
		b.variables = elseBuilder.variables
		b.workingDirectory = elseBuilder.workingDirectory
	default:
		resolution = PartiallyResolved
		markReachability(thenOperations, ReachUnknown)
		markReachability(elseOperations, ReachUnknown)
		b.variables = mergeValues([]map[string]Value{thenBuilder.variables, elseBuilder.variables})
		b.workingDirectory = mergePathValues([]Value{thenBuilder.workingDirectory, elseBuilder.workingDirectory})
	}
	children = append(children, thenOperations...)
	children = append(children, elseOperations...)
	return Operation{Kind: OperationControlFlow, Name: "if", Resolution: resolution,
		Location: shell.LocationOf(b.sourceName, clause), Children: children, workingDirectory: beforeWorkingDirectory}
}

func (b *builder) value(word *syntax.Word) Value {
	if word == nil {
		return literalValue("")
	}
	var value Value
	if len(word.Parts) == 1 {
		value = b.wordPart(word.Parts[0], false)
	} else {
		pieces := make([]Value, 0, len(word.Parts))
		for _, part := range word.Parts {
			pieces = append(pieces, b.wordPart(part, false))
		}
		value = combineValues(pieces)
	}
	if value.Resolution == Resolved && literalSourceWord(word) {
		location := shell.LocationOf(b.sourceName, word)
		value.SourceLocation = &location
	}
	return value
}

func literalSourceWord(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			// The resolved value is represented directly by this source word.
		case *syntax.DblQuoted:
			if !literalSourceParts(part.Parts) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func literalSourceParts(parts []syntax.WordPart) bool {
	if len(parts) == 0 {
		return true
	}
	for _, part := range parts {
		switch nested := part.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
		case *syntax.DblQuoted:
			if !literalSourceParts(nested.Parts) {
				return false
			}
		default:
			return false
		}
	}
	return true
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
		value := Value{Parts: []ValuePart{{Kind: kind, Text: part.Value}}, Resolution: resolution}
		if resolution == Resolved {
			value.Literal = part.Value
		}
		return value
	case *syntax.SglQuoted:
		return Value{Parts: []ValuePart{{Kind: PartQuotedLiteral, Text: part.Value}}, Resolution: Resolved, Literal: part.Value}
	case *syntax.DblQuoted:
		return b.parts(part.Parts, true)
	case *syntax.ParamExp:
		return b.parameterExpansion(part)
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
	pieces := make([]Value, 0, len(parts))
	for _, part := range parts {
		pieces = append(pieces, b.wordPart(part, quoted))
	}
	return combineValues(pieces)
}

func (b *builder) parameterExpansion(part *syntax.ParamExp) Value {
	name := ""
	if part.Param != nil {
		name = part.Param.Value
	}
	reference := ValuePart{Kind: PartVariableReference, Name: name}
	plain := part.Param != nil && part.Flags == nil && !part.Excl && !part.Length && !part.Width && !part.IsSet &&
		part.Split == syntax.OptUnset && part.GlobSubst == syntax.OptUnset && part.RcExpand == syntax.OptUnset &&
		part.NestedParam == nil && part.Index == nil && len(part.Modifiers) == 0 && part.Slice == nil && part.Repl == nil && part.Names == 0
	simple := plain && part.Exp == nil
	known, assigned := b.variables[name]
	if simple && assigned {
		known.Parts = []ValuePart{reference}
		known.SourceLocation = nil
		return known
	}
	if !plain || part.Exp == nil || part.Exp.Word == nil || (part.Exp.Op != syntax.DefaultUnset && part.Exp.Op != syntax.DefaultUnsetOrNull) {
		return Value{Parts: []ValuePart{reference}, Resolution: Unknown}
	}
	if !assigned {
		// An unassigned shell variable may still be supplied by the hook environment.
		return Value{Parts: []ValuePart{reference, ValuePart{Kind: PartUnknownExpansion, Text: render(part)}}, Resolution: Unknown}
	}
	if part.Exp.Op == syntax.DefaultUnset {
		known.Parts = []ValuePart{reference}
		known.SourceLocation = nil
		return known
	}
	defaultValue := b.value(part.Exp.Word)
	defaultValue.SourceLocation = nil
	if known.Resolution == Resolved {
		if known.Literal != "" {
			known.Parts = []ValuePart{reference}
			known.SourceLocation = nil
			return known
		}
		return defaultValue
	}
	if known.Resolution == PartiallyResolved && len(known.Candidates) > 0 && defaultValue.Resolution == Resolved {
		candidates := make([]string, 0, len(known.Candidates))
		for _, candidate := range known.Candidates {
			if candidate == "" {
				candidate = defaultValue.Literal
			}
			if !contains(candidates, candidate) {
				candidates = append(candidates, candidate)
			}
		}
		if len(candidates) <= candidateLimit {
			sort.Strings(candidates)
			return Value{Parts: []ValuePart{reference}, Resolution: PartiallyResolved, Candidates: candidates}
		}
	}
	return Value{Parts: []ValuePart{reference}, Resolution: Unknown}
}

func combineValues(values []Value) Value {
	combined := Value{Resolution: Resolved}
	choices := []string{""}
	bounded := true
	for _, value := range values {
		combined.Parts = append(combined.Parts, value.Parts...)
		switch value.Resolution {
		case Resolved:
			for index := range choices {
				choices[index] += value.Literal
			}
		case PartiallyResolved:
			if combined.Resolution == Resolved {
				combined.Resolution = PartiallyResolved
			}
			if len(value.Candidates) == 0 {
				bounded = false
				continue
			}
			choices = combineCandidates(choices, value.Candidates)
			if len(choices) == 0 {
				bounded = false
			}
		case Unknown:
			combined.Resolution = Unknown
			bounded = false
		}
	}
	if combined.Resolution == Resolved {
		combined.Literal = choices[0]
		return combined
	}
	if combined.Resolution == PartiallyResolved && bounded && len(choices) > 0 {
		sort.Strings(choices)
		combined.Candidates = choices
	}
	return combined
}

func combineCandidates(prefixes, suffixes []string) []string {
	if len(prefixes) == 0 || len(suffixes) == 0 || len(prefixes)*len(suffixes) > candidateLimit {
		return nil
	}
	combined := make([]string, 0, len(prefixes)*len(suffixes))
	for _, prefix := range prefixes {
		for _, suffix := range suffixes {
			candidate := prefix + suffix
			if !contains(combined, candidate) {
				combined = append(combined, candidate)
			}
		}
	}
	return combined
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
		sourceName:         b.sourceName,
		variables:          cloneValues(b.variables),
		functions:          cloneFunctions(b.functions),
		functionDepth:      b.functionDepth,
		workingDirectory:   b.workingDirectory,
		nextStatementGroup: b.nextStatementGroup,
	}
}

func positionalArgumentsValue(arguments []Value) Value {
	if len(arguments) == 0 {
		return literalValue("")
	}
	var values []string
	for _, argument := range arguments {
		if argument.Resolution != Resolved {
			return Value{Resolution: Unknown}
		}
		values = append(values, argument.Literal)
	}
	return literalValue(strings.Join(values, " "))
}

func cloneFunctions(source map[string]*syntax.FuncDecl) map[string]*syntax.FuncDecl {
	clone := make(map[string]*syntax.FuncDecl, len(source))
	for name, declaration := range source {
		clone[name] = declaration
	}
	return clone
}

func initialWorkingDirectory(hook string) Value {
	if hook == "setup-project" {
		return literalValue("/project")
	}
	return Value{Resolution: Unknown}
}

func resolveChangedDirectory(arguments []Value, current Value) Value {
	var target Value
	found := false
	optionsEnded := false
	for _, argument := range arguments {
		if !optionsEnded && argument.Resolution == Resolved && argument.Literal == "--" {
			optionsEnded = true
			continue
		}
		if !optionsEnded && argument.Resolution == Resolved && strings.HasPrefix(argument.Literal, "-") {
			continue
		}
		target = argument
		found = true
		break
	}
	if !found || (target.Resolution == Resolved && target.Literal == "-") {
		return Value{Resolution: Unknown}
	}
	return normalizePathValue(target, current)
}

func mergePathValues(values []Value) Value {
	var candidates []string
	for _, value := range values {
		switch {
		case value.Resolution == Resolved && value.Literal != "":
			if !contains(candidates, value.Literal) {
				candidates = append(candidates, value.Literal)
			}
		case value.Resolution == PartiallyResolved && len(value.Candidates) > 0:
			for _, candidate := range value.Candidates {
				if !contains(candidates, candidate) {
					candidates = append(candidates, candidate)
				}
			}
		default:
			return Value{Resolution: Unknown}
		}
	}
	if len(candidates) == 1 {
		return literalValue(candidates[0])
	}
	if len(candidates) == 0 || len(candidates) > candidateLimit {
		return Value{Resolution: Unknown}
	}
	sort.Strings(candidates)
	return Value{Resolution: PartiallyResolved, Candidates: candidates}
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
