package shell

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

const defaultRecoveryLimit = 10

// Parser wraps mvdan's parser with Latra's stable result and diagnostic model.
// A Parser must not be used concurrently.
type Parser struct {
	recoveryLimit int
}

// NewParser returns a Bash parser that retains comments and performs bounded recovery.
func NewParser() *Parser {
	return &Parser{recoveryLimit: defaultRecoveryLimit}
}

// Parse parses one hook as Bash without executing it.
func (p *Parser) Parse(source []byte, sourceName string) Result {
	result := Result{
		Path:   sourceName,
		Status: StatusFailed,
		Source: append([]byte(nil), source...),
	}
	if !utf8.Valid(source) {
		line, column := invalidUTF8Location(source)
		result.Diagnostics = []Diagnostic{{
			Code:     "invalid-utf8",
			Severity: SeverityError,
			Message:  "hook source is not valid UTF-8",
			Location: pointLocation(sourceName, line, column),
		}}
		return result
	}

	parser := syntax.NewParser(
		syntax.Variant(syntax.LangBash),
		syntax.KeepComments(true),
		syntax.RecoverErrors(p.recoveryLimit),
	)
	program, err := parser.Parse(strings.NewReader(string(source)), sourceName)
	result.Program = program
	if err != nil {
		result.Diagnostics = append(result.Diagnostics, diagnosticFromError(sourceName, err))
		return result
	}

	result.Status = StatusParsed
	result.NodeTypes = nodeTypeCounts(program)
	recovered := recoveredLocations(sourceName, source, program)
	if len(recovered) > 0 {
		result.Status = StatusRecovered
		result.Recovered = true
		for _, location := range recovered {
			result.Diagnostics = append(result.Diagnostics, Diagnostic{
				Code:     "syntax-recovered",
				Severity: SeverityWarning,
				Message:  "parser inserted a missing Bash syntax element",
				Location: location,
			})
		}
	}
	return result
}

// LocationOf returns the one-based, end-exclusive source range of an AST node.
func LocationOf(sourceName string, node syntax.Node) Location {
	if node == nil {
		return Location{Path: sourceName}
	}
	return locationFromPositions(sourceName, node.Pos(), node.End())
}

func diagnosticFromError(sourceName string, err error) Diagnostic {
	diagnostic := Diagnostic{
		Code:     "syntax-error",
		Severity: SeverityError,
		Message:  err.Error(),
		Location: Location{Path: sourceName},
	}
	var parseErr syntax.ParseError
	if errors.As(err, &parseErr) {
		diagnostic.Message = parseErr.Text
		diagnostic.Location = positionLocation(sourceName, parseErr.Pos)
		diagnostic.Incomplete = parseErr.Incomplete
	}
	return diagnostic
}

func nodeTypeCounts(program *syntax.File) map[string]int {
	if program == nil {
		return nil
	}
	counts := make(map[string]int)
	syntax.Walk(program, func(node syntax.Node) bool {
		if node == nil {
			return true
		}
		typeOf := reflect.TypeOf(node)
		if typeOf.Kind() == reflect.Pointer {
			typeOf = typeOf.Elem()
		}
		counts[typeOf.Name()]++
		return true
	})
	return counts
}

func recoveredLocations(sourceName string, source []byte, program *syntax.File) []Location {
	if program == nil {
		return nil
	}
	locations := make([]Location, 0)
	seen := make(map[string]bool)
	syntax.Walk(program, func(node syntax.Node) bool {
		if node == nil {
			return true
		}
		for _, position := range []syntax.Pos{node.Pos(), node.End()} {
			if !position.IsRecovered() {
				continue
			}
			location := positionLocation(sourceName, position)
			if location.StartLine == 0 {
				line, column := endLocation(source)
				location = pointLocation(sourceName, line, column)
			}
			key := fmt.Sprintf("%d:%d", location.StartLine, location.StartColumn)
			if !seen[key] {
				seen[key] = true
				locations = append(locations, location)
			}
		}
		return true
	})
	return locations
}

func endLocation(source []byte) (int, int) {
	line, column := 1, 1
	for len(source) > 0 {
		r, size := utf8.DecodeRune(source)
		if r == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		source = source[size:]
	}
	return line, column
}

func locationFromPositions(sourceName string, start, end syntax.Pos) Location {
	location := Location{Path: sourceName}
	if start.IsValid() || start.IsRecovered() {
		location.StartLine = int(start.Line())
		location.StartColumn = int(start.Col())
	}
	if end.IsValid() || end.IsRecovered() {
		location.EndLine = int(end.Line())
		location.EndColumn = int(end.Col())
	}
	return location
}

func positionLocation(sourceName string, position syntax.Pos) Location {
	if !position.IsValid() && !position.IsRecovered() {
		return Location{Path: sourceName}
	}
	return pointLocation(sourceName, int(position.Line()), int(position.Col()))
}

func pointLocation(sourceName string, line, column int) Location {
	return Location{
		Path:        sourceName,
		StartLine:   line,
		StartColumn: column,
		EndLine:     line,
		EndColumn:   column,
	}
}

func invalidUTF8Location(source []byte) (int, int) {
	line, column := 1, 1
	for len(source) > 0 {
		r, size := utf8.DecodeRune(source)
		if r == utf8.RuneError && size == 1 {
			return line, column
		}
		if r == '\n' {
			line++
			column = 1
		} else {
			column++
		}
		source = source[size:]
	}
	return line, column
}
