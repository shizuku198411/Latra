// Package report renders Latra scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
	"github.com/shizuku198411/Latra/internal/source"
)

// WriteText renders the complete SDK inventory in a deterministic format.
func WriteText(writer io.Writer, result *source.Result) error {
	document := NewDocument(result)
	if _, err := fmt.Fprintf(writer, "Input\n  Kind: %s\n  Root: %s\n", document.Input.Kind, document.Input.Root); err != nil {
		return err
	}
	if len(document.Workshops) > 0 {
		if _, err := fmt.Fprintln(writer, "\nWorkshops"); err != nil {
			return err
		}
		for _, workshop := range document.Workshops {
			if _, err := fmt.Fprintf(writer, "  %s\n    Definition: %s\n    Base: %s\n", workshop.Name, workshop.Definition, workshop.Base); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(writer, "\nSDKs"); err != nil {
		return err
	}
	for _, item := range document.SDKs {
		if err := writeSDK(writer, item); err != nil {
			return err
		}
	}
	return writeSummary(writer, document.Summary)
}

// WriteTextSummary renders input, Workshop definitions, and the summary only.
func WriteTextSummary(writer io.Writer, result *source.Result) error {
	document := NewDocument(result)
	if _, err := fmt.Fprintf(writer, "Input\n  Kind: %s\n  Root: %s\n", document.Input.Kind, document.Input.Root); err != nil {
		return err
	}
	if len(document.Workshops) > 0 {
		if _, err := fmt.Fprintln(writer, "\nWorkshops"); err != nil {
			return err
		}
		for _, workshop := range document.Workshops {
			if _, err := fmt.Fprintf(writer, "  %s\n    Definition: %s\n    Base: %s\n", workshop.Name, workshop.Definition, workshop.Base); err != nil {
				return err
			}
		}
	}
	return writeSummary(writer, document.Summary)
}

func writeSummary(writer io.Writer, summary Summary) error {
	if _, err := fmt.Fprintf(writer, "\nSummary\n  SDKs: %d (%d resolved, %d unresolved)\n    Resolved: %s\n    Unresolved: %s\n",
		summary.SDKs.Count, summary.SDKs.Resolved, summary.SDKs.Unresolved,
		formatSummaryItems(summary.SDKs.SDKNames.Resolved),
		formatSummaryItems(summary.SDKs.SDKNames.Unresolved)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "  Files: %d\n", summary.Files.Count); err != nil {
		return err
	}
	for _, item := range summary.Files.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d): %s\n", item.SDKName, item.Count, formatSummaryItems(item.FilePaths)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "  Hooks: %d\n", summary.Hooks.Count); err != nil {
		return err
	}
	for _, item := range summary.Hooks.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d): %s\n", item.SDKName, item.Count, formatSummaryItems(item.HookNames)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "  Operations: %d\n", summary.Operations.Count); err != nil {
		return err
	}
	for _, item := range summary.Operations.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d): %s\n", item.SDKName, item.Count, formatSummaryItems(item.OperationKinds)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "  Capabilities: %d\n", summary.Capabilities.Count); err != nil {
		return err
	}
	for _, item := range summary.Capabilities.BySDK {
		if _, err := fmt.Fprintf(writer, "    %s (%d): %s\n", item.SDKName, item.Count, formatSummaryItems(item.CapabilityNames)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(writer, "  Diagnostics: %d\n", summary.Diagnostics.Count)
	return err
}

func formatSummaryItems(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ", ")
}

func writeSDK(writer io.Writer, item SDK) error {
	if _, err := fmt.Fprintf(writer, "  %s\n    Source: %s\n    State: %s\n", item.Name, item.Source, item.State); err != nil {
		return err
	}
	if item.Channel != "" {
		if _, err := fmt.Fprintf(writer, "    Channel: %s\n", item.Channel); err != nil {
			return err
		}
	}
	if item.State == sdk.StateNotResolved {
		return nil
	}
	if _, err := fmt.Fprintf(writer, "    Digest: %s\n    Metadata: %s\n", item.Digest, item.MetadataPath); err != nil {
		return err
	}
	if err := writeMetadata(writer, item); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "    Files: %d\n", len(item.Files)); err != nil {
		return err
	}
	for _, file := range item.Files {
		if _, err := fmt.Fprintf(writer, "      %s: %s", file.Path, file.Type); err != nil {
			return err
		}
		if file.Size > 0 {
			if _, err := fmt.Fprintf(writer, " (%d bytes)", file.Size); err != nil {
				return err
			}
		}
		if file.Digest != "" {
			if _, err := fmt.Fprintf(writer, " %s", file.Digest); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
		if file.Content != nil {
			if err := writeFileContent(writer, file); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintln(writer, "    Hooks:"); err != nil {
		return err
	}
	if len(item.Hooks) == 0 {
		_, err := fmt.Fprintln(writer, "      -")
		return err
	}
	for _, hook := range item.Hooks {
		if err := writeHook(writer, hook); err != nil {
			return err
		}
	}
	return nil
}

func writeFileContent(writer io.Writer, file File) error {
	if _, err := fmt.Fprintf(writer, "        Content (%s):\n", file.ContentEncoding); err != nil {
		return err
	}
	content := *file.Content
	if file.ContentEncoding == "utf-8" {
		content = safeText(content)
	}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if _, err := fmt.Fprintf(writer, "          | %s\n", line); err != nil {
			return err
		}
	}
	return nil
}

func safeText(content string) string {
	var safe strings.Builder
	for _, character := range content {
		switch {
		case character == '\n' || character == '\t':
			safe.WriteRune(character)
		case unicode.IsGraphic(character) || character == ' ':
			safe.WriteRune(character)
		default:
			fmt.Fprintf(&safe, "\\u%04x", character)
		}
	}
	return safe.String()
}

func writeMetadata(writer io.Writer, item SDK) error {
	if item.Metadata == nil {
		return nil
	}
	metadata := item.Metadata
	if _, err := fmt.Fprintf(writer, "      Name: %s\n", metadata.Name); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{
		{"Version", metadata.Version}, {"Base", metadata.Base}, {"Architecture", metadata.Architecture},
	} {
		if field.value != "" {
			if _, err := fmt.Fprintf(writer, "      %s: %s\n", field.name, field.value); err != nil {
				return err
			}
		}
	}
	if err := writeInterfaces(writer, "Plugs", metadata.Plugs); err != nil {
		return err
	}
	return writeInterfaces(writer, "Slots", metadata.Slots)
}

func writeInterfaces(writer io.Writer, label string, interfaces map[string]any) error {
	if _, err := fmt.Fprintf(writer, "      %s: %d\n", label, len(interfaces)); err != nil {
		return err
	}
	names := make([]string, 0, len(interfaces))
	for name := range interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		encoded, err := json.Marshal(interfaces[name])
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(writer, "        %s: %s\n", name, encoded); err != nil {
			return err
		}
	}
	return nil
}

func writeHook(writer io.Writer, hook Hook) error {
	if _, err := fmt.Fprintf(writer, "      %s: %s (%d bytes)", hook.Name, hook.Path, hook.Size); err != nil {
		return err
	}
	if hook.Parse != nil {
		if _, err := fmt.Fprintf(writer, " [%s, %d AST nodes]", hook.Parse.Status, countNodes(hook.Parse.NodeTypes)); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer); err != nil {
		return err
	}
	if hook.Context != nil {
		if _, err := fmt.Fprintf(writer, "        Context: root=%t project=%t interfaces=%t state=%t",
			hook.Context.RunAsRoot, hook.Context.ProjectMounted, hook.Context.InterfacesActive, hook.Context.StateMounted); err != nil {
			return err
		}
		if hook.Context.ContextDependent {
			if _, err := fmt.Fprint(writer, " context-dependent=true"); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(writer); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "        Operations: %d\n", countOperations(hook.Operations)); err != nil {
		return err
	}
	for _, operation := range hook.Operations {
		if err := writeOperation(writer, operation, "          "); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "        Capabilities: %d\n", len(hook.Capabilities)); err != nil {
		return err
	}
	for _, capability := range hook.Capabilities {
		if _, err := fmt.Fprintf(writer, "          %s [%s] rule=%s source=%s at %s target=%s\n",
			capability.Kind, capability.Resolution, capability.RuleID, capability.RuleSource,
			locationString(capability.Location), formatValue(capability.Target)); err != nil {
			return err
		}
	}
	if hook.Parse != nil && len(hook.Parse.Diagnostics) > 0 {
		if _, err := fmt.Fprintf(writer, "        Diagnostics: %d\n", len(hook.Parse.Diagnostics)); err != nil {
			return err
		}
		for _, diagnostic := range hook.Parse.Diagnostics {
			if _, err := fmt.Fprintf(writer, "          %s %s at %s: %s\n",
				diagnostic.Severity, diagnostic.Code, locationString(diagnostic.Location), diagnostic.Message); err != nil {
				return err
			}
		}
	}
	return nil
}

func writeOperation(writer io.Writer, operation analysis.Operation, indent string) error {
	if _, err := fmt.Fprintf(writer, "%s%s [%s] at %s", indent, operation.Kind, operation.Resolution, locationString(operation.Location)); err != nil {
		return err
	}
	if operation.Name != "" {
		if _, err := fmt.Fprintf(writer, " name=%q", operation.Name); err != nil {
			return err
		}
	}
	if operation.Command.Resolution != "" {
		if _, err := fmt.Fprintf(writer, " command=%s", formatValue(operation.Command)); err != nil {
			return err
		}
	}
	if len(operation.Wrappers) > 0 {
		if _, err := fmt.Fprintf(writer, " wrappers=%q", operation.Wrappers); err != nil {
			return err
		}
	}
	if len(operation.Arguments) > 0 {
		arguments := make([]string, 0, len(operation.Arguments))
		for _, argument := range operation.Arguments {
			arguments = append(arguments, formatValue(argument))
		}
		if _, err := fmt.Fprintf(writer, " args=[%s]", strings.Join(arguments, ", ")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(writer); err != nil {
		return err
	}
	for _, input := range operation.Inputs {
		if _, err := fmt.Fprintf(writer, "%s  input %s=%s\n", indent, input.Kind, formatValue(input.Value)); err != nil {
			return err
		}
	}
	for _, output := range operation.Outputs {
		if _, err := fmt.Fprintf(writer, "%s  output %s=%s\n", indent, output.Kind, formatValue(output.Value)); err != nil {
			return err
		}
	}
	for _, child := range operation.Children {
		if err := writeOperation(writer, child, indent+"  "); err != nil {
			return err
		}
	}
	return nil
}

func formatValue(value analysis.Value) string {
	if value.Resolution == analysis.Resolved {
		return fmt.Sprintf("%q", value.Literal)
	}
	if len(value.Candidates) > 0 {
		return fmt.Sprintf("%s%q", value.Resolution, value.Candidates)
	}
	parts := make([]string, 0, len(value.Parts))
	for _, part := range value.Parts {
		switch part.Kind {
		case analysis.PartVariableReference:
			parts = append(parts, "${"+part.Name+"}")
		default:
			if part.Text != "" {
				parts = append(parts, part.Text)
			} else {
				parts = append(parts, "<"+string(part.Kind)+">")
			}
		}
	}
	if len(parts) == 0 {
		return string(value.Resolution)
	}
	return fmt.Sprintf("%s(%q)", value.Resolution, strings.Join(parts, ""))
}

func locationString(location shell.Location) string {
	return fmt.Sprintf("%s:%d:%d", location.Path, location.StartLine, location.StartColumn)
}

func countNodes(nodeTypes map[string]int) int {
	var count int
	for _, value := range nodeTypes {
		count += value
	}
	return count
}
