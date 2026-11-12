package finding

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/findingconfig"
	"github.com/shizuku198411/Latra/internal/sdk"
)

type declarationOccurrence struct {
	item        *sdk.SDK
	declaration sdk.Declaration
}

// AnalyzeComposition correlates ordered SDK behavior within the same Workshop
// definition. Display ordering of SDKs is deliberately ignored.
func AnalyzeComposition(items []sdk.SDK) ([]Finding, []CompositionRelation) {
	rule, ok := compositionRule("cross-sdk-artifact-execution")
	if !ok {
		return nil, nil
	}
	groups := make(map[string][]declarationOccurrence)
	for index := range items {
		item := &items[index]
		for _, declaration := range item.Declarations {
			key := declaration.Definition + "\x00" + declaration.Workshop
			groups[key] = append(groups[key], declarationOccurrence{item: item, declaration: declaration})
		}
	}
	var findings []Finding
	var relations []CompositionRelation
	seen := make(map[string]bool)
	for _, occurrences := range groups {
		sort.SliceStable(occurrences, func(i, j int) bool { return occurrences[i].declaration.Order < occurrences[j].declaration.Order })
		for writerIndex, writer := range occurrences {
			writerHook := sdkHook(*writer.item, sdk.HookSetupProject)
			if writerHook == nil || writerHook.Analysis == nil {
				continue
			}
			for _, capability := range writerHook.Analysis.Capabilities {
				artifact := capabilityTarget(capability)
				if capability.Kind != "project-write" || capability.Resolution != analysis.Resolved || artifact == "" {
					continue
				}
				for runnerIndex := writerIndex + 1; runnerIndex < len(occurrences); runnerIndex++ {
					runner := occurrences[runnerIndex]
					if runner.item.Name == writer.item.Name || runner.declaration.Order <= writer.declaration.Order {
						continue
					}
					runnerHook := sdkHook(*runner.item, sdk.HookSetupProject)
					if runnerHook == nil || runnerHook.Analysis == nil {
						continue
					}
					for _, operation := range flatten(runnerHook.Analysis.Operations) {
						executed, resolved := projectCommandPath(operation)
						if !resolved || filepath.Clean(executed) != filepath.Clean(artifact) {
							continue
						}
						key := writer.declaration.Definition + "\x00" + writer.item.Name + "\x00" + runner.item.Name + "\x00" + capability.OperationID + "\x00" + operation.ID
						if seen[key] {
							continue
						}
						seen[key] = true
						relation := CompositionRelation{
							Kind: "project-artifact-execution", Workshop: writer.declaration.Workshop, Definition: writer.declaration.Definition,
							Hook: sdk.HookSetupProject, FromSDK: writer.item.Name, ToSDK: runner.item.Name,
							FromOrder: writer.declaration.Order, ToOrder: runner.declaration.Order,
							FromOperationID: capability.OperationID, ToOperationID: operation.ID,
							Artifact: analysis.Value{Literal: filepath.Clean(artifact), Resolution: analysis.Resolved}, Resolution: analysis.Resolved,
						}
						relations = append(relations, relation)
						writerLocation, runnerLocation := capability.Location, operation.Location
						findings = append(findings, Finding{
							ID: rule.ID, Kind: Kind(rule.Kind), Family: rule.Family, Title: rule.Title,
							Severity: rule.Severity, Confidence: rule.Confidence, Weight: rule.Weight,
							Scope: Scope{SDK: runner.item.Name, Hook: sdk.HookSetupProject},
							Evidence: []Evidence{
								{SDK: writer.item.Name, Type: "capability", ID: "cross-sdk-project-artifact-write", OperationID: capability.OperationID, Value: capability.Target.Literal, NormalizedValue: artifact, Resolution: capability.Resolution, Location: &writerLocation, ValueLocation: uniqueValueLocation(capability.Target.Literal, []analysis.Value{capability.Target})},
								{SDK: runner.item.Name, Type: "composition-flow", ID: "project-artifact-execution", OperationID: operation.ID, FromOperationID: capability.OperationID, ToOperationID: operation.ID, Value: executed, NormalizedValue: filepath.Clean(executed), Resolution: analysis.Resolved, Location: &runnerLocation, ValueLocation: uniqueValueLocation(executed, []analysis.Value{operation.Command})},
							},
							Message: rule.Message, Remediation: rule.Remediation,
							ProtectsAgainst: append([]string{}, rule.ProtectsAgainst...), Limitations: append([]string{}, rule.Limitations...),
						})
					}
				}
			}
		}
	}
	sortFindings(findings)
	sort.SliceStable(relations, func(i, j int) bool {
		if relations[i].Definition != relations[j].Definition {
			return relations[i].Definition < relations[j].Definition
		}
		if relations[i].FromOrder != relations[j].FromOrder {
			return relations[i].FromOrder < relations[j].FromOrder
		}
		return relations[i].ToOrder < relations[j].ToOrder
	})
	return findings, relations
}

func compositionRule(matcherType string) (findingconfig.Rule, bool) {
	for _, rule := range findingconfig.MustDefault().Rules {
		if rule.Matcher.Type == matcherType {
			return rule, true
		}
	}
	return findingconfig.Rule{}, false
}

func projectCommandPath(operation analysis.Operation) (string, bool) {
	if operation.Kind != analysis.OperationCommand || operation.Command.Resolution != analysis.Resolved {
		return "", false
	}
	var rendered strings.Builder
	for _, part := range operation.Command.Parts {
		switch part.Kind {
		case analysis.PartLiteral, analysis.PartQuotedLiteral:
			rendered.WriteString(part.Text)
		default:
			return "", false
		}
	}
	value := filepath.Clean(rendered.String())
	if value == "/project" || strings.HasPrefix(value, "/project/") {
		return value, true
	}
	return "", false
}
