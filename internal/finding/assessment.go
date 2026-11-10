package finding

import (
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

type Score struct {
	Score int    `json:"score"`
	Level string `json:"level"`
}

type ScoredAxis struct {
	Score    int           `json:"score"`
	Level    string        `json:"level"`
	Findings int           `json:"findings"`
	Families []FamilyScore `json:"families"`
}

type FamilyScore struct {
	Family   string `json:"family"`
	Score    int    `json:"score"`
	Findings int    `json:"findings"`
	Cap      int    `json:"cap"`
}

type HookCoverage struct {
	Total     int `json:"total"`
	Parsed    int `json:"parsed"`
	Recovered int `json:"recovered"`
	Failed    int `json:"failed"`
}

type CommandCoverage struct {
	Total      int `json:"total"`
	Known      int `json:"known"`
	Unknown    int `json:"unknown"`
	Unresolved int `json:"unresolved"`
}

type FileCoverage struct {
	Inventoried     int `json:"inventoried"`
	ContentAnalyzed int `json:"contentAnalyzed"`
	BinaryOnly      int `json:"binaryOnly"`
	ContentSkipped  int `json:"contentSkipped"`
}

type Coverage struct {
	Score    int             `json:"score"`
	Level    string          `json:"level"`
	Hooks    HookCoverage    `json:"hooks"`
	Commands CommandCoverage `json:"commands"`
	Files    FileCoverage    `json:"files"`
}

type SDKAssessment struct {
	SDK            string          `json:"sdk"`
	Classification string          `json:"classification"`
	ReviewPriority Score           `json:"reviewPriority"`
	Risk           ScoredAxis      `json:"risk"`
	Assurance      ScoredAxis      `json:"assurance"`
	Coverage       Coverage        `json:"coverage"`
	KeyRisks       []RiskHighlight `json:"keyRisks"`
}

type Assessment struct {
	Classification string          `json:"classification"`
	ReviewPriority Score           `json:"reviewPriority"`
	Risk           ScoredAxis      `json:"risk"`
	Assurance      ScoredAxis      `json:"assurance"`
	Coverage       Coverage        `json:"coverage"`
	KeyRisks       []RiskHighlight `json:"keyRisks"`
	BySDK          []SDKAssessment `json:"bySdk"`
}

type RiskHighlight struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Severity    string      `json:"severity"`
	Score       int         `json:"score"`
	Occurrences int         `json:"occurrences"`
	Scopes      []RiskScope `json:"scopes"`
}

type RiskScope struct {
	SDK      string          `json:"sdk"`
	Hook     sdk.HookName    `json:"hook,omitempty"`
	Location *shell.Location `json:"location,omitempty"`
	Value    string          `json:"value,omitempty"`
}

type AssessmentInput struct {
	SDK      sdk.SDK
	Findings []Finding
}

func AssessProject(inputs []AssessmentInput) Assessment {
	var allFindings []Finding
	var combinedCoverage Coverage
	assessment := Assessment{BySDK: []SDKAssessment{}}
	complete := len(inputs) > 0
	for _, input := range inputs {
		item := AssessSDK(input.SDK, input.Findings)
		assessment.BySDK = append(assessment.BySDK, item)
		allFindings = append(allFindings, input.Findings...)
		addCoverage(&combinedCoverage, item.Coverage)
		if input.SDK.State != sdk.StateResolved || hasResourceLimitDiagnostic(input.SDK) {
			complete = false
		}
	}
	sort.Slice(assessment.BySDK, func(i, j int) bool { return assessment.BySDK[i].SDK < assessment.BySDK[j].SDK })
	assessment.Risk = scoreAxis(allFindings, KindRisk)
	assessment.Assurance = scoreAxis(allFindings, KindAssurance)
	assessment.Coverage = finalizeCoverage(combinedCoverage, complete)
	assessment.KeyRisks = riskHighlights(allFindings)
	finalizeAssessment(&assessment.Classification, &assessment.ReviewPriority, assessment.Risk, assessment.Assurance, assessment.Coverage)
	return assessment
}

func AssessSDK(item sdk.SDK, findings []Finding) SDKAssessment {
	risk := scoreAxis(findings, KindRisk)
	assurance := scoreAxis(findings, KindAssurance)
	coverage := coverageForSDK(item)
	assessment := SDKAssessment{SDK: item.Name, Risk: risk, Assurance: assurance, Coverage: coverage, KeyRisks: riskHighlights(findings)}
	finalizeAssessment(&assessment.Classification, &assessment.ReviewPriority, risk, assurance, coverage)
	return assessment
}

func riskHighlights(findings []Finding) []RiskHighlight {
	type aggregate struct {
		highlight RiskHighlight
		weights   []float64
		seen      map[string]bool
	}
	grouped := make(map[string]*aggregate)
	for _, item := range findings {
		if item.Kind != KindRisk {
			continue
		}
		current := grouped[item.ID]
		if current == nil {
			current = &aggregate{highlight: RiskHighlight{ID: item.ID, Title: item.Title, Severity: item.Severity, Scopes: []RiskScope{}}, seen: make(map[string]bool)}
			grouped[item.ID] = current
		}
		current.highlight.Occurrences++
		current.weights = append(current.weights, float64(item.Weight)*confidenceFactor(item.Confidence))
		for _, evidence := range item.Evidence {
			scope := RiskScope{SDK: item.Scope.SDK, Hook: item.Scope.Hook, Location: evidence.Location, Value: evidence.Value}
			key := scope.SDK + "\x00" + string(scope.Hook) + "\x00" + scope.Value
			if scope.Location != nil {
				key += "\x00" + scope.Location.Path + "\x00" + strconv.Itoa(scope.Location.StartLine) + "\x00" + strconv.Itoa(scope.Location.StartColumn)
			}
			if current.seen[key] {
				continue
			}
			current.seen[key] = true
			current.highlight.Scopes = append(current.highlight.Scopes, scope)
		}
	}
	highlights := make([]RiskHighlight, 0, len(grouped))
	for _, current := range grouped {
		current.highlight.Score = rounded(diminishing(current.weights))
		sort.SliceStable(current.highlight.Scopes, func(i, j int) bool {
			left, right := current.highlight.Scopes[i], current.highlight.Scopes[j]
			if left.SDK != right.SDK {
				return left.SDK < right.SDK
			}
			if left.Hook != right.Hook {
				return left.Hook < right.Hook
			}
			leftPath, rightPath := "", ""
			leftLine, rightLine := 0, 0
			if left.Location != nil {
				leftPath, leftLine = left.Location.Path, left.Location.StartLine
			}
			if right.Location != nil {
				rightPath, rightLine = right.Location.Path, right.Location.StartLine
			}
			if leftPath != rightPath {
				return leftPath < rightPath
			}
			if leftLine != rightLine {
				return leftLine < rightLine
			}
			return left.Value < right.Value
		})
		highlights = append(highlights, current.highlight)
	}
	sort.SliceStable(highlights, func(i, j int) bool {
		if highlights[i].Score != highlights[j].Score {
			return highlights[i].Score > highlights[j].Score
		}
		if levelRank(highlights[i].Severity) != levelRank(highlights[j].Severity) {
			return levelRank(highlights[i].Severity) > levelRank(highlights[j].Severity)
		}
		return highlights[i].ID < highlights[j].ID
	})
	return highlights
}

func scoreAxis(findings []Finding, kind Kind) ScoredAxis {
	grouped := make(map[string][]float64)
	maxLevel := "info"
	count := 0
	for _, item := range findings {
		if item.Kind != kind {
			continue
		}
		count++
		grouped[item.Family] = append(grouped[item.Family], float64(item.Weight)*confidenceFactor(item.Confidence))
		level := item.Strength
		if kind == KindRisk {
			level = item.Severity
		}
		if levelRank(level) > levelRank(maxLevel) {
			maxLevel = level
		}
	}
	axis := ScoredAxis{Findings: count, Families: []FamilyScore{}}
	var familyValues []float64
	for family, weights := range grouped {
		cap := familyCap(kind, family)
		score := math.Min(diminishing(weights), float64(cap))
		familyValues = append(familyValues, score)
		axis.Families = append(axis.Families, FamilyScore{Family: family, Score: rounded(score), Findings: len(weights), Cap: cap})
	}
	sort.Slice(axis.Families, func(i, j int) bool { return axis.Families[i].Family < axis.Families[j].Family })
	axis.Score = rounded(diminishing(familyValues))
	if kind == KindRisk {
		axis.Score = max(axis.Score, riskFloor(maxLevel))
		axis.Level = riskLevel(axis.Score)
	} else {
		axis.Level = assuranceLevel(axis.Score)
	}
	return axis
}

func diminishing(weights []float64) float64 {
	remaining := 1.0
	for _, weight := range weights {
		bounded := math.Max(0, math.Min(100, weight))
		remaining *= 1 - bounded/100
	}
	return 100 * (1 - remaining)
}

func confidenceFactor(confidence string) float64 {
	switch confidence {
	case "high":
		return 1
	case "medium":
		return .75
	default:
		return .5
	}
}

func familyCap(kind Kind, family string) int {
	if kind == KindRisk {
		switch family {
		case "remote-execution", "destructive", "sensitive-data", "data-exposure", "lifecycle-misuse":
			return 95
		case "analysis-gap":
			return 40
		case "persistence":
			return 70
		default:
			return 85
		}
	}
	switch family {
	case "analysis-quality":
		return 60
	case "lifecycle-conformance", "reproducibility":
		return 20
	case "least-privilege":
		return 50
	case "scope-limitation":
		return 60
	default:
		return 60
	}
}

func coverageForSDK(item sdk.SDK) Coverage {
	coverage := Coverage{Files: FileCoverage{Inventoried: len(item.Files)}}
	for _, file := range item.Files {
		if file.Skipped {
			coverage.Files.ContentSkipped++
			continue
		}
		if file.Type != sdk.FileRegular {
			continue
		}
		if file.Binary {
			coverage.Files.BinaryOnly++
		} else if file.Content != nil {
			coverage.Files.ContentAnalyzed++
		}
	}
	for _, hook := range item.Hooks {
		coverage.Hooks.Total++
		if hook.Parse == nil {
			coverage.Hooks.Failed++
		} else {
			switch hook.Parse.Status {
			case shell.StatusParsed:
				coverage.Hooks.Parsed++
			case shell.StatusRecovered:
				coverage.Hooks.Recovered++
			default:
				coverage.Hooks.Failed++
			}
		}
		if hook.Analysis == nil {
			continue
		}
		for _, operation := range flatten(hook.Analysis.Operations) {
			if operation.Kind != analysis.OperationCommand {
				continue
			}
			coverage.Commands.Total++
			switch {
			case operation.Command.Resolution != analysis.Resolved:
				coverage.Commands.Unresolved++
			case analysis.IsKnownCommand(operation.Command):
				coverage.Commands.Known++
			default:
				coverage.Commands.Unknown++
			}
		}
	}
	for _, diagnostic := range item.Diagnostics {
		if strings.HasPrefix(diagnostic.Code, "include-") || diagnostic.Code == "dynamic-include" || diagnostic.Code == "external-include" {
			coverage.Commands.Total++
			coverage.Commands.Unresolved++
		}
	}
	complete := item.State == sdk.StateResolved && !hasResourceLimitDiagnostic(item)
	return finalizeCoverage(coverage, complete)
}

func finalizeCoverage(coverage Coverage, complete bool) Coverage {
	if !complete {
		coverage.Score = 0
		coverage.Level = "insufficient"
		return coverage
	}
	hookScore := 100.0
	if coverage.Hooks.Total > 0 {
		hookScore = 100 * (float64(coverage.Hooks.Parsed) + .5*float64(coverage.Hooks.Recovered)) / float64(coverage.Hooks.Total)
	}
	commandScore := 100.0
	if coverage.Commands.Total > 0 {
		commandScore = 100 * float64(coverage.Commands.Known) / float64(coverage.Commands.Total)
	}
	coverage.Score = rounded(.6*hookScore + .4*commandScore)
	if coverage.Score >= 80 && coverage.Hooks.Failed == 0 {
		coverage.Level = "sufficient"
	} else {
		coverage.Level = "insufficient"
	}
	return coverage
}

func addCoverage(target *Coverage, value Coverage) {
	target.Hooks.Total += value.Hooks.Total
	target.Hooks.Parsed += value.Hooks.Parsed
	target.Hooks.Recovered += value.Hooks.Recovered
	target.Hooks.Failed += value.Hooks.Failed
	target.Commands.Total += value.Commands.Total
	target.Commands.Known += value.Commands.Known
	target.Commands.Unknown += value.Commands.Unknown
	target.Commands.Unresolved += value.Commands.Unresolved
	target.Files.Inventoried += value.Files.Inventoried
	target.Files.ContentAnalyzed += value.Files.ContentAnalyzed
	target.Files.BinaryOnly += value.Files.BinaryOnly
	target.Files.ContentSkipped += value.Files.ContentSkipped
}

func finalizeAssessment(classification *string, priority *Score, risk, assurance ScoredAxis, coverage Coverage) {
	priority.Score = max(risk.Score, 100-coverage.Score)
	priority.Level = riskLevel(priority.Score)
	switch {
	case coverage.Level != "sufficient":
		*classification = "insufficient-evidence"
	case risk.Score >= 80:
		*classification = "high-priority-review"
	case risk.Score >= 50 && assurance.Score >= 60:
		*classification = "powerful-but-controlled"
	case risk.Score >= 50:
		*classification = "high-priority-review"
	case risk.Score <= 49 && assurance.Score >= 60:
		*classification = "expected-and-controlled"
	default:
		*classification = "weakly-controlled"
	}
}

func riskFloor(level string) int {
	switch level {
	case "critical":
		return 80
	case "high":
		return 50
	case "medium":
		return 25
	case "low":
		return 10
	default:
		return 0
	}
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 25:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func assuranceLevel(score int) string {
	switch {
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "info"
	}
}

func levelRank(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func rounded(value float64) int { return int(math.Round(value + 1e-9)) }
