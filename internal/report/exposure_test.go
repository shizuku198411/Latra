package report

import (
	"bytes"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/source"
	"reflect"
	"strings"
	"testing"
)

func TestExposureReviewDoesNotChangeAssessment(t *testing.T) {
	item := sdk.SDK{Name: "example", Source: sdk.SourceProject, State: sdk.StateResolved, Metadata: &sdk.Metadata{Name: "example", Plugs: map[string]any{"key": map[string]any{"interface": "secret"}}}, Declarations: []sdk.Declaration{{Definition: ".workshop/dev.yaml", Order: 0}}}
	result := &source.Result{Kind: source.InputProject, SDKs: []sdk.SDK{item}}
	before := NewDocument(result).Assessment
	result.Configurations = []source.Configuration{{Name: "dev", Definition: ".workshop/dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "project-example", Order: 0}}}}
	after := NewDocument(result).Assessment
	if !reflect.DeepEqual(before, after) {
		t.Fatal("exposure review changed assessment")
	}
	var b bytes.Buffer
	if err := WriteText(&b, result); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Exposure review") || !strings.Contains(b.String(), "Secret plug declared") {
		t.Fatal(b.String())
	}
}

func TestDocumentInterfaceOptions(t *testing.T) {
	item := sdk.SDK{Name: "example", Source: sdk.SourceProject, State: sdk.StateResolved, Metadata: &sdk.Metadata{Name: "example", Plugs: map[string]any{"key": map[string]any{"interface": "secret"}}}, Declarations: []sdk.Declaration{{Workshop: "dev", Definition: ".workshop/dev.yaml"}}}
	result := &source.Result{Kind: source.InputProject, SDKs: []sdk.SDK{item}, Configurations: []source.Configuration{{Name: "dev", Definition: ".workshop/dev.yaml", SDKs: []source.ConfigurationSDK{{Name: "project-example"}}}}}
	full := NewDocument(result)
	for _, tc := range []struct {
		name              string
		options           DocumentOptions
		topology, reviews bool
	}{
		{"core", DocumentOptions{}, false, false},
		{"topology", DocumentOptions{IncludeTopology: true}, true, false},
		{"reviews imply topology", DocumentOptions{IncludeInterfaceReviews: true}, true, true},
		{"full", DocumentOptions{IncludeTopology: true, IncludeInterfaceReviews: true}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := NewDocumentWithOptions(result, tc.options)
			if (len(doc.InterfaceTopology) > 0) != tc.topology || (len(doc.InterfaceReviews) > 0) != tc.reviews {
				t.Fatalf("unexpected interface analysis: topology=%d reviews=%d", len(doc.InterfaceTopology), len(doc.InterfaceReviews))
			}
			if !reflect.DeepEqual(doc.Assessment, full.Assessment) || !reflect.DeepEqual(doc.SDKs, full.SDKs) {
				t.Fatal("interface options changed SDK analysis or assessment")
			}
		})
	}
	result.Kind = source.InputProjectSDK
	result.Configurations = nil
	if len(NewDocumentWithOptions(result, DocumentOptions{}).InterfaceReviews) != 0 || len(NewDocument(result).InterfaceReviews) != 1 {
		t.Fatal("standalone review must only be generated when requested")
	}
}
