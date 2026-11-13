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
