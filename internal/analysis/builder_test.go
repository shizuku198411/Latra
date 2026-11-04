package analysis_test

import (
	"fmt"
	"testing"

	"github.com/shizuku198411/Latra/internal/analysis"
	"github.com/shizuku198411/Latra/internal/shell"
)

func TestAnalyzeCommandsAndValues(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
url="https://example.invalid/install.sh"
curl "$url"
[ -n "$url" ]
sudo env MODE=test /usr/bin/printf '%s' "$url"
"$DYNAMIC" argument
`)
	operations := flatten(result.Operations)

	curl := findCommand(t, operations, "curl")
	if curl.Arguments[0].Resolution != analysis.Resolved || curl.Arguments[0].Literal != "https://example.invalid/install.sh" {
		t.Errorf("curl argument = %#v", curl.Arguments[0])
	}
	testCommand := findCommand(t, operations, "[")
	if testCommand.Command.Resolution != analysis.Resolved {
		t.Errorf("test command = %#v", testCommand.Command)
	}
	printf := findCommand(t, operations, "printf")
	if len(printf.Wrappers) != 2 || printf.Wrappers[0] != "sudo" || printf.Wrappers[1] != "env" {
		t.Errorf("wrappers = %#v", printf.Wrappers)
	}
	if printf.Command.Literal != "printf" {
		t.Errorf("normalized command = %#v", printf.Command)
	}
	if operations[len(operations)-1].Command.Resolution != analysis.Unknown {
		t.Errorf("dynamic command resolution = %q", operations[len(operations)-1].Command.Resolution)
	}
	assertCapability(t, result.Capabilities, "network-download")
	assertCapability(t, result.Capabilities, "dynamic-execution")
}

func TestAnalyzeControlFlowAndCandidates(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
if test -n "$MODE"; then
  target=one
else
  target=two
fi
printf '%s' "$target"
`)
	operation := findCommand(t, flatten(result.Operations), "printf")
	value := operation.Arguments[1]
	if value.Resolution != analysis.PartiallyResolved {
		t.Fatalf("resolution = %q, want %q; value: %#v", value.Resolution, analysis.PartiallyResolved, value)
	}
	if len(value.Candidates) != 2 || value.Candidates[0] != "one" || value.Candidates[1] != "two" {
		t.Errorf("candidates = %#v", value.Candidates)
	}
}

func TestAnalyzeFlowAndSpecialOperations(t *testing.T) {
	t.Parallel()

	result := analyze(t, "check-health", `
producer | consumer > /project/output
reader < /root/.ssh/id_ed25519
value="$(nested "$(inner)")"
source ./helpers.sh
eval "$GENERATED"
bash -c 'echo generated'
build() { echo ok; }
build
cat <(printf data)
cat "$SDK_STATE_DIR/saved"
printf data | tee "$SDK_STATE_DIR/output"
`)
	operations := flatten(result.Operations)
	for _, kind := range []analysis.OperationKind{
		analysis.OperationPipeline,
		analysis.OperationRedirectRead,
		analysis.OperationRedirectWrite,
		analysis.OperationCommandSubstitution,
		analysis.OperationProcessSubstitution,
		analysis.OperationSource,
		analysis.OperationEval,
		analysis.OperationFunctionDeclaration,
		analysis.OperationFunctionInvocation,
	} {
		if !hasOperation(operations, kind) {
			t.Errorf("operation %q not found: %#v", kind, operations)
		}
	}
	pipeline := firstOperation(t, result.Operations, analysis.OperationPipeline)
	if len(pipeline.Children) < 2 || len(pipeline.Children[0].Outputs) == 0 || len(pipeline.Children[1].Inputs) == 0 {
		t.Errorf("pipeline flow = %#v", pipeline.Children)
	}
	for _, capability := range []string{
		"project-write", "credential-read", "code-execution", "dynamic-execution", "state-read", "state-write",
	} {
		assertCapability(t, result.Capabilities, capability)
	}
}

func TestContextForLifecycleHooks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		root       bool
		project    bool
		interfaces bool
		state      bool
		dependent  bool
	}{
		{name: "setup-base", root: true},
		{name: "setup-project", project: true, interfaces: true},
		{name: "check-health", root: true, project: true, interfaces: true},
		{name: "save-state", root: true, state: true, dependent: true},
		{name: "restore-state", root: true, project: true, interfaces: true, state: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := analysis.ContextFor(test.name)
			if context.RunAsRoot != test.root || context.ProjectMounted != test.project ||
				context.InterfacesActive != test.interfaces || context.StateMounted != test.state ||
				context.ContextDependent != test.dependent {
				t.Errorf("context = %#v", context)
			}
		})
	}
}

func TestClassifyPath(t *testing.T) {
	t.Parallel()

	tests := map[string]analysis.PathClass{
		"/project/source":               analysis.PathProject,
		"/home/workshop/.aws/config":    analysis.PathSensitive,
		"/root/.ssh/id_ed25519":         analysis.PathSensitive,
		"/var/lib/workshop/state/data":  analysis.PathState,
		"/etc/systemd/system/x.service": analysis.PathPersistence,
		"/dev/sda":                      analysis.PathDevice,
		"/tmp/result":                   analysis.PathTemporary,
		"/var/lib/workshop/sdk/x/file":  analysis.PathSDK,
		"relative/path":                 analysis.PathUnknown,
	}
	for path, want := range tests {
		value := analysis.Value{Resolution: analysis.Resolved, Literal: path}
		if got := analysis.ClassifyPath(value); got != want {
			t.Errorf("ClassifyPath(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestKnownCommandCoverage(t *testing.T) {
	t.Parallel()

	if !analysis.IsKnownCommand(analysis.Value{Resolution: analysis.Resolved, Literal: "/usr/bin/curl"}) {
		t.Error("curl should be covered by embedded command knowledge")
	}
	for _, command := range []string{"workshop", "/snap/bin/workshopctl"} {
		if !analysis.IsKnownCommand(analysis.Value{Resolution: analysis.Resolved, Literal: command}) {
			t.Errorf("%s should be covered by the official Workshop command definitions", command)
		}
	}
	if analysis.IsKnownCommand(analysis.Value{Resolution: analysis.Resolved, Literal: "latra-unknown-fixture"}) {
		t.Error("fixture command unexpectedly covered by embedded command knowledge")
	}
	if analysis.IsKnownCommand(analysis.Value{Resolution: analysis.Unknown}) {
		t.Error("unresolved command should not be classified as a known command")
	}
}

func TestEmbeddedCapabilityRulesRegression(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
curl -d payload https://example.invalid/upload
bash -c 'echo generated'
cat < /root/.ssh/id_ed25519
tee /project/output
`)
	want := map[string]int{
		"network-access|command.curl-network":      1,
		"network-download|command.curl-download":   1,
		"external-send|command.curl-upload":        1,
		"code-execution|command.interpreter":       1,
		"dynamic-execution|interpreter.shell-code": 1,
		"credential-read|path.sensitive.read":      1,
		"project-write|path.project.write":         1,
	}
	got := make(map[string]int)
	for _, capability := range result.Capabilities {
		got[fmt.Sprintf("%s|%s", capability.Kind, capability.RuleID)]++
		if capability.RuleSource != "embedded-default" {
			t.Errorf("rule source = %q", capability.RuleSource)
		}
	}
	if len(result.Capabilities) != 7 {
		t.Errorf("capability count = %d, want 7: %#v", len(result.Capabilities), got)
	}
	for key, count := range want {
		if got[key] != count {
			t.Errorf("%s count = %d, want %d; all: %#v", key, got[key], count, got)
		}
	}
}

func TestConditionalCommandRules(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
git status
git -C /project status
git clone https://example.invalid/repository
git submodule status
git submodule foreach 'echo test'
git submodule sync
git submodule update --no-fetch
git submodule update
systemctl status fixture.service
systemctl --host fixture status fixture.service
systemctl enable fixture.service
crontab -l
crontab schedule.txt
apt list
apt -o Debug=true list
apt install ./local.deb
apt install remote-package
snap list
snap find package
scp remote:/file ./file
scp ./file remote:/file
`)
	counts := make(map[string]int)
	for _, capability := range result.Capabilities {
		counts[capability.RuleID]++
	}
	for ruleID, want := range map[string]int{
		"command.git-network":           1,
		"command.git-submodule-network": 1,
		"command.systemctl-modify":      1,
		"command.systemctl-persistence": 1,
		"command.crontab":               1,
		"command.apt-network-install":   1,
		"command.apt-modify":            2,
		"command.snap-network":          1,
		"command.scp-network":           2,
		"command.scp-send":              1,
	} {
		if counts[ruleID] != want {
			t.Errorf("%s count = %d, want %d; all: %#v", ruleID, counts[ruleID], want, counts)
		}
	}
	for _, ruleID := range []string{"command.git-send", "command.snap-modify"} {
		if counts[ruleID] != 0 {
			t.Errorf("unexpected %s count = %d", ruleID, counts[ruleID])
		}
	}
}

func TestAptInstallTargetClassification(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
apt install ./local.deb
apt install /tmp/local.deb
apt install local.deb
apt install ../local.deb
apt install file:/tmp/local.deb
apt install ./local.deb remote-package
apt install /tmp/local.deb remote-package
apt install remote-package
apt install "$PACKAGE"
apt upgrade
`)
	var resolved, partial int
	upgrade := 0
	for _, capability := range result.Capabilities {
		if capability.RuleID == "command.apt-network-upgrade" {
			upgrade++
		}
		if capability.RuleID != "command.apt-network-install" {
			continue
		}
		if capability.Resolution == analysis.Resolved {
			resolved++
		}
		if capability.Resolution == analysis.PartiallyResolved {
			partial++
		}
	}
	if resolved != 3 {
		t.Errorf("resolved network installs = %d, want 3", resolved)
	}
	if partial != 1 {
		t.Errorf("partially resolved network installs = %d, want 1", partial)
	}
	if upgrade != 1 {
		t.Errorf("network upgrades = %d, want 1", upgrade)
	}
}

func TestDynamicSubcommandPreservesUncertainty(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `git "$ACTION"`)
	found := false
	for _, capability := range result.Capabilities {
		if capability.RuleID == "command.git-network" {
			found = true
			if capability.Resolution != analysis.PartiallyResolved {
				t.Errorf("resolution = %q, want %q", capability.Resolution, analysis.PartiallyResolved)
			}
		}
	}
	if !found {
		t.Error("dynamic git subcommand was discarded")
	}
}

func TestDynamicNestedSubcommandPreservesUncertainty(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `git submodule "$ACTION"`)
	for _, capability := range result.Capabilities {
		if capability.RuleID == "command.git-submodule-network" {
			if capability.Resolution != analysis.PartiallyResolved {
				t.Errorf("resolution = %q, want %q", capability.Resolution, analysis.PartiallyResolved)
			}
			return
		}
	}
	t.Error("dynamic nested git subcommand was discarded")
}

func TestFileOperandRoles(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
cp /root/.ssh/id_ed25519 /project/key
head -n 5 /project/input
grep secret /project/input
grep -e secret /project/input
grep -f /root/.config/patterns /project/input
cp -t /project/out /root/.ssh/id_one /root/.ssh/id_two
`)
	counts := make(map[string]int)
	for _, capability := range result.Capabilities {
		counts[capability.RuleID]++
	}
	if counts["path.sensitive.read"] != 4 {
		t.Errorf("sensitive reads = %d, want 4; all: %#v", counts["path.sensitive.read"], counts)
	}
	if counts["path.project.read"] != 4 {
		t.Errorf("project reads = %d, want 4; all: %#v", counts["path.project.read"], counts)
	}
	if counts["path.project.write"] != 2 {
		t.Errorf("project writes = %d, want 2; all: %#v", counts["path.project.write"], counts)
	}
}

func TestFileOptionValuesAreNotPositionalPaths(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
grep -A /project/not-a-path pattern /tmp/input
touch -d /project/not-a-path /tmp/output
mkdir -m /project/not-a-path /tmp/output
touch -r /root/.ssh/id_ed25519 /project/output
`)
	counts := make(map[string]int)
	for _, capability := range result.Capabilities {
		counts[capability.RuleID]++
	}
	if counts["path.project.write"] != 1 {
		t.Errorf("project writes = %d, want 1; all: %#v", counts["path.project.write"], counts)
	}
	if counts["path.project.read"] != 0 {
		t.Errorf("unexpected project reads: %#v", counts)
	}
	if counts["path.sensitive.read"] != 1 {
		t.Errorf("sensitive reads = %d, want 1; all: %#v", counts["path.sensitive.read"], counts)
	}
}

func TestOptionTerminatorPreservesFileOperands(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `cp -- -secret /project/output`)
	counts := make(map[string]int)
	for _, capability := range result.Capabilities {
		counts[capability.RuleID]++
	}
	if counts["path.project.write"] != 1 {
		t.Errorf("project writes = %d, want 1; all: %#v", counts["path.project.write"], counts)
	}
	if counts["path.project.read"] != 0 {
		t.Errorf("project destination was treated as source: %#v", counts)
	}
}

func TestHighNoiseRules(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
curl -I https://example.invalid
wget --spider https://example.invalid
ssh host
scp remote:/file ./file
scp ./file remote:/file
tar -xf archive.tar
gzip file
openssl version
dd if=/tmp/image of=/tmp/copy
dd if=/tmp/image of=/dev/sda
`)
	counts := make(map[string]int)
	for _, capability := range result.Capabilities {
		counts[capability.RuleID]++
	}
	if counts["command.curl-download"] != 0 || counts["command.wget-download"] != 0 {
		t.Errorf("header/probe commands classified as download: %#v", counts)
	}
	if counts["command.scp-send"] != 1 {
		t.Errorf("scp send count = %d, want 1", counts["command.scp-send"])
	}
	if counts["command.dd-device-overwrite"] != 1 {
		t.Errorf("dd destructive count = %d, want 1", counts["command.dd-device-overwrite"])
	}
	if counts["command.obfuscation"] != 0 {
		t.Errorf("ordinary archive tools classified as obfuscation: %#v", counts)
	}
}

func TestShortFlagClustersAndOptionTerminator(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
curl -sI https://example.invalid
curl -sL https://example.invalid
curl -HsI https://example.invalid
curl -- -I https://example.invalid
`)
	count := 0
	for _, capability := range result.Capabilities {
		if capability.RuleID == "command.curl-download" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("curl download count = %d, want 3", count)
	}
}

func TestSCPRemotePathBoundary(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
scp ./source ./local:name
scp ./source host:path
`)
	count := 0
	for _, capability := range result.Capabilities {
		if capability.RuleID == "command.scp-send" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("scp send count = %d, want 1", count)
	}
}

func TestCapabilityOptionMatching(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
curl -dpayload https://example.invalid
curl --data=value https://example.invalid
wget -d https://example.invalid
wget -F https://example.invalid
wget -T 30 https://example.invalid
wget --post-file=payload https://example.invalid
ruby -c file.rb
ruby -e 'puts 1'
perl -E 'say 1'
node --eval='console.log(1)'
`)
	counts := make(map[string]int)
	for _, capability := range result.Capabilities {
		counts[capability.RuleID]++
	}
	for ruleID, want := range map[string]int{
		"command.curl-upload":   2,
		"command.wget-upload":   1,
		"interpreter.ruby-code": 1,
		"interpreter.perl-code": 1,
		"interpreter.node-code": 1,
	} {
		if counts[ruleID] != want {
			t.Errorf("%s count = %d, want %d; all: %#v", ruleID, counts[ruleID], want, counts)
		}
	}
}

func TestRemoteTransferAndSocketRules(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
rsync ./source ./destination
rsync --delete ./source ./destination
rsync host:/source ./destination
rsync ./source host:/destination
rsync --rsync-path='sudo rsync' ./source host:/destination
sftp
sftp host
sftp -b /project/batch host
socat - TCP:host:80
socat TCP:host:80 CREATE:/project/output
socat EXEC:/bin/sh -
`)
	counts := capabilityRuleCounts(result.Capabilities)
	for ruleID, want := range map[string]int{
		"command.rsync-network":     3,
		"command.rsync-download":    1,
		"command.rsync-send":        2,
		"command.rsync-delete":      1,
		"command.rsync-remote-exec": 2,
		"command.sftp-network":      2,
		"command.socat-network":     2,
		"command.socat-send":        1,
		"command.socat-download":    1,
		"command.socat-exec":        2,
	} {
		if counts[ruleID] != want {
			t.Errorf("%s count = %d, want %d; all: %#v", ruleID, counts[ruleID], want, counts)
		}
	}
	if counts["path.project.read"] != 1 {
		t.Errorf("sftp batch reads = %d, want 1", counts["path.project.read"])
	}
}

func TestInterpreterAndPackageManagerRules(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
awk --help
awk '{ print $1 }' /project/input
awk -f /project/program.awk /project/input
php -r 'echo 1;'
lua -e 'print(1)'
pip install ./local
pip install requests
pip install -r /project/requirements.txt
python -m pip install ./local
python -m pip install requests
npm install ./local
npm install @scope/package
npm install
npm run build
npx fixture
cargo install --path ./local
cargo install cargo-audit
gem install ./local.gem
gem update
go install ./cmd
go install example.com/tool@latest
go mod download
go generate ./...
`)
	counts := capabilityRuleCounts(result.Capabilities)
	for ruleID, want := range map[string]int{
		"command.awk-exec":                 2,
		"interpreter.php-code":             1,
		"interpreter.lua-code":             1,
		"command.pip-network":              2,
		"command.pip-requirements-network": 2,
		"command.pip-build":                1,
		"command.python-pip-network":       2,
		"command.python-pip-build":         1,
		"command.npm-install-network":      2,
		"command.npm-lock-network":         2,
		"command.npm-exec":                 1,
		"command.npm-lifecycle":            3,
		"command.npx-exec":                 3,
		"command.cargo-network":            2,
		"command.cargo-build":              2,
		"command.gem-update-network":       2,
		"command.go-package-network":       2,
		"command.go-mod-download":          2,
		"command.go-generate":              1,
	} {
		if counts[ruleID] != want {
			t.Errorf("%s count = %d, want %d; all: %#v", ruleID, counts[ruleID], want, counts)
		}
	}
}

func TestSystemAndIndirectExecutionRules(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-base", `
dpkg -l
dpkg -i /tmp/package.deb
xargs echo
find /tmp -name fixture
find /tmp -exec sh -c 'echo test' ';'
find /tmp -delete
mount
mount /dev/sda1 /mnt
service fixture status
service fixture restart
systemd-run echo temporary
systemd-run --on-calendar=daily echo scheduled
atq
at -l
at now
fdisk -l /dev/sda
sfdisk -l /dev/sda
sfdisk /dev/sda
parted /dev/sda print
parted /dev/sda mklabel gpt
wipefs /dev/sda
wipefs -a /dev/sda
blkdiscard --dry-run /dev/sda
blkdiscard /dev/sda
truncate -s 1 /project/file
truncate -s 0 /project/file
passwd --status root
passwd root
useradd fixture
ftp
ftp host
su nobody -c id
`)
	counts := capabilityRuleCounts(result.Capabilities)
	for ruleID, want := range map[string]int{
		"command.dpkg-modify":            2,
		"command.indirect-exec":          1,
		"command.find-exec":              1,
		"command.find-delete":            1,
		"command.mount-modify":           2,
		"command.service-modify":         1,
		"command.systemd-run-timer":      1,
		"command.at-persistence":         1,
		"command.sfdisk-destructive":     1,
		"command.parted-destructive":     1,
		"command.wipefs-destructive":     1,
		"command.blkdiscard-destructive": 1,
		"command.truncate-destructive":   1,
		"command.passwd-modify":          1,
		"command.account-modify":         1,
		"command.legacy-network":         1,
		"command.su-identity":            2,
	} {
		if counts[ruleID] != want {
			t.Errorf("%s count = %d, want %d; all: %#v", ruleID, counts[ruleID], want, counts)
		}
	}
}

func TestWrapperNormalizationAndCapabilities(t *testing.T) {
	t.Parallel()

	result := analyze(t, "setup-project", `
sudo -u nobody env MODE=test timeout 5 nice -n 10 nohup printf test
runuser -u nobody -- printf test
pkexec --user nobody printf test
unshare --mount printf test
nsenter --target 1 --mount printf test
chroot /project/root printf test
setpriv --reuid 1000 printf test
`)
	operations := flatten(result.Operations)
	for _, operation := range operations {
		if operation.Kind == analysis.OperationCommand && operation.Command.Resolution == analysis.Resolved && operation.Command.Literal != "printf" {
			t.Errorf("wrapper normalized to unexpected command %#v", operation.Command)
		}
	}
	counts := capabilityRuleCounts(result.Capabilities)
	if counts["wrapper.identity-change"] != 3 {
		t.Errorf("identity wrapper count = %d, want 3", counts["wrapper.identity-change"])
	}
	if counts["wrapper.execution-context"] != 5 {
		t.Errorf("context wrapper count = %d, want 5", counts["wrapper.execution-context"])
	}
	if counts["wrapper.namespace"] != 4 {
		t.Errorf("namespace wrapper count = %d, want 4", counts["wrapper.namespace"])
	}
}

func capabilityRuleCounts(capabilities []analysis.Capability) map[string]int {
	counts := make(map[string]int)
	for _, capability := range capabilities {
		counts[capability.RuleID]++
	}
	return counts
}

func analyze(t *testing.T, hook, source string) analysis.Result {
	t.Helper()
	parsed := shell.NewParser().Parse([]byte(source), "fixture/"+hook)
	if parsed.Status != shell.StatusParsed {
		t.Fatalf("parse failed: %#v", parsed.Diagnostics)
	}
	return analysis.Analyze(hook, &parsed)
}

func flatten(operations []analysis.Operation) []analysis.Operation {
	var flattened []analysis.Operation
	for _, operation := range operations {
		flattened = append(flattened, operation)
		flattened = append(flattened, flatten(operation.Children)...)
	}
	return flattened
}

func findCommand(t *testing.T, operations []analysis.Operation, command string) analysis.Operation {
	t.Helper()
	for _, operation := range operations {
		if operation.Command.Literal == command {
			return operation
		}
	}
	t.Fatalf("command %q not found", command)
	return analysis.Operation{}
}

func firstOperation(t *testing.T, operations []analysis.Operation, kind analysis.OperationKind) analysis.Operation {
	t.Helper()
	for _, operation := range operations {
		if operation.Kind == kind {
			return operation
		}
	}
	t.Fatalf("operation %q not found", kind)
	return analysis.Operation{}
}

func hasOperation(operations []analysis.Operation, kind analysis.OperationKind) bool {
	for _, operation := range operations {
		if operation.Kind == kind {
			return true
		}
	}
	return false
}

func assertCapability(t *testing.T, capabilities []analysis.Capability, kind string) {
	t.Helper()
	for _, capability := range capabilities {
		if capability.Kind == kind {
			return
		}
	}
	t.Errorf("capability %q not found: %#v", kind, capabilities)
}
