package analysis

import (
	"path/filepath"
	"strings"
)

// PathClass identifies security-relevant filesystem areas.
type PathClass string

const (
	PathSDK         PathClass = "sdk"
	PathProject     PathClass = "project"
	PathUserHome    PathClass = "user-home"
	PathRootHome    PathClass = "root-home"
	PathState       PathClass = "state"
	PathRuntime     PathClass = "runtime"
	PathSystem      PathClass = "system"
	PathPersistence PathClass = "persistence"
	PathSensitive   PathClass = "sensitive"
	PathDevice      PathClass = "device"
	PathTemporary   PathClass = "temporary"
	PathUnknown     PathClass = "unknown"
)

var commandCapabilities = map[string][]string{
	"curl":      {"network-access", "network-download"},
	"wget":      {"network-access", "network-download"},
	"git":       {"network-access"},
	"ssh":       {"network-access", "external-send"},
	"scp":       {"network-access", "external-send"},
	"nc":        {"network-access", "external-send"},
	"bash":      {"code-execution"},
	"sh":        {"code-execution"},
	"python":    {"code-execution"},
	"python3":   {"code-execution"},
	"perl":      {"code-execution"},
	"ruby":      {"code-execution"},
	"node":      {"code-execution"},
	"systemctl": {"system-modification", "persistence"},
	"crontab":   {"persistence"},
	"chmod":     {"privilege-modification"},
	"chown":     {"privilege-modification"},
	"setcap":    {"privilege-modification"},
	"apt":       {"network-access", "system-modification"},
	"apt-get":   {"network-access", "system-modification"},
	"snap":      {"network-access", "system-modification"},
	"rm":        {"destructive-operation"},
	"dd":        {"destructive-operation"},
	"mkfs":      {"destructive-operation"},
	"base64":    {"obfuscation"},
	"xxd":       {"obfuscation"},
	"openssl":   {"obfuscation"},
	"gzip":      {"obfuscation"},
	"tar":       {"obfuscation"},
}

var fileReadCommands = map[string]bool{
	"cat": true, "head": true, "tail": true, "less": true, "grep": true,
}

var fileWriteCommands = map[string]bool{
	"cp": true, "mv": true, "touch": true, "mkdir": true, "tee": true, "install": true,
}

// ClassifyPath maps a resolved or partially resolved path to a security area.
func ClassifyPath(value Value) PathClass {
	for _, part := range value.Parts {
		if part.Kind != PartVariableReference {
			continue
		}
		switch part.Name {
		case "SDK_STATE_DIR":
			return PathState
		case "SDK":
			return PathSDK
		}
	}
	path := value.Literal
	if path == "" && len(value.Candidates) > 0 {
		path = value.Candidates[0]
	}
	path = filepath.Clean(path)
	switch {
	case path == "/project" || strings.HasPrefix(path, "/project/"):
		return PathProject
	case path == "/root" || strings.HasPrefix(path, "/root/"):
		if sensitivePath(path) {
			return PathSensitive
		}
		return PathRootHome
	case strings.HasPrefix(path, "/home/workshop/"):
		if sensitivePath(path) {
			return PathSensitive
		}
		return PathUserHome
	case strings.Contains(path, "/state/") || strings.HasSuffix(path, "/state"):
		return PathState
	case strings.HasPrefix(path, "/run/"):
		return PathRuntime
	case strings.HasPrefix(path, "/var/lib/workshop/sdk/"):
		return PathSDK
	case strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/sys/") || strings.HasPrefix(path, "/dev/"):
		return PathDevice
	case strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/var/tmp/"):
		return PathTemporary
	case persistencePath(path):
		return PathPersistence
	case sensitivePath(path):
		return PathSensitive
	case strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/usr/") || strings.HasPrefix(path, "/opt/"):
		return PathSystem
	case strings.Contains(path, "/sdk/"):
		return PathSDK
	default:
		return PathUnknown
	}
}

// ExtractCapabilities derives factual behaviors without assigning risk scores.
func ExtractCapabilities(operations []Operation, context HookContext) []Capability {
	var capabilities []Capability
	for i := range operations {
		operation := &operations[i]
		capabilities = append(capabilities, capabilitiesForOperation(*operation, context)...)
		capabilities = append(capabilities, ExtractCapabilities(operation.Children, context)...)
	}
	return capabilities
}

func capabilitiesForOperation(operation Operation, _ HookContext) []Capability {
	var capabilities []Capability
	add := func(kind string, target Value, resolution Resolution) {
		capabilities = append(capabilities, Capability{Kind: kind, Operation: operation.Kind,
			Target: target, Resolution: resolution, Location: operation.Location})
	}
	if operation.Kind == OperationEval || operation.Kind == OperationSource || operation.Command.Resolution != Resolved {
		if operation.Kind == OperationEval || operation.Kind == OperationSource || operation.Kind == OperationCommand {
			add("dynamic-execution", operation.Command, operation.Resolution)
		}
	}
	if operation.Kind == OperationEval || operation.Kind == OperationSource || operation.Kind == OperationFunctionInvocation {
		add("code-execution", operation.Command, operation.Resolution)
	}
	if operation.Command.Resolution == Resolved {
		command := filepath.Base(operation.Command.Literal)
		for _, capability := range commandCapabilities[command] {
			add(capability, operation.Command, operation.Resolution)
		}
		for _, argument := range operation.Arguments {
			if !strings.HasPrefix(argument.Literal, "-") {
				if fileReadCommands[command] {
					addPathCapability(&capabilities, operation, argument, false)
				}
				if fileWriteCommands[command] {
					addPathCapability(&capabilities, operation, argument, true)
				}
			}
		}
		if (command == "curl" || command == "wget") && hasUploadArgument(operation.Arguments) {
			add("external-send", operation.Command, operation.Resolution)
		}
		if shellWithCodeArgument(operation.Command.Literal, operation.Arguments) {
			add("dynamic-execution", operation.Arguments[1], operation.Arguments[1].Resolution)
		}
	}
	for _, input := range operation.Inputs {
		addPathCapability(&capabilities, operation, input.Value, false)
	}
	for _, output := range operation.Outputs {
		addPathCapability(&capabilities, operation, output.Value, true)
	}
	return capabilities
}

func hasUploadArgument(arguments []Value) bool {
	for _, argument := range arguments {
		if argument.Resolution != Resolved {
			continue
		}
		switch argument.Literal {
		case "-d", "--data", "--data-binary", "-F", "--form", "-T", "--upload-file", "--post-file":
			return true
		}
	}
	return false
}

func addPathCapability(capabilities *[]Capability, operation Operation, target Value, write bool) {
	kind := ""
	switch ClassifyPath(target) {
	case PathProject:
		if write {
			kind = "project-write"
		} else {
			kind = "project-read"
		}
	case PathSensitive:
		if !write {
			kind = "credential-read"
		}
	case PathState:
		if write {
			kind = "state-write"
		} else {
			kind = "state-read"
		}
	case PathDevice:
		kind = "device-access"
	case PathPersistence:
		kind = "persistence"
	case PathSystem:
		if write {
			kind = "system-modification"
		}
	}
	if kind != "" {
		*capabilities = append(*capabilities, Capability{Kind: kind, Operation: operation.Kind,
			Target: target, Resolution: target.Resolution, Location: operation.Location})
	}
}

func shellWithCodeArgument(command string, arguments []Value) bool {
	switch filepath.Base(command) {
	case "bash", "sh", "python", "python3", "perl", "ruby", "node":
	default:
		return false
	}
	return len(arguments) > 1 && arguments[0].Resolution == Resolved && arguments[0].Literal == "-c"
}

func sensitivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, marker := range []string{"/.ssh", "/.aws", "/.config", "credential", "token", "secret"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func persistencePath(path string) bool {
	for _, marker := range []string{"/systemd/", "/cron", "/profile", "/.bashrc", "/.zshrc", "/.git/hooks/"} {
		if strings.Contains(path, marker) {
			return true
		}
	}
	return false
}
