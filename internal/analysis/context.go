package analysis

// ContextFor returns the Workshop v0.9.9 execution context for a hook.
func ContextFor(hook string) HookContext {
	context := HookContext{Name: hook}
	switch hook {
	case "setup-base":
		context.RunAsRoot = true
	case "setup-project":
		context.ProjectMounted = true
		context.InterfacesActive = true
	case "check-health":
		context.RunAsRoot = true
		context.ProjectMounted = true
		context.InterfacesActive = true
	case "save-state":
		context.RunAsRoot = true
		context.StateMounted = true
		context.ContextDependent = true
	case "restore-state":
		context.RunAsRoot = true
		context.ProjectMounted = true
		context.InterfacesActive = true
		context.StateMounted = true
	}
	return context
}
