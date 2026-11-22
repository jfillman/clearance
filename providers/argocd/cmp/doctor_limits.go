package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// doctorFSSandbox reports the filesystem sandbox of the render steps (fssandbox.go): on, unavailable or off.
func doctorFSSandbox(env DoctorEnv, add func(level, name, msg, fix string)) {
	const name = "fs-sandbox"
	mode, err := ParseFSSandbox(env.Get(FSSandboxEnv))
	if err != nil {
		add(levelFail, name, err.Error(), "set "+FSSandboxEnv+" to try, require or off")
		return
	}
	SetFSSandbox(mode, orDefault(env.Get("CLEARANCE_TOKEN_FILE"), "/var/run/secrets/tokens/clearance"))
	switch state := FSSandboxState(); {
	case state == "on":
		add(levelOK, name, "on: render steps can read only the system directories, their source and their own scratch; the token is out of their reach (Landlock, mode "+mode+")", "")
	case state == "off":
		add(levelOK, name, "off: "+FSSandboxEnv+"=off, render steps can read every file this user can, the clearance token included", "")
	case mode == NetnsRequire:
		add(levelFail, name, fmt.Sprintf("unavailable and %s=require: every render would be refused (%v)", FSSandboxEnv, fsSandboxCause()),
			"run on a kernel with Landlock (Linux 5.13+, landlock among the active LSMs), or set "+FSSandboxEnv+"=try")
	default:
		add(levelWarn, name, fmt.Sprintf("unavailable: render steps run WITHOUT the filesystem sandbox and can read the clearance token (%v)", fsSandboxCause()),
			"run on a kernel with Landlock (Linux 5.13+, landlock among the active LSMs), then set "+FSSandboxEnv+"=require")
	}
}

// doctorLimits prints the render limits in force and checks that a full set of concurrent renders fits the container's
// memory limit (cgroup v2 memory.max), when it can be read.
func doctorLimits(env DoctorEnv, cfg Config, add func(level, name, msg, fix string)) {
	const name = "render-limits"
	lim := cfg.Limits
	if lim == (Limits{}) {
		lim = DefaultLimits()
	}
	msg := fmt.Sprintf("wall %s per render (slot wait included), per step CPU %s, memory %s, stdout %s; scratch %s per render; %d renders at once",
		lim.Timeout, lim.CPU, FormatSize(lim.Memory), FormatSize(lim.Output), FormatSize(lim.Temp), lim.Renders)
	if !shimSupported {
		add(levelOK, name, msg+" (off Linux, where the sidecar never runs, only the wall time, output and scratch bounds hold)", "")
		return
	}
	read := env.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	raw, err := read("/sys/fs/cgroup/memory.max")
	memMax, perr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || perr != nil || memMax <= 0 {
		add(levelOK, name, msg+" (the container's memory limit could not be read)", "")
		return
	}
	if need := int64(lim.Renders) * lim.Memory; need > memMax {
		add(levelWarn, name, fmt.Sprintf("%s; %d renders of %s each could use %s, over the container's memory limit of %s: the kernel would kill a step instead of the plugin stopping it with a clear error",
			msg, lim.Renders, FormatSize(lim.Memory), FormatSize(need), humanBytes(memMax)),
			fmt.Sprintf("raise the container's memory limit, or lower %s or %s", EnvMaxRenders, EnvMaxMemory))
		return
	}
	add(levelOK, name, fmt.Sprintf("%s; fits the container's memory limit of %s", msg, humanBytes(memMax)), "")
}
