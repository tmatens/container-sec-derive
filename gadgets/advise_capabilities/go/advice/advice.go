// Copyright 2026 The container-sec-derive authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// Package advice holds the pure capability-bitmap → advice logic, deliberately
// free of any wasmapi import so it is unit-testable on the host. The WASM
// operator (../program.go) is a thin adapter that reads gadget fields and calls
// Render.
package advice

import (
	"fmt"
	"slices"
	"strings"
)

// CapNames maps a kernel capability number (the bit index in the eBPF bitmap)
// to its name without the CAP_ prefix (compose/k8s convention). Order matches
// <linux/capability.h> (CAP_CHOWN=0 .. CAP_CHECKPOINT_RESTORE=40) and the enum
// in Inspektor Gadget's trace_capabilities gadget. This ordering is
// correctness-critical: a wrong index→name mapping recommends the wrong
// capability. It is asserted against the canonical list in advice_test.go.
var CapNames = []string{
	"CHOWN", "DAC_OVERRIDE", "DAC_READ_SEARCH", "FOWNER", "FSETID",
	"KILL", "SETGID", "SETUID", "SETPCAP", "LINUX_IMMUTABLE",
	"NET_BIND_SERVICE", "NET_BROADCAST", "NET_ADMIN", "NET_RAW", "IPC_LOCK",
	"IPC_OWNER", "SYS_MODULE", "SYS_RAWIO", "SYS_CHROOT", "SYS_PTRACE",
	"SYS_PACCT", "SYS_ADMIN", "SYS_BOOT", "SYS_NICE", "SYS_RESOURCE",
	"SYS_TIME", "SYS_TTY_CONFIG", "MKNOD", "LEASE", "AUDIT_WRITE",
	"AUDIT_CONTROL", "SETFCAP", "MAC_OVERRIDE", "MAC_ADMIN", "SYSLOG",
	"WAKE_ALARM", "BLOCK_SUSPEND", "AUDIT_READ", "PERFMON", "BPF",
	"CHECKPOINT_RESTORE",
}

// HeldCaps decodes a held-capability bitmap into a sorted, deduplicated list of
// capability names. Bits beyond the known capability range are ignored.
func HeldCaps(bitmap uint64) []string {
	var held []string
	for i := 0; i < len(CapNames); i++ {
		if bitmap&(1<<uint(i)) != 0 {
			held = append(held, CapNames[i])
		}
	}
	slices.Sort(held)
	return held
}

// Render turns a held-capability bitmap into a compose-style cap_drop/cap_add
// block for one container. An empty bitmap yields cap_drop: ALL with an explicit
// "no cap_add required" note (never a bare/malformed block).
func Render(containerName string, bitmap uint64) string {
	held := HeldCaps(bitmap)

	var b strings.Builder
	if containerName != "" {
		fmt.Fprintf(&b, "# %s\n", containerName)
	}
	b.WriteString("cap_drop:\n  - ALL\n")
	if len(held) == 0 {
		b.WriteString("# no non-default capabilities observed; cap_add not required\n")
		return b.String()
	}
	b.WriteString("cap_add:\n")
	for _, c := range held {
		fmt.Fprintf(&b, "  - %s\n", c)
	}
	return b.String()
}
