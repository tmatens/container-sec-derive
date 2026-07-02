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
// See the License for the specific language governing permissions and
// limitations under the License.

// WASM operator for the advise_capabilities gadget. It reads the per-container
// held-capability bitmap emitted by the eBPF map iterator and turns it into a
// compose-style cap_drop/cap_add recommendation, one packet per container.
//
// This is the MECHANICAL half of the advisor (per-container union of held
// capabilities). The opinionated half — init-window / runc-noise suppression,
// the confidence rubric, entrypoint cross-check, and multi-format output — lives
// in the csd/compose-lint front-end by design, not here. See ../README.md.
package main

import (
	"fmt"
	"slices"
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// capNames maps a kernel capability number (the bit index in the eBPF bitmap)
// to its name. Order matches <linux/capability.h> (CAP_CHOWN=0 .. =40) and the
// enum in Inspektor Gadget's trace_capabilities gadget.
var capNames = []string{
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

var (
	adviseDS    api.DataSource
	adviseField api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error
	adviseDS, err = api.NewDataSource("advise", api.DataSourceTypeSingle)
	if err != nil {
		api.Errorf("creating datasource: %s", err)
		return 1
	}
	adviseField, err = adviseDS.AddField("text", api.Kind_String)
	if err != nil {
		api.Errorf("adding field: %s", err)
		return 1
	}
	return 0
}

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	capsDS, err := api.GetDataSource("capabilities")
	if err != nil {
		api.Errorf("getting capabilities datasource: %s", err)
		return 1
	}

	capsF, err := capsDS.GetField("caps")
	if err != nil {
		api.Errorf("getting caps field: %s", err)
		return 1
	}
	mntnsF, err := capsDS.GetField("mntns_id_raw")
	if err != nil {
		api.Errorf("getting mntns_id_raw field: %s", err)
		return 1
	}
	k8sContainerF, err := capsDS.GetField("k8s.containerName")
	if err != nil {
		api.Errorf("getting k8s.containerName field: %s", err)
		return 1
	}
	runtimeContainerF, err := capsDS.GetField("runtime.containerName")
	if err != nil {
		api.Errorf("getting runtime.containerName field: %s", err)
		return 1
	}

	err = capsDS.SubscribeArray(func(source api.DataSource, dataArr api.DataArray) error {
		for j := 0; j < dataArr.Len(); j++ {
			data := dataArr.Get(j)

			mntnsid, err := mntnsF.Uint64(data)
			if err != nil {
				api.Warnf("reading mntns id: %s", err)
				continue
			}
			if api.ShouldDiscardMntNsID(mntnsid) {
				continue
			}

			bitmap, err := capsF.Uint64(data)
			if err != nil {
				api.Warnf("reading caps bitmap: %s", err)
				continue
			}

			k8sName, _ := k8sContainerF.String(data, 512)
			runtimeName, _ := runtimeContainerF.String(data, 512)
			containerName := k8sName
			if containerName == "" {
				containerName = runtimeName
			}

			nd, err := adviseDS.NewPacketSingle()
			if err != nil {
				api.Warnf("creating packet: %s", err)
				continue
			}
			adviseField.SetString(api.Data(nd), renderAdvice(containerName, bitmap))
			adviseDS.EmitAndRelease(api.Packet(nd))
		}
		return nil
	}, 9999)
	if err != nil {
		api.Warnf("subscribing to capabilities: %s", err)
		return 1
	}
	return 0
}

// renderAdvice turns a held-capability bitmap into a compose-style block.
// Exported-in-spirit (package-private but pure) so the unit test can exercise
// the bit decode without a running gadget.
func renderAdvice(containerName string, bitmap uint64) string {
	var held []string
	for i := 0; i < len(capNames); i++ {
		if bitmap&(1<<uint(i)) != 0 {
			held = append(held, capNames[i])
		}
	}
	slices.Sort(held)

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

func main() {}
