package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The v0.3 privileged formatters compose the existing capability and device
// formatters: the minimum non-privileged equivalent of `privileged: true` IS
// the observed cap set (the cap formatter's output) plus the observed device
// nodes (the device formatter's output). Reusing the single-observer formatters
// keeps one source of truth per output shape; the privileged variant only adds
// the "drop privileged: true" framing and stitches the two halves together.
// JSON needs no privileged variant — writeJSON already serializes the full
// sidecar (capabilities + device_recommendation + privileged_decomposition).

// privilegedCaveatComment writes the partial-decomposition warning as a
// `#`-prefixed line (safe in compose/k8s/docker-run output). It names the
// AppArmor/seccomp dimension the decomposition does NOT recover so a user
// pasting the minimum config still sees that relaxed MAC, if relied upon, is
// not covered. Kept out of the compose-patch unified diff (a `#` line there
// would not be a valid hunk); that path relies on the JSON block + stderr
// advisory instead.
func privilegedCaveatComment(w io.Writer) error {
	_, err := fmt.Fprintf(w, "# WARNING (partial decomposition): %s\n", PrivilegedSecurityOptCaveat)
	return err
}

// writePrivilegedCompose emits the compose decomposition of `privileged: true`:
// a drop-privileged header, then the capability stanza (cap_drop: [ALL] +
// cap_add), then the device stanza (devices:). The result pastes under a
// service in place of `privileged: true`.
func writePrivilegedCompose(w io.Writer, s *Sidecar) error {
	if _, err := fmt.Fprintln(w, "# privileged: true is not required; drop it and apply the minimum below:"); err != nil {
		return err
	}
	if err := privilegedCaveatComment(w); err != nil {
		return err
	}
	if err := writeCompose(w, s); err != nil {
		return err
	}
	if s.DeviceRecommendation != nil {
		if err := writeDeviceCompose(w, *s.DeviceRecommendation); err != nil {
			return err
		}
	}
	return nil
}

// writePrivilegedDockerRun composes the cap and device docker-run formatters
// under a drop-privileged header. Cap flags and device flags concatenate
// cleanly (both are flag strings), so this reuses both single-observer writers.
func writePrivilegedDockerRun(w io.Writer, s *Sidecar) error {
	if _, err := fmt.Fprintln(w, "# privileged: true is not required; drop it and apply the minimum below:"); err != nil {
		return err
	}
	if err := privilegedCaveatComment(w); err != nil {
		return err
	}
	if err := writeDockerRun(w, s); err != nil {
		return err
	}
	if s.DeviceRecommendation != nil {
		if err := writeDeviceDockerRun(w, *s.DeviceRecommendation); err != nil {
			return err
		}
	}
	return nil
}

// writePrivilegedK8s emits a single Kubernetes securityContext carrying both the
// decomposition's `privileged: false` and the capability drop/add — the two
// halves can't be concatenated (each single-observer writer emits its own
// securityContext: header), so this is a bespoke merge. Device access is
// surfaced as a `#`-commented node list pointing at the device-plugin
// framework, exactly as writeDeviceK8s does (k8s has no per-device
// SecurityContext grant).
func writePrivilegedK8s(w io.Writer, s *Sidecar) error {
	if _, err := fmt.Fprintln(w, "# privileged: true is not required; the minimum non-privileged equivalent is below."); err != nil {
		return err
	}
	if err := privilegedCaveatComment(w); err != nil {
		return err
	}
	var devices []string
	if s.DeviceRecommendation != nil {
		devices = s.DeviceRecommendation.Devices
	}
	if len(devices) > 0 {
		if _, err := fmt.Fprintln(w, "# Devices have no per-device SecurityContext grant; the container opened:"); err != nil {
			return err
		}
		for _, d := range devices {
			if _, err := fmt.Fprintf(w, "#   - %s\n", d); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(w, "# Grant them via the device-plugin framework (e.g. intel.com/gpu, smarter-devices)."); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "securityContext:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  privileged: false"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  capabilities:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "    drop:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "      - ALL"); err != nil {
		return err
	}
	caps := s.CapNames()
	if len(caps) > 0 {
		if _, err := fmt.Fprintln(w, "    add:"); err != nil {
			return err
		}
		for _, c := range caps {
			if _, err := fmt.Fprintf(w, "      - %s\n", c); err != nil {
				return err
			}
		}
	}
	return nil
}

// writePrivilegedOCI emits a single OCI config.json fragment merging the cap
// process.capabilities block (CAP_-prefixed, as writeOCI) with the device
// annotations (as writeDeviceOCI) — two JSON objects can't be concatenated, so
// this is a bespoke merge into one object. major/minor for linux.devices is
// unavailable from trace_open, so devices stay in annotations with the same
// host-resolution note.
func writePrivilegedOCI(w io.Writer, s *Sidecar) error {
	caps := s.CapNames()
	prefixed := make([]string, len(caps))
	for i, c := range caps {
		prefixed[i] = "CAP_" + c
	}
	var devices, derivedCaps []string
	if s.DeviceRecommendation != nil {
		devices = s.DeviceRecommendation.Devices
		derivedCaps = s.DeviceRecommendation.DerivedCaps
	}
	annotations := map[string]string{
		"org.containersecderive.privileged":   "not-required; minimum equivalent is process.capabilities + the devices below",
		"org.containersecderive.security-opt": PrivilegedSecurityOptCaveat,
	}
	if len(devices) > 0 {
		annotations["org.containersecderive.observed-devices"] = strings.Join(devices, ",")
		annotations["org.containersecderive.devices-note"] = "csd observes device paths, not numbers; resolve each node's major/minor on the host (e.g. `stat -c '%t:%T' <path>`) to populate linux.devices."
		if len(derivedCaps) > 0 {
			annotations["org.containersecderive.derived-caps"] = strings.Join(derivedCaps, ",")
		}
	}
	snippet := struct {
		Process struct {
			Capabilities struct {
				Bounding    []string `json:"bounding"`
				Effective   []string `json:"effective"`
				Permitted   []string `json:"permitted"`
				Inheritable []string `json:"inheritable"`
				Ambient     []string `json:"ambient"`
			} `json:"capabilities"`
		} `json:"process"`
		Annotations map[string]string `json:"annotations"`
	}{Annotations: annotations}
	snippet.Process.Capabilities.Bounding = prefixed
	snippet.Process.Capabilities.Effective = prefixed
	snippet.Process.Capabilities.Permitted = prefixed
	snippet.Process.Capabilities.Inheritable = []string{}
	snippet.Process.Capabilities.Ambient = []string{}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(snippet)
}

// writePrivilegedComposePatch emits one unified diff that performs the full
// decomposition on services.<service>: remove `privileged: true`, set
// cap_drop: [ALL] + cap_add, and set the devices: block — all in a single hunk,
// reusing the shared compose-locate + rewrite + unified-diff machinery. A key
// already present is replaced in place; missing ones are inserted together at
// the top of the service body. As with the standalone device patch, an empty
// device observation leaves an existing devices: block untouched (the #92
// under-coverage foot-gun); cap_add follows the cap patch's convention (an
// empty observed set removes an existing cap_add).
func writePrivilegedComposePatch(w io.Writer, s *Sidecar, original []byte, inPath, service string) error {
	if service == "" {
		return fmt.Errorf("--service is required")
	}
	origLines := splitComposeLines(original)
	loc, err := locateComposeService(origLines, service)
	if err != nil {
		return err
	}
	bodyIndent := strings.Repeat(" ", loc.bodyIndent)
	childIndent := bodyIndent + "  "

	capDropBlock := []string{bodyIndent + "cap_drop:", childIndent + "- ALL"}
	var capAddBlock []string
	if caps := s.CapNames(); len(caps) > 0 {
		capAddBlock = append(capAddBlock, bodyIndent+"cap_add:")
		for _, c := range caps {
			capAddBlock = append(capAddBlock, childIndent+"- "+c)
		}
	}
	var devicesBlock []string
	var devices []string
	if s.DeviceRecommendation != nil {
		devices = s.DeviceRecommendation.Devices
	}
	if len(devices) > 0 {
		devicesBlock = append(devicesBlock, bodyIndent+"devices:")
		for _, d := range devices {
			devicesBlock = append(devicesBlock, fmt.Sprintf("%s- %s:%s", childIndent, d, d))
		}
	}

	var rewrites []capRewrite
	// Remove privileged: true if present (rewrite the block to nothing).
	if ps, pe := findChildKeyBlock(origLines, loc, "privileged"); ps >= 0 {
		rewrites = append(rewrites, capRewrite{ps, pe, nil})
	}

	var insert []string
	manage := []struct {
		key       string
		block     []string
		keepEmpty bool // when false, an empty block is skipped (never deletes an existing key)
	}{
		{"cap_drop", capDropBlock, true},
		{"cap_add", capAddBlock, true},   // empty cap_add removes an existing one (cap-patch convention)
		{"devices", devicesBlock, false}, // empty devices leaves an existing block alone (foot-gun)
	}
	for _, m := range manage {
		ks, ke := findChildKeyBlock(origLines, loc, m.key)
		switch {
		case ks >= 0 && (len(m.block) > 0 || m.keepEmpty):
			rewrites = append(rewrites, capRewrite{ks, ke, m.block})
		case ks < 0 && len(m.block) > 0:
			insert = append(insert, m.block...)
		}
	}
	if len(insert) > 0 {
		rewrites = append(rewrites, capRewrite{loc.bodyStart, loc.bodyStart, insert})
	}
	sort.Slice(rewrites, func(i, j int) bool { return rewrites[i].start < rewrites[j].start })

	edited := applyRewriteSequence(origLines, rewrites)
	if equalLines(origLines, edited) {
		return nil
	}
	marks := markRewrites(origLines, rewrites)
	return emitUnifiedDiff(w, inPath, marks)
}

// writePrivilegedComposeLintProfile emits the CL-0002 contribution entry for the
// privileged decomposition (observer: privileged; body = cap_add + devices)
// behind the strictest acceptance contract: the cap, device, AND both
// replica-disagreement gates must all pass (checkPrivilegedComposeLintContract).
func writePrivilegedComposeLintProfile(w io.Writer, s *Sidecar, allowExploratory bool) error {
	violations := checkPrivilegedComposeLintContract(s)
	if len(violations) > 0 && !allowExploratory {
		return fmt.Errorf("compose-lint-profile acceptance contract not met; pass --allow-exploratory to emit anyway:\n  - %s",
			strings.Join(violations, "\n  - "))
	}

	exploratory := len(violations) > 0
	keyIndent := ""
	bodyIndent := "  "
	if exploratory {
		if _, err := fmt.Fprintln(w, "exploratory:"); err != nil {
			return err
		}
		keyIndent = "  "
		bodyIndent = "    "
	}

	if _, err := fmt.Fprintf(w, "%s%s:\n", keyIndent, composeLintKey(s)); err != nil {
		return err
	}

	var devices []string
	if s.DeviceRecommendation != nil {
		devices = s.DeviceRecommendation.Devices
	}
	fmt.Fprintf(w, "%sprivileged: false\n", bodyIndent)
	fmt.Fprintf(w, "%scap_add: [%s]\n", bodyIndent, strings.Join(s.CapNames(), ", "))
	fmt.Fprintf(w, "%sdevices: [%s]\n", bodyIndent, strings.Join(devices, ", "))

	fmt.Fprintf(w, "%sderivation:\n", bodyIndent)
	fmt.Fprintf(w, "%s  tool: container-sec-derive\n", bodyIndent)
	fmt.Fprintf(w, "%s  observer: privileged\n", bodyIndent)
	fmt.Fprintf(w, "%s  partial_decomposition: true # %s\n", bodyIndent, PrivilegedSecurityOptCaveat)
	fmt.Fprintf(w, "%s  tool_version: %s\n", bodyIndent, s.ToolVersion)
	fmt.Fprintf(w, "%s  schema_version: %q\n", bodyIndent, s.SchemaVersion)
	fmt.Fprintf(w, "%s  duration_seconds: %d\n", bodyIndent, s.DurationSeconds)
	fmt.Fprintf(w, "%s  workload: %s\n", bodyIndent, s.Workload)
	fmt.Fprintf(w, "%s  confidence: %s\n", bodyIndent, s.Confidence.Level)

	validatedImage := s.Image
	if s.ImageDigest != "" {
		validatedImage = s.Image + "@" + s.ImageDigest
	}
	fmt.Fprintf(w, "%svalidated_image: %s\n", bodyIndent, validatedImage)
	fmt.Fprintf(w, "%svalidated_date: %s\n", bodyIndent, s.ObservedAt.UTC().Format("2006-01-02"))
	fmt.Fprintf(w, "%svalidated_via: [bpf-observation]\n", bodyIndent)

	if exploratory {
		fmt.Fprintf(w, "%sacceptance_contract_violations:\n", bodyIndent)
		for _, v := range violations {
			fmt.Fprintf(w, "%s  - %s\n", bodyIndent, v)
		}
	}
	return nil
}

// checkPrivilegedComposeLintContract is the union of the cap and device
// contracts: a privileged decomposition is contributable only if BOTH halves
// clear their gates. The shared checks (schema/digest/workload/duration/
// confidence/drop_rate) are evaluated once; the two replica-disagreement gates
// are both enforced.
func checkPrivilegedComposeLintContract(s *Sidecar) []string {
	v := checkComposeLintContract(s) // shared gates + cap-replica disagreement
	if len(s.Target.ReplicaDeviceDisagreement) > 0 {
		v = append(v, fmt.Sprintf("replica_device_disagreement non-empty (%d nodes disagree across replicas)", len(s.Target.ReplicaDeviceDisagreement)))
	}
	return v
}
