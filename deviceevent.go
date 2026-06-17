package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The v0.3 device-decomposition observer reuses the v0.2 trace_open signal and
// its fileEvent attribution (an open of a device node is just an open whose
// path is under /dev). It needs no new event type — only a different classifier
// (isDeviceOpen, the complement of isRootfsWrite's /dev exclusion) and a
// device-node aggregator. See issue #92.

// defaultDevices are the device nodes (and pseudo-fs mounts under /dev) that a
// container receives WITHOUT privileged: the Docker/OCI default device set plus
// the standard /dev mounts. An open of one of these says nothing about what a
// privileged container actually needs, so the decomposition observer excludes
// them — its job is surfacing the *extra* devices privileged unlocks (e.g.
// /dev/dri, /dev/kvm, /dev/net/tun, block devices). Sourced from the OCI
// runtime-spec default devices and Docker's default cgroup device allowlist.
var defaultDevices = map[string]struct{}{
	"/dev/null":    {},
	"/dev/zero":    {},
	"/dev/full":    {},
	"/dev/random":  {},
	"/dev/urandom": {},
	"/dev/tty":     {},
	"/dev/console": {},
	"/dev/ptmx":    {},
	"/dev/fd":      {},
	"/dev/stdin":   {},
	"/dev/stdout":  {},
	"/dev/stderr":  {},
	"/dev/shm":     {},
	"/dev/mqueue":  {},
}

// defaultDevicePrefixes are the directory mounts under /dev whose children are
// likewise always present unprivileged: pseudo-terminals (/dev/pts/*), shared
// memory (/dev/shm/*), and POSIX message queues (/dev/mqueue/*). Files opened
// under them are not device grants.
var defaultDevicePrefixes = []string{"/dev/pts/", "/dev/shm/", "/dev/mqueue/"}

// isDeviceOpen reports whether p is an open of a non-default device node — an
// absolute path directly under /dev that is not in the default container device
// set. It is the decomposition complement of isRootfsWrite (which drops all of
// /dev as pseudo-fs): here /dev is exactly the namespace of interest, minus the
// nodes every container already gets. A bare "/dev" or "/dev/" (the directory
// itself) is not a device grant and is excluded.
func isDeviceOpen(p string) bool {
	if !strings.HasPrefix(p, "/dev/") || p == "/dev/" {
		return false
	}
	if _, ok := defaultDevices[p]; ok {
		return false
	}
	for _, pre := range defaultDevicePrefixes {
		if strings.HasPrefix(p, pre) {
			return false
		}
	}
	return true
}

// deviceObservation is the v0.3 device observer's aggregate: the distinct
// non-default device nodes opened (unioned and per-replica) plus the count of
// device-open events behind them. It mirrors writeObservation field-for-field
// so the sidecar/confidence/multi-replica machinery built for v0.2 fs carries
// over; the decision layer (deviceRecommendation) sits on top.
type deviceObservation struct {
	Devices    []string            // sorted union of non-default /dev nodes
	PerReplica map[string][]string // replica id (or name) -> sorted device nodes
	EventCount int                 // device-open events counted post-filter

	// PerReplicaCount is the device-open count per replica (the cap
	// aggregator's per_replica_event_counts analog).
	PerReplicaCount map[string]int
	// Stats is per-device detail (event count + comm samples) feeding the
	// sidecar's device_paths section — the DevicePath analog of writeStats.
	Stats map[string]*deviceStats
	// Dropped is ig's ringbuf-lost-sample count for the live observe path;
	// 0 in fixture mode. Feeds trace_health.
	Dropped int
	// Image is the first observed container image, mirroring the cap/fs
	// aggregators.
	Image string
}

// deviceStats collapses N opens of one device node into the numbers the
// sidecar's device_paths section needs. Mirrors writeStats.
type deviceStats struct {
	eventCount  int
	commSamples map[string]struct{}
}

// aggregateDevices reads trace_open NDJSON from r, keeps events that match the
// target selector (aggregateOpts.matchesRuntime) and open a non-default device
// node (isDeviceOpen), and collects the device paths per replica and unioned.
// Unlike aggregateWrites it does NOT filter on write intent — a read-only open
// of /dev/dri/card0 still needs the device granted. Replica identity and the
// >1-replica ambiguity guard mirror aggregateWrites exactly.
func aggregateDevices(r io.Reader, opts aggregateOpts) (*deviceObservation, error) {
	union := map[string]struct{}{}
	perReplica := map[string]map[string]struct{}{}
	perReplicaCount := map[string]int{}
	perReplicaName := map[string]string{}
	stats := map[string]*deviceStats{}
	count := 0
	image := ""
	scan := bufio.NewScanner(r)
	scan.Buffer(make([]byte, 64*1024), 1024*1024)
	for scan.Scan() {
		line := scan.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var ev fileEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			return nil, fmt.Errorf("parse trace_open event: %w", err)
		}
		if !opts.matchesRuntime(ev.Runtime.ContainerID, ev.Runtime.ContainerName, ev.Runtime.ContainerImage) {
			continue
		}
		p := ev.Path()
		if !isDeviceOpen(p) {
			continue
		}
		count++
		if image == "" {
			image = ev.Runtime.ContainerImage
		}
		union[p] = struct{}{}
		rid := ev.Runtime.ContainerID
		if rid == "" {
			rid = ev.Runtime.ContainerName
		}
		if perReplica[rid] == nil {
			perReplica[rid] = map[string]struct{}{}
		}
		perReplica[rid][p] = struct{}{}
		perReplicaCount[rid]++
		if ev.Runtime.ContainerName != "" {
			perReplicaName[rid] = ev.Runtime.ContainerName
		}
		st := stats[p]
		if st == nil {
			st = &deviceStats{commSamples: map[string]struct{}{}}
			stats[p] = st
		}
		st.eventCount++
		if comm := strings.TrimSpace(ev.Proc.Comm); comm != "" {
			st.commSamples[comm] = struct{}{}
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}

	// Ambiguity: the selector (--image, or a too-short --container prefix)
	// matched >1 replica without --all-matching. Mirrors aggregate()/
	// aggregateWrites — the tool refuses to silently union the device sets of
	// replicas the user didn't opt into aggregating.
	if opts.ambiguous(len(perReplica)) {
		labels := make([]string, 0, len(perReplica))
		for rid := range perReplica {
			if name := perReplicaName[rid]; name != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", name, rid))
			} else {
				labels = append(labels, rid)
			}
		}
		sort.Strings(labels)
		return nil, opts.newAmbiguousSelectionError(labels)
	}

	obs := &deviceObservation{
		Devices:         sortedKeys(union),
		PerReplica:      map[string][]string{},
		EventCount:      count,
		PerReplicaCount: perReplicaCount,
		Stats:           stats,
		Image:           image,
	}
	for rid, set := range perReplica {
		obs.PerReplica[rid] = sortedKeys(set)
	}
	return obs, nil
}
