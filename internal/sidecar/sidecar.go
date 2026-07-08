// Package sidecar defines the canonical JSON evidence artifact and the
// evidence/recommendation types every observer fills in and every formatter
// reads back. It is the schema source of truth (PLAN.md §Output schema): the
// observers (internal/observe/*) derive these types from kernel signals, and
// the formatters (internal/format) render them. It is a foundation leaf —
// stdlib-only, imported by the layers above, importing none of them — so the
// recommendation structs live here rather than in the observer packages to
// keep the import direction one-way.
package sidecar

import (
	"net"
	"strconv"
	"time"
)

// Canonical evidence-artifact identity fields.
//
// SchemaVersion follows semver-on-schema: additive changes stay within 1.x;
// consumers (including the compose-lint contribution flow) reject unknown
// majors. See PLAN.md §Output schema. v0.2 bumped 1.0 → 1.1 for the additive,
// omitempty fs fields (writable_paths, fs_recommendation,
// replica_write_path_disagreement); v0.3 bumps 1.1 → 1.2 for the additive,
// omitempty device fields (device_paths, device_recommendation,
// replica_device_disagreement) — a caps or fs sidecar is byte-identical under
// 1.2, and a 1.2-aware consumer knows the document may carry the device block.
// v0.5 bumps 1.2 -> 1.3 for the additive, omitempty capadd_validation block (the
// dangerous-cap_add validator); caps/fs/device sidecars stay byte-identical under
// 1.3, and a 1.3-aware consumer knows the document may carry the capadd block.
// v0.8 bumps 1.3 -> 1.4 for the additive, omitempty egress block (egress_destinations,
// egress_recommendation, replica_egress_disagreement — the network-egress observer);
// prior sidecars stay byte-identical under 1.4 save for the schema_version string.
// The egress DNS/hostname follow-up (issue #159) bumps 1.4 -> 1.5 for two more
// additive, omitempty egress fields: per-destination `hostnames` (the names that
// resolved to each IP, from trace_dns) and `dns_resolvers` on the recommendation
// (the UDP/53 resolver endpoints a default-DROP allowlist must permit). A
// TCP-only egress sidecar (no --dns-fixture / no live trace_dns) is byte-identical
// under 1.5 save for the schema_version string; all prior sidecars likewise.
// The #206 egress provenance model bumps 1.5 -> 1.6 for one more additive,
// omitempty egress field: `egress_destination_intel`, a name-centric,
// provenance- and visibility-tagged view of the observed egress (see
// EgressDestinationIntel). A non-egress sidecar is byte-identical under 1.6 save
// for the schema_version string; a 1.6-aware consumer knows an egress document
// may carry the intel block.
const (
	SchemaVersion = "1.6"
	ToolVersion   = "0.7.0"
	// Caveat is hardcoded so downstream consumers cannot strip the
	// "this is workload-bounded, not a correctness proof" framing.
	Caveat = "BPF-observed profiles reflect only the paths the workload exercised. Not a correctness proof."
	// PrivilegedSecurityOptCaveat names the dimension the v0.3 privileged
	// decomposition does NOT recover. `privileged: true` relaxes caps +
	// devices + masked-path bypass + AppArmor unconfined + seccomp unconfined;
	// csd observes only the caps + devices halves (no AppArmor/seccomp denial
	// gadget at the pinned IG). A container that genuinely relies on relaxed
	// MAC will break if privileged: true is dropped on the strength of this
	// decomposition alone, so the gap is surfaced explicitly — in the JSON
	// (privileged_decomposition.security_opt), in every text formatter header,
	// and as a stderr advisory — rather than left to the generic Caveat.
	PrivilegedSecurityOptCaveat = "AppArmor/seccomp (security_opt) not observed; this decomposition covers caps + devices only. Verify the workload does not rely on unconfined MAC before dropping privileged: true."
)

// Confidence levels. String values match PLAN.md §Confidence scoring.
const (
	ConfidenceHigh     = "high"
	ConfidenceModerate = "moderate"
	ConfidenceLow      = "low"
)

// Target selection modes. Values match PLAN.md §Target selection.
const (
	TargetModeContainer   = "container"
	TargetModeImage       = "image"
	TargetModeAllMatching = "all-matching"
)

// CrossCheckStatusOK is the sentinel CrossCheckStatus value used when the
// entrypoint cross-check ran successfully (cap sets are authoritative
// regardless of whether signals fired).
const CrossCheckStatusOK = "ok"

// CrossCheckStatusPartialHistoryPrefix prefixes a CrossCheckStatus when the
// `inspect` half of the cross-check succeeded (argv heuristics + digest are
// authoritative) but the `history` half failed, so only the setcap-from-history
// signals are absent. This is a graceful degradation, not a failure: a `history`
// regression under Docker 29's containerd image store (see issue #180) must not
// discard the good digest/Config that `inspect` already returned. The confidence
// rubric treats this distinctly from a full "unavailable" so argv-derived
// coverage warnings still apply.
const CrossCheckStatusPartialHistoryPrefix = "partial (history unavailable): "

// Sidecar is the canonical JSON evidence artifact. All formatters derive
// from this struct; it is the single source of truth for an observation run.
// See PLAN.md §Output schema for the full field-by-field contract.
type Sidecar struct {
	SchemaVersion              string       `json:"schema_version"`
	Image                      string       `json:"image,omitempty"`
	ImageDigest                string       `json:"image_digest,omitempty"`
	ObservedAt                 time.Time    `json:"observed_at"`
	DurationSeconds            int          `json:"duration_seconds"`
	Workload                   string       `json:"workload,omitempty"`
	ToolVersion                string       `json:"tool_version"`
	KernelVersion              string       `json:"kernel_version,omitempty"`
	Target                     Target       `json:"target"`
	Capabilities               []Capability `json:"capabilities"`
	ExpectedCapsFromEntrypoint []string     `json:"expected_caps_from_entrypoint"`
	CoverageWarnings           []string     `json:"coverage_warnings"`

	// v0.2 read-only-filesystem observer section. Both fields are
	// omitempty + nil on a capability run, so a `--observe caps` sidecar
	// serializes byte-identically to pre-v0.2 (PLAN.md §Output schema:
	// "future observers add their own top-level block ... formatters
	// select the relevant section"). On an `--observe fs` run the
	// capability scaffolding (Capabilities/ExpectedCaps/...) stays empty
	// and these carry the observation.
	WritablePaths    []WritablePath    `json:"writable_paths,omitempty"`
	FSRecommendation *FSRecommendation `json:"fs_recommendation,omitempty"`

	// v0.3 device-decomposition observer section. Both fields are
	// omitempty + nil on a capability or fs run, so those sidecars serialize
	// byte-identically to pre-v0.3 (PLAN.md §Output schema). On an
	// `--observe devices` run the capability and fs scaffolding stay empty
	// and these carry the observation.
	DevicePaths          []DevicePath          `json:"device_paths,omitempty"`
	DeviceRecommendation *DeviceRecommendation `json:"device_recommendation,omitempty"`

	// v0.3 privileged-mode decomposition (the --observe privileged composition).
	// omitempty + nil on every single-observer run; present only when both the
	// capability and device observers ran together and csd synthesized the
	// minimum non-privileged equivalent. The Capabilities + DeviceRecommendation
	// blocks above carry the full evidence; this block is the headline
	// conclusion (drop privileged: true → cap_add + devices).
	PrivilegedDecomposition *PrivilegedDecomposition `json:"privileged_decomposition,omitempty"`

	// v0.5 dangerous-cap_add validator section (the --observe capadd mode).
	// omitempty + nil on every other observer's run, so caps/fs/device/privileged
	// sidecars serialize byte-identically under the 1.3 schema bump (PLAN.md
	// §Output schema). On an `--observe capadd` run the other observers'
	// scaffolding stays empty and this block carries the per-cap validation.
	CapaddValidation *CapaddValidation `json:"capadd_validation,omitempty"`

	// v0.8 network-egress observer section (the --observe egress mode).
	// omitempty + nil on every other observer's run, so prior sidecars
	// serialize byte-identically under the 1.5 schema bump (PLAN.md §Output
	// schema). On an `--observe egress` run the other observers' scaffolding
	// stays empty and these carry the observed outbound destinations + the
	// minimum allowlist recommendation.
	EgressDestinations   []EgressDestination   `json:"egress_destinations,omitempty"`
	EgressRecommendation *EgressRecommendation `json:"egress_recommendation,omitempty"`
	// EgressDestinationIntel is the #206 name-centric provenance view of the
	// egress. Additive, omitempty; see the type doc. Never widens the enforced
	// allowlist (EgressRecommendation.Allowlist) — it is data alongside it.
	EgressDestinationIntel []EgressDestinationIntel `json:"egress_destination_intel,omitempty"`

	TraceHealth TraceHealth `json:"trace_health"`
	Confidence  Confidence  `json:"confidence"`
	Caveat      string      `json:"caveat"`

	// CrossCheckStatus is an internal (unserialized) handoff from the
	// observe/run path to the confidence rubric. Empty = skipped (e.g.
	// fixture mode without --inspect-fixture, or no image reference
	// available). "ok" = ran successfully (cap sets are authoritative
	// regardless of whether signals fired). Any other non-empty value
	// is a short reason explaining why the live inspect failed, and
	// feeds an "entrypoint cross-check unavailable: ..." factor in
	// the rubric. Not serialized because PLAN.md §Output schema does
	// not define a sidecar field for cross-check status; the public
	// contract is ExpectedCapsFromEntrypoint + CoverageWarnings, and
	// everything else is internal telemetry.
	CrossCheckStatus string `json:"-"`
}

// Target captures which container(s) produced the observation and how
// selection + restart handling played out over the window.
type Target struct {
	Mode                   string              `json:"mode"`
	Selector               string              `json:"selector"`
	ReplicasObserved       int                 `json:"replicas_observed"`
	PerReplicaEventCounts  map[string]int      `json:"per_replica_event_counts"`
	PerReplicaCaps         map[string][]string `json:"per_replica_caps"`
	ReplicaCapDisagreement []string            `json:"replica_cap_disagreement"`
	Restarts               []Restart           `json:"restarts"`
	FollowRestart          bool                `json:"follow_restart"`
	TargetExitedEarly      bool                `json:"target_exited_early"`
	// InitWindowSuppressed is how many events the init filter dropped:
	// either the time-window filter (--init-window-ms) or the comm-aware
	// runc:[*] filter (Step 21). Exposed so reviewers can tell whether
	// a sparse derived cap set is genuine workload behavior or an
	// init-filter artifact. The two suppression sources are summed
	// because both are "init noise removed before reaching the cap set"
	// from a reviewer's perspective; if the distinction matters later,
	// split into separate counters in a schema-additive bump.
	InitWindowSuppressed int `json:"init_window_suppressed"`
	// DistinctComms is the count of distinct `comm` values observed across
	// all replicas after the init-window filter. Feeds the comm-diversity
	// factor in PLAN.md §Confidence scoring. Tracked here (rather than in
	// a private aggregator field) so reviewers can audit the rubric input
	// from the sidecar alone.
	DistinctComms int `json:"distinct_comms"`
	// ReplicaWritePathDisagreement is the v0.2 fs analog of
	// ReplicaCapDisagreement: write paths observed on fewer than all
	// replicas under --all-matching. omitempty + nil on a capability run and
	// on single-replica fs runs; populated by the multi-replica fs
	// correlation (PR-C) and read by computeFSConfidence.
	ReplicaWritePathDisagreement []string `json:"replica_write_path_disagreement,omitempty"`
	// ReplicaDeviceDisagreement is the v0.3 device analog: device nodes
	// observed on fewer than all replicas under --all-matching. omitempty +
	// nil on caps/fs runs and single-replica device runs; populated by the
	// multi-replica device correlation (PR5) and read by
	// computeDeviceConfidence.
	ReplicaDeviceDisagreement []string `json:"replica_device_disagreement,omitempty"`
	// ReplicaEgressDisagreement is the v0.8 egress analog: outbound
	// destinations observed on fewer than all replicas under --all-matching.
	// omitempty + nil otherwise; populated by the multi-replica egress
	// correlation and read by computeEgressConfidence.
	ReplicaEgressDisagreement []string `json:"replica_egress_disagreement,omitempty"`
}

// Restart records a single exit-during-observation event. Attribution is
// cgroup-id-keyed (PLAN.md §Target selection), so a new container sharing
// the image ref is a different subject and does not merge here.
type Restart struct {
	AtOffsetMs int64  `json:"at_offset_ms"`
	ExitCode   int    `json:"exit_code"`
	Reason     string `json:"reason"` // "signal" | "oom" | "normal"
}

// Capability is one distinct capability observed during the window. The
// aggregator collapses N raw events per cap into a single entry with
// counts and offsets for reviewer auditability.
type Capability struct {
	Name              string   `json:"name"`
	EventCount        int      `json:"event_count"`
	FirstSeenOffsetMs int64    `json:"first_seen_offset_ms"`
	LastSeenOffsetMs  int64    `json:"last_seen_offset_ms"`
	CommSamples       []string `json:"comm_samples"`
}

// WritablePath is one distinct write-intent path observed by the v0.2 fs
// observer, the read-only-filesystem analog of Capability. The aggregator
// collapses N write opens per path into a single entry with an event count
// and comm samples for reviewer auditability. Disposition records how the
// decision layer classified the path against the container's mounts:
// "volume_covered" (at/below an existing bind/volume mount — left as-is) or
// "tmpfs_candidate" (a rootfs write the recommendation routes to tmpfs).
type WritablePath struct {
	Path        string   `json:"path"`
	EventCount  int      `json:"event_count"`
	Disposition string   `json:"disposition"`
	CommSamples []string `json:"comm_samples,omitempty"`
}

// WritablePath disposition values.
const (
	DispositionVolumeCovered  = "volume_covered"
	DispositionTmpfsCandidate = "tmpfs_candidate"
)

// DevicePath is one distinct non-default device node opened by the v0.3 device
// observer, the privileged-decomposition analog of WritablePath. The aggregator
// collapses N opens of one node into a single entry with an event count and
// comm samples for reviewer auditability. There is no Disposition field: a
// device node is not volume-correlated — it is either granted (in the
// recommendation) or not.
type DevicePath struct {
	Path        string   `json:"path"`
	EventCount  int      `json:"event_count"`
	CommSamples []string `json:"comm_samples,omitempty"`
}

// EgressDestination is one distinct outbound destination contacted by the v0.8
// egress observer, the network analog of DevicePath. The aggregator collapses N
// connect events to one (addr, port) destination into a single entry with an
// event count and comm samples for reviewer auditability. Addr is the resolved
// IP connect() observed — not the hostname the app requested (issue #136).
type EgressDestination struct {
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Version int    `json:"version,omitempty"` // 4 or 6
	// Hostnames are the names that resolved to Addr, from trace_dns response
	// packets (issue #159). Empty when DNS was not observed (TCP-only egress) or
	// the IP was contacted without a preceding observed lookup (a hardcoded IP,
	// a connection reusing a cached resolution, or a lookup that predates the
	// observation window). Sorted, distinct.
	Hostnames   []string `json:"hostnames,omitempty"`
	EventCount  int      `json:"event_count"`
	CommSamples []string `json:"comm_samples,omitempty"`
}

// Egress provenance + visibility tag values (issue #206). Provenance separates a
// destination the container actually dialed from one it merely resolved;
// visibility separates a public endpoint that generalizes across deployments
// from the operator's own topology, which must never reach a public profile.
const (
	// EgressProvenanceConfirmed: an observed connect() reached one of Addrs.
	EgressProvenanceConfirmed = "confirmed"
	// EgressProvenanceResolvedOnly: the name was resolved (trace_dns) but none of
	// its addresses were dialed this run — a coverage candidate, surfaced but
	// never auto-added to the enforced allowlist.
	EgressProvenanceResolvedOnly = "resolved_only"
	// EgressVisibilityImageIntrinsic: a public-routable destination (public FQDN /
	// public IP) that is a property of the image — publishable (names only).
	EgressVisibilityImageIntrinsic = "image_intrinsic"
	// EgressVisibilityDeploymentSpecific: a private/internal destination — the
	// operator's topology; local-only, never published. The conservative default
	// on any ambiguity.
	EgressVisibilityDeploymentSpecific = "deployment_specific"
)

// EgressDestinationIntel is the #206 name-centric, provenance- and
// visibility-tagged view of the observed egress. It is DATA, not enforcement:
// the enforced allowlist stays EgressRecommendation.Allowlist (confirmed
// connects only). This block additionally surfaces names the container RESOLVED
// but did not dial (Provenance == "resolved_only"), so a coverage gap is visible
// without widening the allowlist, and tags each destination's publish Visibility
// so a consumer never leaks the operator's topology into a public profile.
//
// Grouped by the resolved hostname where DNS was observed (folding the many IPs
// a name resolves to into one entry); an IP contacted with no observed lookup is
// one entry with an empty Name. Addrs are a POINT-IN-TIME SNAPSHOT — they rot as
// services move, so a durable name-based policy needs a name-aware enforcer, not
// these IPs frozen.
type EgressDestinationIntel struct {
	Name       string   `json:"name,omitempty"` // resolved hostname; empty for an IP dialed with no observed DNS
	Addrs      []string `json:"addrs"`          // observed/resolved IPs for this destination (snapshot; sorted, distinct)
	Ports      []int    `json:"ports,omitempty"`
	Provenance string   `json:"provenance"` // EgressProvenance*
	Visibility string   `json:"visibility"` // EgressVisibility*
}

// FSRecommendation is the v0.2 read-only-filesystem conclusion: make the
// rootfs read-only and route the observed rootfs writes to tmpfs, leaving
// writes already covered by a bind/volume mount as-is. The fs observer's
// decision layer (internal/observe/fs) derives it; the formatters render it.
type FSRecommendation struct {
	ReadOnly      bool     `json:"read_only"`
	TmpfsPaths    []string `json:"tmpfs_paths"`
	VolumeCovered []string `json:"volume_covered"`
}

// DeviceRecommendation is the v0.3 device conclusion: the minimum set of
// non-default device nodes to grant, plus any capabilities those nodes imply.
type DeviceRecommendation struct {
	Devices     []string `json:"devices"`
	DerivedCaps []string `json:"derived_caps,omitempty"`
}

// EgressDest is one (addr, port) destination in an egress allowlist — the
// minimal triple, distinct from EgressDestination which also carries the
// per-destination evidence. It is the serialized element of an
// EgressRecommendation allowlist.
type EgressDest struct {
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	Version int    `json:"version,omitempty"` // 4 or 6
}

func (d EgressDest) String() string {
	return net.JoinHostPort(d.Addr, strconv.Itoa(d.Port))
}

// EgressRecommendation is the v0.8 conclusion: the minimum outbound allowlist
// the workload exercised, with a non-strippable caveat that a too-tight
// allowlist blocks destinations the workload never contacted.
type EgressRecommendation struct {
	Allowlist []EgressDest `json:"allowlist"`
	// Resolvers are the DNS resolver endpoints (UDP, typically :53) the workload
	// used, from trace_dns (issue #159). They are kept separate from Allowlist
	// because they are a different protocol (UDP vs the TCP connects trace_tcp
	// records) and because a default-DROP allowlist that omits them silently
	// breaks all name resolution — the single most common egress foot-gun. Empty
	// when DNS was not observed. Sorted, distinct.
	Resolvers []EgressDest `json:"dns_resolvers,omitempty"`
	Caveat    string       `json:"caveat"`
}

// CapaddValidation is the v0.5 dangerous-cap_add conclusion: per-cap findings
// (was the granted cap actually exercised, and by which syscalls) plus, when a
// granted set was provided, the minimized cap_add recommendation.
type CapaddValidation struct {
	Findings           []CapaddFinding `json:"findings"`
	GrantedSetProvided bool            `json:"granted_set_provided"`
	RecommendedCapAdd  []string        `json:"recommended_cap_add"`
}

// CapaddFinding is one granted dangerous capability's validation result.
type CapaddFinding struct {
	Cap        string        `json:"cap"`
	Used       bool          `json:"used"`
	Removable  bool          `json:"removable"`
	EventCount int           `json:"event_count"`
	Syscalls   []SyscallStat `json:"syscalls"`
	Advice     string        `json:"advice"`
	FinerCaps  []string      `json:"finer_caps,omitempty"`
}

// SyscallStat is one syscall name and how many times it was observed
// exercising the capability under validation.
type SyscallStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// PrivilegedDecomposition is the v0.3 headline conclusion of the
// --observe privileged composition: `privileged: true` is not required, and the
// minimum non-privileged equivalent is the observed cap set plus the observed
// device nodes. The decomposition is PARTIAL: security_opt (AppArmor/seccomp
// unconfined) is out of scope for v0.3 (no denial gadget at the pinned IG), so
// Partial is always true at v0.3 and SecurityOpt carries
// PrivilegedSecurityOptCaveat — naming the uncovered dimension to any JSON
// consumer, not just the stdout reader. When a denial gadget lands and the MAC
// dimension is observed, Partial flips false and SecurityOpt empties.
type PrivilegedDecomposition struct {
	DropPrivileged bool     `json:"drop_privileged"`
	CapAdd         []string `json:"cap_add"`
	Devices        []string `json:"devices"`
	// Partial: the decomposition recovers caps + devices but not the
	// AppArmor/seccomp (MAC) dimension privileged: true also relaxes.
	Partial bool `json:"partial"`
	// SecurityOpt names the uncovered dimension (PrivilegedSecurityOptCaveat
	// at v0.3); "" once csd observes the MAC dimension.
	SecurityOpt string `json:"security_opt"`
}

// TraceHealth surfaces the IG ringbuf drop counter (PLAN.md §Event-loss
// reporting). Always emitted; never hidden. drop_rate >= 1% downgrades
// confidence; >= 10% aborts emission.
type TraceHealth struct {
	EventsRecorded int     `json:"events_recorded"`
	EventsDropped  int     `json:"events_dropped"`
	DropRate       float64 `json:"drop_rate"`
}

// Confidence is PLAN.md §Confidence scoring's mechanical output. Level is
// reproducible from Factors — reviewers must be able to trace the grade
// back to the evidence.
type Confidence struct {
	Level   string   `json:"level"`
	Factors []string `json:"factors"`
}

// Finalise computes DropRate once both sides of the ratio are known. The
// observers fill EventsRecorded/EventsDropped while streaming and call this
// before scoring confidence.
func (th *TraceHealth) Finalise() {
	if th.EventsRecorded > 0 {
		th.DropRate = float64(th.EventsDropped) / float64(th.EventsRecorded)
	} else if th.EventsDropped > 0 {
		// All-dropped-no-recorded is a pathological case we can still
		// report as "everything lost". Without this branch a 0-record
		// run with losses would look clean.
		th.DropRate = 1.0
	}
}

// CapNames returns the capability names from s.Capabilities in the order
// aggregate() stored them (sorted ascending). Formatters and the v0.1
// stdout path both go through this helper so the one source of truth for
// "the observed cap set" is the Sidecar, not a parallel slice.
func (s *Sidecar) CapNames() []string {
	out := make([]string, 0, len(s.Capabilities))
	for _, c := range s.Capabilities {
		out = append(out, c.Name)
	}
	return out
}

// NewSidecar returns a Sidecar with identity fields locked and every
// collection pre-initialized to empty (not nil). Empty vs null matters
// because downstream parsers (including the compose-lint contribution
// flow) treat `null` arrays as schema drift.
func NewSidecar() *Sidecar {
	return &Sidecar{
		SchemaVersion:              SchemaVersion,
		ToolVersion:                ToolVersion,
		Caveat:                     Caveat,
		Capabilities:               []Capability{},
		ExpectedCapsFromEntrypoint: []string{},
		CoverageWarnings:           []string{},
		Target: Target{
			PerReplicaEventCounts:  map[string]int{},
			PerReplicaCaps:         map[string][]string{},
			ReplicaCapDisagreement: []string{},
			Restarts:               []Restart{},
		},
		Confidence: Confidence{
			Factors: []string{},
		},
	}
}
