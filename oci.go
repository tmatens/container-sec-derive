package main

import (
	"encoding/json"
	"io"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// writeOCI emits an OCI runtime spec snippet ({"process":{"capabilities":
// {...}}}) derived from s.CapNames(). Users paste the output into an OCI
// bundle's config.json, or pipe it through a merge tool (jq, umoci, etc.)
// against an existing config. CAP_-prefixed names match the OCI runtime
// spec's config.md -- they are NOT the bare form used by compose /
// docker-run / k8s.
//
// Five sets are emitted: bounding, effective, permitted populated from
// the observed cap set; inheritable and ambient as explicit empty arrays.
// The explicit-empty choice matters for the merge-tool case: an existing
// config.json may already carry non-empty inheritable/ambient values from
// a template, and omitting those keys here would leave them in place.
// Emitting [] overwrites to empty, which is the "no caps leak to child
// processes" posture minimum-privilege derivation is expressing.
func writeOCI(w io.Writer, s *sidecar.Sidecar) error {
	caps := s.CapNames()
	prefixed := make([]string, len(caps))
	for i, c := range caps {
		prefixed[i] = "CAP_" + c
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
	}{}
	snippet.Process.Capabilities.Bounding = prefixed
	snippet.Process.Capabilities.Effective = prefixed
	snippet.Process.Capabilities.Permitted = prefixed
	snippet.Process.Capabilities.Inheritable = []string{}
	snippet.Process.Capabilities.Ambient = []string{}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(snippet)
}
