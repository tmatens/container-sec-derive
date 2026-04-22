package main

import (
	"encoding/json"
	"io"
)

// writeJSON emits the canonical sidecar as indented JSON. It is the single
// source of truth for the on-the-wire JSON shape -- writeSidecar (--out)
// goes through the same path so stdout (`--format json`) and the sidecar
// file are byte-identical.
func writeJSON(w io.Writer, s *Sidecar) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
