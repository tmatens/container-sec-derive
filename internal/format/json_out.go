package format

import (
	"encoding/json"
	"io"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// WriteJSON emits the canonical sidecar as indented JSON. It is the single
// source of truth for the on-the-wire JSON shape -- WriteSidecar (--out)
// goes through the same path so stdout (`--format json`) and the sidecar
// file are byte-identical.
func WriteJSON(w io.Writer, s *sidecar.Sidecar) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
