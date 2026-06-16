package main

import (
	"fmt"
	"io"
)

// The v0.5 capadd formatters express a VALIDATION, not a from-scratch config, so
// their shape differs from the cap/device formatters: the per-cap advisory is
// always emitted as `#`-comments (it is reference guidance, workload-bounded),
// and a concrete config block (the recommended minimized cap_add) is emitted only
// when the user supplied the granted set via --cap-add — otherwise there is no
// granted set to rewrite and csd must not invent one.

// capaddDropped returns the caps flagged removable (granted but unused) in finding
// order — the explicit "dropped" list the formatters surface so a reader sees
// what the recommended cap_add left out, rather than inferring it.
func capaddDropped(val *capaddValidation) []string {
	var out []string
	for _, f := range val.Findings {
		if f.Removable && !f.Used {
			out = append(out, f.Cap)
		}
	}
	return out
}

// writeCapaddComment writes the shared `#`-comment preamble: a workload-bounded
// header, one line per finding (CAP: advice), and — when a granted set was given
// — the dropped-cap list. Used by every text formatter so the advisory is
// consistent across compose / docker-run / k8s. commentPrefix lets a caller
// indent the block (e.g. inside an exploratory: profile); pass "" for none.
func writeCapaddComment(w io.Writer, val *capaddValidation, commentPrefix string) error {
	cp := commentPrefix
	if _, err := fmt.Fprintf(w, "%s# csd dangerous cap_add validation (workload-bounded — NOT a correctness proof).\n", cp); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "%s# Verify with a fuller workload before removing or substituting any capability.\n", cp); err != nil {
		return err
	}
	if len(val.Findings) == 0 {
		if _, err := fmt.Fprintf(w, "%s# no dangerous capabilities observed in use under this workload.\n", cp); err != nil {
			return err
		}
		return nil
	}
	for _, f := range val.Findings {
		if _, err := fmt.Fprintf(w, "%s# %s: %s\n", cp, f.Cap, f.Advice); err != nil {
			return err
		}
	}
	if val.GrantedSetProvided {
		if dropped := capaddDropped(val); len(dropped) > 0 {
			if _, err := fmt.Fprintf(w, "%s# dropped (unused under this workload): %s\n", cp, joinComma(dropped)); err != nil {
				return err
			}
		}
	}
	return nil
}

// writeCapaddCompose emits the validation as a compose stanza: the `#`-comment
// advisory, then — only when the granted set was supplied — a `cap_add:` block
// holding the recommended minimized set (finer substitutions applied, unused caps
// dropped). Without a granted set it emits the advisory alone: there is no
// declared cap_add for csd to rewrite, and proposing one would be fabrication.
func writeCapaddCompose(w io.Writer, val *capaddValidation) error {
	if err := writeCapaddComment(w, val, ""); err != nil {
		return err
	}
	if !val.GrantedSetProvided {
		return nil
	}
	if len(val.RecommendedCapAdd) == 0 {
		_, err := fmt.Fprintln(w, "cap_add: []  # all validated caps were unused under this workload — none required")
		return err
	}
	if _, err := fmt.Fprintln(w, "cap_add:"); err != nil {
		return err
	}
	for _, c := range val.RecommendedCapAdd {
		if _, err := fmt.Fprintf(w, "  - %s\n", c); err != nil {
			return err
		}
	}
	return nil
}

// joinComma joins with ", " — a tiny helper so the formatters read cleanly
// without importing strings just for one Join.
func joinComma(s []string) string {
	out := ""
	for i, v := range s {
		if i > 0 {
			out += ", "
		}
		out += v
	}
	return out
}
