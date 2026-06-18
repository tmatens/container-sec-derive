package format

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

// The v0.5 capadd docker-run / k8s / oci formatters carry the same validation as
// WriteCapaddCompose into the other target syntaxes. All three lead with the
// shared `#`-comment advisory; the concrete config (recommended minimized cap_add
// / capabilities.add) is emitted only when --cap-add supplied the granted set.

// WriteCapaddDockerRun emits the advisory as `#`-comments, then — when the
// granted set was given — a `--cap-add` flag string realizing the recommended
// minimized set. An empty recommendation (all caps unused) yields a comment
// rather than an empty flag string.
func WriteCapaddDockerRun(w io.Writer, val *sidecar.CapaddValidation) error {
	if err := WriteCapaddComment(w, val, ""); err != nil {
		return err
	}
	if !val.GrantedSetProvided {
		return nil
	}
	if len(val.RecommendedCapAdd) == 0 {
		_, err := fmt.Fprintln(w, "# no --cap-add required: all validated caps were unused under this workload")
		return err
	}
	parts := make([]string, 0, len(val.RecommendedCapAdd))
	for _, c := range val.RecommendedCapAdd {
		parts = append(parts, "--cap-add "+c)
	}
	_, err := fmt.Fprintln(w, strings.Join(parts, " "))
	return err
}

// WriteCapaddK8s emits the advisory as `#`-comments, then — when the granted set
// was given — a securityContext.capabilities block with the recommended add list
// (drop: [ALL] + add: [...] is the k8s idiom the cap formatter uses, so a reviewer
// gets a complete, self-contained context rather than a bare add list). Without a
// granted set it emits the advisory alone.
func WriteCapaddK8s(w io.Writer, val *sidecar.CapaddValidation) error {
	if err := WriteCapaddComment(w, val, ""); err != nil {
		return err
	}
	if !val.GrantedSetProvided {
		return nil
	}
	if _, err := fmt.Fprintln(w, "securityContext:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "  capabilities:"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "    drop: [ALL]"); err != nil {
		return err
	}
	if len(val.RecommendedCapAdd) == 0 {
		_, err := fmt.Fprintln(w, "    add: []")
		return err
	}
	_, err := fmt.Fprintf(w, "    add: [%s]\n", strings.Join(val.RecommendedCapAdd, ", "))
	return err
}

// WriteCapaddOCI emits an OCI runtime-spec snippet for the validation. Like the
// device OCI formatter, the validation is advisory and an OCI process.capabilities
// rewrite needs the full effective/permitted/bounding/inheritable sets (which the
// validator does not own), so the conclusion is carried in the spec's free-form
// `annotations` map: a per-cap verdict summary plus, when a granted set was given,
// the recommended add list. Inert to runtimes that ignore annotations,
// informative to humans and tooling that read them.
func WriteCapaddOCI(w io.Writer, val *sidecar.CapaddValidation) error {
	annotations := map[string]string{
		"org.containersecderive.capadd-note": "workload-bounded dangerous-cap_add validation; not a correctness proof. Verify before removing or substituting any capability.",
	}
	if len(val.Findings) == 0 {
		annotations["org.containersecderive.capadd-validation"] = "no dangerous capabilities observed in use under this workload"
	} else {
		summaries := make([]string, 0, len(val.Findings))
		for _, f := range val.Findings {
			summaries = append(summaries, f.Cap+": "+f.Advice)
		}
		annotations["org.containersecderive.capadd-validation"] = strings.Join(summaries, " | ")
	}
	if val.GrantedSetProvided {
		annotations["org.containersecderive.recommended-cap-add"] = strings.Join(val.RecommendedCapAdd, ",")
	}
	snippet := struct {
		Annotations map[string]string `json:"annotations"`
	}{Annotations: annotations}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Advice strings carry `>=` and `/`; config.json is not HTML, so disable
	// HTML escaping to keep the operator-facing note readable.
	enc.SetEscapeHTML(false)
	return enc.Encode(snippet)
}
