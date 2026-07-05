package egress

import "strings"

// RFC 1035 / 1123 length limits, reused as the upper bounds for a name accepted
// into a generated artifact.
const (
	maxHostnameLen = 253
	maxLabelLen    = 63
)

// validHostname reports whether name is a syntactically valid DNS hostname that
// is safe to embed verbatim in a generated enforcement artifact (an nftables
// comment or a k8s NetworkPolicy YAML comment). It is the integrity gate for
// issue #202.
//
// The observed container fully controls the DNS query names it emits during the
// observation window, and DNS labels permit arbitrary octets on the wire, so a
// name carrying a newline (or other control byte) could break out of the
// trailing `#` comment and inject an attacker-chosen line into a ruleset the
// operator is expected to apply as root (`nft -f`) — a single injected
// `ip daddr 0.0.0.0/0 accept` would defeat the default-deny allowlist that is
// the entire point of the feature. Rather than trust the pinned ig to escape
// control bytes, csd validates the charset itself and drops anything that is not
// a plain hostname.
//
// Rules: total length 1..253; one or more dot-separated labels; each label
// 1..63 chars drawn from [A-Za-z0-9_-] (uppercase is accepted for
// externally-supplied sidecars — the live path lowercases via normalizeDNSName;
// the leading underscore covers the `_service` labels real resolvers emit). This
// admits no byte — newline, quote, comma, space, `#`, `{` — that could terminate
// or inject into a comment line, which is the whole security property.
func validHostname(name string) bool {
	if len(name) == 0 || len(name) > maxHostnameLen {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > maxLabelLen {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z',
				c >= 'A' && c <= 'Z',
				c >= '0' && c <= '9',
				c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}

// validHostnames returns the subset of names that pass validHostname, preserving
// order. Returns nil (not an empty slice) when none qualify so callers emit no
// comment rather than an empty one.
func validHostnames(names []string) []string {
	var out []string
	for _, n := range names {
		if validHostname(n) {
			out = append(out, n)
		}
	}
	return out
}
