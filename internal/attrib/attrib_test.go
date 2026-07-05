package attrib

import (
	"testing"

	"github.com/tmatens/container-sec-derive/internal/sidecar"
)

func TestMatchesRuntime(t *testing.T) {
	const (
		id    = "abcdef0123456789"
		name  = "web-1"
		image = "postgres:16"
	)
	tests := []struct {
		name                  string
		opts                  Opts
		evID, evName, evImage string
		want                  bool
	}{
		{"no selector matches anything", Opts{}, id, name, image, true},
		{"no selector matches empty event", Opts{}, "", "", "", true},
		{"container exact id", Opts{Container: id}, id, name, image, true},
		{"container exact name", Opts{Container: name}, id, name, image, true},
		{"container id-prefix >=6 matches", Opts{Container: "abcdef"}, id, name, image, true},
		{"container id-prefix >=6 no match", Opts{Container: "ffffff"}, id, name, image, false},
		{"container prefix <6 does not prefix-match", Opts{Container: "abcde"}, id, name, image, false},
		{"container set but nothing matches", Opts{Container: name}, id, "other", image, false},
		{"image exact match", Opts{Image: image}, id, name, image, true},
		{"image no match", Opts{Image: image}, id, name, "redis:7", false},
		{"image set, container empty, no match", Opts{Image: image}, id, name, "redis:7", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.MatchesRuntime(tt.evID, tt.evName, tt.evImage); got != tt.want {
				t.Errorf("MatchesRuntime(%q,%q,%q) = %v, want %v", tt.evID, tt.evName, tt.evImage, got, tt.want)
			}
		})
	}
}

func TestAmbiguous(t *testing.T) {
	tests := []struct {
		name    string
		opts    Opts
		replica int
		want    bool
	}{
		{"single replica never ambiguous", Opts{Image: "x"}, 1, false},
		{"zero replicas never ambiguous", Opts{Image: "x"}, 0, false},
		{"all-matching clears image ambiguity", Opts{Image: "x", AllMatching: true}, 5, false},
		{"image with multiple replicas is ambiguous", Opts{Image: "x"}, 2, true},
		{"container prefix with multiple replicas is ambiguous", Opts{Container: "abcdef"}, 3, true},
		{"no selector is never ambiguous even with many replicas", Opts{}, 5, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.Ambiguous(tt.replica); got != tt.want {
				t.Errorf("Ambiguous(%d) = %v, want %v", tt.replica, got, tt.want)
			}
		})
	}
}

func TestModeLabel(t *testing.T) {
	tests := []struct {
		name string
		opts Opts
		want string
	}{
		{"image + all-matching", Opts{Image: "x", AllMatching: true}, sidecar.TargetModeAllMatching},
		{"image only", Opts{Image: "x"}, sidecar.TargetModeImage},
		{"container", Opts{Container: "c"}, sidecar.TargetModeContainer},
		{"no selector defaults to container", Opts{}, sidecar.TargetModeContainer},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.ModeLabel(); got != tt.want {
				t.Errorf("ModeLabel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelector(t *testing.T) {
	if got := (Opts{Image: "postgres:16"}).Selector(); got != "postgres:16" {
		t.Errorf("image Selector() = %q, want postgres:16", got)
	}
	if got := (Opts{Container: "web-1"}).Selector(); got != "web-1" {
		t.Errorf("container Selector() = %q, want web-1", got)
	}
	// Image wins over Container when both are set (matches ModeLabel/Selector priority).
	if got := (Opts{Image: "postgres:16", Container: "web-1"}).Selector(); got != "postgres:16" {
		t.Errorf("both-set Selector() = %q, want postgres:16", got)
	}
}

func TestNewAmbiguousSelectionError(t *testing.T) {
	labels := []string{"web-1 (abc)", "web-2 (def)"}

	imgErr := (Opts{Image: "postgres:16"}).NewAmbiguousSelectionError(labels)
	if imgErr.Flag() != "--image" {
		t.Errorf("image error Flag() = %q, want --image", imgErr.Flag())
	}
	if !imgErr.AllMatchingHint() {
		t.Error("image error should offer --all-matching as a remedy")
	}
	if len(imgErr.Replicas()) != 2 {
		t.Errorf("Replicas() = %v, want 2 labels", imgErr.Replicas())
	}

	ctrErr := (Opts{Container: "abcdef"}).NewAmbiguousSelectionError(labels)
	if ctrErr.Flag() != "--container" {
		t.Errorf("container error Flag() = %q, want --container", ctrErr.Flag())
	}
	if ctrErr.AllMatchingHint() {
		t.Error("container error must not offer --all-matching (it requires --image)")
	}
}
