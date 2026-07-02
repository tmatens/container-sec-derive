// Copyright 2026 The container-sec-derive authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package advice

import (
	"strings"
	"testing"
)

func TestTmpfsDirs(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{"empty", nil, []string{}},
		{
			"files reduce to parent dirs, deduped + sorted",
			[]string{
				"/var/run/postgresql/.s.PGSQL.5432.lock",
				"/var/run/postgresql/.s.PGSQL.5432",
				"/var/log/postgresql/postgresql.log",
			},
			[]string{"/var/log/postgresql", "/var/run/postgresql"},
		},
		{"relative and empty paths ignored", []string{"", "relative/x", "/tmp/a"}, []string{"/tmp"}},
		{"trailing-slash normalized", []string{"/data/foo/"}, []string{"/data"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TmpfsDirs(tc.paths)
			if !equal(got, tc.want) {
				t.Errorf("TmpfsDirs(%v) = %v, want %v", tc.paths, got, tc.want)
			}
			if !isSorted(got) {
				t.Errorf("result not sorted: %v", got)
			}
		})
	}
}

func TestRenderAlwaysReadOnly(t *testing.T) {
	for _, paths := range [][]string{nil, {"/tmp/x"}, {"/a/b", "/c/d"}} {
		out := Render("c", paths)
		if !strings.Contains(out, "read_only: true") {
			t.Errorf("Render(%v) missing read_only: true:\n%s", paths, out)
		}
	}
}

func TestRenderNoWritesHasNoTmpfs(t *testing.T) {
	out := Render("app", nil)
	if strings.Contains(out, "tmpfs:") {
		t.Errorf("no writes should not emit tmpfs:\n%s", out)
	}
	if !strings.Contains(out, "needs no tmpfs") {
		t.Errorf("no writes should note no tmpfs required:\n%s", out)
	}
}

func TestRenderTmpfsBlock(t *testing.T) {
	out := Render("my-app", []string{"/var/run/x/f", "/var/run/x/g", "/tmp/h"})
	if !strings.HasPrefix(out, "# my-app\n") {
		t.Errorf("expected container comment header:\n%s", out)
	}
	// dirs deduped (/var/run/x once) and sorted before /var/run/x? /tmp < /var
	want := "tmpfs:\n  - /tmp\n  - /var/run/x\n"
	if !strings.Contains(out, want) {
		t.Errorf("expected sorted deduped tmpfs block %q in:\n%s", want, out)
	}
	// The review caveat must be present so users don't tmpfs a path that should
	// be a persistent volume.
	if !strings.Contains(out, "move any that must persist to a named volume") {
		t.Errorf("expected volume caveat in:\n%s", out)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isSorted(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}
