// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/resources/nfs"
)

func TestLoadExports_LinuxIncludesExportsDFragments(t *testing.T) {
	fs := afero.NewMemMapFs()
	mustWrite(t, fs, "/etc/exports", "/srv/main host1(rw,no_root_squash)\n")
	mustWrite(t, fs, "/etc/exports.d/zeta.exports", "/srv/zeta host-z(ro)\n")
	mustWrite(t, fs, "/etc/exports.d/alpha.exports", "/srv/alpha host-a(rw)\n")
	// A non-matching file should be ignored — nfs-utils only reads `*.exports`.
	mustWrite(t, fs, "/etc/exports.d/notes.txt", "/srv/decoy world(rw,no_root_squash)\n")

	got, err := loadExports(fs, nfs.PlatformLinux)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []nfs.ExportEntry{
		{Path: "/srv/main", Client: "host1", Options: []string{"rw", "no_root_squash"}, NoRootSquash: true},
		{Path: "/srv/alpha", Client: "host-a", Options: []string{"rw"}},
		{Path: "/srv/zeta", Client: "host-z", Options: []string{"ro"}, ReadOnly: true},
	}
	if len(got) != len(want) {
		t.Fatalf("entry count: got %d, want %d\ngot: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Path != want[i].Path || got[i].Client != want[i].Client {
			t.Errorf("entry %d: got (%q, %q), want (%q, %q)",
				i, got[i].Path, got[i].Client, want[i].Path, want[i].Client)
		}
		if got[i].ReadOnly != want[i].ReadOnly || got[i].NoRootSquash != want[i].NoRootSquash {
			t.Errorf("entry %d: flags mismatch — got ro=%v nrs=%v, want ro=%v nrs=%v",
				i, got[i].ReadOnly, got[i].NoRootSquash, want[i].ReadOnly, want[i].NoRootSquash)
		}
	}
}

func TestLoadExports_OnlyFragmentsPresent(t *testing.T) {
	// Modern container hosts often leave /etc/exports empty (or absent)
	// and put all exports in /etc/exports.d/. The resource must still
	// surface them.
	fs := afero.NewMemMapFs()
	mustWrite(t, fs, "/etc/exports.d/ceph.exports", "/cephfs *(rw,no_root_squash)\n")

	got, err := loadExports(fs, nfs.PlatformLinux)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %#v", len(got), got)
	}
	if got[0].Path != "/cephfs" || got[0].Client != "*" || !got[0].NoRootSquash {
		t.Errorf("unexpected entry: %#v", got[0])
	}
}

func TestLoadExports_MissingFilesReturnEmpty(t *testing.T) {
	fs := afero.NewMemMapFs()
	got, err := loadExports(fs, nfs.PlatformLinux)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result, got %#v", got)
	}
}

func TestLoadExports_NonLinuxSkipsFragments(t *testing.T) {
	// FreeBSD/macOS/AIX don't honour /etc/exports.d/; the fragments
	// there should be ignored even if present.
	fs := afero.NewMemMapFs()
	mustWrite(t, fs, "/etc/exports", "/data -ro host1\n")
	mustWrite(t, fs, "/etc/exports.d/extra.exports", "/decoy -rw host2\n")

	got, err := loadExports(fs, nfs.PlatformFreeBSD)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1 (fragments must be ignored on FreeBSD): %#v", len(got), got)
	}
	if got[0].Path != "/data" || got[0].Client != "host1" {
		t.Errorf("unexpected entry: %#v", got[0])
	}
}

func mustWrite(t *testing.T, fs afero.Fs, path, content string) {
	t.Helper()
	if err := afero.WriteFile(fs, path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// exportfs ignores fragments whose name starts with a dot (exports(5)), such as
// an editor's or a package manager's hidden copy.
func TestLoadExports_SkipsDotfileFragments(t *testing.T) {
	fs := afero.NewMemMapFs()
	mustWrite(t, fs, "/etc/exports.d/main.exports", "/srv/main host1(ro)\n")
	mustWrite(t, fs, "/etc/exports.d/.hidden.exports", "/srv/hidden world(rw,no_root_squash)\n")

	got, err := loadExports(fs, nfs.PlatformLinux)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].Path != "/srv/main" {
		t.Fatalf("got %#v, want only /srv/main", got)
	}
}
