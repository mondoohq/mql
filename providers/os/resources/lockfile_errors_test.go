// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// unreadableFs refuses to open the files in files, the way a mode 0600 file
// owned by root refuses a scan that is not root, and refuses to stat or open
// anything below the directories in dirs, the way a mode 0700 directory does.
type unreadableFs struct {
	afero.Fs
	files []string
	dirs  []string
}

func (f *unreadableFs) refused(name string, open bool) bool {
	for _, d := range f.dirs {
		if strings.HasPrefix(name, d+"/") {
			return true
		}
	}
	return open && slices.Contains(f.files, name)
}

func (f *unreadableFs) Open(name string) (afero.File, error) {
	if f.refused(name, true) {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	return f.Fs.Open(name)
}

func (f *unreadableFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if f.refused(name, true) {
		return nil, &os.PathError{Op: "open", Path: name, Err: syscall.EACCES}
	}
	return f.Fs.OpenFile(name, flag, perm)
}

func (f *unreadableFs) Stat(name string) (os.FileInfo, error) {
	if f.refused(name, false) {
		return nil, &os.PathError{Op: "stat", Path: name, Err: syscall.EACCES}
	}
	return f.Fs.Stat(name)
}

// lockfileCollector is one ecosystem's collector for an explicit path:
// lockfile is the file it reads in a project directory, corrupt is a
// truncated copy of it, as used in the sweep that found the bug.
type lockfileCollector struct {
	name     string
	lockfile string
	corrupt  string
	collect  func(afs *afero.Afero, path string) error
}

func lockfileCollectors() []lockfileCollector {
	return []lockfileCollector{
		// a GEM section with a line Bundler does not recognize is one Bundler
		// skips as well, so only the garbage case below applies
		{"ruby", "Gemfile.lock", "", func(afs *afero.Afero, p string) error {
			_, _, _, _, err := collectRubyPackages(afs, afs.Fs, p)
			return err
		}},
		{"rust", "Cargo.lock", "[[package]\nname = \"serde\n", func(afs *afero.Afero, p string) error {
			_, _, _, _, err := collectRustPackages(afs, p)
			return err
		}},
		{"php", "composer.lock", `{"packages": [ {"name": `, func(afs *afero.Afero, p string) error {
			_, _, _, _, err := collectPhpPackages(afs, p)
			return err
		}},
		{"dart", "pubspec.lock", "packages:\n  intl: [unclosed\n", func(afs *afero.Afero, p string) error {
			_, _, _, _, err := collectDartPackages(afs, afs.Fs, p)
			return err
		}},
		{"go", "go.mod", "module x\nrequire (\n  github.com/a/b v1.0.0\n", func(afs *afero.Afero, p string) error {
			_, _, err := collectGoPackages(afs, p)
			return err
		}},
		{"terraform", ".terraform.lock.hcl", "provider \"x\" {\n version = \n", func(afs *afero.Afero, p string) error {
			_, _, err := collectTerraformPackages(afs, p)
			return err
		}},
		{"java", "pom.xml", "<project><dependencies><dependency>", func(afs *afero.Afero, p string) error {
			_, _, _, _, err := collectJavaPackages(afs, p)
			return err
		}},
		{"dotnet", "packages.lock.json", `{ "version": 1, "dependencies": `, func(afs *afero.Afero, p string) error {
			_, _, _, _, err := collectDotnetPackages(afs, p)
			return err
		}},
		{"elixir", "mix.lock", `%{"jason": {:hex, `, func(afs *afero.Afero, p string) error {
			_, _, err := collectElixirPackages(afs, afs.Fs, p)
			return err
		}},
		{"erlang", "rebar.lock", `{"1.2.0",[{<<"x">>,{pkg`, func(afs *afero.Afero, p string) error {
			_, _, err := collectErlangPackages(afs, afs.Fs, p)
			return err
		}},
		{"haskell", "stack.yaml.lock", "packages:\n- completed: [\n", func(afs *afero.Afero, p string) error {
			_, _, err := collectHaskellPackages(afs, afs.Fs, p)
			return err
		}},
		{"julia", "Manifest.toml", "[[deps.JSON]\nversion = \n", func(afs *afero.Afero, p string) error {
			_, _, err := collectJuliaPackages(afs, afs.Fs, p)
			return err
		}},
		{"r", "renv.lock", `{"Packages": {`, func(afs *afero.Afero, p string) error {
			_, _, err := collectRPackages(afs, afs.Fs, p)
			return err
		}},
		{"swift", "Package.resolved", `{"pins": [`, func(afs *afero.Afero, p string) error {
			_, _, err := collectSwiftPackages(afs, p)
			return err
		}},
		{"vcpkg", "vcpkg.json", `{"dependencies": [`, func(afs *afero.Afero, p string) error {
			_, _, err := collectVcpkgPackages(afs, p)
			return err
		}},
		{"haskell-cabal", "cabal.project.freeze", "", func(afs *afero.Afero, p string) error {
			_, _, err := collectHaskellPackages(afs, afs.Fs, p)
			return err
		}},
		{"githubactions", "wf.yml", "jobs: [ {\n  x: : :\n", func(afs *afero.Afero, p string) error {
			_, _, err := collectGithubActionsPackages(afs, afs.Fs, p)
			return err
		}},
		{"opam", "dune.opam", "", func(afs *afero.Afero, p string) error {
			_, _, err := collectOpamPackages(afs, p)
			return err
		}},
	}
}

// A lockfile the scan may not read made every one of these report no
// packages, so ruby.packages(path: ...).list.none(name == "nokogiri") passed
// for a scan that is not root on a project that pins a vulnerable nokogiri.
// Fails if a collector logs and drops the open error again.
func TestLockfileCollectorsReportUnreadableLockfile(t *testing.T) {
	withStructuredErrors(t, true)
	for _, c := range lockfileCollectors() {
		t.Run(c.name, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			lock := filepath.Join("/srv/app", c.lockfile)
			require.NoError(t, afero.WriteFile(mem, lock, []byte("x"), 0o600))
			afs := &afero.Afero{Fs: &unreadableFs{Fs: mem, files: []string{lock}}}

			for _, p := range []string{"/srv/app", lock} {
				err := explicitLockfileError(c.collect(afs, p))
				require.Error(t, err, p)
				assert.ErrorIs(t, err, llx.ErrForbidden, p)
				assert.Contains(t, err.Error(), lock)
			}
		})
	}
}

// A project directory the scan may not enter (mode 0700) is a refusal too,
// not a directory without a lockfile.
func TestLockfileCollectorsReportUnenterableDirectory(t *testing.T) {
	withStructuredErrors(t, true)
	for _, c := range lockfileCollectors() {
		t.Run(c.name, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(mem, filepath.Join("/srv/app", c.lockfile), []byte("x"), 0o600))
			afs := &afero.Afero{Fs: &unreadableFs{Fs: mem, dirs: []string{"/srv/app"}}}

			err := explicitLockfileError(c.collect(afs, "/srv/app"))
			assert.ErrorIs(t, err, llx.ErrForbidden)
		})
	}
}

// A truncated lockfile is not a project without dependencies. Fails if a
// collector drops the parse error, or if one of the line-based parsers goes
// back to returning what it read before the file broke off (go and terraform
// reported one package, elixir and erlang none).
func TestLockfileCollectorsReportCorruptLockfile(t *testing.T) {
	// a parse failure was never a legitimate empty list, flag or not
	withStructuredErrors(t, false)
	for _, c := range lockfileCollectors() {
		if c.corrupt == "" {
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			lock := filepath.Join("/srv/bad", c.lockfile)
			require.NoError(t, afero.WriteFile(mem, lock, []byte(c.corrupt), 0o644))
			afs := &afero.Afero{Fs: mem}

			err := explicitLockfileError(c.collect(afs, "/srv/bad"))
			require.Error(t, err)
			assert.ErrorIs(t, err, llx.ErrMalformedData)
			assert.Contains(t, err.Error(), lock)
		})
	}
}

// The same for a file of garbage, as the RHEL sweep used: the line-based
// parsers (go.mod, Gemfile.lock, cabal.project.freeze, mix.lock, the
// terraform lock file) found nothing they knew in it and reported no
// packages. Fails if one of them goes back to accepting text it does not
// recognize.
func TestLockfileCollectorsReportGarbageLockfile(t *testing.T) {
	withStructuredErrors(t, false)
	for _, c := range lockfileCollectors() {
		if c.name == "opam" || c.name == "java" {
			// opam is a field grammar of its own; java's lockfile is a pom
			continue
		}
		t.Run(c.name, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			lock := filepath.Join("/srv/bad", c.lockfile)
			require.NoError(t, afero.WriteFile(mem, lock, []byte("this is { not a [ valid lockfile\n\x00\x01"), 0o644))
			afs := &afero.Afero{Fs: mem}

			err := explicitLockfileError(c.collect(afs, lock))
			assert.ErrorIs(t, err, llx.ErrMalformedData)
		})
	}
}

// A path that does not exist, or a directory without a lockfile, has no
// packages and is not an error.
func TestLockfileCollectorsMissingIsEmpty(t *testing.T) {
	withStructuredErrors(t, true)
	for _, c := range lockfileCollectors() {
		t.Run(c.name, func(t *testing.T) {
			mem := afero.NewMemMapFs()
			require.NoError(t, mem.MkdirAll("/srv/empty", 0o755))
			afs := &afero.Afero{Fs: mem}
			assert.NoError(t, explicitLockfileError(c.collect(afs, "/srv/missing")))
			assert.NoError(t, explicitLockfileError(c.collect(afs, "/srv/empty")))
		})
	}
}

// Without structured errors a refused lockfile keeps reporting no packages,
// as it did in v13 (ADR 046 §9); a corrupt one is an error either way.
func TestExplicitLockfileErrorFlag(t *testing.T) {
	refused := llx.Forbidden(&os.PathError{Op: "open", Path: "/a", Err: syscall.EACCES})
	corrupt := llx.MalformedData(errors.New("cannot parse /b"))
	missing := &os.PathError{Op: "stat", Path: "/c", Err: syscall.ENOENT}

	withStructuredErrors(t, false)
	assert.NoError(t, explicitLockfileError(refused))
	assert.NoError(t, explicitLockfileError(missing))
	assert.Equal(t, corrupt, explicitLockfileError(errors.Join(refused, corrupt)))

	withStructuredErrors(t, true)
	assert.Equal(t, refused, explicitLockfileError(errors.Join(missing, refused, corrupt)))
	assert.NoError(t, explicitLockfileError(missing))
	assert.NoError(t, explicitLockfileError(nil))
}
