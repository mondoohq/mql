// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// apk_alpine324.log is /var/log/apk.log from an Alpine 3.24.2 EC2 instance
// (apk-tools 3.0.8): the image bootstrap, six `apk update` runs, three `apk
// add` runs (one of which downgrades tree through a virtual package), an `apk
// del`, and finally `apk upgrade tree`.
func TestParseApkLogAlpine324(t *testing.T) {
	raw, err := os.ReadFile("./testdata/apk_alpine324.log")
	require.NoError(t, err)

	t.Run("the upgrade run answers, timestamped by its Running line", func(t *testing.T) {
		got, stop, err := ParseApkLog(strings.NewReader(string(raw)))
		require.NoError(t, err)
		assert.False(t, stop)
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2026, 9, 28, 6, 0, 0, 0, time.UTC), got.Time)
		assert.Equal(t, LastUpdateSourceApkLog, got.Source)
	})

	// The same log cut just before `apk upgrade tree`. What is left is the
	// bootstrap, index refreshes and operator installs, none of which is an
	// update, even though every one of them moved /lib/apk/db/installed.
	t.Run("installs and index refreshes do not count", func(t *testing.T) {
		idx := strings.Index(string(raw), "\nRunning `apk upgrade tree`")
		require.Positive(t, idx)

		got, stop, err := ParseApkLog(strings.NewReader(string(raw[:idx])))
		require.NoError(t, err)
		assert.False(t, stop)
		assert.Nil(t, got)
	})
}

// apk_alpine321_bootstrap.log is /var/log/apk.log from an Alpine 3.21.8 EC2
// instance. Its apk-tools 2.14 writes no log, so the file holds only what the
// apk-tools 3 that built the image wrote: two `apk --root /mnt add` runs.
func TestParseApkLogBootstrapOnly(t *testing.T) {
	f, err := os.Open("./testdata/apk_alpine321_bootstrap.log")
	require.NoError(t, err)
	defer f.Close()

	got, stop, err := ParseApkLog(f)
	require.NoError(t, err)
	assert.False(t, stop)
	assert.Nil(t, got)
}

func TestParseApkLogCases(t *testing.T) {
	const upgrade = "\nRunning `apk upgrade` at 2026-09-01 10:00:00\n" +
		"apk-tools 3.0.8-r0, compiled for x86_64.\n" +
		"(1/1) Upgrading openssl (3.5.1-r0 -> 3.5.2-r0)\n" +
		"OK: 129.7 MiB in 208 packages\n"

	tests := []struct {
		name     string
		log      string
		want     string
		wantStop bool
	}{
		{
			name: "completed upgrade",
			log:  upgrade,
			want: "2026-09-01T10:00:00Z",
		},
		{
			name: "global options ahead of the applet",
			log: "\nRunning `/sbin/apk --root / -U --no-cache upgrade --available` at 2026-09-02 11:00:00\n" +
				"(1/2) Upgrading musl (1.2.5-r10 -> 1.2.5-r11)\n" +
				"(2/2) Upgrading busybox (1.37.0-r30 -> 1.37.0-r31)\n" +
				"OK: 129.7 MiB in 208 packages\n",
			want: "2026-09-02T11:00:00Z",
		},
		{
			name: "the newest upgrade wins",
			log: upgrade +
				"\nRunning `apk upgrade` at 2026-09-05 08:30:00\n" +
				"(1/1) Upgrading curl (8.14.1-r1 -> 8.14.1-r2)\n" +
				"OK: 129.7 MiB in 208 packages\n",
			want: "2026-09-05T08:30:00Z",
		},
		{
			// apk add can pull a dependency forward, and prints Upgrading for
			// it, but the run was the operator installing a package.
			name: "an add that upgrades a dependency does not count",
			log: "\nRunning `apk add -u curl` at 2026-09-03 09:00:00\n" +
				"(1/2) Upgrading libcurl (8.14.1-r1 -> 8.14.1-r2)\n" +
				"(2/2) Installing curl (8.14.1-r2)\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "an add after an upgrade leaves the upgrade answering",
			log: upgrade +
				"\nRunning `apk add jq` at 2026-09-03 09:00:00\n" +
				"(1/1) Installing jq (1.8.2-r0)\n" +
				"OK: 129.7 MiB in 208 packages\n",
			want: "2026-09-01T10:00:00Z",
		},
		{
			name: "an upgrade with nothing to upgrade is not an install event",
			log: "\nRunning `apk upgrade` at 2026-09-03 09:00:00\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "an upgrade that only downgrades or replaces does not count",
			log: "\nRunning `apk upgrade --available` at 2026-09-03 09:00:00\n" +
				"(1/2) Downgrading tree (2.3.2-r0 -> 2.2.1-r0)\n" +
				"(2/2) Replacing jq (1.8.2-r0)\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "an upgrade of apk-tools alone is not a system upgrade",
			log: "\nRunning `apk upgrade --self-upgrade-only` at 2026-09-03 09:00:00\n" +
				"(1/1) Upgrading apk-tools (3.0.7-r0 -> 3.0.8-r0)\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "an upgrade that reports errors does not count",
			log: upgrade +
				"\nRunning `apk upgrade` at 2026-09-04 09:00:00\n" +
				"(1/1) Upgrading linux-virt (6.12.110-r0 -> 6.12.111-r0)\n" +
				"ERROR: linux-virt-6.12.111-r0: failed to extract\n" +
				"1 error; 129.7 MiB in 208 packages\n",
			want: "2026-09-01T10:00:00Z",
		},
		{
			// A killed run, or one still in progress, is the newest evidence
			// and it is unusable, so the older upgrade must not answer for it.
			name: "an upgrade with no summary voids the answer",
			log: upgrade +
				"\nRunning `apk upgrade` at 2026-09-04 09:00:00\n" +
				"(1/2) Upgrading musl (1.2.5-r10 -> 1.2.5-r11)\n",
			wantStop: true,
		},
		{
			name: "a completed upgrade after an incomplete one answers",
			log: "\nRunning `apk upgrade` at 2026-08-30 09:00:00\n" +
				"(1/2) Upgrading musl (1.2.5-r10 -> 1.2.5-r11)\n" +
				upgrade,
			want: "2026-09-01T10:00:00Z",
		},
		{
			// `apk -U upgrade` can print an OK line for the index refresh
			// before it changes anything; only the summary after the changes
			// is evidence the transaction completed.
			name: "a summary ahead of the changes is not the transaction's",
			log: "\nRunning `apk -U upgrade` at 2026-09-04 09:00:00\n" +
				"OK: 28654 distinct packages available\n" +
				"(1/1) Upgrading musl (1.2.5-r10 -> 1.2.5-r11)\n",
			wantStop: true,
		},
		{
			name: "a package named after the applet is still an install",
			log: "\nRunning `apk add upgrade-helper upgrade` at 2026-09-03 09:00:00\n" +
				"(1/1) Upgrading upgrade (1.0-r0 -> 1.1-r0)\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "an unreadable timestamp cannot be evidence",
			log: "\nRunning `apk upgrade` at yesterday\n" +
				"(1/1) Upgrading openssl (3.5.1-r0 -> 3.5.2-r0)\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "an unreadable Running line still closes the block before it",
			log: "\nRunning `apk upgrade` at 2026-09-01 10:00:00\n" +
				"OK: 129.7 MiB in 208 packages\n" +
				"\nRunning `apk upgrade` at 2026-13-45 99:99:99\n" +
				"(1/1) Upgrading openssl (3.5.1-r0 -> 3.5.2-r0)\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "lines ahead of the first Running line are ignored",
			log: "(1/1) Upgrading openssl (3.5.1-r0 -> 3.5.2-r0)\n" +
				"OK: 129.7 MiB in 208 packages\n",
		},
		{
			name: "empty log",
			log:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, stop, err := ParseApkLog(strings.NewReader(tc.log))
			require.NoError(t, err)
			assert.Equal(t, tc.wantStop, stop)
			if tc.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.Time.Format(time.RFC3339))
			assert.Equal(t, LastUpdateSourceApkLog, got.Source)
		})
	}
}

func TestClassifyApkCommandline(t *testing.T) {
	tests := map[string]bool{
		"apk upgrade":                         true,
		"/sbin/apk upgrade":                   true,
		"apk upgrade tree":                    true,
		"apk -U upgrade":                      true,
		"apk --root /mnt upgrade --available": true,
		"apk add jq":                          false,
		"apk add --upgrade curl":              false,
		"apk del tree":                        false,
		"apk fix openssl":                     false,
		"apk update":                          false,
		"apk upgrade --self-upgrade-only":     false,
		"apk upgrade --preupgrade-only":       false,
		"apk":                                 false,
		"":                                    false,
		// Only the argument vector after the program counts: a binary that
		// happens to be named upgrade is not the applet.
		"upgrade": false,
	}
	for cmdline, want := range tests {
		assert.Equal(t, want, classifyApkCommandline(cmdline), cmdline)
	}
}

// The installed database is not a fallback. Its mtime moves on `apk add jq`
// exactly as it does on an upgrade, so a host without an apk log reads null.
func TestLastInstalledApkRequiresLog(t *testing.T) {
	t.Run("installed db mtime is not a fallback", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		mtime := time.Date(2026, 9, 19, 0, 5, 47, 0, time.UTC)
		for _, p := range []string{"/lib/apk/db/installed", "/etc/apk/world"} {
			require.NoError(t, afero.WriteFile(fs, p, []byte("P:jq\n"), 0o644))
			require.NoError(t, fs.Chtimes(p, mtime, mtime))
		}

		got, err := lastInstalledApkFS(fs)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("an older rotation answers when the current log holds no upgrade", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, apkLogPath, []byte(
			"\nRunning `apk add jq` at 2026-09-10 09:00:00\n"+
				"(1/1) Installing jq (1.8.2-r0)\n"+
				"OK: 129.7 MiB in 208 packages\n"), 0o644))
		require.NoError(t, afero.WriteFile(fs, apkLogPath+".1", []byte(
			"\nRunning `apk upgrade` at 2026-09-01 10:00:00\n"+
				"(1/1) Upgrading openssl (3.5.1-r0 -> 3.5.2-r0)\n"+
				"OK: 129.7 MiB in 208 packages\n"), 0o644))

		got, err := lastInstalledApkFS(fs)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "2026-09-01T10:00:00Z", got.Time.Format(time.RFC3339))
	})
}

// Alpine is dispatched to the apk log. Before it was, every Alpine asset read
// null regardless of what the log held.
func TestResolveLastInstalledUpdateAlpine(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "alpine", Family: []string{"linux", "unix", "os"}},
	}, mock.WithData(&mock.TomlData{
		Files: map[string]*mock.MockFileData{
			apkLogPath: {
				Content: "\nRunning `apk upgrade` at 2026-09-01 10:00:00\n" +
					"(1/1) Upgrading openssl (3.5.1-r0 -> 3.5.2-r0)\n" +
					"OK: 129.7 MiB in 208 packages\n",
			},
		},
	}))
	require.NoError(t, err)

	got, err := ResolveLastInstalledUpdate(conn)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, LastUpdateSourceApkLog, got.Source)
	assert.Equal(t, "2026-09-01T10:00:00Z", got.Time.Format(time.RFC3339))
}
