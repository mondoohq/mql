// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func vendorSet(names ...string) func(string) bool {
	set := map[string]bool{}
	for _, name := range names {
		set[name] = true
	}
	return func(name string) bool { return set[name] }
}

func TestParseDnfRpmLog(t *testing.T) {
	t.Run("only upgrade lines are evidence", func(t *testing.T) {
		// vim is a vendor rpm and its install is the newest line, but
		// installing a package is not updating the operating system; the
		// upgrade pair from February is the answer.
		log := "2026-01-10T08:00:00+0000 INFO --- logging initialized ---\n" +
			"2026-01-10T08:00:02+0000 SUBDEBUG Installed: kernel-core-5.14.0-503.el9.x86_64\n" +
			"2026-02-14T09:30:12+0000 SUBDEBUG Upgrade: openssl-libs-1:3.2.2-6.el9.x86_64\n" +
			"2026-02-14T09:30:14+0000 SUBDEBUG Upgraded: openssl-libs-1:3.0.7-27.el9.x86_64\n" +
			"2026-03-01T10:00:00+0000 SUBDEBUG Installed: vim-enhanced-2:9.1.083-1.el9.x86_64\n"

		got, err := ParseDnfRpmLog(strings.NewReader(log),
			vendorSet("kernel-core", "openssl-libs", "vim-enhanced"))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "2026-02-14T09:30:14Z", got.Time.Format(time.RFC3339))
		assert.Equal(t, LastUpdateSourceDnfRpmLog, got.Source)
	})

	t.Run("install-only log is no evidence", func(t *testing.T) {
		log := "2026-03-01T10:00:00+0000 SUBDEBUG Installed: vim-enhanced-2:9.1.083-1.el9.x86_64\n"

		got, err := ParseDnfRpmLog(strings.NewReader(log), vendorSet("vim-enhanced"))
		require.NoError(t, err)
		assert.Nil(t, got, "an install is not an update, even of a vendor rpm")
	})

	t.Run("third-party upgrades do not count", func(t *testing.T) {
		// Docker CE moves far more often than a distribution does; counting it
		// would report an unpatched host as patched last week.
		log := "2026-02-14T09:30:14+0000 SUBDEBUG Upgraded: openssl-libs-1:3.0.7-27.el9.x86_64\n" +
			"2026-08-01T12:00:00+0000 SUBDEBUG Upgraded: docker-ce-3:27.1.1-1.el9.x86_64\n"

		got, err := ParseDnfRpmLog(strings.NewReader(log), vendorSet("openssl-libs"))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "2026-02-14T09:30:14Z", got.Time.Format(time.RFC3339))

		got, err = ParseDnfRpmLog(strings.NewReader(log), vendorSet("nothing"))
		require.NoError(t, err)
		assert.Nil(t, got, "an upgrade that cannot be attributed to the vendor is no evidence")
	})

	t.Run("downgrades and reinstalls are not updates", func(t *testing.T) {
		log := "2026-02-14T09:30:14+0000 SUBDEBUG Downgraded: openssl-libs-1:3.2.2-6.el9.x86_64\n" +
			"2026-02-15T09:30:14+0000 SUBDEBUG Downgrade: openssl-libs-1:3.0.7-27.el9.x86_64\n" +
			"2026-02-16T09:30:14+0000 SUBDEBUG Reinstalled: bash-5.1.8-9.el9.x86_64\n" +
			"2026-02-17T09:30:14+0000 SUBDEBUG Erased: telnet-1:0.17-85.el9.x86_64\n" +
			"2026-02-18T09:30:14+0000 SUBDEBUG Cleanup: bash-5.1.8-8.el9.x86_64\n"

		got, err := ParseDnfRpmLog(strings.NewReader(log), vendorSet("openssl-libs", "bash", "telnet"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("timestamps carry their own zone", func(t *testing.T) {
		tests := []struct {
			name string
			line string
			want string
		}{
			{
				name: "utc with Z",
				line: "2026-02-14T09:30:14Z SUBDEBUG Upgraded: bash-5.1.8-9.el9.x86_64\n",
				want: "2026-02-14T09:30:14Z",
			},
			{
				name: "utc with numeric offset",
				line: "2026-02-14T09:30:14+0000 SUBDEBUG Upgraded: bash-5.1.8-9.el9.x86_64\n",
				want: "2026-02-14T09:30:14Z",
			},
			{
				name: "local time with offset",
				line: "2026-02-14T04:30:14-0500 SUBDEBUG Upgraded: bash-5.1.8-9.el9.x86_64\n",
				want: "2026-02-14T09:30:14Z",
			},
			{
				name: "offset with colon",
				line: "2026-02-14T10:30:14+01:00 SUBDEBUG Upgraded: bash-5.1.8-9.el9.x86_64\n",
				want: "2026-02-14T09:30:14Z",
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				got, err := ParseDnfRpmLog(strings.NewReader(test.line), vendorSet("bash"))
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, test.want, got.Time.Format(time.RFC3339))
			})
		}
	})

	t.Run("a timestamp without a zone is skipped", func(t *testing.T) {
		// Ancient dnf wrote local time with no offset. Reading it as UTC would
		// shift the answer by the asset's zone, so the line is not evidence.
		log := "2019-02-14T09:30:14 SUBDEBUG Upgraded: bash-4.4.19-14.el8.x86_64\n"

		got, err := ParseDnfRpmLog(strings.NewReader(log), vendorSet("bash"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("malformed lines are skipped", func(t *testing.T) {
		log := "garbage\n" +
			"2026-02-14T09:30:14+0000\n" +
			"2026-02-14T09:30:14+0000 SUBDEBUG\n" +
			"2026-02-14T09:30:14+0000 SUBDEBUG Upgraded: nonevra\n"

		got, err := ParseDnfRpmLog(strings.NewReader(log), vendorSet("bash"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("empty log", func(t *testing.T) {
		got, err := ParseDnfRpmLog(strings.NewReader(""), vendorSet("bash"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})
}

// A line past the scanner's cap surfaces as an error, never as a silently
// shortened log.
func TestParseDnfRpmLogScannerError(t *testing.T) {
	log := "2026-02-14T09:30:14+0000 SUBDEBUG Upgraded: bash-5.1.8-9.el9.x86_64\n" +
		strings.Repeat("a", 128*1024) + "\n"

	got, err := ParseDnfRpmLog(strings.NewReader(log), vendorSet("bash"))
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestRpmNevraName(t *testing.T) {
	tests := []struct {
		nevra string
		want  string
	}{
		{"openssl-libs-1:3.0.7-27.el9.x86_64", "openssl-libs"},
		{"kernel-5.14.0-503.el9.x86_64", "kernel"},
		{"glibc-2.34-100.el9_4.2.x86_64", "glibc"},
		{"NetworkManager-1:1.46.0-2.el9.x86_64", "NetworkManager"},
		{"bash-5.1.8-9.el9.noarch", "bash"},
		{"noversion", ""},
		{"one-hyphen", ""},
		{"", ""},
	}
	for _, test := range tests {
		t.Run(test.nevra, func(t *testing.T) {
			assert.Equal(t, test.want, rpmNevraName(test.nevra))
		})
	}
}

func TestDnfRpmLogPresent(t *testing.T) {
	fs := afero.NewMemMapFs()
	assert.False(t, DnfRpmLogPresent(fs))

	require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath+".2.gz", []byte{}, 0o644))
	assert.True(t, DnfRpmLogPresent(fs), "a rotated copy alone counts as present")

	fs = afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath, []byte{}, 0o644))
	assert.True(t, DnfRpmLogPresent(fs))
}

func TestLastInstalledRpm(t *testing.T) {
	upgraded := "2026-02-14T09:30:14+0000 SUBDEBUG Upgraded: openssl-libs-1:3.0.7-27.el9.x86_64\n"

	t.Run("the live log answers", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath, []byte(upgraded), 0o644))

		got, err := LastInstalledRpm(fs, vendorSet("openssl-libs"))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "2026-02-14T09:30:14Z", got.Time.Format(time.RFC3339))
		assert.Equal(t, LastUpdateSourceDnfRpmLog, got.Source)
	})

	t.Run("no transaction log means no evidence", func(t *testing.T) {
		// The rpm database still lists every package with an install time, but
		// without the log there is nothing that distinguishes an update from
		// an install, and inferring one is exactly what this field refuses.
		got, err := LastInstalledRpm(afero.NewMemMapFs(), vendorSet("openssl-libs"))
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("nil vendor attribution means no evidence", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath, []byte(upgraded), 0o644))

		got, err := LastInstalledRpm(fs, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("a rotation answers when the live log holds no upgrade", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		installOnly := "2026-03-01T10:00:00+0000 SUBDEBUG Installed: vim-enhanced-2:9.1.083-1.el9.x86_64\n"
		require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath, []byte(installOnly), 0o644))
		require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath+".1", []byte(upgraded), 0o644))

		got, err := LastInstalledRpm(fs, vendorSet("openssl-libs", "vim-enhanced"))
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, "2026-02-14T09:30:14Z", got.Time.Format(time.RFC3339))
	})

	t.Run("a corrupt newest rotation reads null", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath+".1.gz", []byte("not gzip"), 0o644))
		require.NoError(t, afero.WriteFile(fs, dnfRpmLogPath+".2", []byte(upgraded), 0o644))

		got, err := LastInstalledRpm(fs, vendorSet("openssl-libs"))
		require.NoError(t, err)
		assert.Nil(t, got, "a corrupt newest rotation must not surface an older answer")
	})
}
