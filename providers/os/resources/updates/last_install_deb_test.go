// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAptHistory(t *testing.T) {
	f, err := os.Open("./testdata/apt_history.log")
	require.NoError(t, err)
	defer f.Close()

	got, stop, err := ParseAptHistory(f, time.UTC)
	require.NoError(t, err)
	assert.False(t, stop)
	require.NotNil(t, got)

	// 05-01 was an operator installing a package, 05-09 only removed one,
	// 05-11 failed, and the killed install at the tail never completed, so the
	// unattended upgrade on 05-04 is the newest run that actually patched the
	// operating system. Its End-Date is the answer: that is when the packages
	// were in place, and the line apt writes last.
	assert.Equal(t, time.Date(2026, 5, 4, 3, 22, 9, 0, time.UTC), got.Time)
	assert.Equal(t, LastUpdateSourceAptSecurity, got.Source)
}

func TestParseAptHistoryCases(t *testing.T) {
	tests := []struct {
		name     string
		log      string
		want     string
		source   string
		wantStop bool
	}{
		{
			name: "completed unattended upgrade returns its End-Date",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.5)\n" +
				"End-Date: 2026-05-04  03:22:09\n",
			want:   "2026-05-04T03:22:09Z",
			source: LastUpdateSourceAptSecurity,
		},
		{
			name: "operator dist-upgrade",
			log: "Start-Date: 2026-05-11  08:00:00\n" +
				"Commandline: apt-get dist-upgrade\n" +
				"Upgrade: openssl:amd64 (3.0.13-0ubuntu3.4, 3.0.13-0ubuntu3.5)\n" +
				"End-Date: 2026-05-11  08:00:04\n",
			want:   "2026-05-11T08:00:04Z",
			source: LastUpdateSourceAptHistory,
		},
		{
			// The whole point of the field: an operator adding a package is not
			// evidence that the operating system was patched.
			name: "targeted install does not count",
			log: "Start-Date: 2026-06-01  09:00:00\n" +
				"Commandline: apt-get install curl\n" +
				"Install: curl:amd64 (8.5.0-2ubuntu10.6)\n" +
				"End-Date: 2026-06-01  09:00:02\n",
			want: "",
		},
		{
			// Installing the unattended-upgrades package must be read as the
			// install it is, not as the security channel its argument names.
			name: "installing the unattended-upgrades package does not count",
			log: "Start-Date: 2026-06-01  09:00:00\n" +
				"Commandline: apt-get install unattended-upgrades\n" +
				"Install: unattended-upgrades:all (2.9.1+nmu4ubuntu1)\n" +
				"End-Date: 2026-06-01  09:00:02\n",
			want: "",
		},
		{
			name: "a newer upgrade outranks an older security run",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.5)\n" +
				"End-Date: 2026-05-04  03:22:09\n" +
				"\n" +
				"Start-Date: 2026-05-20  10:00:00\n" +
				"Commandline: apt full-upgrade\n" +
				"Upgrade: openssl:amd64 (3.0.13, 3.0.14)\n" +
				"End-Date: 2026-05-20  10:00:05\n",
			want:   "2026-05-20T10:00:05Z",
			source: LastUpdateSourceAptHistory,
		},
		{
			name: "an older security run answers when the newer install does not count",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.5)\n" +
				"End-Date: 2026-05-04  03:22:09\n" +
				"\n" +
				"Start-Date: 2026-05-20  10:00:00\n" +
				"Commandline: apt-get install nginx\n" +
				"Install: nginx:amd64 (1.24.0)\n" +
				"End-Date: 2026-05-20  10:00:05\n",
			want:   "2026-05-04T03:22:09Z",
			source: LastUpdateSourceAptSecurity,
		},
		{
			name: "removal only",
			log: "Start-Date: 2026-05-09  14:17:19\n" +
				"Commandline: apt-get remove --purge telnet\n" +
				"Remove: telnet:amd64 (0.17-44build1)\n" +
				"End-Date: 2026-05-09  14:17:20\n",
			want: "",
		},
		{
			name: "failed upgrade run",
			log: "Start-Date: 2026-05-11  08:00:00\n" +
				"Commandline: apt-get dist-upgrade\n" +
				"Upgrade: openssl:amd64 (3.0.13-0ubuntu3.4, 3.0.13-0ubuntu3.5)\n" +
				"Error: Sub-process /usr/bin/dpkg returned an error code (1)\n" +
				"End-Date: 2026-05-11  08:00:04\n",
			want: "",
		},
		{
			// A front end that writes no command line cannot be attributed, and
			// counting it would read an install as a patch.
			name: "block without a commandline",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.5)\n" +
				"End-Date: 2026-05-04  03:22:09\n",
			want: "",
		},
		{
			// A qualifying run with no End-Date was killed or partially
			// written; either way it never demonstrably completed, so it must
			// not count.
			name: "qualifying run killed before End-Date reads null",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3, 1.5.4)\n" +
				"Start-Date: 2026-05-05  03:22:07\n" +
				"Commandline: apt-get remove telnet\n" +
				"Remove: telnet:amd64 (0.17)\n" +
				"End-Date: 2026-05-05  03:22:09\n",
			want:     "",
			wantStop: true,
		},
		{
			// When the newest relevant run is incomplete, an older completed
			// one must not stand in for it: the log tail is suspect, and "last
			// patched three weeks ago" is not a known fact at that point.
			name: "killed qualifying run at EOF nulls an older completed one",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3, 1.5.4)\n" +
				"End-Date: 2026-05-04  03:22:09\n" +
				"\n" +
				"Start-Date: 2026-05-20  10:00:00\n" +
				"Commandline: apt-get dist-upgrade\n" +
				"Upgrade: openssl:amd64 (3.0.13, 3.0.14)\n",
			want:     "",
			wantStop: true,
		},
		{
			name: "a later completed run recovers from an earlier killed one",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3, 1.5.4)\n" +
				"Start-Date: 2026-05-20  10:00:00\n" +
				"Commandline: apt-get dist-upgrade\n" +
				"Upgrade: openssl:amd64 (3.0.13, 3.0.14)\n" +
				"End-Date: 2026-05-20  10:00:05\n",
			want:   "2026-05-20T10:00:05Z",
			source: LastUpdateSourceAptHistory,
		},
		{
			name: "unparseable End-Date is an incomplete run",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3, 1.5.4)\n" +
				"End-Date: garbage\n",
			want:     "",
			wantStop: true,
		},
		{
			// A dangling block that would not have counted anyway does not
			// void the answer; only a relevant one does.
			name: "killed targeted run at the tail does not null an older patch run",
			log: "Start-Date: 2026-05-04  03:22:07\n" +
				"Commandline: /usr/bin/unattended-upgrade\n" +
				"Upgrade: libpam-modules:amd64 (1.5.3, 1.5.4)\n" +
				"End-Date: 2026-05-04  03:22:09\n" +
				"\n" +
				"Start-Date: 2026-05-20  10:00:00\n" +
				"Commandline: apt-get install htop\n" +
				"Install: htop:amd64 (3.3.0)\n",
			want:   "2026-05-04T03:22:09Z",
			source: LastUpdateSourceAptSecurity,
		},
		{
			// A file that begins mid-block (a truncated head) has keys with no
			// Start-Date; such a fragment cannot qualify.
			name: "fragment without a Start-Date cannot qualify",
			log: "Commandline: apt-get dist-upgrade\n" +
				"Upgrade: openssl:amd64 (3.0.13, 3.0.14)\n" +
				"End-Date: 2026-05-04  03:22:09\n",
			want: "",
		},
		{
			name: "empty log",
			log:  "",
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, stop, err := ParseAptHistory(strings.NewReader(test.log), time.UTC)
			require.NoError(t, err)
			assert.Equal(t, test.wantStop, stop)
			if test.want == "" {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, test.want, got.Time.Format(time.RFC3339))
			assert.Equal(t, test.source, got.Source)
		})
	}
}

// A line past the cap stops the scan with an error rather than silently
// dropping the rest of the log. The caller reads that as "no answer", never as
// permission to answer from what happened to fit.
func TestParseAptHistoryScannerError(t *testing.T) {
	log := "Start-Date: 2026-05-04  03:22:07\n" +
		"Commandline: /usr/bin/unattended-upgrade\n" +
		"Upgrade: " + strings.Repeat("a", aptHistoryMaxLine+1) + "\n" +
		"End-Date: 2026-05-04  03:22:09\n"

	got, stop, err := ParseAptHistory(strings.NewReader(log), time.UTC)
	assert.Error(t, err)
	assert.Nil(t, got)
	assert.False(t, stop)
}

// An apt run is classified from its command line, and both directions matter: a
// missed upgrade verb nulls the field on a patched host, while a missed
// targeted verb reports an operator's install as a patch.
func TestClassifyAptCommandline(t *testing.T) {
	tests := []struct {
		cmdline string
		want    string
	}{
		{"/usr/bin/unattended-upgrade", LastUpdateSourceAptSecurity},
		{"/usr/bin/unattended-upgrades --download-only", LastUpdateSourceAptSecurity},
		{"unattended-upgrade", LastUpdateSourceAptSecurity},
		{"apt-get upgrade", LastUpdateSourceAptHistory},
		{"apt-get dist-upgrade", LastUpdateSourceAptHistory},
		{"apt full-upgrade", LastUpdateSourceAptHistory},
		{"aptitude safe-upgrade", LastUpdateSourceAptHistory},
		// An option value sits between the program and the subcommand, so
		// locating "the verb" positionally would read the option as the verb.
		{"apt-get -o Dpkg::Options::=--force-confdef upgrade", LastUpdateSourceAptHistory},
		{"apt-get -y --with-new-pkgs upgrade", LastUpdateSourceAptHistory},
		{"apt-get install curl", ""},
		{"apt-get install -y nginx", ""},
		{"apt-get remove --purge telnet", ""},
		{"apt-get autoremove", ""},
		{"apt-get build-dep foo", ""},
		{"apt reinstall curl", ""},
		// unattended-upgrades as an argument is a package name, not the
		// program that ran. The targeted verb settles it first.
		{"apt-get install unattended-upgrades", ""},
		{"apt-get remove unattended-upgrades", ""},
		// Only the executable token earns the security channel, so a command
		// that merely mentions the name elsewhere does not.
		{"/usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown", ""},
		// A package whose name contains a subcommand must not be read as one.
		{"apt-get install upgrade-helper", ""},
		// An upgrade verb alongside a targeted one is a targeted run.
		{"apt-get install --only-upgrade curl", ""},
		{"", ""},
		{"   ", ""},
	}

	for _, test := range tests {
		t.Run(test.cmdline, func(t *testing.T) {
			assert.Equal(t, test.want, classifyAptCommandline(test.cmdline))
		})
	}
}

func TestParseAptTimeUsesLocation(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	require.NoError(t, err)

	got, err := parseAptTime("2026-01-02  03:04:05", berlin)
	require.NoError(t, err)
	assert.Equal(t, "2026-01-02T02:04:05Z", got.UTC().Format(time.RFC3339))

	got, err = parseAptTime("2026-01-02 03:04:05", nil)
	require.NoError(t, err)
	assert.Equal(t, "2026-01-02T03:04:05Z", got.UTC().Format(time.RFC3339),
		"a nil location must fall back to UTC rather than panic")

	_, err = parseAptTime("2026-01-02", time.UTC)
	assert.Error(t, err)
}

// dpkg.log names neither the invoking command nor a repository, so a host whose
// apt history is gone reads null rather than falling back to a record that
// cannot tell an install from a patch.
func TestLastInstalledDebianRequiresAptHistory(t *testing.T) {
	t.Run("apt history answers", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		aptLog := "Start-Date: 2026-05-04  03:22:07\n" +
			"Commandline: /usr/bin/unattended-upgrade\n" +
			"Upgrade: libpam-modules:amd64 (1.5.3-5ubuntu5, 1.5.3-5ubuntu5.5)\n" +
			"End-Date: 2026-05-04  03:22:09\n"
		require.NoError(t, afero.WriteFile(fs, aptHistoryPath, []byte(aptLog), 0o644))

		got, err := lastInstalledDebianFS(fs, time.UTC)
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(t, LastUpdateSourceAptSecurity, got.Source)
		assert.Equal(t, "2026-05-04T03:22:09Z", got.Time.Format(time.RFC3339))
	})

	t.Run("dpkg log is not a fallback", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/var/log/dpkg.log",
			[]byte("2026-05-01 09:14:13 status installed curl:amd64 8.5.0\n"), 0o644))

		got, err := lastInstalledDebianFS(fs, time.UTC)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("dpkg status mtime is not a fallback", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		mtime := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
		require.NoError(t, afero.WriteFile(fs, "/var/lib/dpkg/status", []byte("Package: curl\n"), 0o644))
		require.NoError(t, fs.Chtimes("/var/lib/dpkg/status", mtime, mtime))

		got, err := lastInstalledDebianFS(fs, time.UTC)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("apt history holding no patch run", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		installOnly := "Start-Date: 2026-05-09  14:17:19\n" +
			"Commandline: apt-get install curl\n" +
			"Install: curl:amd64 (8.5.0)\n" +
			"End-Date: 2026-05-09  14:17:20\n"
		require.NoError(t, afero.WriteFile(fs, aptHistoryPath, []byte(installOnly), 0o644))

		got, err := lastInstalledDebianFS(fs, time.UTC)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("nothing to read", func(t *testing.T) {
		got, err := lastInstalledDebianFS(afero.NewMemMapFs(), time.UTC)
		require.NoError(t, err)
		assert.Nil(t, got, "an absent record is null, not an error")
	})
}

// Right after a rotation the live log is empty and the answer is in the gzipped
// copy. Without the walk this reports nothing at all.
func TestLastInstalledDebianReadsRotatedLog(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath, []byte(""), 0o644))

	rotated := "Start-Date: 2026-04-02  01:02:03\n" +
		"Commandline: /usr/bin/unattended-upgrade\n" +
		"Install: curl:amd64 (8.5.0)\n" +
		"End-Date: 2026-04-02  01:02:04\n"
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath+".1.gz", gzipBytes(t, rotated), 0o644))

	got, err := lastInstalledDebianFS(fs, time.UTC)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, LastUpdateSourceAptSecurity, got.Source)
	assert.Equal(t, "2026-04-02T01:02:04Z", got.Time.Format(time.RFC3339))
}

// A rotation that exists but is not readable is withheld evidence, not
// permission to look further back: the newest answer could be inside it, and
// answering from an older rotation would report a stale event as the newest
// one.
func TestLastInstalledDebianCorruptGzipReadsNull(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath+".1.gz", []byte("not gzip"), 0o644))

	rotated := "Start-Date: 2026-03-02  01:02:03\n" +
		"Commandline: apt-get dist-upgrade\n" +
		"Upgrade: curl:amd64 (8.4.0, 8.5.0)\n" +
		"End-Date: 2026-03-02  01:02:04\n"
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath+".2", []byte(rotated), 0o644))

	got, err := lastInstalledDebianFS(fs, time.UTC)
	require.NoError(t, err)
	assert.Nil(t, got, "a corrupt newest rotation must not surface an older answer")
}

// A truncated gzip opens fine (the header is intact) and fails mid-read. That
// failure surfaces through scanner.Err, and like a corrupt header it means the
// newest evidence is unreadable, so no older rotation may answer.
func TestLastInstalledDebianTruncatedGzipReadsNull(t *testing.T) {
	fs := afero.NewMemMapFs()

	newest := "Start-Date: 2026-05-02  01:02:03\n" +
		"Commandline: apt-get dist-upgrade\n" +
		"Upgrade: curl:amd64 (8.4.0, 8.5.0), openssl:amd64 (3.0.13, 3.0.14)\n" +
		"End-Date: 2026-05-02  01:02:04\n"
	full := gzipBytes(t, newest)
	require.Greater(t, len(full), 40, "the truncated copy must keep a valid header")
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath+".1.gz", full[:len(full)/2], 0o644))

	older := "Start-Date: 2026-03-02  01:02:03\n" +
		"Commandline: apt-get dist-upgrade\n" +
		"Upgrade: curl:amd64 (8.3.0, 8.4.0)\n" +
		"End-Date: 2026-03-02  01:02:04\n"
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath+".2", []byte(older), 0o644))

	got, err := lastInstalledDebianFS(fs, time.UTC)
	require.NoError(t, err)
	assert.Nil(t, got, "a truncated newest rotation must not surface an older answer")
}

// unreadableFs makes one path fail to open the way a permission problem does,
// which afero's in-memory filesystem cannot otherwise express.
type unreadableFs struct {
	afero.Fs
	path string
}

func (u *unreadableFs) Open(name string) (afero.File, error) {
	if name == u.path {
		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	return u.Fs.Open(name)
}

// Only a genuinely missing file moves the walk to an older rotation. A file
// that exists but cannot be opened is unknown patch state, and unknown reads
// null.
func TestLastInstalledDebianUnreadableLogReadsNull(t *testing.T) {
	base := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(base, aptHistoryPath, []byte("unreadable"), 0o600))

	older := "Start-Date: 2026-03-02  01:02:03\n" +
		"Commandline: apt-get dist-upgrade\n" +
		"Upgrade: curl:amd64 (8.3.0, 8.4.0)\n" +
		"End-Date: 2026-03-02  01:02:04\n"
	require.NoError(t, afero.WriteFile(base, aptHistoryPath+".1", []byte(older), 0o644))

	got, err := lastInstalledDebianFS(&unreadableFs{Fs: base, path: aptHistoryPath}, time.UTC)
	require.NoError(t, err)
	assert.Nil(t, got, "an unreadable newest log must not surface an older answer")
}

// A killed patch run in the live log voids the answer outright: the walk must
// not read on into a rotation that predates it.
func TestLastInstalledDebianIncompleteNewestRunDoesNotFallBack(t *testing.T) {
	fs := afero.NewMemMapFs()
	killed := "Start-Date: 2026-05-20  10:00:00\n" +
		"Commandline: apt-get dist-upgrade\n" +
		"Upgrade: openssl:amd64 (3.0.13, 3.0.14)\n"
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath, []byte(killed), 0o644))

	older := "Start-Date: 2026-04-02  01:02:03\n" +
		"Commandline: /usr/bin/unattended-upgrade\n" +
		"Upgrade: curl:amd64 (8.4.0, 8.5.0)\n" +
		"End-Date: 2026-04-02  01:02:04\n"
	require.NoError(t, afero.WriteFile(fs, aptHistoryPath+".1", []byte(older), 0o644))

	got, err := lastInstalledDebianFS(fs, time.UTC)
	require.NoError(t, err)
	assert.Nil(t, got, "an incomplete newest patch run must not fall back to an older one")
}

func gzipBytes(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, err := gz.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, gz.Close())
	return buf.Bytes()
}
