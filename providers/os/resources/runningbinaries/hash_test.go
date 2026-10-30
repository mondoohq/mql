// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

func TestHashOnAsset(t *testing.T) {
	// a local scan reads the files itself
	assert.False(t, HashOnAsset(local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})))
}

func TestUnixSHA256s(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the digest command runs in a unix shell")
	}
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte(content), 0o755))
		return p
	}
	server := write("it's a server", "on disk")
	running := write("running", "the running file")
	tool := write("tool", "a tool")

	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	bins := []Binary{
		// replaced on disk: the running file is hashed through ContentPath
		{Path: server, ContentPath: running},
		{Path: tool},
		{Path: filepath.Join(dir, "gone")},
	}
	digests, err := unixSHA256s(conn, bins)
	require.NoError(t, err)

	want := func(b Binary) string {
		d, err := SHA256(afero.NewOsFs(), b)
		require.NoError(t, err)
		return d
	}
	assert.Equal(t, map[string]string{
		server: want(bins[0]),
		tool:   want(bins[1]),
	}, digests)
}

func TestParseSHA256Sums(t *testing.T) {
	d := strings.Repeat("ab", 32)
	out := d + "  /usr/bin/a b\n" +
		strings.ToUpper(d) + " */usr/bin/binary-mode\n" +
		`\` + d + `  /opt/odd\\name\nline` + "\n" +
		"sha256sum: /gone: No such file or directory\n"
	assert.Equal(t, map[string]string{
		"/usr/bin/a b":         d,
		"/usr/bin/binary-mode": d,
		"/opt/odd\\name\nline": d,
	}, parseSHA256Sums(strings.NewReader(out)))
}

func TestWindowsSHA256ScriptFitsCommandLine(t *testing.T) {
	assert.True(t, powershell.FitsCommandLine(windowsSHA256Script))
}

func TestParseWindowsFileHashes(t *testing.T) {
	d := strings.Repeat("AB", 32)
	hashes, err := parseWindowsFileHashes([]byte(`[{"Path": "C:\\Program Files\\Mondoo\\cnspec.exe", "Hash": "` + d + `"}, {"Path": "C:\\x.exe", "Hash": ""}]`))
	require.NoError(t, err)
	assert.Equal(t, map[string]string{`c:\program files\mondoo\cnspec.exe`: strings.ToLower(d)}, hashes)

	hashes, err = parseWindowsFileHashes([]byte("[]"))
	require.NoError(t, err)
	assert.Empty(t, hashes)

	_, err = parseWindowsFileHashes([]byte("{nope"))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}
