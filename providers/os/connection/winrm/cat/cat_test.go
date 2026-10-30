// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cat

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func TestCatFs(t *testing.T) {
	filepath, _ := filepath.Abs("./testdata/winrm.toml")
	p, err := mock.New(0, &inventory.Asset{}, mock.WithPath(filepath))
	require.NoError(t, err)

	catfs := New(p)

	// fetch file content
	f, err := catfs.Open("C:\\test.txt")
	require.NoError(t, err)

	data, err := io.ReadAll(f)
	require.NoError(t, err)

	expected := "hi\n"
	assert.Equal(t, expected, string(data))

	// get file stats
	fi, err := catfs.Stat("C:\\test.txt")
	require.NoError(t, err)

	assert.Equal(t, "test.txt", fi.Name())
	assert.Equal(t, int64(2), fi.Size())
	assert.Equal(t, false, fi.IsDir())
	assert.Equal(t, int64(1603529613), fi.ModTime().Unix())
}

// constRunner answers every command with the same output and exit status.
type constRunner struct {
	stdout     string
	stderr     string
	exitStatus int
}

func (r *constRunner) RunCommand(command string) (*shared.Command, error) {
	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(r.stdout),
		Stderr:     bytes.NewBufferString(r.stderr),
		ExitStatus: r.exitStatus,
	}, nil
}

func TestOpenReturnsTheFileBytes(t *testing.T) {
	// UTF-8 without a BOM, LF line endings and bytes no text encoding keeps
	first := []byte("caf\xc3\xa9\nl2\n")
	second := []byte{0x00, 0x01, 0xff, 0x0d, 0x0a, 0x80}
	stdout := base64.StdEncoding.EncodeToString(first) + "\r\n" +
		base64.StdEncoding.EncodeToString(second) + "\r\n"

	catfs := New(&constRunner{stdout: stdout})
	f, err := catfs.Open(`C:\mqltest\file.bin`)
	require.NoError(t, err)
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, first...), second...), data)
}

func TestOpenEmptyFile(t *testing.T) {
	catfs := New(&constRunner{})
	f, err := catfs.Open(`C:\mqltest\empty.txt`)
	require.NoError(t, err)
	data, err := io.ReadAll(f)
	require.NoError(t, err)
	assert.Empty(t, data)
}

func TestOpenRejectsGarbledOutput(t *testing.T) {
	catfs := New(&constRunner{stdout: "hello world\r\n"})
	_, err := catfs.Open(`C:\mqltest\plain.txt`)
	assert.Error(t, err)
}

func TestOpenErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		catfs := New(&constRunner{exitStatus: 66, stderr: "Could not find file 'C:\\missing.txt'."})
		_, err := catfs.Open(`C:\missing.txt`)
		assert.ErrorIs(t, err, os.ErrNotExist)
		assert.NotErrorIs(t, err, os.ErrPermission)
	})

	t.Run("access denied", func(t *testing.T) {
		catfs := New(&constRunner{exitStatus: 67, stderr: "Access to the path 'C:\\secret.txt' is denied."})
		_, err := catfs.Open(`C:\secret.txt`)
		assert.ErrorIs(t, err, os.ErrPermission)
		assert.NotErrorIs(t, err, os.ErrNotExist)
	})

	t.Run("file in use", func(t *testing.T) {
		msg := "The process cannot access the file 'C:\\Windows\\System32\\config\\SAM' because it is being used by another process."
		catfs := New(&constRunner{exitStatus: 1, stderr: msg + "\r\n"})
		_, err := catfs.Open(`C:\Windows\System32\config\SAM`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), msg)
		assert.NotErrorIs(t, err, os.ErrNotExist)
		assert.NotErrorIs(t, err, os.ErrPermission)
	})

	t.Run("failure without a message", func(t *testing.T) {
		catfs := New(&constRunner{exitStatus: 1})
		_, err := catfs.Open(`C:\mqltest\x.txt`)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit status 1")
		assert.NotErrorIs(t, err, os.ErrNotExist)
	})
}
