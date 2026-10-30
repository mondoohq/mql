// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package fsutil_test

import (
	"path/filepath"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/fsutil"
)

func TestFileResource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test_hash")

	conn := local.NewConnection(0, &inventory.Config{
		Path: path,
	}, &inventory.Asset{})

	fs := conn.FileSystem()
	afutil := afero.Afero{Fs: fs}

	// create the file and set the content
	err := afutil.WriteFile(path, []byte("hello world"), 0o666)
	assert.Nil(t, err)

	f, err := fs.Open(path)
	assert.Nil(t, err)
	if assert.NotNil(t, f) {
		defer f.Close()
		assert.Equal(t, path, f.Name(), "they should be equal")

		md5, err := fsutil.Md5(f)
		assert.Nil(t, err)
		assert.Equal(t, "5eb63bbbe01eeed093cb22bb8f5acdc3", md5)

		sha256, err := fsutil.Sha256(f)
		assert.Nil(t, err)
		assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256)
	}
}
