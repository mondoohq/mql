// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagelockjson

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A package-lock.json saved by a Windows editor starts with a UTF-8 byte order
// mark. npm reads it, but the decoder failed with "invalid character 'ï'", so
// the project errored with an explicit path and vanished from a default scan.
// Fails if the BOM is no longer skipped.
func TestPackageLockWithByteOrderMark(t *testing.T) {
	data, err := os.ReadFile("./testdata/lockfile-v3.json")
	require.NoError(t, err)

	plain, err := (&Extractor{}).Parse(bytes.NewReader(data), "package-lock.json")
	require.NoError(t, err)
	withBOM, err := (&Extractor{}).Parse(bytes.NewReader(append([]byte("\xef\xbb\xbf"), data...)), "package-lock.json")
	require.NoError(t, err)

	require.NotEmpty(t, plain.Transitive())
	assert.Equal(t, plain.Transitive(), withBOM.Transitive())
	assert.Equal(t, plain.Root(), withBOM.Root())
}
