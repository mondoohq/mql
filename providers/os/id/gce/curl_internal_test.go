// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gce

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/encoding/unicode"
)

// The Windows metadata command is encoded like the AWS and IBM ones: its
// script is multi-line and quoted, and would not survive `powershell -c` or
// the SSH shell as plain text.
func TestWindowsMetadataCmdStringIsEncoded(t *testing.T) {
	cmd := windowsMetadataCmdString("instance/tags")
	const prefix = "powershell.exe -NoProfile -EncodedCommand "
	require.True(t, strings.HasPrefix(cmd, prefix), cmd)

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmd, prefix))
	require.NoError(t, err)
	script, err := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder().Bytes(raw)
	require.NoError(t, err)
	assert.Contains(t, string(script), `"Metadata-Flavor" = "Google"`)
	assert.Contains(t, string(script), metadataSvcURL+"instance/tags")
	assert.Contains(t, string(script), "ConvertTo-Json")
}
