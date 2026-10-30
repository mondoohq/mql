// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustchk -p for each attribute on AIX 7.3 TL4 SP2 after trustchk -p te=on.
func TestParseTrustchk(t *testing.T) {
	out, err := os.ReadFile("testdata/trustchk_aix73_te_on.txt")
	require.NoError(t, err)
	p := ParseTrustchk(string(out))

	assert.Equal(t, "on", p.Values["TE"])
	assert.Equal(t, "off", p.Values["STOP_UNTRUSTD"])
	assert.Equal(t, "off", p.Values["TEP"], "the path line does not replace the state")
	assert.Len(t, p.Paths["TEP"], 16)
	assert.Equal(t, "/usr/bin", p.Paths["TEP"][0])
	assert.Contains(t, p.Paths["TLP"], "/usr/lib/security")
}

// AIX 7.2 has no SIG_VER and reports it as an invalid attribute.
func TestParseTrustchkInvalidAttribute(t *testing.T) {
	out, err := os.ReadFile("testdata/trustchk_aix72.txt")
	require.NoError(t, err)
	p := ParseTrustchk(string(out))
	assert.Equal(t, map[string]string{"TE": "on", "CHKEXEC": "off"}, p.Values)
}
