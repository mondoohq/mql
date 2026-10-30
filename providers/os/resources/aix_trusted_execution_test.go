// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/aix"
)

func aixTrustedExecution(t *testing.T, fixture string) *mqlAixTrustedExecution {
	t.Helper()
	out, err := os.ReadFile(fixture)
	require.NoError(t, err)
	rt := newAixRuntime(t, aixPlatform, nil, map[string]*mock.Command{
		aix.TrustchkCommand: {Stdout: string(out)},
	})
	r, err := CreateResource(rt, "aix.trustedExecution", map[string]*llx.RawData{})
	require.NoError(t, err)
	return r.(*mqlAixTrustedExecution)
}

func TestAixTrustedExecution(t *testing.T) {
	te := aixTrustedExecution(t, "aix/testdata/trustchk_aix73_te_on.txt")
	assert.True(t, te.GetEnabled().Data)
	assert.False(t, te.GetCheckExecutables().Data)
	assert.Equal(t, "off", te.GetStopUntrusted().Data)
	assert.False(t, te.GetTrustedExecutionPathEnabled().Data)
	path := te.GetTrustedExecutionPath()
	require.NoError(t, path.Error)
	assert.Len(t, path.Data, 16)
}

// AIX 7.2 has no SIG_VER, so it reads null rather than false.
func TestAixTrustedExecutionUnknownAttributeIsNull(t *testing.T) {
	te := aixTrustedExecution(t, "aix/testdata/trustchk_aix72.txt")
	assert.True(t, te.GetEnabled().Data)
	sig := te.GetSignatureVerification()
	require.NoError(t, sig.Error)
	assert.True(t, sig.IsNull())
	// the cut 7.2 output has no STOP_UNTRUSTD line
	stop := te.GetStopUntrusted()
	require.NoError(t, stop.Error)
	assert.True(t, stop.IsNull())
}
