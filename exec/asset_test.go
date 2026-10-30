// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package exec_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// A typed asset reference must keep behaving as an asset value at execution
// time: the root rides on the type, so the nil comparisons - the only thing MQL
// could ever do with an asset - have to keep dispatching on the asset type
// rather than falling through to a missing-function error. See ADR 031.
func TestAssetReferenceExec(t *testing.T) {
	rt := testutils.LinuxMock()

	res, err := exec.Exec("muser.running != null", rt, testutils.Features, nil)
	require.NoError(t, err)
	require.NoError(t, res.Error)
	assert.Equal(t, true, res.Value)

	res, err = exec.Exec("muser.running == null", rt, testutils.Features, nil)
	require.NoError(t, err)
	require.NoError(t, res.Error)
	assert.Equal(t, false, res.Value)
}

// A single-asset recording holds neither the reverse edge nor the target, so
// both legs come up empty: nothing recorded is anchored on it, and the target
// the provider names is not in this recording either.
//
// The chain compiles either way, so this error is the only thing standing
// between a user and a confusing result. It has to name the asset it could not
// reach rather than surfacing as a missing function on the asset type, or as a
// null that reads like an answer.
func TestAssetChainWithNothingToResolveTo(t *testing.T) {
	rt := testutils.LinuxMock()

	res, err := exec.Exec("muser.running.name", rt, testutils.Features, nil)
	require.NoError(t, err, "the chain compiles")
	require.Error(t, res.Error)
	assert.Contains(t, res.Error.Error(), "resolved-target", "the error names the asset it could not reach")
}

// The whole phase 7 path, end to end through llx: a typed asset reference is
// dereferenced by the $assetRoot chunk, the host-side resolver finds the target
// through its reverse edge in the recording, connects it, and the field read
// above the deref goes to *that* asset's runtime.
//
// The value is the point: `mgroup.name` is "group one" on the parent asset and
// "resolved-group" on the target. Asserting the second is what proves the read
// crossed, rather than falling back to the local runtime and looking like it
// worked.
func TestAssetChainResolvesThroughTheRecording(t *testing.T) {
	rt := testutils.CrossAssetMock()

	res, err := exec.Exec("muser.running.name", rt, testutils.Features, nil)
	require.NoError(t, err)
	require.NoError(t, res.Error)
	assert.Equal(t, "resolved-group", res.Value)
}

// Resolving into another asset must not disturb the asset the query is running
// against. A runtime opened for a target inherits its parent's providers *by
// pointer*, so mock-connecting into the inherited ConnectedProvider rather than
// a fresh one replaces the connection the parent is still reading through. The
// parent then silently answers from the target's recording.
//
// `mgroup` is recorded on the target and not on the parent, so reading it bare
// is what tells the two apart: null is the parent's own answer, and the target's
// value appearing here means the connection was taken over. Making
// addRecordedProvider return the inherited provider turns the last assertion
// into "resolved-group".
func TestAssetChainLeavesTheParentConnectionAlone(t *testing.T) {
	rt := testutils.CrossAssetMock()

	before, err := exec.Exec("mgroup.name", rt, testutils.Features, nil)
	require.NoError(t, err)
	require.NoError(t, before.Error)
	require.Nil(t, before.Value, "the parent asset records no mgroup")

	crossed, err := exec.Exec("muser.running.name", rt, testutils.Features, nil)
	require.NoError(t, err)
	require.NoError(t, crossed.Error)
	require.Equal(t, "resolved-group", crossed.Value, "the target does record one")

	after, err := exec.Exec("mgroup.name", rt, testutils.Features, nil)
	require.NoError(t, err)
	require.NoError(t, after.Error)
	assert.Nil(t, after.Value, "the parent still reads its own asset, not the target's")
}

// The same crossing over the live leg. With no reverse edge recorded, the
// recorded lookup misses and the provider that owns the anchor is asked for the
// target instead (ADR 031 phase 8) - which is the half that cannot come from
// the value, because the value carries identity and never reachability.
//
// Same query, same answer, different path: `mgroup.name` is "group one" on the
// parent and "resolved-group" on the target, so the value proves the read
// crossed rather than falling back locally.
func TestAssetChainResolvesThroughTheProvider(t *testing.T) {
	rt := testutils.CrossAssetLiveMock()

	res, err := exec.Exec("muser.running.name", rt, testutils.Features, nil)
	require.NoError(t, err)
	require.NoError(t, res.Error)
	assert.Equal(t, "resolved-group", res.Value)
}

// A resource reached from the root by an alias compiles to a createResource
// chunk bound to the root, not to a field read - a different execution path,
// and one that used to build the resource on the *querying* runtime after the
// chain had already crossed into another asset.
//
// It is the path most of an OS root goes through: `running.packages`,
// `running.file("/etc/os-release")`, `running.users`. Against a real container
// it read the host's package list and the host's files while `running.hostname`
// - a plain field - was correctly reporting the container. `mthing` is recorded
// on both assets with different values, so a read that fails to cross shows up
// as the parent's value rather than as an absence.
func TestAssetChainCrossesForAliasedResources(t *testing.T) {
	for name, rt := range map[string]llx.Runtime{
		"recorded": testutils.CrossAssetMock(),
		"live":     testutils.CrossAssetLiveMock(),
	} {
		t.Run(name, func(t *testing.T) {
			parent, err := exec.Exec("mthing.value", rt, testutils.Features, nil)
			require.NoError(t, err)
			require.NoError(t, parent.Error)
			require.Equal(t, "parent-thing", parent.Value, "the parent has its own")

			res, err := exec.Exec("muser.running.mthing.value", rt, testutils.Features, nil)
			require.NoError(t, err)
			require.NoError(t, res.Error)
			assert.Equal(t, "target-thing", res.Value)
		})
	}
}
