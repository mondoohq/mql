// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	workspacestypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ===== client properties are absent =====

// A directory the caller cannot read client properties for reports the defaults
// rather than an error, so a fleet-wide query is not lost to one directory.
func TestDirectoryClientPropertiesAbsent(t *testing.T) {
	d := &mqlAwsWorkspacesDirectory{}
	d.clientPropsFetched.Store(true) // fetched, but nothing came back

	policy, err := d.clientExperiencePolicy()
	require.NoError(t, err)
	assert.Equal(t, "", policy)

	reconnect, err := d.clientReconnectEnabled()
	require.NoError(t, err)
	assert.False(t, reconnect)

	logUpload, err := d.clientLogUploadEnabled()
	require.NoError(t, err)
	assert.False(t, logUpload)
}

// ===== client properties are present =====

func TestDirectoryClientPropertiesPresent(t *testing.T) {
	policy := "FORCE_UI_2026"
	d := &mqlAwsWorkspacesDirectory{}
	d.clientProps = &workspacestypes.ClientProperties{
		// the SDK models the policy as a *string, unlike the two enums beside it
		ClientExperiencePolicy: &policy,
		ReconnectEnabled:       workspacestypes.ReconnectEnumEnabled,
		LogUploadEnabled:       workspacestypes.LogUploadEnumEnabled,
	}
	d.clientPropsFetched.Store(true)

	got, err := d.clientExperiencePolicy()
	require.NoError(t, err)
	assert.Equal(t, "FORCE_UI_2026", got)

	reconnect, err := d.clientReconnectEnabled()
	require.NoError(t, err)
	assert.True(t, reconnect)

	logUpload, err := d.clientLogUploadEnabled()
	require.NoError(t, err)
	assert.True(t, logUpload)
}

// The enums carry a disabled value of their own, which must not be read as the
// zero value the absent case already reports.
func TestDirectoryClientPropertiesDisabled(t *testing.T) {
	d := &mqlAwsWorkspacesDirectory{}
	d.clientProps = &workspacestypes.ClientProperties{
		ReconnectEnabled: workspacestypes.ReconnectEnumDisabled,
		LogUploadEnabled: workspacestypes.LogUploadEnumDisabled,
	}
	d.clientPropsFetched.Store(true)

	reconnect, err := d.clientReconnectEnabled()
	require.NoError(t, err)
	assert.False(t, reconnect)

	logUpload, err := d.clientLogUploadEnabled()
	require.NoError(t, err)
	assert.False(t, logUpload)

	// a nil policy pointer must not panic
	policy, err := d.clientExperiencePolicy()
	require.NoError(t, err)
	assert.Equal(t, "", policy)
}

// ===== bundle reference =====

// A WorkSpace with no bundle ID reports a null bundle rather than an error, so
// a fleet-wide query is not lost to one desktop whose bundle cannot be named.
func TestWorkspaceBundleAbsent(t *testing.T) {
	w := &mqlAwsWorkspacesWorkspace{}

	bundle, err := w.bundle()
	require.NoError(t, err)
	assert.Nil(t, bundle)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, w.Bundle.State)
}

// ===== bundle init arguments =====

// A bundle is fetched by ID within a region, both of which the init function
// reads off the args the reference was created with.
func TestParseWorkspacesBundleRef(t *testing.T) {
	region, bundleId, err := parseWorkspacesBundleRef(map[string]*llx.RawData{
		"bundleId": llx.StringData("wsb-ccc333fff"),
		"region":   llx.StringData("us-east-1"),
	})
	require.NoError(t, err)
	assert.Equal(t, "us-east-1", region)
	assert.Equal(t, "wsb-ccc333fff", bundleId)
}

// Without both halves of the reference there is nothing to look up. The init
// function has to say so rather than fall through to DescribeWorkspaceBundles
// with an empty filter, which answers with every bundle the account owns and
// would bind an arbitrary one to the WorkSpace.
func TestParseWorkspacesBundleRefIncomplete(t *testing.T) {
	_, _, err := parseWorkspacesBundleRef(map[string]*llx.RawData{
		"bundleId": llx.StringData("wsb-ccc333fff"),
	})
	require.Error(t, err)

	_, _, err = parseWorkspacesBundleRef(map[string]*llx.RawData{
		"region": llx.StringData("us-east-1"),
	})
	require.Error(t, err)
}

// ===== unresolvable bundles =====

// A bundle that cannot be named — deleted after the WorkSpace was built, or in a
// region the caller cannot read — is reported as a null bundle. Any other
// failure is a real error and must not be swallowed into a null.
func TestWorkspacesBundleUnresolvedClassification(t *testing.T) {
	notFound := fmt.Errorf("%w: id %q in %s", errWorkspacesBundleUnresolved, "wsb-ccc333fff", "us-east-1")
	assert.True(t, errors.Is(notFound, errWorkspacesBundleUnresolved))

	assert.False(t, errors.Is(errors.New("connection reset by peer"), errWorkspacesBundleUnresolved))
}
