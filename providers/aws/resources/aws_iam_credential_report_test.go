// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func reportEntry(props map[string]any) *mqlAwsIamUsercredentialreportentry {
	return &mqlAwsIamUsercredentialreportentry{
		Properties: plugin.TValue[map[string]any]{Data: props, State: plugin.StateIsSet},
	}
}

// The root account is always in the credential report and never has an IAM user
// behind it, so `user` is null. It used to return an error, and because a field
// error renders as the value of the enclosing collection, that error took the
// whole credentialReport with it - making every root-MFA and key-rotation check
// unrunnable on every account.
func TestCredentialReportRootEntryReportsNoUser(t *testing.T) {
	entry := reportEntry(map[string]any{"user": "<root_account>"})

	got, err := entry.user()

	require.NoError(t, err, "the root entry is expected, not a failure")
	assert.Nil(t, got)
	assert.NotZero(t, entry.User.State&plugin.StateIsSet, "the field must be marked resolved")
	assert.NotZero(t, entry.User.State&plugin.StateIsNull, "the field must be marked null")
}

// isRoot is how a caller selects that entry, so it has to agree with the branch
// user() takes.
func TestCredentialReportIsRootAgreesWithTheUserBranch(t *testing.T) {
	root := reportEntry(map[string]any{"user": "<root_account>"})
	isRoot, err := root.isRoot()
	require.NoError(t, err)
	assert.True(t, isRoot)

	human := reportEntry(map[string]any{"user": "andre"})
	isRoot, err = human.isRoot()
	require.NoError(t, err)
	assert.False(t, isRoot)
}

// A report we could not read at all is still an error: that is a genuine failure
// rather than an entry with nothing to resolve.
func TestCredentialReportUnreadableReportStillErrors(t *testing.T) {
	entry := reportEntry(nil)

	_, err := entry.user()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not read the credentials report")
}

// An entry whose user column is missing or not a string is malformed input, not
// the root account, and must not be quietly treated as null.
func TestCredentialReportMalformedUserStillErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		props map[string]any
	}{
		{name: "no user column", props: map[string]any{"arn": "arn:aws:iam::1:user/x"}},
		{name: "user is not a string", props: map[string]any{"user": 42}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := reportEntry(tc.props)

			_, err := entry.user()

			require.Error(t, err)
			assert.Contains(t, err.Error(), "no user")
		})
	}
}
