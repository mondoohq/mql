// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===== qualifiedId =====

func TestQualifiedId(t *testing.T) {
	got := qualifiedId("stackit.secretsManager.user", "instance-a", "user-1")
	assert.Equal(t, "stackit.secretsManager.user/instance-a/user-1", got)
}

// The whole point of the qualifier: the same child id under two parents must
// not produce the same cache key, or one parent's child masks the other's.
func TestQualifiedIdDistinctPerParent(t *testing.T) {
	a := qualifiedId("stackit.secretsManager.user", "instance-a", "same-uuid")
	b := qualifiedId("stackit.secretsManager.user", "instance-b", "same-uuid")
	assert.NotEqual(t, a, b)
}

// A blank parent is what the old id() method produced, since it ran before the
// parent could be recorded. Every user then collided on one key. The helper
// cannot prevent a blank parent being passed, but the shape it produces is
// visibly wrong rather than plausible.
func TestQualifiedIdBlankParentIsVisible(t *testing.T) {
	got := qualifiedId("stackit.secretsManager.user", "", "user-1")
	assert.Equal(t, "stackit.secretsManager.user//user-1", got)
	assert.NotEqual(t, qualifiedId("stackit.secretsManager.user", "instance-a", "user-1"), got)
}

// ===== back-reference null-state =====
//
// Each of these resources carries its parent on the Internal struct rather than
// as a schema field. When that cache is empty the back-reference has to report
// null, not a blank resource.

func TestSecretsManagerUserInstanceNullWhenNoCache(t *testing.T) {
	u := &mqlStackitSecretsManagerUser{}
	got, err := u.instance()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, u.Instance.IsNull())
	assert.True(t, u.Instance.IsSet())
}

func TestKmsWrappingKeyKeyRingNullWhenNoCache(t *testing.T) {
	wk := &mqlStackitKmsWrappingKey{}
	got, err := wk.keyRing()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, wk.KeyRing.IsNull())
	assert.True(t, wk.KeyRing.IsSet())
}

func TestFederatedIdentityProviderServiceAccountNullWhenNoCache(t *testing.T) {
	fip := &mqlStackitServiceAccountFederatedIdentityProvider{}
	got, err := fip.serviceAccount()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, fip.ServiceAccount.IsNull())
	assert.True(t, fip.ServiceAccount.IsSet())
}
