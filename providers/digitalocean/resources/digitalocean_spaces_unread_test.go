// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// boolRead is a bool field the API actually answered.
func boolRead(v bool) plugin.TValue[bool] {
	return plugin.TValue[bool]{Data: v, State: plugin.StateIsSet}
}

// boolUnread is a bool field whose read never happened: null, not false.
func boolUnread() plugin.TValue[bool] {
	return plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
}

func TestDictListData(t *testing.T) {
	// A list that was never read must not render as an empty list, or
	// "nothing came back" reads as "there is nothing".
	assert.Equal(t, llx.NilData, dictListData(nil))

	read := dictListData([]any{})
	assert.NotEqual(t, llx.NilData, read)
	assert.Equal(t, types.Array(types.Dict), read.Type)
	assert.Equal(t, []any{}, read.Value)
}

// hasWildcardPolicy has to separate a bucket with no policy from a bucket whose
// policy was never read. Both leave the policy field null.
func TestHasWildcardPolicyNullWhenPolicyUnread(t *testing.T) {
	t.Run("policy read and absent is a real answer", func(t *testing.T) {
		b := &mqlDigitaloceanSpacesBucket{}
		b.policyRead = true
		b.Policy = plugin.TValue[any]{State: plugin.StateIsSet | plugin.StateIsNull}

		got := b.GetHasWildcardPolicy()
		assert.Zero(t, got.State&plugin.StateIsNull, "a bucket with no policy should answer false, not null")
		assert.False(t, got.Data)
	})

	t.Run("policy never read is unknown", func(t *testing.T) {
		b := &mqlDigitaloceanSpacesBucket{}
		b.policyRead = false
		b.Policy = plugin.TValue[any]{State: plugin.StateIsSet | plugin.StateIsNull}

		got := b.GetHasWildcardPolicy()
		assert.NotZero(t, got.State&plugin.StateIsNull, "an unread policy must not answer false")
	})
}

// isPublic used to be a plain OR over four booleans that were left at false
// whenever their read failed, so a bucket whose ACL and policy could not be
// read reported "not reachable by anyone on the internet" having read neither.
func TestSpacesBucketIsPublicThreeValued(t *testing.T) {
	wildcardPolicy := map[string]any{
		"Statement": []any{
			map[string]any{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"},
		},
	}
	ownerPolicy := map[string]any{
		"Statement": []any{
			map[string]any{"Effect": "Allow", "Principal": map[string]any{"AWS": "acct-1"}, "Action": "s3:GetObject"},
		},
	}

	for _, tc := range []struct {
		name       string
		publicRead plugin.TValue[bool]
		publicWt   plugin.TValue[bool]
		authRead   plugin.TValue[bool]
		policy     any
		policyRead bool
		wantNull   bool
		want       bool
	}{
		{
			name:       "everything read and nothing is public",
			publicRead: boolRead(false), publicWt: boolRead(false), authRead: boolRead(false),
			policy: ownerPolicy, policyRead: true,
			want: false,
		},
		{
			name:       "an anonymous read grant is public",
			publicRead: boolRead(true), publicWt: boolRead(false), authRead: boolRead(false),
			policy: ownerPolicy, policyRead: true,
			want: true,
		},
		{
			name:       "an authenticated-users grant is public",
			publicRead: boolRead(false), publicWt: boolRead(false), authRead: boolRead(true),
			policy: ownerPolicy, policyRead: true,
			want: true,
		},
		{
			name:       "a wildcard policy is public",
			publicRead: boolRead(false), publicWt: boolRead(false), authRead: boolRead(false),
			policy: wildcardPolicy, policyRead: true,
			want: true,
		},

		// The cases this test exists for.
		{
			name:       "an unread acl is unknown, not clear",
			publicRead: boolUnread(), publicWt: boolUnread(), authRead: boolUnread(),
			policy: ownerPolicy, policyRead: true,
			wantNull: true,
		},
		{
			name:       "an unread policy is unknown, not clear",
			publicRead: boolRead(false), publicWt: boolRead(false), authRead: boolRead(false),
			policy: nil, policyRead: false,
			wantNull: true,
		},
		{
			name:       "nothing read at all is unknown",
			publicRead: boolUnread(), publicWt: boolUnread(), authRead: boolUnread(),
			policy: nil, policyRead: false,
			wantNull: true,
		},
		{
			// A grant that was read and is public settles it regardless of what
			// else could not be read: unknown must not mask a known exposure.
			name:       "a read public grant outweighs an unread policy",
			publicRead: boolRead(true), publicWt: boolUnread(), authRead: boolUnread(),
			policy: nil, policyRead: false,
			want: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &mqlDigitaloceanSpacesBucket{}
			b.PublicAccessBlocked = plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}
			b.PublicReadAcl = tc.publicRead
			b.PublicWriteAcl = tc.publicWt
			b.AuthenticatedReadAcl = tc.authRead
			b.policyRead = tc.policyRead
			if tc.policy == nil {
				b.Policy = plugin.TValue[any]{State: plugin.StateIsSet | plugin.StateIsNull}
			} else {
				b.Policy = plugin.TValue[any]{Data: tc.policy, State: plugin.StateIsSet}
			}

			got := b.GetIsPublic()
			if tc.wantNull {
				assert.NotZero(t, got.State&plugin.StateIsNull,
					"verdict must be null when a signal was never read")
				return
			}
			assert.Zero(t, got.State&plugin.StateIsNull, "verdict should not be null here")
			assert.Equal(t, tc.want, got.Data)
		})
	}
}

// A fully blocked bucket short-circuits before the ACL is consulted. Spaces
// never reports this, but the branch is shared with S3-compatible services
// that do.
func TestSpacesBucketPublicAccessBlockedShortCircuits(t *testing.T) {
	b := &mqlDigitaloceanSpacesBucket{}
	b.PublicAccessBlocked = boolRead(true)
	b.PublicReadAcl = boolRead(true)

	got := b.GetIsPublic()
	assert.Zero(t, got.State&plugin.StateIsNull)
	assert.False(t, got.Data)
}
