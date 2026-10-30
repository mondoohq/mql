// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func stringValue(s string) plugin.TValue[string] {
	return plugin.TValue[string]{Data: s, State: plugin.StateIsSet}
}

func testUser(id, loginName string) *mqlTailscaleUser {
	return &mqlTailscaleUser{
		Id:        stringValue(id),
		LoginName: stringValue(loginName),
	}
}

func testDevice(id, user string) *mqlTailscaleDevice {
	return &mqlTailscaleDevice{
		Id:   stringValue(id),
		User: stringValue(user),
	}
}

func testAuthKey(id, userId string) *mqlTailscaleAuthKey {
	return &mqlTailscaleAuthKey{
		Id:     stringValue(id),
		UserId: stringValue(userId),
	}
}

func TestBuildUserIndexAndLookup(t *testing.T) {
	alice := testUser("uid-alice", "alice@example.com")
	bob := testUser("uid-bob", "bob@example.com")
	index := buildUserIndex([]any{alice, bob})

	t.Run("hit by id", func(t *testing.T) {
		// A tailnet key names its owner by user id.
		assert.Same(t, alice, index.lookup("uid-alice"))
	})

	t.Run("hit by login name", func(t *testing.T) {
		// A device and a webhook name their account by login name, which
		// Users().Get would reject. Indexing both handles is the whole point.
		assert.Same(t, bob, index.lookup("bob@example.com"))
	})

	t.Run("miss", func(t *testing.T) {
		// A departed account still named by a webhook's creatorLoginName.
		assert.Nil(t, index.lookup("carol@example.com"))
	})

	t.Run("empty key names nobody", func(t *testing.T) {
		// A tagged device carries no user. It must not collide with an
		// account that happens to index under the empty string.
		assert.Nil(t, index.lookup(""))
	})
}

func TestBuildUserIndexSkipsUnusableEntries(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		index := buildUserIndex(nil)
		assert.Empty(t, index)
		assert.Nil(t, index.lookup("uid-alice"))
	})

	t.Run("entry of another type is skipped, not asserted", func(t *testing.T) {
		// A bare type assertion here would panic inside a provider goroutine
		// and take down the entire scan rather than this one query.
		alice := testUser("uid-alice", "alice@example.com")
		index := buildUserIndex([]any{testDevice("d1", "alice@example.com"), nil, alice})
		assert.Same(t, alice, index.lookup("uid-alice"))
		assert.Len(t, index, 2)
	})

	t.Run("blank handles are not indexed", func(t *testing.T) {
		index := buildUserIndex([]any{testUser("", "")})
		assert.Empty(t, index)
	})

	t.Run("a user with only one handle is still reachable", func(t *testing.T) {
		u := testUser("uid-shared", "")
		index := buildUserIndex([]any{u})
		assert.Same(t, u, index.lookup("uid-shared"))
		assert.Len(t, index, 1)
	})

	t.Run("an errored handle is not indexed", func(t *testing.T) {
		u := testUser("uid-alice", "alice@example.com")
		u.LoginName = plugin.TValue[string]{Error: errors.New("unreadable"), State: plugin.StateIsSet | plugin.StateIsNull}
		index := buildUserIndex([]any{u})
		assert.Same(t, u, index.lookup("uid-alice"))
		assert.Nil(t, index.lookup("alice@example.com"))
	})

	t.Run("an id wins over a colliding login name", func(t *testing.T) {
		// Improbable, but the id is the handle the API treats as canonical,
		// so resolution stays deterministic if the two ever collide.
		byLogin := testUser("uid-1", "shared-handle")
		byId := testUser("shared-handle", "other@example.com")
		index := buildUserIndex([]any{byLogin, byId})
		assert.Same(t, byId, index.lookup("shared-handle"))
	})
}

func TestDevicesRegisteredBy(t *testing.T) {
	laptop := testDevice("d1", "alice@example.com")
	phone := testDevice("d2", "alice@example.com")
	server := testDevice("d3", "bob@example.com")
	tagged := testDevice("d4", "")
	devices := []any{laptop, phone, server, tagged, nil, testUser("uid-x", "x@example.com")}

	t.Run("selects only the account's devices", func(t *testing.T) {
		got := devicesRegisteredBy(devices, "alice@example.com")
		assert.Equal(t, []any{laptop, phone}, got)
	})

	t.Run("account with nothing enrolled reports empty, not null", func(t *testing.T) {
		got := devicesRegisteredBy(devices, "carol@example.com")
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("empty login name matches nothing, including a tagged device", func(t *testing.T) {
		got := devicesRegisteredBy(devices, "")
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("empty device list", func(t *testing.T) {
		got := devicesRegisteredBy(nil, "alice@example.com")
		require.NotNil(t, got)
		assert.Empty(t, got)
	})
}

func TestAuthKeysOwnedBy(t *testing.T) {
	oauth := testAuthKey("k1", "uid-alice")
	preauth := testAuthKey("k2", "uid-alice")
	other := testAuthKey("k3", "uid-bob")
	orphan := testAuthKey("k4", "")
	keys := []any{oauth, preauth, other, orphan, nil, testDevice("d1", "alice@example.com")}

	t.Run("selects only the account's keys", func(t *testing.T) {
		assert.Equal(t, []any{oauth, preauth}, authKeysOwnedBy(keys, "uid-alice"))
	})

	t.Run("account owning no keys reports empty, not null", func(t *testing.T) {
		got := authKeysOwnedBy(keys, "uid-carol")
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("empty user id matches nothing", func(t *testing.T) {
		got := authKeysOwnedBy(keys, "")
		require.NotNil(t, got)
		assert.Empty(t, got)
	})
}

func TestMemo(t *testing.T) {
	t.Run("computes once and shares the value", func(t *testing.T) {
		var m memo[int]
		calls := 0
		compute := func() (int, error) {
			calls++
			return 42, nil
		}

		for range 3 {
			got, err := m.get(compute)
			require.NoError(t, err)
			assert.Equal(t, 42, got)
		}
		assert.Equal(t, 1, calls, "the underlying list must be fetched once, not once per reference")
	})

	t.Run("a failed read is not retried per reference", func(t *testing.T) {
		var m memo[int]
		calls := 0
		wantErr := errors.New("user list unavailable")
		compute := func() (int, error) {
			calls++
			return 0, wantErr
		}

		for range 3 {
			_, err := m.get(compute)
			assert.ErrorIs(t, err, wantErr)
		}
		assert.Equal(t, 1, calls, "a tailnet whose user list cannot be read must not retry once per device")
	})

	t.Run("concurrent readers see one computation", func(t *testing.T) {
		var m memo[int]
		var mu sync.Mutex
		calls := 0
		compute := func() (int, error) {
			mu.Lock()
			calls++
			mu.Unlock()
			return 7, nil
		}

		var wg sync.WaitGroup
		for range 64 {
			wg.Go(func() {
				got, err := m.get(compute)
				assert.NoError(t, err)
				assert.Equal(t, 7, got)
			})
		}
		wg.Wait()
		assert.Equal(t, 1, calls)
	})
}
