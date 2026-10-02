// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	mailboxUserID = "3c4d5e6f-7a8b-4c9d-8e0f-1a2b3c4d5e6f"
	otherUserID   = "4d5e6f7a-8b9c-4dae-9f10-2b3c4d5e6f7a"
)

// newMailboxTestRuntime returns a runtime whose microsoft.users resource
// carries the given list value, plus a shared mailbox linked to linkedID.
func newMailboxTestRuntime(t *testing.T, list plugin.TValue[[]any], linkedID string) (*mqlMicrosoft, *mqlMs365ExchangeonlineExoMailbox) {
	t.Helper()
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)

	usersRes, err := CreateResource(runtime, "microsoft.users", map[string]*llx.RawData{})
	require.NoError(t, err)
	users := usersRes.(*mqlMicrosoftUsers)
	users.List = list

	msRes, err := CreateResource(runtime, "microsoft", map[string]*llx.RawData{})
	require.NoError(t, err)
	ms := msRes.(*mqlMicrosoft)
	ms.Users = plugin.TValue[*mqlMicrosoftUsers]{Data: users, State: plugin.StateIsSet}

	mbRes, err := CreateResource(runtime, "ms365.exchangeonline.exoMailbox", map[string]*llx.RawData{
		"__id":                      llx.StringData("exoMailbox/shared"),
		"identity":                  llx.StringData("shared"),
		"externalDirectoryObjectId": llx.StringData(linkedID),
	})
	require.NoError(t, err)
	return ms, mbRes.(*mqlMs365ExchangeonlineExoMailbox)
}

func newListedTestUser(t *testing.T, ms *mqlMicrosoft, id, name string) *mqlMicrosoftUser {
	t.Helper()
	res, err := CreateResource(ms.MqlRuntime, "microsoft.user", map[string]*llx.RawData{
		"__id":        llx.StringData(id),
		"id":          llx.StringData(id),
		"displayName": llx.StringData(name),
	})
	require.NoError(t, err)
	return res.(*mqlMicrosoftUser)
}

func TestExoMailboxUser(t *testing.T) {
	t.Run("resolves the linked user from the tenant user list", func(t *testing.T) {
		ms, mailbox := newMailboxTestRuntime(t, plugin.TValue[[]any]{}, mailboxUserID)
		other := newListedTestUser(t, ms, otherUserID, "Other")
		linked := newListedTestUser(t, ms, mailboxUserID, "Shared Inbox")
		ms.Users.Data.List = plugin.TValue[[]any]{Data: []any{other, linked}, State: plugin.StateIsSet}

		user, err := mailbox.user()
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.Equal(t, "Shared Inbox", user.DisplayName.Data)

		indexed, ok := ms.userById(mailboxUserID)
		require.True(t, ok, "the match is indexed so the next mailbox doesn't scan the list")
		assert.Same(t, linked, indexed)
	})

	t.Run("prefers the user index the list already built", func(t *testing.T) {
		ms, mailbox := newMailboxTestRuntime(t, plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}, mailboxUserID)
		linked := newListedTestUser(t, ms, mailboxUserID, "Shared Inbox")
		ms.indexUser(linked)

		user, err := mailbox.user()
		require.NoError(t, err)
		assert.Same(t, linked, user)
	})

	t.Run("a failed user list is an error, not a missing user", func(t *testing.T) {
		listErr := errors.New("Authorization_RequestDenied")
		_, mailbox := newMailboxTestRuntime(t, plugin.TValue[[]any]{State: plugin.StateIsSet, Error: listErr}, mailboxUserID)

		user, err := mailbox.user()
		require.ErrorIs(t, err, listErr)
		assert.Nil(t, user)
	})

	t.Run("a mailbox whose user is not in the directory reads null", func(t *testing.T) {
		ms, mailbox := newMailboxTestRuntime(t, plugin.TValue[[]any]{}, mailboxUserID)
		other := newListedTestUser(t, ms, otherUserID, "Other")
		ms.Users.Data.List = plugin.TValue[[]any]{Data: []any{other}, State: plugin.StateIsSet}

		user, err := mailbox.user()
		require.NoError(t, err)
		assert.Nil(t, user)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, mailbox.User.State)
	})

	t.Run("a mailbox without a directory object reads null", func(t *testing.T) {
		_, mailbox := newMailboxTestRuntime(t, plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}, "")

		user, err := mailbox.user()
		require.NoError(t, err)
		assert.Nil(t, user)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, mailbox.User.State)
	})
}
