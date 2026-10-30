// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// memo caches the result of one computation, error included, and shares it
// across every resource that needs it.
//
// The cross-resource references are read once per referring resource, so a
// per-reference fetch would scale with the size of the tailnet. Caching the
// error alongside the value matters just as much: a tailnet whose user list
// cannot be read would otherwise retry the failing call once per device.
//
// done is atomic rather than a plain bool so a reader that observes it set
// also observes the value and error written before it, without taking the
// lock. This mirrors the settingsFetched memo on the tailnet resource.
type memo[T any] struct {
	lock  sync.Mutex
	done  atomic.Bool
	value T
	err   error
}

func (m *memo[T]) get(compute func() (T, error)) (T, error) {
	if m.done.Load() {
		return m.value, m.err
	}
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.done.Load() {
		return m.value, m.err
	}
	m.value, m.err = compute()
	m.done.Store(true)
	return m.value, m.err
}

// userIndex resolves an account by either of the two handles the Tailscale API
// uses to name one.
//
// The handles are not interchangeable at the API: a device and a webhook name
// their account by login name, while a tailnet key names it by user id, and
// Users().Get accepts only the id. Indexing the one user list under both keys
// is what lets all three references resolve without a per-item request.
type userIndex map[string]*mqlTailscaleUser

// buildUserIndex keys the tailnet's users by login name and by id. Ids are
// applied second so that in the improbable event a login name collides with
// another account's id, the id wins and `tailscale.user(id:)` semantics hold.
func buildUserIndex(users []any) userIndex {
	// One entry per user is a lower bound rather than the final size, since an
	// account contributes both a login name and an id. Sizing to the count we
	// know keeps the hint free of arithmetic; the map grows past it on its own.
	index := make(userIndex, len(users))

	for _, entry := range users {
		// Comma-ok rather than a bare assertion: an unexpected entry in a
		// cached list would otherwise panic inside a provider goroutine and
		// take down the whole scan, not just this query.
		user, ok := entry.(*mqlTailscaleUser)
		if !ok || user == nil {
			continue
		}
		if login := user.LoginName.Data; login != "" && user.LoginName.Error == nil {
			index[login] = user
		}
	}

	for _, entry := range users {
		user, ok := entry.(*mqlTailscaleUser)
		if !ok || user == nil {
			continue
		}
		if id := user.Id.Data; id != "" && user.Id.Error == nil {
			index[id] = user
		}
	}

	return index
}

// lookup returns the account named by key, or nil when the tailnet has no such
// account. An empty key names nobody and never matches.
func (i userIndex) lookup(key string) *mqlTailscaleUser {
	if key == "" {
		return nil
	}
	return i[key]
}

// resolveUserIndex returns the tailnet's user index, building it from a single
// Users().List on first use.
func (t *mqlTailscale) resolveUserIndex() (userIndex, error) {
	return t.userIndexMemo.get(func() (userIndex, error) {
		users, err := t.users()
		if err != nil {
			return nil, err
		}
		return buildUserIndex(users), nil
	})
}

// resolveDevices returns the tailnet's device list, fetched once and shared by
// every user that reports the devices registered to it.
func (t *mqlTailscale) resolveDevices() ([]any, error) {
	return t.deviceListMemo.get(t.devices)
}

// resolveAuthKeys returns the tailnet's key list, fetched once and shared by
// every user that reports the keys it owns. The list endpoint returns ids
// only, so building this costs one request per key; re-walking it per user
// would multiply that by the size of the tailnet.
func (t *mqlTailscale) resolveAuthKeys() ([]any, error) {
	return t.authKeyListMemo.get(t.authKeys)
}

// lookupTailscaleUser resolves an account named by id or by login name.
//
// It goes through the tailnet's memoized user list rather than
// NewResource("tailscale.user"): that init runs before the runtime cache is
// consulted and would issue a Users().Get per reference, and it accepts only
// an id, so a login name would come back as an error. Resolving out of the
// list also hands back the same resource instances the tailnet's users field
// produced, because CreateResource returns the cache hit on a matching id.
func lookupTailscaleUser(runtime *plugin.Runtime, key string) (*mqlTailscaleUser, error) {
	if key == "" {
		return nil, nil
	}

	tailnet, err := getMqlTailscale(runtime)
	if err != nil {
		return nil, err
	}

	index, err := tailnet.resolveUserIndex()
	if err != nil {
		return nil, err
	}

	return index.lookup(key), nil
}

// owner resolves the account a device is registered to. A tagged device and a
// device shared in from another tailnet are attributed to no account here, so
// both report null.
func (d *mqlTailscaleDevice) owner() (*mqlTailscaleUser, error) {
	if d.User.Error != nil {
		return nil, d.User.Error
	}

	user, err := lookupTailscaleUser(d.MqlRuntime, d.User.Data)
	if err != nil {
		return nil, err
	}
	if user == nil {
		d.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

// user resolves the account a tailnet key was issued under. A key whose owner
// has since left the tailnet reports null.
func (k *mqlTailscaleAuthKey) user() (*mqlTailscaleUser, error) {
	if k.UserId.Error != nil {
		return nil, k.UserId.Error
	}

	user, err := lookupTailscaleUser(k.MqlRuntime, k.UserId.Data)
	if err != nil {
		return nil, err
	}
	if user == nil {
		k.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

// creator resolves the account that registered a webhook endpoint. Tailscale
// keeps reporting the creator's login name after the account leaves the
// tailnet, so this reports null while creatorLoginName still names them.
func (w *mqlTailscaleWebhook) creator() (*mqlTailscaleUser, error) {
	if w.CreatorLoginName.Error != nil {
		return nil, w.CreatorLoginName.Error
	}

	user, err := lookupTailscaleUser(w.MqlRuntime, w.CreatorLoginName.Data)
	if err != nil {
		return nil, err
	}
	if user == nil {
		w.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

// devicesRegisteredBy selects the devices attributed to a login name. An empty
// login name names nobody, so nothing matches it, including a device that
// carries no user of its own.
func devicesRegisteredBy(devices []any, loginName string) []any {
	matches := []any{}
	if loginName == "" {
		return matches
	}

	for _, entry := range devices {
		device, ok := entry.(*mqlTailscaleDevice)
		if !ok || device == nil {
			continue
		}
		if device.User.Error == nil && device.User.Data == loginName {
			matches = append(matches, device)
		}
	}
	return matches
}

// authKeysOwnedBy selects the tailnet keys issued under a user id. An empty id
// names nobody, so nothing matches it.
func authKeysOwnedBy(keys []any, userId string) []any {
	matches := []any{}
	if userId == "" {
		return matches
	}

	for _, entry := range keys {
		key, ok := entry.(*mqlTailscaleAuthKey)
		if !ok || key == nil {
			continue
		}
		if key.UserId.Error == nil && key.UserId.Data == userId {
			matches = append(matches, key)
		}
	}
	return matches
}

// devices lists the devices registered to this account. The tailnet's device
// list backs it, so reporting this for every user costs one request rather
// than one per user.
func (u *mqlTailscaleUser) devices() ([]any, error) {
	if u.LoginName.Error != nil {
		return nil, u.LoginName.Error
	}

	tailnet, err := getMqlTailscale(u.MqlRuntime)
	if err != nil {
		return nil, err
	}

	devices, err := tailnet.resolveDevices()
	if err != nil {
		return nil, err
	}

	return devicesRegisteredBy(devices, u.LoginName.Data), nil
}

// authKeys lists the tailnet keys issued under this account, drawn from the
// tailnet's key list so the per-key metadata fetch happens once for the whole
// tailnet rather than once per user.
func (u *mqlTailscaleUser) authKeys() ([]any, error) {
	if u.Id.Error != nil {
		return nil, u.Id.Error
	}

	tailnet, err := getMqlTailscale(u.MqlRuntime)
	if err != nil {
		return nil, err
	}

	keys, err := tailnet.resolveAuthKeys()
	if err != nil {
		return nil, err
	}

	return authKeysOwnedBy(keys, u.Id.Data), nil
}
