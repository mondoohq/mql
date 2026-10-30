// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"sync/atomic"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/tailscale/connection"
	tsclient "tailscale.com/client/tailscale/v2"
)

// mqlTailscaleInternal caches tailnet-level settings so multiple field accessors
// share the result of a single TailnetSettings API call. settingsFetched is
// atomic because the accessors that read it are distinct MQL fields, which the
// runtime may resolve concurrently.
//
// The three memos below back the cross-resource references. Each one is read
// once per referring resource, so without memoization a tailnet of N devices
// would issue N user lists. See identity.go.
type mqlTailscaleInternal struct {
	settingsLock    sync.Mutex
	settingsFetched atomic.Bool
	settings        *tsclient.TailnetSettings

	userIndexMemo   memo[userIndex]
	deviceListMemo  memo[[]any]
	authKeyListMemo memo[[]any]
}

func (r *mqlTailscale) id() (string, error) {
	return r.Tailnet.Data, nil
}

func initTailscale(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.TailscaleConnection)
	mqlResource, err := CreateResource(runtime, "tailscale",
		map[string]*llx.RawData{
			"tailnet": llx.StringData(conn.ResolveTailnet()),
		})
	if err != nil {
		return args, nil, err
	}
	return args, mqlResource, nil
}

func (t *mqlTailscale) devices() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)
	// The default field set omits subnet routes, posture identity, SSH state
	// and connectivity. Requesting all fields fills them from this one call
	// instead of a follow-up request per device.
	devices, err := conn.Client().Devices().List(context.Background(),
		tsclient.WithFields(tsclient.IncludeFieldsAll))
	if err != nil {
		return nil, err
	}

	var resources []any
	for _, device := range devices {
		resource, err := createTailscaleDeviceResource(t.MqlRuntime, &device)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

func (t *mqlTailscale) users() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)
	// TODO we can do filter here for user type and role
	users, err := conn.Client().Users().List(context.Background(), nil, nil)
	if err != nil {
		return nil, err
	}

	var resources []any
	for _, user := range users {
		resource, err := createTailscaleUserResource(t.MqlRuntime, &user)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}

	return resources, nil
}

func (t *mqlTailscale) nameservers() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)
	nameservers, err := conn.Client().DNS().Nameservers(context.Background())
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(nameservers), nil
}

// fetchSettings returns the cached TailnetSettings, fetching it on first call.
// Multiple tailnet-level field accessors share the same response.
func (t *mqlTailscale) fetchSettings() (*tsclient.TailnetSettings, error) {
	if t.settingsFetched.Load() {
		return t.settings, nil
	}
	t.settingsLock.Lock()
	defer t.settingsLock.Unlock()
	if t.settingsFetched.Load() {
		return t.settings, nil
	}
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)
	settings, err := conn.Client().TailnetSettings().Get(context.Background())
	if err != nil {
		return nil, err
	}
	t.settings = settings
	t.settingsFetched.Store(true)
	return t.settings, nil
}

func (t *mqlTailscale) deviceApprovalRequired() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.DevicesApprovalOn, nil
}

func (t *mqlTailscale) userApprovalRequired() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.UsersApprovalOn, nil
}

func (t *mqlTailscale) devicesAutoUpdatesEnabled() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.DevicesAutoUpdatesOn, nil
}

func (t *mqlTailscale) devicesKeyDurationDays() (int64, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return 0, err
	}
	return int64(s.DevicesKeyDurationDays), nil
}

func (t *mqlTailscale) networkFlowLoggingEnabled() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.NetworkFlowLoggingOn, nil
}

func (t *mqlTailscale) postureIdentityCollectionEnabled() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.PostureIdentityCollectionOn, nil
}

func (t *mqlTailscale) regionalRoutingEnabled() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.RegionalRoutingOn, nil
}

func (t *mqlTailscale) routeSelection() (string, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return "", err
	}
	if s.RouteSelection == "" {
		t.RouteSelection.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(s.RouteSelection), nil
}

func (t *mqlTailscale) httpsEnabled() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.HTTPSEnabled, nil
}

func (t *mqlTailscale) aclsExternallyManaged() (bool, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.ACLsExternallyManagedOn, nil
}

func (t *mqlTailscale) aclsExternalLink() (string, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return "", err
	}
	return s.ACLsExternalLink, nil
}

func (t *mqlTailscale) usersRoleAllowedToJoinExternalTailnets() (string, error) {
	s, err := t.fetchSettings()
	if err != nil {
		return "", err
	}
	return string(s.UsersRoleAllowedToJoinExternalTailnets), nil
}

func (t *mqlTailscale) aclPolicy() (*mqlTailscaleAclPolicy, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)
	ctx := context.Background()

	acl, err := conn.Client().PolicyFile().Get(ctx)
	if err != nil {
		return nil, err
	}

	resource, err := createTailscaleAclPolicyResource(t.MqlRuntime, t.Tailnet.Data, acl)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlTailscaleAclPolicy), nil
}
