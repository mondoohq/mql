// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nextdns/connection"
)

// initNextdnsAccount fills in the derived account id when the resource is
// referenced directly (for example `nextdns.account.id`) rather than reached
// through the `account` accessor on a parent. NextDNS exposes no account
// object, so the id is the connection's stable API-key fingerprint.
func initNextdnsAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["id"]; !ok {
		conn := runtime.Connection.(*connection.NextdnsConnection)
		args["id"] = llx.StringData(conn.AccountID())
	}
	return args, nil, nil
}

func (r *mqlNextdnsAccount) id() (string, error) {
	return "nextdns.account/" + r.Id.Data, nil
}

func (r *mqlNextdnsAccount) profiles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.NextdnsConnection)
	return profilesToResources(r.MqlRuntime, conn)
}
