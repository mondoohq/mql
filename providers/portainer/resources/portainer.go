// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

// unixTimePtr converts a Portainer Unix-seconds timestamp into a *time.Time,
// returning nil when the value is 0 so the field resolves to null ("unset")
// instead of the 1970 epoch.
func unixTimePtr(sec int64) *time.Time {
	if sec == 0 {
		return nil
	}
	t := time.Unix(sec, 0).UTC()
	return &t
}

func (r *mqlPortainer) id() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	if id := conn.InstanceID(); id != "" {
		return "portainer/" + id, nil
	}
	return "portainer", nil
}

func (r *mqlPortainer) version() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	return conn.Version(), nil
}

func (r *mqlPortainer) instanceId() (string, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	return conn.InstanceID(), nil
}

// resolvePortainerEnvironment resolves an environment (endpoint) id to its
// resource through the connection's cached environment list, so a reference
// costs no extra API call. The field state is set to null when the id is unset
// or names an environment the token cannot see, which is what the caller's
// nil result means.
func resolvePortainerEnvironment(runtime *plugin.Runtime, conn *connection.PortainerConnection, id int64, field *plugin.TValue[*mqlPortainerEnvironment]) (*mqlPortainerEnvironment, error) {
	// Portainer environment ids start at 1; 0 means unset.
	if id == 0 {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	endpoints, err := conn.Endpoints()
	if err != nil {
		return nil, err
	}
	for _, e := range endpoints {
		if e.ID == id {
			return newMqlPortainerEnvironment(runtime, e)
		}
	}
	field.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// grantedAuthorizations returns the names of the authorizations set to true, in
// ascending order. Portainer reports an authorization map that carries both
// granted and revoked entries, so the false ones must be dropped rather than
// counted as grants.
//
// A nil map means the instance computed no authorizations at all, which is not
// the same as an account holding none, so it is reported as null by returning
// nil with ok false.
func grantedAuthorizations(auths map[string]bool) ([]any, bool) {
	if auths == nil {
		return nil, false
	}
	names := make([]string, 0, len(auths))
	for name, granted := range auths {
		if granted {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	res := make([]any, 0, len(names))
	for _, name := range names {
		res = append(res, name)
	}
	return res, true
}
