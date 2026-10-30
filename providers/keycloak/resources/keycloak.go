// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sort"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
)

func (k *mqlKeycloak) id() (string, error) {
	return "keycloak", nil
}

// keycloakConn returns the Keycloak connection backing the runtime.
func keycloakConn(runtime *plugin.Runtime) *connection.KeycloakConnection {
	return runtime.Connection.(*connection.KeycloakConnection)
}

// getKeycloak returns the root resource, which cross-resource accessors go
// through so its cached realm list is reused rather than refetched.
func getKeycloak(runtime *plugin.Runtime) (*mqlKeycloak, error) {
	res, err := CreateResource(runtime, "keycloak", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlKeycloak), nil
}

func (k *mqlKeycloak) serverUrl() (string, error) {
	return keycloakConn(k.MqlRuntime).BaseURL(), nil
}

// realmBrief is the shape of an entry in the realm list. The list endpoint
// answers with brief representations, so the settings each realm carries are
// read from its own endpoint.
type realmBrief struct {
	ID    string `json:"id"`
	Realm string `json:"realm"`
}

// realms lists the realms in scope. With --realm set, only that realm is read,
// which is what lets a service account scoped to one realm work without the
// permission to enumerate the others.
func (k *mqlKeycloak) realms() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(k.MqlRuntime)

	names, err := realmNames(ctx, c)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(names))
	for _, name := range names {
		var rec realmRecord
		if err := c.Get(ctx, connection.AdminPath(name), nil, &rec); err != nil {
			return nil, err
		}
		realm, err := newKeycloakRealm(k.MqlRuntime, &rec)
		if err != nil {
			return nil, err
		}
		res = append(res, realm)
	}
	return res, nil
}

func realmNames(ctx context.Context, c *connection.KeycloakConnection) ([]string, error) {
	if filter := c.RealmFilter(); filter != "" {
		return []string{filter}, nil
	}

	var brief []realmBrief
	if err := c.Get(ctx, "/admin/realms", nil, &brief); err != nil {
		return nil, err
	}

	names := make([]string, 0, len(brief))
	for _, b := range brief {
		if b.Realm != "" {
			names = append(names, b.Realm)
		}
	}
	// The list endpoint does not promise an order, so the assets a scan emits
	// stay comparable between runs only if the order is fixed here.
	sort.Strings(names)
	return names, nil
}

// clients flattens every client of every realm in scope. The realm list is read
// through its cached field so that querying realms and clients together walks
// the realms once rather than once per field.
func (k *mqlKeycloak) clients() ([]any, error) {
	realms := k.GetRealms()
	if realms.Error != nil {
		return nil, realms.Error
	}

	var res []any
	for _, it := range realms.Data {
		realm, ok := it.(*mqlKeycloakRealm)
		if !ok {
			continue
		}
		clients := realm.GetClients()
		if clients.Error != nil {
			return nil, clients.Error
		}
		res = append(res, clients.Data...)
	}
	return res, nil
}

// --- shared helpers -------------------------------------------------------

// strSliceToAny widens a string slice into an any slice for llx.ArrayData.
func strSliceToAny(in []string) []any {
	out := make([]any, len(in))
	for i := range in {
		out[i] = in[i]
	}
	return out
}

// mapStrToAny widens a string map into the any-valued map llx.MapData expects.
func mapStrToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// multiMapToDict widens a map of string lists, which is how Keycloak stores
// every attribute and component setting, into the shape a dict field holds.
func multiMapToDict(in map[string][]string) any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = strSliceToAny(v)
	}
	return out
}

// epochMillisToTime converts a Keycloak timestamp, which counts milliseconds
// since the epoch, into a time. A zero or negative value is reported as null
// rather than as 1 January 1970, which would read as a real date.
func epochMillisToTime(millis int64) *time.Time {
	if millis <= 0 {
		return nil
	}
	t := time.UnixMilli(millis).UTC()
	return &t
}

// firstConfigValue reads a component setting, which Keycloak stores as a list
// even when it holds a single value.
func firstConfigValue(config map[string][]string, key string) string {
	values, ok := config[key]
	if !ok || len(values) == 0 {
		return ""
	}
	return values[0]
}

// configBool reads a setting Keycloak stores as the string "true" or "false".
// An absent or unparseable setting reads as false, which is the state Keycloak
// itself applies when the setting is missing.
func configBool(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "true")
}

// setNullResource marks a singular resource field as resolved and null. The
// runtime needs the state before a nil resource is returned, otherwise it
// treats the field as unresolved and fetches it again.
func setNullResource[T any](field *plugin.TValue[T]) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
}

// clientScopes flattens every client scope of every realm in scope.
func (k *mqlKeycloak) clientScopes() ([]any, error) {
	realms := k.GetRealms()
	if realms.Error != nil {
		return nil, realms.Error
	}

	var res []any
	for _, it := range realms.Data {
		realm, ok := it.(*mqlKeycloakRealm)
		if !ok {
			continue
		}
		scopes := realm.GetClientScopes()
		if scopes.Error != nil {
			return nil, scopes.Error
		}
		res = append(res, scopes.Data...)
	}
	return res, nil
}
