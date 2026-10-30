// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/types"
)

// --- realm signing keys ---------------------------------------------------

// keyStatusActive is the state of a key the realm signs new tokens with. A
// PASSIVE key only validates tokens already issued, and a DISABLED key does
// neither.
const keyStatusActive = "ACTIVE"

type realmKeysResponse struct {
	Keys []realmKeyRecord `json:"keys"`
}

type realmKeyRecord struct {
	Kid              string `json:"kid"`
	Algorithm        string `json:"algorithm"`
	Type             string `json:"type"`
	Use              string `json:"use"`
	Status           string `json:"status"`
	ProviderID       string `json:"providerId"`
	ProviderPriority int64  `json:"providerPriority"`
	Certificate      string `json:"certificate"`
	PublicKey        string `json:"publicKey"`
}

type mqlKeycloakRealmKeyInternal struct {
	parentRealm *mqlKeycloakRealm
}

func (r *mqlKeycloakRealm) keys() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	var resp realmKeysResponse
	if err := c.Get(ctx, connection.AdminPath(r.realmName(), "keys"), nil, &resp); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(resp.Keys))
	for i := range resp.Keys {
		rec := resp.Keys[i]

		created, err := CreateResource(r.MqlRuntime, "keycloak.realm.key", map[string]*llx.RawData{
			"__id":             llx.StringData(r.realmName() + "/key/" + rec.Kid),
			"kid":              llx.StringData(rec.Kid),
			"algorithm":        llx.StringData(rec.Algorithm),
			"type":             llx.StringData(rec.Type),
			"use":              llx.StringData(rec.Use),
			"status":           llx.StringData(rec.Status),
			"providerId":       llx.StringData(rec.ProviderID),
			"providerPriority": llx.IntData(rec.ProviderPriority),
			"certificate":      llx.StringData(rec.Certificate),
			"publicKey":        llx.StringData(rec.PublicKey),
			"isActive":         llx.BoolData(IsActiveKey(rec.Status)),
		})
		if err != nil {
			return nil, err
		}

		key := created.(*mqlKeycloakRealmKey)
		key.parentRealm = r
		res = append(res, key)
	}
	return res, nil
}

// IsActiveKey reports whether the realm signs new tokens with a key of this
// status. The comparison ignores case and surrounding space, since the value
// is a server-side enum rendered as a string.
func IsActiveKey(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), keyStatusActive)
}

func (k *mqlKeycloakRealmKey) id() (string, error) {
	return k.__id, nil
}

func (k *mqlKeycloakRealmKey) realm() (*mqlKeycloakRealm, error) {
	if k.parentRealm == nil {
		setNullResource(&k.Realm)
		return nil, nil
	}
	return k.parentRealm, nil
}

// --- events configuration -------------------------------------------------

type eventsConfigRecord struct {
	EventsEnabled             bool     `json:"eventsEnabled"`
	EventsExpiration          int64    `json:"eventsExpiration"`
	EnabledEventTypes         []string `json:"enabledEventTypes"`
	EventsListeners           []string `json:"eventsListeners"`
	AdminEventsEnabled        bool     `json:"adminEventsEnabled"`
	AdminEventsDetailsEnabled bool     `json:"adminEventsDetailsEnabled"`
}

type mqlKeycloakRealmEventsConfigInternal struct {
	parentRealm *mqlKeycloakRealm
}

func (r *mqlKeycloakRealm) eventsConfig() (*mqlKeycloakRealmEventsConfig, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	var rec eventsConfigRecord
	if err := c.Get(ctx, connection.AdminPath(r.realmName(), "events", "config"), nil, &rec); err != nil {
		return nil, err
	}

	created, err := CreateResource(r.MqlRuntime, "keycloak.realm.eventsConfig", map[string]*llx.RawData{
		"__id":                      llx.StringData(r.realmName() + "/eventsConfig"),
		"eventsEnabled":             llx.BoolData(rec.EventsEnabled),
		"eventsExpiration":          llx.IntData(rec.EventsExpiration),
		"enabledEventTypes":         llx.ArrayData(strSliceToAny(rec.EnabledEventTypes), types.String),
		"eventsListeners":           llx.ArrayData(strSliceToAny(rec.EventsListeners), types.String),
		"adminEventsEnabled":        llx.BoolData(rec.AdminEventsEnabled),
		"adminEventsDetailsEnabled": llx.BoolData(rec.AdminEventsDetailsEnabled),
	})
	if err != nil {
		return nil, err
	}

	config := created.(*mqlKeycloakRealmEventsConfig)
	config.parentRealm = r
	return config, nil
}

func (e *mqlKeycloakRealmEventsConfig) id() (string, error) {
	return e.__id, nil
}

func (e *mqlKeycloakRealmEventsConfig) realm() (*mqlKeycloakRealm, error) {
	if e.parentRealm == nil {
		setNullResource(&e.Realm)
		return nil, nil
	}
	return e.parentRealm, nil
}

// --- client profiles and policies -----------------------------------------

type clientProfilesResponse struct {
	Profiles       []clientProfileRecord `json:"profiles"`
	GlobalProfiles []clientProfileRecord `json:"globalProfiles"`
}

type clientProfileRecord struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Executors   []clientExecutor `json:"executors"`
}

type clientExecutor struct {
	Executor      string         `json:"executor"`
	Configuration map[string]any `json:"configuration"`
}

type clientPoliciesResponse struct {
	Policies       []clientPolicyRecord `json:"policies"`
	GlobalPolicies []clientPolicyRecord `json:"globalPolicies"`
}

type clientPolicyRecord struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Enabled     bool              `json:"enabled"`
	Profiles    []string          `json:"profiles"`
	Conditions  []clientCondition `json:"conditions"`
}

type clientCondition struct {
	Condition     string         `json:"condition"`
	Configuration map[string]any `json:"configuration"`
}

type mqlKeycloakClientProfileInternal struct {
	parentRealm *mqlKeycloakRealm
}

type mqlKeycloakClientPolicyInternal struct {
	parentRealm *mqlKeycloakRealm
}

// clientProfiles lists the profiles the realm defines together with the ones
// Keycloak ships. Both lists are walked, since a policy may name either and
// reading only the realm's own would report a built-in profile as missing.
func (r *mqlKeycloakRealm) clientProfiles() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	query := connection.IncludeGlobals(connection.IncludeGlobalProfilesParam)
	var resp clientProfilesResponse
	if err := c.Get(ctx, connection.AdminPath(r.realmName(), "client-policies", "profiles"), query, &resp); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(resp.Profiles)+len(resp.GlobalProfiles))
	for _, group := range []struct {
		records []clientProfileRecord
		builtIn bool
	}{
		{records: resp.Profiles},
		{records: resp.GlobalProfiles, builtIn: true},
	} {
		for i := range group.records {
			profile, err := newKeycloakClientProfile(r, &group.records[i], group.builtIn)
			if err != nil {
				return nil, err
			}
			res = append(res, profile)
		}
	}
	return res, nil
}

func newKeycloakClientProfile(realm *mqlKeycloakRealm, rec *clientProfileRecord, builtIn bool) (*mqlKeycloakClientProfile, error) {
	executorTypes := make([]string, 0, len(rec.Executors))
	executors := make([]any, 0, len(rec.Executors))
	for _, ex := range rec.Executors {
		executorTypes = append(executorTypes, ex.Executor)
		executors = append(executors, map[string]any{
			"executor":      ex.Executor,
			"configuration": ex.Configuration,
		})
	}

	created, err := CreateResource(realm.MqlRuntime, "keycloak.clientProfile", map[string]*llx.RawData{
		"__id":          llx.StringData(realm.realmName() + "/clientProfile/" + rec.Name),
		"name":          llx.StringData(rec.Name),
		"description":   llx.StringData(rec.Description),
		"isBuiltIn":     llx.BoolData(builtIn),
		"executorTypes": llx.ArrayData(strSliceToAny(executorTypes), types.String),
		"executors":     llx.DictData(executors),
	})
	if err != nil {
		return nil, err
	}

	profile := created.(*mqlKeycloakClientProfile)
	profile.parentRealm = realm
	return profile, nil
}

func (p *mqlKeycloakClientProfile) id() (string, error) {
	return p.__id, nil
}

func (p *mqlKeycloakClientProfile) realm() (*mqlKeycloakRealm, error) {
	if p.parentRealm == nil {
		setNullResource(&p.Realm)
		return nil, nil
	}
	return p.parentRealm, nil
}

// clientPolicies lists the policies the realm defines together with the ones
// Keycloak ships, since either can be the one that puts a profile in force.
func (r *mqlKeycloakRealm) clientPolicies() ([]any, error) {
	ctx := context.Background()
	c := keycloakConn(r.MqlRuntime)

	query := connection.IncludeGlobals(
		connection.IncludeGlobalPoliciesParam,
		connection.IncludeGlobalClientPoliciesParam,
	)
	var resp clientPoliciesResponse
	if err := c.Get(ctx, connection.AdminPath(r.realmName(), "client-policies", "policies"), query, &resp); err != nil {
		return nil, err
	}

	records := append(append([]clientPolicyRecord{}, resp.Policies...), resp.GlobalPolicies...)

	res := make([]any, 0, len(records))
	for i := range records {
		policy, err := newKeycloakClientPolicy(r, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, policy)
	}
	return res, nil
}

func newKeycloakClientPolicy(realm *mqlKeycloakRealm, rec *clientPolicyRecord) (*mqlKeycloakClientPolicy, error) {
	conditionTypes := make([]string, 0, len(rec.Conditions))
	conditions := make([]any, 0, len(rec.Conditions))
	for _, cond := range rec.Conditions {
		conditionTypes = append(conditionTypes, cond.Condition)
		conditions = append(conditions, map[string]any{
			"condition":     cond.Condition,
			"configuration": cond.Configuration,
		})
	}

	created, err := CreateResource(realm.MqlRuntime, "keycloak.clientPolicy", map[string]*llx.RawData{
		"__id":           llx.StringData(realm.realmName() + "/clientPolicy/" + rec.Name),
		"name":           llx.StringData(rec.Name),
		"description":    llx.StringData(rec.Description),
		"enabled":        llx.BoolData(rec.Enabled),
		"profiles":       llx.ArrayData(strSliceToAny(rec.Profiles), types.String),
		"conditionTypes": llx.ArrayData(strSliceToAny(conditionTypes), types.String),
		"conditions":     llx.DictData(conditions),
	})
	if err != nil {
		return nil, err
	}

	policy := created.(*mqlKeycloakClientPolicy)
	policy.parentRealm = realm
	return policy, nil
}

func (p *mqlKeycloakClientPolicy) id() (string, error) {
	return p.__id, nil
}

func (p *mqlKeycloakClientPolicy) realm() (*mqlKeycloakRealm, error) {
	if p.parentRealm == nil {
		setNullResource(&p.Realm)
		return nil, nil
	}
	return p.parentRealm, nil
}
