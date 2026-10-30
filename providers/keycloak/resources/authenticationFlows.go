// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/types"
)

// mqlKeycloakAuthenticationFlowInternal holds the realm the flow belongs to,
// which the execution lookup addresses.
type mqlKeycloakAuthenticationFlowInternal struct {
	parentRealm *mqlKeycloakRealm
}

type authenticationFlowRecord struct {
	ID          string `json:"id"`
	Alias       string `json:"alias"`
	Description string `json:"description"`
	ProviderID  string `json:"providerId"`
	TopLevel    bool   `json:"topLevel"`
	BuiltIn     bool   `json:"builtIn"`
}

func newKeycloakAuthenticationFlow(runtime *plugin.Runtime, realm *mqlKeycloakRealm, rec *authenticationFlowRecord) (*mqlKeycloakAuthenticationFlow, error) {
	res, err := CreateResource(runtime, "keycloak.authenticationFlow", map[string]*llx.RawData{
		"__id":        llx.StringData(realm.realmName() + "/flow/" + rec.Alias),
		"id":          llx.StringData(rec.ID),
		"alias":       llx.StringData(rec.Alias),
		"description": llx.StringData(rec.Description),
		"providerId":  llx.StringData(rec.ProviderID),
		"topLevel":    llx.BoolData(rec.TopLevel),
		"builtIn":     llx.BoolData(rec.BuiltIn),
	})
	if err != nil {
		return nil, err
	}

	flow := res.(*mqlKeycloakAuthenticationFlow)
	flow.parentRealm = realm
	return flow, nil
}

func (f *mqlKeycloakAuthenticationFlow) id() (string, error) {
	return f.__id, nil
}

func (f *mqlKeycloakAuthenticationFlow) realm() (*mqlKeycloakRealm, error) {
	if f.parentRealm == nil {
		setNullResource(&f.Realm)
		return nil, nil
	}
	return f.parentRealm, nil
}

type executionRecord struct {
	DisplayName          string   `json:"displayName"`
	ProviderID           string   `json:"providerId"`
	Requirement          string   `json:"requirement"`
	RequirementChoices   []string `json:"requirementChoices"`
	Level                int64    `json:"level"`
	Index                int64    `json:"index"`
	FlowID               string   `json:"flowId"`
	Configurable         bool     `json:"configurable"`
	AuthenticationFlow   bool     `json:"authenticationFlow"`
	AuthenticationConfig string   `json:"authenticationConfig"`
	ID                   string   `json:"id"`
}

// executions lists the steps of the flow in the order they run. A sub-flow is
// returned as a step whose flowAlias names it, so a nested requirement is
// reachable without expanding the tree here.
func (f *mqlKeycloakAuthenticationFlow) executions() ([]any, error) {
	if f.parentRealm == nil {
		return nil, nil
	}

	// Only a top-level flow is addressable by alias. A sub-flow's steps appear
	// in the execution list of the flow that runs it.
	if !f.TopLevel.Data {
		return nil, nil
	}

	ctx := context.Background()
	conn := keycloakConn(f.MqlRuntime)
	path := connection.AdminPath(f.parentRealm.realmName(), "authentication", "flows", f.Alias.Data, "executions")

	var records []executionRecord
	if err := conn.Get(ctx, path, nil, &records); err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]

		// A step carries no identifier of its own on some server versions, so
		// its position in the flow is what keeps the cache key unique.
		key := rec.ID
		if key == "" {
			key = strconv.FormatInt(rec.Level, 10) + "/" + strconv.FormatInt(rec.Index, 10)
		}

		created, err := CreateResource(f.MqlRuntime, "keycloak.authenticationFlow.execution", map[string]*llx.RawData{
			"__id":                 llx.StringData(f.__id + "/execution/" + key),
			"displayName":          llx.StringData(rec.DisplayName),
			"providerId":           llx.StringData(rec.ProviderID),
			"requirement":          llx.StringData(rec.Requirement),
			"requirementChoices":   llx.ArrayData(strSliceToAny(rec.RequirementChoices), types.String),
			"level":                llx.IntData(rec.Level),
			"index":                llx.IntData(rec.Index),
			"flowAlias":            llx.StringData(SubFlowAlias(&rec)),
			"configurable":         llx.BoolData(rec.Configurable),
			"authenticationConfig": llx.StringData(rec.AuthenticationConfig),
		})
		if err != nil {
			return nil, err
		}

		execution := created.(*mqlKeycloakAuthenticationFlowExecution)
		execution.parentFlow = f
		res = append(res, execution)
	}
	return res, nil
}

// SubFlowAlias returns the alias of the sub-flow a step runs, or an empty value
// for a leaf step. Keycloak reports a sub-flow with no authenticator and marks
// it with authenticationFlow, and the display name is the alias it was created
// under.
func SubFlowAlias(rec *executionRecord) string {
	if !rec.AuthenticationFlow {
		return ""
	}
	return rec.DisplayName
}

// mqlKeycloakAuthenticationFlowExecutionInternal holds the flow the step
// belongs to, so the flow accessor costs no call.
type mqlKeycloakAuthenticationFlowExecutionInternal struct {
	parentFlow *mqlKeycloakAuthenticationFlow
}

func (e *mqlKeycloakAuthenticationFlowExecution) id() (string, error) {
	return e.__id, nil
}

func (e *mqlKeycloakAuthenticationFlowExecution) flow() (*mqlKeycloakAuthenticationFlow, error) {
	if e.parentFlow == nil {
		setNullResource(&e.Flow)
		return nil, nil
	}
	return e.parentFlow, nil
}

type executionConfigRecord struct {
	ID     string            `json:"id"`
	Alias  string            `json:"alias"`
	Config map[string]string `json:"config"`
}

// config reads the settings of one step. A step without a configuration
// identifier carries none, so it is answered without a call.
func (e *mqlKeycloakAuthenticationFlowExecution) config() (map[string]any, error) {
	configID := e.AuthenticationConfig.Data
	if configID == "" || e.parentFlow == nil || e.parentFlow.parentRealm == nil {
		return map[string]any{}, nil
	}

	ctx := context.Background()
	conn := keycloakConn(e.MqlRuntime)
	path := connection.AdminPath(e.parentFlow.parentRealm.realmName(), "authentication", "config", configID)

	var rec executionConfigRecord
	if err := conn.Get(ctx, path, nil, &rec); err != nil {
		// A configuration the token cannot read leaves the step's settings
		// unknown, which is reported rather than answered as none.
		return nil, err
	}

	return mapStrToAny(rec.Config), nil
}
