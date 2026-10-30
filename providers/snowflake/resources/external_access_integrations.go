// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// mqlSnowflakeExternalAccessIntegrationInternal defers the DESC that populates
// the egress allowlists until one of those fields is queried, so listing many
// integrations for a query that only reads name/enabled does not issue a DESC
// per integration.
type mqlSnowflakeExternalAccessIntegrationInternal struct {
	descOnce         sync.Once
	descNetworkRules []any
	descSecrets      []any
	descApiAuth      []any
}

// External access integrations have no typed SDK object, so they are read with
// raw SHOW / DESC statements through the driver.
func (r *mqlSnowflakeAccount) externalAccessIntegrations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	rows, err := client.QueryUnsafe(ctx, "SHOW EXTERNAL ACCESS INTEGRATIONS")
	if err != nil {
		return nil, err
	}

	list := []any{}
	for _, row := range rows {
		name := unsafeString(row["name"])
		if name == "" {
			continue
		}
		res, err := newMqlSnowflakeExternalAccessIntegration(r.MqlRuntime, name, unsafeBool(row["enabled"]), unsafeString(row["comment"]))
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// initSnowflakeExternalAccessIntegration resolves a single external access
// integration by name so typed references (such as
// snowflake.function.externalAccessIntegrations) can hydrate a full integration
// from just its name.
func initSnowflakeExternalAccessIntegration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, _ := nameRaw.Value.(string)
	if name == "" {
		return nil, nil, fmt.Errorf("snowflake.externalAccessIntegration requires a non-empty name")
	}

	conn := runtime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	rows, err := client.QueryUnsafe(ctx, fmt.Sprintf("SHOW EXTERNAL ACCESS INTEGRATIONS LIKE '%s'", strings.ReplaceAll(name, "'", "''")))
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if unsafeString(row["name"]) != name {
			continue
		}
		res, err := newMqlSnowflakeExternalAccessIntegration(runtime, name, unsafeBool(row["enabled"]), unsafeString(row["comment"]))
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	}
	return nil, nil, fmt.Errorf("snowflake.externalAccessIntegration %q not found", name)
}

// newMqlSnowflakeExternalAccessIntegration builds the resource from the SHOW
// columns only. The egress allowlists are populated lazily via DESC on first
// access (gatherDesc).
func newMqlSnowflakeExternalAccessIntegration(runtime *plugin.Runtime, name string, enabled bool, comment string) (*mqlSnowflakeExternalAccessIntegration, error) {
	res, err := CreateResource(runtime, "snowflake.externalAccessIntegration", map[string]*llx.RawData{
		"__id":    llx.StringData("snowflake.externalAccessIntegration/" + name),
		"name":    llx.StringData(name),
		"enabled": llx.BoolData(enabled),
		"comment": llx.StringData(comment),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlSnowflakeExternalAccessIntegration), nil
}

// gatherDesc runs DESC EXTERNAL ACCESS INTEGRATION once and caches the three
// allowlists it exposes. A DESC failure leaves the lists empty (logged), so a
// permissions/transient error is visible without failing the field.
func (r *mqlSnowflakeExternalAccessIntegration) gatherDesc() {
	r.descOnce.Do(func() {
		r.descNetworkRules = []any{}
		r.descSecrets = []any{}
		r.descApiAuth = []any{}

		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		client := conn.Client()
		ctx := context.Background()

		name := r.Name.Data
		descRows, derr := client.QueryUnsafe(ctx, fmt.Sprintf(`DESC EXTERNAL ACCESS INTEGRATION "%s"`, name))
		if derr != nil {
			log.Warn().Err(derr).Str("integration", name).Msg("snowflake: DESC EXTERNAL ACCESS INTEGRATION failed, allowlists will be empty")
			return
		}
		for _, drow := range descRows {
			value := unsafeString(drow["property_value"])
			switch strings.ToUpper(unsafeString(drow["property"])) {
			case "ALLOWED_NETWORK_RULES":
				r.descNetworkRules = parseExternalAccessList(value)
			case "ALLOWED_AUTHENTICATION_SECRETS":
				r.descSecrets = parseExternalAccessList(value)
			case "ALLOWED_API_AUTHENTICATION_INTEGRATIONS":
				r.descApiAuth = parseExternalAccessList(value)
			}
		}
	})
}

func (r *mqlSnowflakeExternalAccessIntegration) allowedNetworkRules() ([]any, error) {
	r.gatherDesc()
	return r.descNetworkRules, nil
}

func (r *mqlSnowflakeExternalAccessIntegration) allowedAuthenticationSecrets() ([]any, error) {
	r.gatherDesc()
	return r.descSecrets, nil
}

func (r *mqlSnowflakeExternalAccessIntegration) allowedApiAuthenticationIntegrations() ([]any, error) {
	r.gatherDesc()
	return r.descApiAuth, nil
}

// unsafeString coerces a QueryUnsafe cell (which the driver returns as *any) to
// a string.
func unsafeString(v *any) string {
	if v == nil || *v == nil {
		return ""
	}
	switch x := (*v).(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return fmt.Sprintf("%v", x)
	}
}

// unsafeBool coerces a QueryUnsafe cell to a bool, accepting the driver's bool
// or the string form SHOW returns.
func unsafeBool(v *any) bool {
	if v == nil || *v == nil {
		return false
	}
	switch x := (*v).(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(strings.TrimSpace(x), "true")
	default:
		return false
	}
}

// parseExternalAccessList splits a DESC property value like "[DB.SCH.RULE1,
// DB.SCH.RULE2]" into the individual fully qualified names, dropping brackets
// and blank entries.
func parseExternalAccessList(raw string) []any {
	out := []any{}
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	for part := range strings.SplitSeq(raw, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
