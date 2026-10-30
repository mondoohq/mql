// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

// --- attack protection (org-level singleton) ---

// initOktaAttackProtection populates the singleton on construction. It is an
// init rather than an okta accessor because okta.attackProtection is a
// directly-addressable resource: a field of the same dotted name would collide
// with the resource and leave the fields unset when queried as
// `okta.attackProtection`.
func initOktaAttackProtection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	// Fetched through the extension: the SDK types both attack-protection
	// endpoints as slices, but each returns a single JSON object, so the SDK's
	// Execute() fails to unmarshal.
	settings, _, err := apiSupplement.GetAttackProtectionSettings(ctx)
	if err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData("okta.attackProtection")
	args["preventBruteForceLockoutFromUnknownDevices"] = llx.BoolData(settings.PreventBruteForceLockoutFromUnknownDevices)
	args["verifyKnowledgeSecondWhen2faRequired"] = llx.BoolData(settings.VerifyKnowledgeSecondWhen2faRequired)
	return args, nil, nil
}

// --- behavior detection rules ---

func (o *mqlOkta) behaviorRules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	// Fetched through the extension rather than the SDK: the /api/v1/behaviors
	// endpoint returns non-RFC3339 timestamps ("2026-07-20 17:34:59.0") that
	// break the SDK's strict time unmarshaling.
	rules, resp, err := apiSupplement.ListBehaviorRules(ctx)
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	for i := range rules {
		r, err := newMqlOktaBehaviorRule(o.MqlRuntime, rules[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func newMqlOktaBehaviorRule(runtime *plugin.Runtime, rule map[string]any) (any, error) {
	settings, err := convert.JsonToDict(rule["settings"])
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.behaviorRule", map[string]*llx.RawData{
		"id":          llx.StringData(oktaMapStr(rule, "id")),
		"name":        llx.StringData(oktaMapStr(rule, "name")),
		"type":        llx.StringData(oktaMapStr(rule, "type")),
		"status":      llx.StringData(oktaMapStr(rule, "status")),
		"settings":    llx.DictData(settings),
		"created":     llx.TimeDataPtr(parseOktaTimestamp(oktaMapStr(rule, "created"))),
		"lastUpdated": llx.TimeDataPtr(parseOktaTimestamp(oktaMapStr(rule, "lastUpdated"))),
	})
}

func (o *mqlOktaBehaviorRule) id() (string, error) {
	return "okta.behaviorRule/" + o.Id.Data, o.Id.Error
}

// oktaMapStr reads a string value from an untyped JSON map, returning "" when
// the key is missing or not a string.
func oktaMapStr(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// parseOktaTimestamp parses the timestamp forms Okta returns, including the
// legacy space-separated form some endpoints (behaviors) use in addition to
// RFC3339. Returns nil when the value is empty or unparseable so the field
// renders as null rather than a zero time.
func parseOktaTimestamp(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// --- risk providers ---

func (o *mqlOkta) riskProviders() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	slice, resp, err := conn.ApiExtension().ListRiskProviders(ctx)
	if err != nil {
		// The risk providers endpoint is not available on every org edition
		// and answers 410 Gone (or 404) when the feature is absent. That is a
		// list we could not read, not a list we read and found empty, so it
		// degrades to null: an empty list would assert the org has no risk
		// providers, and an audit written on that would pass without anything
		// having been checked.
		if resp != nil && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			return oktaUnreadableList(&o.RiskProviders)
		}
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.RiskProvider) error {
		for i := range datalist {
			r, err := newMqlOktaRiskProvider(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	// ListRiskProviders follows the Link header itself, so slice is already
	// every page.
	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	return list, nil
}

func newMqlOktaRiskProvider(runtime *plugin.Runtime, entry *okta.RiskProvider) (any, error) {
	return CreateResource(runtime, "okta.riskProvider", map[string]*llx.RawData{
		"id":          llx.StringData(entry.Id),
		"name":        llx.StringData(entry.Name),
		"action":      llx.StringData(entry.Action),
		"clientId":    llx.StringData(entry.ClientId),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaRiskProvider) id() (string, error) {
	return "okta.riskProvider/" + o.Id.Data, o.Id.Error
}

// --- security events providers (shared signals framework) ---

func (o *mqlOkta) securityEventsProviders() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.SSFReceiverAPI.ListSecurityEventsProviderInstances(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.SecurityEventsProviderResponse) error {
		for i := range datalist {
			r, err := newMqlOktaSecurityEventsProvider(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.SecurityEventsProviderResponse
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaSecurityEventsProvider(runtime *plugin.Runtime, entry *okta.SecurityEventsProviderResponse) (any, error) {
	settings, err := convert.JsonToDict(entry.Settings)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.securityEventsProvider", map[string]*llx.RawData{
		"id":       llx.StringData(oktaStr(entry.Id)),
		"name":     llx.StringData(oktaStr(entry.Name)),
		"type":     llx.StringData(oktaStr(entry.Type)),
		"status":   llx.StringData(oktaStr(entry.Status)),
		"settings": llx.DictData(settings),
	})
}

func (o *mqlOktaSecurityEventsProvider) id() (string, error) {
	return "okta.securityEventsProvider/" + o.Id.Data, o.Id.Error
}
