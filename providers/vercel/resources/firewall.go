// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vercel/connection"
	"go.mondoo.com/mql/types"
)

// mqlVercelFirewallInternal caches the firewall scope and the rules fetched with
// the active configuration so rules() and ipRules() avoid a second API call.
type mqlVercelFirewallInternal struct {
	teamID       string
	projectID    string
	cacheRules   []firewallRuleRecord
	cacheIPs     []firewallIPRecord
	cacheManaged map[string]managedRulesetRecord
	cacheCRS     map[string]coreRuleRecord
}

// managedRulesetRecord is one entry of the managedRules object, keyed by
// ruleset identifier. active is the only field Vercel guarantees; action and
// the attribution fields are absent on a ruleset that has never been
// configured, so every one of them is a pointer and stays null when omitted.
type managedRulesetRecord struct {
	Active    *bool    `json:"active"`
	Action    *string  `json:"action"`
	UpdatedAt flexTime `json:"updatedAt"`
	UserID    *string  `json:"userId"`
	Username  *string  `json:"username"`
}

// coreRuleRecord is one attack-class entry of the crs object.
type coreRuleRecord struct {
	Active *bool   `json:"active"`
	Action *string `json:"action"`
}

// decodeRulesetMap decodes a keyed ruleset object into records. An absent or
// null object yields no entries rather than an error, since a project whose
// firewall has never been configured returns neither key.
func decodeRulesetMap[T any](raw json.RawMessage) (map[string]T, error) {
	if len(raw) == 0 || isJSONNullRaw(raw) {
		return nil, nil
	}
	var out map[string]T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// decodeAnyOrEmpty decodes a raw object for a dict field, yielding an empty
// object when the key was absent or null so the field renders as {} rather
// than failing.
func decodeAnyOrEmpty(raw json.RawMessage) any {
	if len(raw) == 0 || isJSONNullRaw(raw) {
		return map[string]any{}
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}

func isJSONNullRaw(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

type firewallConfig struct {
	FirewallEnabled bool                 `json:"firewallEnabled"`
	ManagedRules    json.RawMessage      `json:"managedRules"`
	CRS             json.RawMessage      `json:"crs"`
	BotIDEnabled    *bool                `json:"botIdEnabled"`
	LogHeaders      logHeaders           `json:"logHeaders"`
	Version         *int64               `json:"version"`
	UpdatedAt       flexTime             `json:"updatedAt"`
	Rules           []firewallRuleRecord `json:"rules"`
	IPs             []firewallIPRecord   `json:"ips"`
}

// logHeaders decodes the recorded-header setting, which Vercel returns either as
// a list of header names or as the string "*" meaning every header.
type logHeaders struct {
	values []string
}

func (l *logHeaders) UnmarshalJSON(b []byte) error {
	if s := strings.TrimSpace(string(b)); s == "null" || s == "" {
		return nil
	}
	var list []string
	if err := json.Unmarshal(b, &list); err == nil {
		l.values = list
		return nil
	}
	var single string
	if err := json.Unmarshal(b, &single); err != nil {
		return err
	}
	l.values = []string{single}
	return nil
}

type firewallRuleRecord struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	Description    *string          `json:"description"`
	Active         bool             `json:"active"`
	Action         any              `json:"action"`
	ConditionGroup []map[string]any `json:"conditionGroup"`
}

type firewallIPRecord struct {
	ID       string  `json:"id"`
	Hostname *string `json:"hostname"`
	IP       string  `json:"ip"`
	Action   string  `json:"action"`
	Notes    *string `json:"notes"`
}

// firewallMitigation is the mitigation a custom rule applies to the traffic it
// matches. Vercel reports the action verb on every rule and omits the rest, so
// each remaining field is a pointer that stays null when the rule does not set
// it. bypassSystem in particular must never be reported as false on a rule
// Vercel said nothing about: a fabricated false would let an assertion that no
// rule bypasses the system mitigations pass without having read anything.
type firewallMitigation struct {
	Action         *string            `json:"action"`
	RateLimit      *firewallRateLimit `json:"rateLimit"`
	Redirect       *firewallRedirect  `json:"redirect"`
	ActionDuration *string            `json:"actionDuration"`
	BypassSystem   *bool              `json:"bypassSystem"`
	LogHeaders     logHeaders         `json:"logHeaders"`
}

type firewallRateLimit struct {
	Algo   *string  `json:"algo"`
	Window *int64   `json:"window"`
	Limit  *int64   `json:"limit"`
	Keys   []string `json:"keys"`
	Action *string  `json:"action"`
}

type firewallRedirect struct {
	Location  *string `json:"location"`
	Permanent *bool   `json:"permanent"`
}

// firewallRuleMitigation decodes a custom rule action into its mitigation. The
// action arrives either as a bare verb string, as {"mitigate": {...}}, or as a
// mitigation object inline, and only the object forms carry the fields beyond
// the verb. A bare verb yields a mitigation holding just that verb, so every
// other field stays null rather than becoming a value the rule never set.
func firewallRuleMitigation(a any) firewallMitigation {
	switch v := a.(type) {
	case string:
		verb := v
		return firewallMitigation{Action: &verb}
	case map[string]any:
		if inner, ok := v["mitigate"].(map[string]any); ok {
			return decodeMitigation(inner)
		}
		return decodeMitigation(v)
	}
	return firewallMitigation{}
}

// decodeMitigation round-trips the decoded object through the typed struct so
// the mitigation fields are read by their JSON tags rather than by hand.
func decodeMitigation(m map[string]any) firewallMitigation {
	raw, err := json.Marshal(m)
	if err != nil {
		return firewallMitigation{}
	}
	var out firewallMitigation
	if err := json.Unmarshal(raw, &out); err != nil {
		return firewallMitigation{}
	}
	return out
}

// firewallRuleAction reduces a custom rule action to its action verb.
func firewallRuleAction(a any) string {
	if v := firewallRuleMitigation(a).Action; v != nil {
		return *v
	}
	return ""
}

func (p *mqlVercelProject) firewall() (*mqlVercelFirewall, error) {
	conn := p.MqlRuntime.Connection.(*connection.VercelConnection)
	query := connection.TeamQuery(p.teamID)
	query.Set("projectId", p.Id.Data)

	var cfg firewallConfig
	if err := conn.Get(context.Background(), "/v1/security/firewall/config/active", query, &cfg); err != nil {
		// The configurable WAF is an Enterprise feature; treat an absent or
		// forbidden configuration as null rather than failing the scan.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			p.Firewall.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	managedRuleSets, err := decodeRulesetMap[managedRulesetRecord](cfg.ManagedRules)
	if err != nil {
		return nil, err
	}
	coreRules, err := decodeRulesetMap[coreRuleRecord](cfg.CRS)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(p.MqlRuntime, "vercel.firewall", map[string]*llx.RawData{
		"__id":            llx.StringData(p.Id.Data + "/firewall"),
		"enabled":         llx.BoolData(cfg.FirewallEnabled),
		"managedRulesets": llx.DictData(decodeAnyOrEmpty(cfg.ManagedRules)),
		"coreRuleSet":     llx.DictData(decodeAnyOrEmpty(cfg.CRS)),
		"botIdEnabled":    llx.BoolDataPtr(cfg.BotIDEnabled),
		"logHeaders":      llx.ArrayData(strSliceToAny(cfg.LogHeaders.values), types.String),
		"configVersion":   llx.IntData(intPtrOrZero(cfg.Version)),
		"updatedAt":       llx.TimeDataPtr(cfg.UpdatedAt.Time()),
	})
	if err != nil {
		return nil, err
	}

	fw := res.(*mqlVercelFirewall)
	fw.teamID = p.teamID
	fw.projectID = p.Id.Data
	fw.cacheRules = cfg.Rules
	fw.cacheIPs = cfg.IPs
	fw.cacheManaged = managedRuleSets
	fw.cacheCRS = coreRules
	return fw, nil
}

// managedRuleSetOrder is the order managed rulesets are reported in, so a scan
// lists them the same way every time rather than in Go's map order.
var managedRuleSetOrder = []string{"owasp", "bot_protection", "ai_bots", "traffic_sources", "vercel_ruleset"}

// coreRuleOrder is the order core rule set categories are reported in.
var coreRuleOrder = []string{"sqli", "xss", "rce", "lfi", "rfi", "php", "java", "ma", "sd", "sf", "gen"}

// orderedKeys returns the keys of m, listing the ones named in order first and
// appending any key the API added since, sorted, so a new ruleset is reported
// rather than dropped.
func orderedKeys[T any](m map[string]T, order []string) []string {
	out := make([]string, 0, len(m))
	seen := make(map[string]bool, len(m))
	for _, k := range order {
		if _, ok := m[k]; ok {
			out = append(out, k)
			seen[k] = true
		}
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !seen[k] {
			rest = append(rest, k)
		}
	}
	sort.Strings(rest)
	return append(out, rest...)
}

// managedRules reports the rulesets Vercel maintains and evaluates for the
// project. Every field but the ruleset name comes back as a pointer, so a
// ruleset Vercel reports without an action reads null rather than as an action
// nobody configured.
func (f *mqlVercelFirewall) managedRules() ([]any, error) {
	res := []any{}
	for _, name := range orderedKeys(f.cacheManaged, managedRuleSetOrder) {
		rec := f.cacheManaged[name]
		ruleset, err := CreateResource(f.MqlRuntime, "vercel.firewall.managedRuleset", map[string]*llx.RawData{
			"__id":              llx.StringData(f.projectID + "/managedRule/" + name),
			"name":              llx.StringData(name),
			"active":            llx.BoolDataPtr(rec.Active),
			"action":            llx.StringDataPtr(rec.Action),
			"updatedAt":         llx.TimeDataPtr(rec.UpdatedAt.Time()),
			"updatedByUserId":   llx.StringDataPtr(rec.UserID),
			"updatedByUsername": llx.StringDataPtr(rec.Username),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ruleset)
	}
	return res, nil
}

// coreRules reports the OWASP Core Rule Set categories configured for the
// project.
func (f *mqlVercelFirewall) coreRules() ([]any, error) {
	res := []any{}
	for _, name := range orderedKeys(f.cacheCRS, coreRuleOrder) {
		rec := f.cacheCRS[name]
		rule, err := CreateResource(f.MqlRuntime, "vercel.firewall.coreRule", map[string]*llx.RawData{
			"__id":   llx.StringData(f.projectID + "/coreRule/" + name),
			"name":   llx.StringData(name),
			"active": llx.BoolDataPtr(rec.Active),
			"action": llx.StringDataPtr(rec.Action),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, rule)
	}
	return res, nil
}

// --- system bypass --------------------------------------------------------

type bypassRuleRecord struct {
	ID            string   `json:"Id"`
	IP            string   `json:"Ip"`
	Domain        string   `json:"Domain"`
	Action        string   `json:"Action"`
	IsProjectRule *bool    `json:"IsProjectRule"`
	Note          *string  `json:"Note"`
	ActorID       string   `json:"ActorId"`
	ExpiresAt     flexTime `json:"ExpiresAt"`
	CreatedAt     flexTime `json:"CreatedAt"`
	UpdatedAt     flexTime `json:"UpdatedAt"`
}

// bypassRules lists the entries that skip firewall evaluation for a source
// address and hostname. The endpoint uses PascalCase keys and an offset cursor
// of its own rather than the shared pagination envelope, so it pages here.
func (f *mqlVercelFirewall) bypassRules() ([]any, error) {
	conn := f.MqlRuntime.Connection.(*connection.VercelConnection)

	records, err := f.fetchBypassRules(conn)
	if err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			f.BypassRules.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the collection is not provisioned for this scope,
		// which genuinely is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for i := range records {
		rec := records[i]
		rule, err := CreateResource(f.MqlRuntime, "vercel.firewall.bypassRule", map[string]*llx.RawData{
			"id":            llx.StringData(rec.ID),
			"ip":            llx.StringData(rec.IP),
			"domain":        llx.StringData(rec.Domain),
			"action":        llx.StringData(rec.Action),
			"projectScoped": llx.BoolData(rec.IsProjectRule != nil && *rec.IsProjectRule),
			"note":          llx.StringDataPtr(rec.Note),
			"actorId":       llx.StringData(rec.ActorID),
			"expiresAt":     llx.TimeDataPtr(rec.ExpiresAt.Time()),
			"createdAt":     llx.TimeDataPtr(rec.CreatedAt.Time()),
			"updatedAt":     llx.TimeDataPtr(rec.UpdatedAt.Time()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, rule)
	}
	return res, nil
}

// fetchBypassRules walks the offset cursor, which carries the id of the last
// item returned rather than a page number.
func (f *mqlVercelFirewall) fetchBypassRules(conn *connection.VercelConnection) ([]bypassRuleRecord, error) {
	query := connection.TeamQuery(f.teamID)
	query.Set("projectId", f.projectID)
	query.Set("limit", "256")

	var all []bypassRuleRecord
	for {
		var page struct {
			Result     []bypassRuleRecord `json:"result"`
			Pagination *struct {
				ID string `json:"Id"`
			} `json:"pagination"`
		}
		if err := conn.Get(context.Background(), "/v1/security/firewall/bypass", query, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Result...)

		if page.Pagination == nil || page.Pagination.ID == "" || query.Get("offset") == page.Pagination.ID {
			break
		}
		query.Set("offset", page.Pagination.ID)
	}
	return all, nil
}

func (c *mqlVercelFirewallBypassRule) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

// attackAnomalies reports traffic Vercel flagged as an attack over the last
// day. The endpoint returns an empty object rather than an empty list when
// nothing was flagged.
func (f *mqlVercelFirewall) attackAnomalies() ([]any, error) {
	conn := f.MqlRuntime.Connection.(*connection.VercelConnection)

	query := connection.TeamQuery(f.teamID)
	query.Set("projectId", f.projectID)

	var resp struct {
		Anomalies []map[string]any `json:"anomalies"`
	}
	if err := conn.Get(context.Background(), "/v1/security/firewall/attack-status", query, &resp); err != nil {
		// A refused read establishes nothing about what exists, so the field
		// is reported null rather than as an empty list that would assert
		// there is none.
		if connection.IsForbidden(err) {
			f.AttackAnomalies.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		// A 404 means the collection is not provisioned for this scope,
		// which genuinely is none.
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}
	return dictSliceToAny(resp.Anomalies), nil
}

func (f *mqlVercelFirewall) rules() ([]any, error) {
	var res []any
	for i := range f.cacheRules {
		rec := f.cacheRules[i]
		mit := firewallRuleMitigation(rec.Action)

		var rateAlgo, rateAction, redirectLocation *string
		var rateWindow, rateLimit *int64
		var rateKeys []string
		var redirectPermanent *bool
		if mit.RateLimit != nil {
			rateAlgo = mit.RateLimit.Algo
			rateAction = mit.RateLimit.Action
			rateWindow = mit.RateLimit.Window
			rateLimit = mit.RateLimit.Limit
			rateKeys = mit.RateLimit.Keys
		}
		if mit.Redirect != nil {
			redirectLocation = mit.Redirect.Location
			redirectPermanent = mit.Redirect.Permanent
		}

		rule, err := CreateResource(f.MqlRuntime, "vercel.firewall.rule", map[string]*llx.RawData{
			"id":                llx.StringData(rec.ID),
			"name":              llx.StringData(rec.Name),
			"description":       llx.StringDataPtr(rec.Description),
			"active":            llx.BoolData(rec.Active),
			"action":            llx.StringData(firewallRuleAction(rec.Action)),
			"conditionGroup":    llx.ArrayData(dictSliceToAny(rec.ConditionGroup), types.Dict),
			"bypassSystem":      llx.BoolDataPtr(mit.BypassSystem),
			"actionDuration":    llx.StringDataPtr(mit.ActionDuration),
			"redirectLocation":  llx.StringDataPtr(redirectLocation),
			"redirectPermanent": llx.BoolDataPtr(redirectPermanent),
			"rateLimitAlgo":     llx.StringDataPtr(rateAlgo),
			"rateLimitWindow":   llx.IntDataPtr(rateWindow),
			"rateLimitLimit":    llx.IntDataPtr(rateLimit),
			"rateLimitKeys":     llx.ArrayData(strSliceToAny(rateKeys), types.String),
			"rateLimitAction":   llx.StringDataPtr(rateAction),
			"logHeaders":        llx.ArrayData(strSliceToAny(mit.LogHeaders.values), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, rule)
	}
	return res, nil
}

func (c *mqlVercelFirewallRule) id() (string, error) {
	return c.Id.Data, c.Id.Error
}

func (f *mqlVercelFirewall) ipRules() ([]any, error) {
	var res []any
	for i := range f.cacheIPs {
		rec := f.cacheIPs[i]
		rule, err := CreateResource(f.MqlRuntime, "vercel.firewall.ipRule", map[string]*llx.RawData{
			"id":       llx.StringData(rec.ID),
			"ip":       llx.StringData(rec.IP),
			"hostname": llx.StringDataPtr(rec.Hostname),
			"action":   llx.StringData(rec.Action),
			"notes":    llx.StringDataPtr(rec.Notes),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, rule)
	}
	return res, nil
}

func (c *mqlVercelFirewallIpRule) id() (string, error) {
	return c.Id.Data, c.Id.Error
}
