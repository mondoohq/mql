// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/cloudflare/cloudflare-go/v7"
	"github.com/cloudflare/cloudflare-go/v7/ai_gateway"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// aiGatewayRecord is the subset of an AI Gateway the provider reads. Besides
// the decode panic noted on listAIGateways, the cloudflare-go types lose two
// things this resource needs: the DLP union collapses both of its variants
// into the one without policies (and the policy type it names does not
// exist), and nullable integers decode to 0, so "no limit" and "limit 0" read
// the same.
//
// Otel exporters and the Stripe integration are not decoded: they carry
// authorization headers and keys.
type aiGatewayRecord struct {
	ID                      string               `json:"id"`
	Authentication          bool                 `json:"authentication"`
	ByokOnly                bool                 `json:"byok_only"`
	IsDefault               bool                 `json:"is_default"`
	CollectLogs             bool                 `json:"collect_logs"`
	Logpush                 bool                 `json:"logpush"`
	LogManagement           *int64               `json:"log_management"`
	LogManagementStrategy   *string              `json:"log_management_strategy"`
	Zdr                     bool                 `json:"zdr"`
	FedrampLevel            *string              `json:"fedramp_level"`
	FedrampMode             *string              `json:"fedramp_mode"`
	CacheTTL                *int64               `json:"cache_ttl"`
	CacheInvalidateOnUpdate bool                 `json:"cache_invalidate_on_update"`
	RateLimitingLimit       *int64               `json:"rate_limiting_limit"`
	RateLimitingInterval    *int64               `json:"rate_limiting_interval"`
	RateLimitingTechnique   *string              `json:"rate_limiting_technique"`
	DLP                     *aiGatewayDLP        `json:"dlp"`
	Guardrails              *aiGatewayGuardrails `json:"guardrails"`
	SpendLimits             *aiGatewaySpendLimit `json:"spend_limits"`
	CreatedAt               time.Time            `json:"created_at"`
	ModifiedAt              time.Time            `json:"modified_at"`
}

// aiGatewayDLP holds either shape the API returns: one action for a list of
// profiles, or a list of policies each with its own action and profiles.
type aiGatewayDLP struct {
	Enabled  bool                 `json:"enabled"`
	Action   *string              `json:"action"`
	Profiles []string             `json:"profiles"`
	Policies []aiGatewayDLPPolicy `json:"policies"`
}

type aiGatewayDLPPolicy struct {
	ID       string   `json:"id"`
	Enabled  bool     `json:"enabled"`
	Action   string   `json:"action"`
	Check    []string `json:"check"`
	Profiles []string `json:"profiles"`
}

type aiGatewayGuardrails struct {
	Prompt   map[string]string `json:"prompt"`
	Response map[string]string `json:"response"`
}

type aiGatewaySpendLimit struct {
	Enabled bool                      `json:"enabled"`
	Rules   []aiGatewaySpendLimitRule `json:"rules"`
}

type aiGatewaySpendLimitRule struct {
	ID        string                    `json:"id"`
	Enabled   bool                      `json:"enabled"`
	Limit     float64                   `json:"limit"`
	// camelCase on the wire, unlike the rest of the record; cloudflare-go's
	// generated type uses the same tag.
	LimitType string                    `json:"limitType"`
	Window    int64                     `json:"window"`
	Technique string                    `json:"technique"`
	Model     *aiGatewaySpendLimitScope `json:"model"`
	Provider  *aiGatewaySpendLimitScope `json:"provider"`
	Metadata  map[string]any            `json:"metadata"`
}

type aiGatewaySpendLimitScope struct {
	Mode   string   `json:"mode"`
	Values []string `json:"values"`
}

// aiGatewayProviderConfigRecord is a stored provider key. The key preview
// (`secret_preview`) is deliberately not decoded.
type aiGatewayProviderConfigRecord struct {
	ID              string    `json:"id"`
	Alias           string    `json:"alias"`
	ProviderSlug    string    `json:"provider_slug"`
	DefaultConfig   bool      `json:"default_config"`
	SecretID        string    `json:"secret_id"`
	LastUsedAt      *string   `json:"last_used_at"`
	RateLimit       *float64  `json:"rate_limit"`
	RateLimitPeriod *float64  `json:"rate_limit_period"`
	ModifiedAt      time.Time `json:"modified_at"`
}

type mqlCloudflareAccountAiGatewayInternal struct {
	accountID string
	record    aiGatewayRecord
}

type mqlCloudflareAccountAiGatewayDlpPolicyInternal struct {
	accountID  string
	profileIDs []string
}

func decodeAIGatewayProviderConfig(raw string) (aiGatewayProviderConfigRecord, error) {
	var rec aiGatewayProviderConfigRecord
	err := json.Unmarshal([]byte(raw), &rec)
	return rec, err
}

// guardrailActions converts one direction of the guardrail settings into MQL
// map data. Guardrails that were never configured read as null rather than an
// empty map, which would claim every category was checked and left unset.
func guardrailActions(g *aiGatewayGuardrails, response bool) *llx.RawData {
	if g == nil {
		return llx.NilData
	}
	src := g.Prompt
	if response {
		src = g.Response
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		if v == "" {
			continue
		}
		out[k] = v
	}
	return llx.MapData(out, types.String)
}

// dlpAction reports the gateway-wide DLP action, which only the profiles shape
// of the setting carries.
func (r aiGatewayRecord) dlpAction() *llx.RawData {
	if r.DLP == nil || r.DLP.Action == nil || *r.DLP.Action == "" {
		return llx.NilData
	}
	return llx.StringData(*r.DLP.Action)
}

func spendLimitScopeValues(s *aiGatewaySpendLimitScope) []any {
	if s == nil {
		return []any{}
	}
	return strAnySlice(s.Values)
}

// providerConfigLastUsed parses the date the gateway last used a key. The API
// sends a bare YYYY-MM-DD date, or null for a key it has no record of using.
func providerConfigLastUsed(s *string) *llx.RawData {
	if s == nil {
		return llx.NilData
	}
	return cfTimeString(*s)
}

// aiGatewayPageSize is the page size requested from the gateway list.
const aiGatewayPageSize = 50

// aiGatewayPage is one page of the gateway list endpoint.
type aiGatewayPage struct {
	Result     []aiGatewayRecord `json:"result"`
	ResultInfo struct {
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
}

// hasNextAIGatewayPage decides whether to request the page after `page`,
// having read `seen` gateways so far. The endpoint reports a total count but
// not always a page count, and may serve fewer per page than requested.
func hasNextAIGatewayPage(p aiGatewayPage, page, seen int) bool {
	if len(p.Result) == 0 {
		return false
	}
	if p.ResultInfo.TotalPages > 0 {
		return page < p.ResultInfo.TotalPages
	}
	if p.ResultInfo.TotalCount > 0 {
		return seen < p.ResultInfo.TotalCount
	}
	perPage := p.ResultInfo.PerPage
	if perPage <= 0 {
		perPage = aiGatewayPageSize
	}
	return len(p.Result) >= perPage
}

// listAIGateways reads every gateway in the account. It decodes the raw
// response instead of using AIGateway.ListAutoPaging: cloudflare-go v7.14.0
// panics decoding a spend limit rule that has metadata (its union port calls
// SetString on a struct), which would take the provider down on such a
// gateway.
func listAIGateways(conn *connection.CloudflareConnection, accountID string) ([]aiGatewayRecord, error) {
	var all []aiGatewayRecord
	// The cap guards against a server that never reports the end.
	for page := 1; page <= 1000; page++ {
		var p aiGatewayPage
		uri := fmt.Sprintf("accounts/%s/ai-gateway/gateways?page=%d&per_page=%d", accountID, page, aiGatewayPageSize)
		if err := conn.Cf.Get(context.TODO(), uri, nil, &p); err != nil {
			return nil, err
		}
		all = append(all, p.Result...)
		if !hasNextAIGatewayPage(p, page, len(all)) {
			break
		}
	}
	return all, nil
}

func (c *mqlCloudflareAccount) aiGateways() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)
	accountID := c.Id.Data

	records, err := listAIGateways(conn, accountID)
	if err != nil {
		return degradedList(err)
	}

	result := make([]any, 0, len(records))
	for _, rec := range records {
		spendEnabled := false
		if rec.SpendLimits != nil {
			spendEnabled = rec.SpendLimits.Enabled
		}
		dlpEnabled := false
		if rec.DLP != nil {
			dlpEnabled = rec.DLP.Enabled
		}

		res, err := CreateResource(c.MqlRuntime, "cloudflare.account.aiGateway", map[string]*llx.RawData{
			"__id":                    llx.StringData("cloudflare.account.aiGateway@" + accountID + "/" + rec.ID),
			"id":                      llx.StringData(rec.ID),
			"authentication":          llx.BoolData(rec.Authentication),
			"byokOnly":                llx.BoolData(rec.ByokOnly),
			"isDefault":               llx.BoolData(rec.IsDefault),
			"collectLogs":             llx.BoolData(rec.CollectLogs),
			"logpush":                 llx.BoolData(rec.Logpush),
			"logManagement":           llx.IntDataPtr(rec.LogManagement),
			"logManagementStrategy":   llx.StringDataPtr(rec.LogManagementStrategy),
			"zeroDataRetention":       llx.BoolData(rec.Zdr),
			"fedrampLevel":            llx.StringDataPtr(rec.FedrampLevel),
			"fedrampMode":             llx.StringDataPtr(rec.FedrampMode),
			"cacheTtl":                llx.IntDataPtr(rec.CacheTTL),
			"cacheInvalidateOnUpdate": llx.BoolData(rec.CacheInvalidateOnUpdate),
			"rateLimitingLimit":       llx.IntDataPtr(rec.RateLimitingLimit),
			"rateLimitingInterval":    llx.IntDataPtr(rec.RateLimitingInterval),
			"rateLimitingTechnique":   llx.StringDataPtr(rec.RateLimitingTechnique),
			"dlpEnabled":              llx.BoolData(dlpEnabled),
			"dlpAction":               rec.dlpAction(),
			"promptGuardrails":        guardrailActions(rec.Guardrails, false),
			"responseGuardrails":      guardrailActions(rec.Guardrails, true),
			"spendLimitsEnabled":      llx.BoolData(spendEnabled),
			"createdAt":               timeOrNil(rec.CreatedAt),
			"modifiedAt":              timeOrNil(rec.ModifiedAt),
		})
		if err != nil {
			return nil, err
		}
		g := res.(*mqlCloudflareAccountAiGateway)
		g.accountID = accountID
		g.record = rec
		result = append(result, g)
	}
	return result, nil
}

func (c *mqlCloudflareAccountAiGateway) dlpProfiles() ([]any, error) {
	if c.record.DLP == nil || len(c.record.DLP.Profiles) == 0 {
		return []any{}, nil
	}
	return resolveDlpProfiles(c.MqlRuntime, c.accountID, c.record.DLP.Profiles)
}

func (c *mqlCloudflareAccountAiGateway) dlpPolicies() ([]any, error) {
	if c.record.DLP == nil {
		return []any{}, nil
	}
	result := make([]any, 0, len(c.record.DLP.Policies))
	for _, p := range c.record.DLP.Policies {
		res, err := CreateResource(c.MqlRuntime, "cloudflare.account.aiGateway.dlpPolicy", map[string]*llx.RawData{
			"__id":    llx.StringData("cloudflare.account.aiGateway.dlpPolicy@" + c.accountID + "/" + c.record.ID + "/" + p.ID),
			"id":      llx.StringData(p.ID),
			"enabled": llx.BoolData(p.Enabled),
			"action":  llx.StringData(p.Action),
			"check":   llx.ArrayData(strAnySlice(p.Check), types.String),
		})
		if err != nil {
			return nil, err
		}
		policy := res.(*mqlCloudflareAccountAiGatewayDlpPolicy)
		policy.accountID = c.accountID
		policy.profileIDs = p.Profiles
		result = append(result, policy)
	}
	return result, nil
}

func (c *mqlCloudflareAccountAiGatewayDlpPolicy) profiles() ([]any, error) {
	if len(c.profileIDs) == 0 {
		return []any{}, nil
	}
	return resolveDlpProfiles(c.MqlRuntime, c.accountID, c.profileIDs)
}

// resolveDlpProfiles maps DLP profile IDs onto the account's Cloudflare One
// DLP profiles, reusing the one profile listing every gateway and policy
// shares. An ID absent from that listing (the token cannot read Zero Trust,
// or the profile was deleted) is left out and logged.
func resolveDlpProfiles(runtime *plugin.Runtime, accountID string, ids []string) ([]any, error) {
	one, err := newOne(runtime, accountID, "")
	if err != nil {
		return nil, err
	}
	all := one.GetDlpProfiles()
	if all.Error != nil {
		return nil, all.Error
	}
	byID := make(map[string]any, len(all.Data))
	for _, p := range all.Data {
		profile := p.(*mqlCloudflareOneDlpProfile)
		byID[profile.Id.Data] = profile
	}

	result := make([]any, 0, len(ids))
	for _, id := range ids {
		if p, ok := byID[id]; ok {
			result = append(result, p)
			continue
		}
		log.Debug().Str("profile", id).Msg("cloudflare> DLP profile referenced by AI Gateway not found in the account's DLP profiles")
	}
	return result, nil
}

func (c *mqlCloudflareAccountAiGateway) spendLimitRules() ([]any, error) {
	if c.record.SpendLimits == nil {
		return []any{}, nil
	}
	result := make([]any, 0, len(c.record.SpendLimits.Rules))
	for i, r := range c.record.SpendLimits.Rules {
		key := r.ID
		if key == "" {
			key = "#" + strconv.Itoa(i)
		}
		metadata := r.Metadata
		if metadata == nil {
			metadata = map[string]any{}
		}
		res, err := CreateResource(c.MqlRuntime, "cloudflare.account.aiGateway.spendLimitRule", map[string]*llx.RawData{
			"__id":      llx.StringData("cloudflare.account.aiGateway.spendLimitRule@" + c.accountID + "/" + c.record.ID + "/" + key),
			"id":        llx.StringData(r.ID),
			"enabled":   llx.BoolData(r.Enabled),
			"limit":     llx.FloatData(r.Limit),
			"limitType": llx.StringData(r.LimitType),
			"window":    llx.IntData(r.Window),
			"technique": llx.StringData(r.Technique),
			"models":    llx.ArrayData(spendLimitScopeValues(r.Model), types.String),
			"providers": llx.ArrayData(spendLimitScopeValues(r.Provider), types.String),
			"metadata":  llx.DictData(metadata),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	return result, nil
}

func (c *mqlCloudflareAccountAiGateway) providerConfigs() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	var result []any
	iter := conn.Cf.AIGateway.ProviderConfigs.ListAutoPaging(context.TODO(), c.record.ID, ai_gateway.ProviderConfigListParams{
		AccountID: cloudflare.F(c.accountID),
	})
	for iter.Next() {
		item := iter.Current()
		rec, err := decodeAIGatewayProviderConfig(item.JSON.RawJSON())
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(c.MqlRuntime, "cloudflare.account.aiGateway.providerConfig", map[string]*llx.RawData{
			"__id":            llx.StringData("cloudflare.account.aiGateway.providerConfig@" + c.accountID + "/" + c.record.ID + "/" + rec.ID),
			"id":              llx.StringData(rec.ID),
			"alias":           llx.StringData(rec.Alias),
			"providerSlug":    llx.StringData(rec.ProviderSlug),
			"defaultConfig":   llx.BoolData(rec.DefaultConfig),
			"secretId":        llx.StringData(rec.SecretID),
			"lastUsedAt":      providerConfigLastUsed(rec.LastUsedAt),
			"rateLimit":       llx.FloatDataPtr(rec.RateLimit),
			"rateLimitPeriod": llx.FloatDataPtr(rec.RateLimitPeriod),
			"modifiedAt":      timeOrNil(rec.ModifiedAt),
		})
		if err != nil {
			return nil, err
		}
		result = append(result, res)
	}
	if err := iter.Err(); err != nil {
		return degradedList(err)
	}
	return result, nil
}
