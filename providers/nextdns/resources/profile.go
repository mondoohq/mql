// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nextdns/connection"
	"go.mondoo.com/mql/types"
)

// initNextdnsProfile resolves the top-level nextdns.profile resource. When the
// scan is scoped to a single profile, it populates the profile from the
// connection so checks can assert against `nextdns.profile` directly and have
// findings attributed to that profile. An explicit `id` argument is honored as
// well; without one, the connection must be scoped to a single profile.
func initNextdnsProfile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if id, ok := args["id"]; ok && id.Value != nil {
		if s, ok := id.Value.(string); ok && s != "" {
			return args, nil, nil
		}
	}

	conn := runtime.Connection.(*connection.NextdnsConnection)
	if conn.ProfileID() == "" {
		return nil, nil, errors.New("nextdns.profile is only available when the scan is scoped to a single profile; use nextdns.profiles to enumerate every profile in an account")
	}

	profiles, err := fetchProfiles(conn)
	if err != nil {
		return nil, nil, err
	}
	if len(profiles) != 1 {
		return nil, nil, errors.New("expected exactly one scoped NextDNS profile")
	}

	p := profiles[0]
	args["id"] = llx.StringData(p.ID)
	args["name"] = llx.StringData(p.Name)
	args["fingerprint"] = llx.StringData(p.Fingerprint)
	return args, nil, nil
}

// mqlNextdnsProfileInternal caches the full profile detail. Every section
// (security, privacy, parentalControl, settings, setup, lists, rewrites) is
// served by a single GET /profiles/:id call, so accessors share one fetch.
// The detail is cached only on success so a transient failure can be retried.
type mqlNextdnsProfileInternal struct {
	fetched atomic.Bool
	lock    sync.Mutex
	detail  *profileDetail
}

func (r *mqlNextdnsProfile) id() (string, error) {
	return "nextdns.profile/" + r.Id.Data, nil
}

// profileDetail is the GET /profiles/:id response model.
type profileDetail struct {
	ID              string              `json:"id"`
	Name            string              `json:"name"`
	Fingerprint     string              `json:"fingerprint"`
	Security        securityData        `json:"security"`
	Privacy         privacyData         `json:"privacy"`
	ParentalControl parentalControlData `json:"parentalControl"`
	Settings        settingsData        `json:"settings"`
	Setup           setupData           `json:"setup"`
	Denylist        []listEntryData     `json:"denylist"`
	Allowlist       []listEntryData     `json:"allowlist"`
	Rewrites        []rewriteData       `json:"rewrites"`
}

type profileDetailResponse struct {
	Data profileDetail `json:"data"`
}

type securityData struct {
	ThreatIntelligenceFeeds bool     `json:"threatIntelligenceFeeds"`
	AiThreatDetection       bool     `json:"aiThreatDetection"`
	GoogleSafeBrowsing      bool     `json:"googleSafeBrowsing"`
	Cryptojacking           bool     `json:"cryptojacking"`
	DNSRebinding            bool     `json:"dnsRebinding"`
	IdnHomographs           bool     `json:"idnHomographs"`
	Typosquatting           bool     `json:"typosquatting"`
	Dga                     bool     `json:"dga"`
	Nrd                     bool     `json:"nrd"`
	DDNS                    bool     `json:"ddns"`
	Parking                 bool     `json:"parking"`
	Csam                    bool     `json:"csam"`
	Tlds                    []idItem `json:"tlds"`
}

type privacyData struct {
	Blocklists        []blocklistData `json:"blocklists"`
	Natives           []idItem        `json:"natives"`
	DisguisedTrackers bool            `json:"disguisedTrackers"`
	AllowAffiliate    bool            `json:"allowAffiliate"`
}

type blocklistData struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Website   string     `json:"website"`
	Entries   int64      `json:"entries"`
	UpdatedOn *time.Time `json:"updatedOn"`
}

type parentalControlData struct {
	Services              []pcRuleData   `json:"services"`
	Categories            []pcRuleData   `json:"categories"`
	Recreation            recreationData `json:"recreation"`
	SafeSearch            bool           `json:"safeSearch"`
	YoutubeRestrictedMode bool           `json:"youtubeRestrictedMode"`
	BlockBypass           bool           `json:"blockBypass"`
}

type pcRuleData struct {
	ID         string `json:"id"`
	Active     bool   `json:"active"`
	Recreation bool   `json:"recreation"`
}

type recreationData struct {
	Times    map[string]any `json:"times"`
	Timezone string         `json:"timezone"`
}

type settingsData struct {
	Logs        logsData        `json:"logs"`
	BlockPage   blockPageData   `json:"blockPage"`
	Performance performanceData `json:"performance"`
	Web3        bool            `json:"web3"`
}

type logsData struct {
	Enabled   bool     `json:"enabled"`
	Drop      dropData `json:"drop"`
	Retention int64    `json:"retention"`
	Location  string   `json:"location"`
}

type dropData struct {
	IP     bool `json:"ip"`
	Domain bool `json:"domain"`
}

type blockPageData struct {
	Enabled bool `json:"enabled"`
}

type performanceData struct {
	Ecs             bool `json:"ecs"`
	CacheBoost      bool `json:"cacheBoost"`
	CnameFlattening bool `json:"cnameFlattening"`
}

type setupData struct {
	Ipv4     []string      `json:"ipv4"`
	Ipv6     []string      `json:"ipv6"`
	LinkedIP *linkedIPData `json:"linkedIp"`
	Dnscrypt string        `json:"dnscrypt"`
}

type linkedIPData struct {
	Servers []string `json:"servers"`
	IP      string   `json:"ip"`
	Ddns    string   `json:"ddns"`
}

type listEntryData struct {
	ID     string `json:"id"`
	Active bool   `json:"active"`
}

type rewriteData struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

// fetchDetail loads the full profile once and caches it. The result is cached
// only on success, so a transient failure on the first call can be retried by
// later accessors rather than being remembered forever.
func (r *mqlNextdnsProfile) fetchDetail() (*profileDetail, error) {
	if r.fetched.Load() {
		return r.detail, nil
	}
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.fetched.Load() {
		return r.detail, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.NextdnsConnection)
	var resp profileDetailResponse
	if err := conn.Get(context.Background(), "/profiles/"+r.Id.Data, &resp); err != nil {
		return nil, err
	}
	r.detail = &resp.Data
	r.fetched.Store(true)
	return r.detail, nil
}

// account resolves the typed account that owns this profile, enabling
// cross-resource traversal such as nextdns.profiles.account.profiles.
func (r *mqlNextdnsProfile) account() (*mqlNextdnsAccount, error) {
	conn := r.MqlRuntime.Connection.(*connection.NextdnsConnection)
	res, err := CreateResource(r.MqlRuntime, "nextdns.account", map[string]*llx.RawData{
		"id": llx.StringData(conn.AccountID()),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNextdnsAccount), nil
}

func (r *mqlNextdnsProfile) security() (*mqlNextdnsProfileSecurity, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	s := d.Security
	res, err := CreateResource(r.MqlRuntime, "nextdns.profileSecurity", map[string]*llx.RawData{
		"__id":                    llx.StringData(r.Id.Data + "/security"),
		"threatIntelligenceFeeds": llx.BoolData(s.ThreatIntelligenceFeeds),
		"aiThreatDetection":       llx.BoolData(s.AiThreatDetection),
		"googleSafeBrowsing":      llx.BoolData(s.GoogleSafeBrowsing),
		"cryptojacking":           llx.BoolData(s.Cryptojacking),
		"dnsRebinding":            llx.BoolData(s.DNSRebinding),
		"idnHomographs":           llx.BoolData(s.IdnHomographs),
		"typosquatting":           llx.BoolData(s.Typosquatting),
		"dga":                     llx.BoolData(s.Dga),
		"nrd":                     llx.BoolData(s.Nrd),
		"ddns":                    llx.BoolData(s.DDNS),
		"parking":                 llx.BoolData(s.Parking),
		"csam":                    llx.BoolData(s.Csam),
		"tlds":                    strArray(idItemsToStrings(s.Tlds)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNextdnsProfileSecurity), nil
}

func (r *mqlNextdnsProfile) privacy() (*mqlNextdnsProfilePrivacy, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	p := d.Privacy

	blocklists := make([]any, 0, len(p.Blocklists))
	for _, bl := range p.Blocklists {
		mqlBl, err := CreateResource(r.MqlRuntime, "nextdns.profileBlocklist", map[string]*llx.RawData{
			"__id":      llx.StringData(r.Id.Data + "/blocklist/" + bl.ID),
			"id":        llx.StringData(bl.ID),
			"name":      llx.StringData(bl.Name),
			"website":   llx.StringData(bl.Website),
			"entries":   llx.IntData(bl.Entries),
			"updatedOn": timeOrNil(bl.UpdatedOn),
		})
		if err != nil {
			return nil, err
		}
		blocklists = append(blocklists, mqlBl)
	}

	res, err := CreateResource(r.MqlRuntime, "nextdns.profilePrivacy", map[string]*llx.RawData{
		"__id":              llx.StringData(r.Id.Data + "/privacy"),
		"disguisedTrackers": llx.BoolData(p.DisguisedTrackers),
		"allowAffiliate":    llx.BoolData(p.AllowAffiliate),
		"natives":           strArray(idItemsToStrings(p.Natives)),
		"blocklists":        llx.ArrayData(blocklists, types.Resource("nextdns.profileBlocklist")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNextdnsProfilePrivacy), nil
}

func (r *mqlNextdnsProfile) parentalControl() (*mqlNextdnsProfileParentalControl, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	pc := d.ParentalControl

	services, err := r.pcRules("nextdns.profileParentalControlService", "service", pc.Services)
	if err != nil {
		return nil, err
	}
	categories, err := r.pcRules("nextdns.profileParentalControlCategory", "category", pc.Categories)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(r.MqlRuntime, "nextdns.profileParentalControl", map[string]*llx.RawData{
		"__id":                  llx.StringData(r.Id.Data + "/parentalControl"),
		"safeSearch":            llx.BoolData(pc.SafeSearch),
		"youtubeRestrictedMode": llx.BoolData(pc.YoutubeRestrictedMode),
		"blockBypass":           llx.BoolData(pc.BlockBypass),
		"recreationTimezone":    llx.StringData(pc.Recreation.Timezone),
		"recreationTimes":       llx.DictData(pc.Recreation.Times),
		"services":              llx.ArrayData(services, types.Resource("nextdns.profileParentalControlService")),
		"categories":            llx.ArrayData(categories, types.Resource("nextdns.profileParentalControlCategory")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNextdnsProfileParentalControl), nil
}

// pcRules builds the shared {id, active, recreation} rule resources used for
// both parental-control services and categories.
func (r *mqlNextdnsProfile) pcRules(resourceName, kind string, rules []pcRuleData) ([]any, error) {
	res := make([]any, 0, len(rules))
	for _, rule := range rules {
		mqlRule, err := CreateResource(r.MqlRuntime, resourceName, map[string]*llx.RawData{
			"__id":       llx.StringData(r.Id.Data + "/parentalControl/" + kind + "/" + rule.ID),
			"id":         llx.StringData(rule.ID),
			"active":     llx.BoolData(rule.Active),
			"recreation": llx.BoolData(rule.Recreation),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (r *mqlNextdnsProfile) settings() (*mqlNextdnsProfileSettings, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	s := d.Settings
	res, err := CreateResource(r.MqlRuntime, "nextdns.profileSettings", map[string]*llx.RawData{
		"__id":             llx.StringData(r.Id.Data + "/settings"),
		"logsEnabled":      llx.BoolData(s.Logs.Enabled),
		"logsDropIp":       llx.BoolData(s.Logs.Drop.IP),
		"logsDropDomain":   llx.BoolData(s.Logs.Drop.Domain),
		"logsRetention":    llx.IntData(s.Logs.Retention),
		"logsLocation":     llx.StringData(s.Logs.Location),
		"blockPageEnabled": llx.BoolData(s.BlockPage.Enabled),
		"ecs":              llx.BoolData(s.Performance.Ecs),
		"cacheBoost":       llx.BoolData(s.Performance.CacheBoost),
		"cnameFlattening":  llx.BoolData(s.Performance.CnameFlattening),
		"web3":             llx.BoolData(s.Web3),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNextdnsProfileSettings), nil
}

func (r *mqlNextdnsProfile) setup() (*mqlNextdnsProfileSetup, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	s := d.Setup

	linkedIP := ""
	linkedIPDdns := ""
	var linkedIPServers []string
	if s.LinkedIP != nil {
		linkedIP = s.LinkedIP.IP
		linkedIPDdns = s.LinkedIP.Ddns
		linkedIPServers = s.LinkedIP.Servers
	}

	res, err := CreateResource(r.MqlRuntime, "nextdns.profileSetup", map[string]*llx.RawData{
		"__id":            llx.StringData(r.Id.Data + "/setup"),
		"ipv4":            strArray(s.Ipv4),
		"ipv6":            strArray(s.Ipv6),
		"dnscrypt":        llx.StringData(s.Dnscrypt),
		"linkedIp":        llx.StringData(linkedIP),
		"linkedIpServers": strArray(linkedIPServers),
		"linkedIpDdns":    llx.StringData(linkedIPDdns),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNextdnsProfileSetup), nil
}

func (r *mqlNextdnsProfile) denylist() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	return r.listEntries("nextdns.profileDenylistEntry", "denylist", d.Denylist)
}

func (r *mqlNextdnsProfile) allowlist() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	return r.listEntries("nextdns.profileAllowlistEntry", "allowlist", d.Allowlist)
}

func (r *mqlNextdnsProfile) listEntries(resourceName, kind string, entries []listEntryData) ([]any, error) {
	res := make([]any, 0, len(entries))
	for _, e := range entries {
		mqlEntry, err := CreateResource(r.MqlRuntime, resourceName, map[string]*llx.RawData{
			"__id":   llx.StringData(r.Id.Data + "/" + kind + "/" + e.ID),
			"id":     llx.StringData(e.ID),
			"active": llx.BoolData(e.Active),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntry)
	}
	return res, nil
}

func (r *mqlNextdnsProfile) rewrites() ([]any, error) {
	d, err := r.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(d.Rewrites))
	for _, rw := range d.Rewrites {
		mqlRewrite, err := CreateResource(r.MqlRuntime, "nextdns.profileRewrite", map[string]*llx.RawData{
			"__id":    llx.StringData(r.Id.Data + "/rewrite/" + rw.ID),
			"id":      llx.StringData(rw.ID),
			"name":    llx.StringData(rw.Name),
			"type":    llx.StringData(rw.Type),
			"content": llx.StringData(rw.Content),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRewrite)
	}
	return res, nil
}
