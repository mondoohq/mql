// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

const (
	powerbiScope = "https://analysis.windows.net/powerbi/api/.default"

	// powerBiApiBase is the Power BI REST API root. The admin endpoints below
	// are the same ones the MicrosoftPowerBIMgmt module reaches through
	// Invoke-PowerBIRestMethod, so the payloads are unchanged.
	powerBiApiBase = "https://api.powerbi.com/v1.0/myorg/"

	// fabricTenantSettingsUrl serves tenant settings. They live on the Fabric
	// admin API rather than the Power BI REST API, but accept the same bearer
	// token.
	fabricTenantSettingsUrl = "https://api.fabric.microsoft.com/v1/admin/tenantsettings"

	// powerBiWorkspacePageSize is the maximum page size the admin groups
	// endpoint accepts.
	powerBiWorkspacePageSize = 5000

	// powerBiMaxPages bounds continuation following so a service that keeps
	// handing back a link cannot spin forever.
	powerBiMaxPages = 512

	// powerBiHTTPTimeout bounds a single request. powerBiMaxPages caps how many
	// requests a walk makes but says nothing about how long one may hang, and
	// these requests do not go through an SDK pipeline that would impose a
	// deadline of its own. Without it a stalled connection blocks the section
	// forever, and the sections are collected concurrently, so one hung endpoint
	// holds the whole report.
	powerBiHTTPTimeout = 60 * time.Second
)

// powerBiHTTPClient is shared by the admin API requests so they all get the
// timeout. http.Client is safe for concurrent use.
var powerBiHTTPClient = &http.Client{Timeout: powerBiHTTPTimeout}

// powerBiSection is one report section: its payload as raw JSON plus any error
// captured while collecting it. Each section is collected independently: the
// Power BI admin endpoints and the Fabric admin API have separate authorization
// requirements, so a permission gap in one section (for example tenant
// settings) must not blank the others. A non-nil error is surfaced by the
// section's getter so callers see the real cause (for example missing admin API
// access) instead of an empty result.
type powerBiSection struct {
	Data  json.RawMessage `json:"data"`
	Error *string         `json:"error"`
}

type powerBiReportRaw struct {
	TenantSettings            powerBiSection `json:"TenantSettings"`
	Workspaces                powerBiSection `json:"Workspaces"`
	Capacities                powerBiSection `json:"Capacities"`
	PublishedToWeb            powerBiSection `json:"PublishedToWeb"`
	SharedToWholeOrganization powerBiSection `json:"SharedToWholeOrganization"`
}

type powerBiTenantSetting struct {
	SettingName              string `json:"settingName"`
	Title                    string `json:"title"`
	Enabled                  bool   `json:"enabled"`
	CanSpecifySecurityGroups bool   `json:"canSpecifySecurityGroups"`
	TenantSettingGroup       string `json:"tenantSettingGroup"`
	EnabledSecurityGroups    []any  `json:"enabledSecurityGroups"`
}

type powerBiWorkspace struct {
	Id                    string          `json:"id"`
	Name                  string          `json:"name"`
	Type                  string          `json:"type"`
	State                 string          `json:"state"`
	IsOnDedicatedCapacity bool            `json:"isOnDedicatedCapacity"`
	IsReadOnly            bool            `json:"isReadOnly"`
	CapacityId            string          `json:"capacityId"`
	Description           string          `json:"description"`
	Users                 []powerBiWsUser `json:"users"`
}

type powerBiWsUser struct {
	DisplayName          string `json:"displayName"`
	EmailAddress         string `json:"emailAddress"`
	Identifier           string `json:"identifier"`
	PrincipalType        string `json:"principalType"`
	GroupUserAccessRight string `json:"groupUserAccessRight"`
	GraphId              string `json:"graphId"`
}

type powerBiCapacity struct {
	Id          string   `json:"id"`
	DisplayName string   `json:"displayName"`
	Sku         string   `json:"sku"`
	State       string   `json:"state"`
	Region      string   `json:"region"`
	Admins      []string `json:"admins"`
}

type powerBiArtifactAccess struct {
	ArtifactId   string `json:"artifactId"`
	DisplayName  string `json:"displayName"`
	ArtifactType string `json:"artifactType"`
	AccessRight  string `json:"accessRight"`
	ShareType    string `json:"shareType"`
	Sharer       struct {
		EmailAddress string `json:"emailAddress"`
		DisplayName  string `json:"displayName"`
	} `json:"sharer"`
}

// unmarshalPowerBiSection returns the section error when present, otherwise
// decodes the payload into a slice. Both the array and the bare-object form are
// accepted so an endpoint that returns a single object instead of a collection
// still decodes.
func unmarshalPowerBiSection[T any](s powerBiSection) ([]T, error) {
	if s.Error != nil && *s.Error != "" {
		return nil, errors.New(*s.Error)
	}
	trimmed := bytes.TrimSpace(s.Data)
	if len(trimmed) == 0 || string(trimmed) == "null" {
		return nil, nil
	}
	if trimmed[0] == '[' {
		var out []T
		if err := json.Unmarshal(trimmed, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	var single T
	if err := json.Unmarshal(trimmed, &single); err != nil {
		return nil, err
	}
	return []T{single}, nil
}

type mqlMicrosoftPowerbiInternal struct {
	reportLock sync.Mutex
	fetched    bool
	fetchErr   error
	raw        *powerBiReportRaw
}

// gatherReport runs the PowerShell collection once and caches the raw sections.
// The returned error covers connection and transport failures that affect the
// whole report; per-section authorization errors are carried inside the raw
// sections and surfaced by the individual getters.
func (r *mqlMicrosoftPowerbi) gatherReport() (*powerBiReportRaw, error) {
	r.reportLock.Lock()
	defer r.reportLock.Unlock()

	if r.fetched {
		return r.raw, r.fetchErr
	}
	r.fetched = true

	raw, err := r.fetchReport()
	r.raw = raw
	r.fetchErr = err
	return raw, err
}

func (r *mqlMicrosoftPowerbi) fetchReport() (*powerBiReportRaw, error) {
	conn := r.MqlRuntime.Connection.(*connection.Ms365Connection)
	ctx := context.Background()

	pbiToken, err := conn.Token().GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{powerbiScope},
	})
	if err != nil {
		return nil, err
	}
	token := pbiToken.Token

	// collect runs one section and converts a failure into a section error, so
	// a permission gap on one endpoint leaves the other sections intact.
	collect := func(fetch func() (json.RawMessage, error)) powerBiSection {
		data, err := fetch()
		if err != nil {
			msg := err.Error()
			return powerBiSection{Error: &msg}
		}
		return powerBiSection{Data: data}
	}
	get := func(url string, envelope ...string) func() (json.RawMessage, error) {
		return func() (json.RawMessage, error) {
			return powerBiGet(ctx, token, url, envelope...)
		}
	}

	raw := &powerBiReportRaw{
		// the documented envelope is "value"; "tenantSettings" is accepted as a
		// fallback because that is the name the previous collection looked for
		TenantSettings: collect(get(fabricTenantSettingsUrl, "value", "tenantSettings")),
		Workspaces: collect(func() (json.RawMessage, error) {
			return fetchPowerBiWorkspaces(ctx, token)
		}),
		Capacities:     collect(get(powerBiApiBase+"admin/capacities", "value")),
		PublishedToWeb: collect(get(powerBiApiBase+"admin/widelySharedArtifacts/publishedToWeb", "artifactAccessEntities")),
		SharedToWholeOrganization: collect(get(powerBiApiBase+"admin/widelySharedArtifacts/linksSharedToWholeOrganization",
			"artifactAccessEntities")),
	}

	if dump, err := json.Marshal(raw); err == nil {
		logger.DebugDumpJSON("ms-powerbi-report", string(dump))
	}
	return raw, nil
}

// powerBiGet issues an authenticated GET and returns the collection named by
// envelope, following continuation links so a large collection is not
// truncated at the service chunk size.
func powerBiGet(ctx context.Context, token string, url string, envelope ...string) (json.RawMessage, error) {
	all := []json.RawMessage{}
	next := url
	seen := map[string]struct{}{}

	for page := 0; next != ""; page++ {
		if page >= powerBiMaxPages {
			return nil, fmt.Errorf("power bi request to %s returned more than %d pages", url, powerBiMaxPages)
		}
		// a service that echoes the same continuation would otherwise loop
		if _, repeated := seen[next]; repeated {
			return nil, fmt.Errorf("power bi request to %s repeated the same continuation link", url)
		}
		seen[next] = struct{}{}

		body, err := powerBiRequest(ctx, token, next)
		if err != nil {
			return nil, err
		}

		raw, err := extractPowerBiEnvelope(body, envelope...)
		if err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			var chunk []json.RawMessage
			if err := json.Unmarshal(raw, &chunk); err != nil {
				// a single object rather than a collection ends the walk
				if page == 0 {
					return raw, nil
				}
				return nil, err
			}
			all = append(all, chunk...)
		}

		if next, err = powerBiContinuation(body); err != nil {
			return nil, err
		}
	}

	return json.Marshal(all)
}

func powerBiRequest(ctx context.Context, token string, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := powerBiHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, errors.New("access denied; ensure the service principal is granted read-only admin API access in the Power BI tenant settings")
		}
		return nil, fmt.Errorf("power bi request to %s failed with status %d: %s", url, resp.StatusCode, string(body))
	}

	return body, nil
}

// extractPowerBiEnvelope pulls the first of the named collections out of a
// response body. Several names are accepted because the endpoints do not agree
// on one: collections arrive under "value", "artifactAccessEntities" or
// "tenantSettings" depending on the API.
//
// The match is case-insensitive. PowerShell property access was, so a name
// whose casing differs from the response (the widely-shared-artifacts
// endpoints answer with "artifactAccessEntities") must still resolve.
//
// A response that carries none of the names has nothing to report, which
// yields a nil payload rather than an error.
func extractPowerBiEnvelope(body []byte, envelope ...string) (json.RawMessage, error) {
	var wrapper map[string]json.RawMessage
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return nil, err
	}

	for _, name := range envelope {
		if raw, ok := wrapper[name]; ok {
			return raw, nil
		}
		for key, raw := range wrapper {
			if strings.EqualFold(key, name) {
				return raw, nil
			}
		}
	}
	return nil, nil
}

// powerBiContinuation returns the link to the next chunk, or an empty string
// when the response is the last one. Both the Power BI admin endpoints and the
// Fabric admin API chunk their results this way.
func powerBiContinuation(body []byte) (string, error) {
	var wrapper struct {
		ContinuationUri   string `json:"continuationUri"`
		ContinuationToken string `json:"continuationToken"`
	}
	if err := json.Unmarshal(body, &wrapper); err != nil {
		return "", err
	}
	// the service hands back a ready-made uri; the token alone is ambiguous to
	// re-encode, so it only signals that a uri was expected
	if wrapper.ContinuationUri == "" && wrapper.ContinuationToken != "" {
		log.Warn().Msg("power bi returned a continuation token without a uri, results may be incomplete")
	}
	return wrapper.ContinuationUri, nil
}

// fetchPowerBiWorkspaces pages the admin groups endpoint so tenants with more
// than one page of workspaces are not silently truncated.
func fetchPowerBiWorkspaces(ctx context.Context, token string) (json.RawMessage, error) {
	return fetchPowerBiWorkspacePages(ctx, token, powerBiApiBase, powerBiWorkspacePageSize)
}

// fetchPowerBiWorkspacePages walks the admin groups endpoint until a short page
// signals the end of the collection. The pages are concatenated into a single
// array so the section decodes like any other.
//
// The walk is bounded by powerBiMaxPages for the same reason the continuation
// walk is: the only termination signal is a page shorter than pageSize, so an
// endpoint that ignores $skip answers every request with a full page and the
// loop never ends, appending pageSize workspaces per iteration until the scan
// is out of memory.
func fetchPowerBiWorkspacePages(ctx context.Context, token string, baseUrl string, pageSize int) (json.RawMessage, error) {
	all := []json.RawMessage{}
	for page := 0; ; page++ {
		if page >= powerBiMaxPages {
			return nil, fmt.Errorf("power bi admin/groups returned more than %d pages, the endpoint may be ignoring $skip", powerBiMaxPages)
		}

		url := fmt.Sprintf("%sadmin/groups?$top=%d&$expand=users&$skip=%d", baseUrl, pageSize, page*pageSize)
		raw, err := powerBiGet(ctx, token, url, "value")
		if err != nil {
			return nil, err
		}

		var chunk []json.RawMessage
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &chunk); err != nil {
				return nil, err
			}
		}
		all = append(all, chunk...)

		if len(chunk) < pageSize {
			break
		}
	}
	return json.Marshal(all)
}

func (r *mqlMicrosoftPowerbi) tenantSettings() ([]any, error) {
	raw, err := r.gatherReport()
	if err != nil {
		return nil, err
	}
	settings, err := unmarshalPowerBiSection[powerBiTenantSetting](raw.TenantSettings)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(settings))
	for i := range settings {
		s := settings[i]
		groups, err := convert.JsonToDictSlice(s.EnabledSecurityGroups)
		if err != nil {
			return nil, err
		}
		o, err := CreateResource(r.MqlRuntime, "microsoft.powerbi.tenantSetting", map[string]*llx.RawData{
			"__id":                     llx.StringData(s.SettingName),
			"name":                     llx.StringData(s.SettingName),
			"title":                    llx.StringData(s.Title),
			"enabled":                  llx.BoolData(s.Enabled),
			"canSpecifySecurityGroups": llx.BoolData(s.CanSpecifySecurityGroups),
			"tenantSettingGroup":       llx.StringData(s.TenantSettingGroup),
			"enabledSecurityGroups":    llx.ArrayData(groups, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlMicrosoftPowerbi) workspaces() ([]any, error) {
	raw, err := r.gatherReport()
	if err != nil {
		return nil, err
	}
	workspaces, err := unmarshalPowerBiSection[powerBiWorkspace](raw.Workspaces)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(workspaces))
	for i := range workspaces {
		ws := workspaces[i]
		o, err := CreateResource(r.MqlRuntime, "microsoft.powerbi.workspace", map[string]*llx.RawData{
			"__id":                  llx.StringData(ws.Id),
			"id":                    llx.StringData(ws.Id),
			"name":                  llx.StringData(ws.Name),
			"type":                  llx.StringData(ws.Type),
			"state":                 llx.StringData(ws.State),
			"isOnDedicatedCapacity": llx.BoolData(ws.IsOnDedicatedCapacity),
			"isReadOnly":            llx.BoolData(ws.IsReadOnly),
			"description":           llx.StringData(ws.Description),
		})
		if err != nil {
			return nil, err
		}
		mqlWs := o.(*mqlMicrosoftPowerbiWorkspace)
		mqlWs.cacheCapacityId = ws.CapacityId
		mqlWs.cacheUsers = ws.Users
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlMicrosoftPowerbi) capacities() ([]any, error) {
	raw, err := r.gatherReport()
	if err != nil {
		return nil, err
	}
	capacities, err := unmarshalPowerBiSection[powerBiCapacity](raw.Capacities)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(capacities))
	for i := range capacities {
		c := capacities[i]
		admins := make([]any, 0, len(c.Admins))
		for _, a := range c.Admins {
			admins = append(admins, a)
		}
		o, err := CreateResource(r.MqlRuntime, "microsoft.powerbi.capacity", map[string]*llx.RawData{
			"__id":        llx.StringData(c.Id),
			"id":          llx.StringData(c.Id),
			"displayName": llx.StringData(c.DisplayName),
			"sku":         llx.StringData(c.Sku),
			"state":       llx.StringData(c.State),
			"region":      llx.StringData(c.Region),
			"admins":      llx.ArrayData(admins, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

func (r *mqlMicrosoftPowerbi) publishedToWeb() ([]any, error) {
	raw, err := r.gatherReport()
	if err != nil {
		return nil, err
	}
	entries, err := unmarshalPowerBiSection[powerBiArtifactAccess](raw.PublishedToWeb)
	if err != nil {
		return nil, err
	}
	return r.createArtifactAccess(entries, "publishedToWeb")
}

func (r *mqlMicrosoftPowerbi) sharedToWholeOrganization() ([]any, error) {
	raw, err := r.gatherReport()
	if err != nil {
		return nil, err
	}
	entries, err := unmarshalPowerBiSection[powerBiArtifactAccess](raw.SharedToWholeOrganization)
	if err != nil {
		return nil, err
	}
	return r.createArtifactAccess(entries, "sharedToWholeOrganization")
}

func (r *mqlMicrosoftPowerbi) createArtifactAccess(entries []powerBiArtifactAccess, shareKind string) ([]any, error) {
	res := make([]any, 0, len(entries))
	for i := range entries {
		a := entries[i]
		o, err := CreateResource(r.MqlRuntime, "microsoft.powerbi.artifactAccess", map[string]*llx.RawData{
			"__id":               llx.StringData(shareKind + "/" + a.ArtifactId + "/" + a.ShareType),
			"artifactId":         llx.StringData(a.ArtifactId),
			"displayName":        llx.StringData(a.DisplayName),
			"artifactType":       llx.StringData(a.ArtifactType),
			"accessRight":        llx.StringData(a.AccessRight),
			"shareType":          llx.StringData(a.ShareType),
			"sharerEmailAddress": llx.StringData(a.Sharer.EmailAddress),
			"sharerDisplayName":  llx.StringData(a.Sharer.DisplayName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}

type mqlMicrosoftPowerbiWorkspaceInternal struct {
	cacheCapacityId string
	cacheUsers      []powerBiWsUser
}

func (w *mqlMicrosoftPowerbiWorkspace) capacity() (*mqlMicrosoftPowerbiCapacity, error) {
	if w.cacheCapacityId == "" {
		w.Capacity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	o, err := CreateResource(w.MqlRuntime, "microsoft.powerbi", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	caps := o.(*mqlMicrosoftPowerbi).GetCapacities()
	if caps.Error != nil {
		return nil, caps.Error
	}
	for _, c := range caps.Data {
		mqlCap := c.(*mqlMicrosoftPowerbiCapacity)
		if mqlCap.Id.Data == w.cacheCapacityId {
			return mqlCap, nil
		}
	}

	w.Capacity.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (w *mqlMicrosoftPowerbiWorkspace) users() ([]any, error) {
	res := make([]any, 0, len(w.cacheUsers))
	for i := range w.cacheUsers {
		u := w.cacheUsers[i]
		ident := u.Identifier
		if ident == "" {
			ident = u.GraphId
		}
		if ident == "" {
			ident = u.EmailAddress
		}
		o, err := CreateResource(w.MqlRuntime, "microsoft.powerbi.workspace.user", map[string]*llx.RawData{
			"__id":          llx.StringData(w.Id.Data + "/" + ident),
			"displayName":   llx.StringData(u.DisplayName),
			"emailAddress":  llx.StringData(u.EmailAddress),
			"identifier":    llx.StringData(u.Identifier),
			"principalType": llx.StringData(u.PrincipalType),
			"accessRight":   llx.StringData(u.GroupUserAccessRight),
			"graphId":       llx.StringData(u.GraphId),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, o)
	}
	return res, nil
}
