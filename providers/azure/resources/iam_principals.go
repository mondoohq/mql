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
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

const (
	// graphScope is the OAuth scope a Microsoft Graph call needs. The same
	// credential the ARM clients use can request it, provided the app (or the
	// signed-in user) has been granted directory read access.
	graphScope = "https://graph.microsoft.com/.default"

	// graphEndpoint is the Graph v1.0 base URL for the public cloud. The
	// provider targets the public cloud throughout (see getArmSecurityConnection,
	// which pins cloud.AzurePublic the same way).
	graphEndpoint = "https://graph.microsoft.com/v1.0"

	// graphGetByIdsBatchSize is the maximum number of object IDs Graph accepts
	// in a single directoryObjects/getByIds request.
	graphGetByIdsBatchSize = 1000

	// graphRequestTimeout bounds a single getByIds round trip. Without it an
	// unresponsive Graph endpoint would hang the request forever, and because
	// resolvePrincipal deliberately holds its memo lock across the fetch to
	// coalesce concurrent resolves, that hang would stall every other
	// principal() accessor for the rest of the scan. A full 1000-ID batch
	// normally returns in a few seconds, so this bounds the failure without
	// cutting off legitimate work.
	graphRequestTimeout = 30 * time.Second
)

// graphPrincipalTypes are the directory object types worth requesting. Naming
// them explicitly (rather than letting Graph default to directoryObject) is
// what makes the type-specific properties below come back populated.
var graphPrincipalTypes = []string{"user", "group", "servicePrincipal", "application", "device"}

// graphPrincipal is the subset of a Microsoft Graph directory object this
// provider models. Graph returns a union of the requested types, so most
// fields are populated for only some of them.
type graphPrincipal struct {
	ODataType              string `json:"@odata.type"`
	ID                     string `json:"id"`
	DisplayName            string `json:"displayName"`
	UserPrincipalName      string `json:"userPrincipalName"`
	AppID                  string `json:"appId"`
	AppOwnerOrganizationID string `json:"appOwnerOrganizationId"`
	ServicePrincipalType   string `json:"servicePrincipalType"`
	AccountEnabled         *bool  `json:"accountEnabled"`
	IsAssignableToRole     *bool  `json:"isAssignableToRole"`
}

type graphGetByIdsRequest struct {
	IDs   []string `json:"ids"`
	Types []string `json:"types"`
}

type graphGetByIdsResponse struct {
	Value []graphPrincipal `json:"value"`
}

// principalTypeFromODataType turns a Graph type annotation
// ("#microsoft.graph.servicePrincipal") into the bare type name
// ("servicePrincipal"), or "" for a type this provider does not model.
func principalTypeFromODataType(odataType string) string {
	name := strings.TrimPrefix(strings.TrimPrefix(odataType, "#"), "microsoft.graph.")
	for _, t := range graphPrincipalTypes {
		if strings.EqualFold(name, t) {
			return t
		}
	}
	return ""
}

// graphDirectoryReadDenied marks the case where the credential reached Graph
// but is not allowed to read the directory. It is reported as an error rather
// than as an absent principal: a privilege audit that silently rendered every
// grant as "no principal" would understate who holds access, which is the most
// dangerous way for this to fail.
var graphDirectoryReadDenied = errors.New(
	"cannot resolve Microsoft Entra principals: the credential is not authorized to read the directory. " +
		"Grant it Microsoft Graph Directory.Read.All (application permission, admin-consented) to resolve role assignment principals")

// fetchGraphPrincipals resolves directory object IDs to principals via
// directoryObjects/getByIds, in batches of graphGetByIdsBatchSize. The returned
// map is keyed by object ID and omits IDs Graph did not resolve: getByIds
// silently drops unknown IDs, which is how a role assignment naming a deleted
// principal is detected.
func fetchGraphPrincipals(ctx context.Context, conn *connection.AzureConnection, ids []string) (map[string]*graphPrincipal, error) {
	res := map[string]*graphPrincipal{}
	if len(ids) == 0 {
		return res, nil
	}

	client := http.Client{Timeout: graphRequestTimeout}
	url := graphEndpoint + "/directoryObjects/getByIds"

	for start := 0; start < len(ids); start += graphGetByIdsBatchSize {
		end := min(start+graphGetByIdsBatchSize, len(ids))

		body, err := json.Marshal(graphGetByIdsRequest{IDs: ids[start:end], Types: graphPrincipalTypes})
		if err != nil {
			return nil, err
		}

		// Fetch the token per batch so resolving a large tenant doesn't fail on
		// an expired bearer token; the credential caches and only refreshes when
		// the token is near expiry (mirrors getPolicyAssignments).
		token, err := conn.Token().GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{graphScope}})
		if err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token.Token)

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			resp.Body.Close()
			return nil, graphDirectoryReadDenied
		}
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to resolve Entra principals: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
		}

		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		page := graphGetByIdsResponse{}
		if err := json.Unmarshal(raw, &page); err != nil {
			return nil, err
		}
		for i := range page.Value {
			p := page.Value[i]
			if p.ID != "" {
				res[strings.ToLower(p.ID)] = &p
			}
		}
	}
	return res, nil
}

type mqlAzureSubscriptionAuthorizationServiceInternal struct {
	// principalsMu guards the memo below and is deliberately held across the
	// Graph call, so concurrent block evaluation resolves principals in one
	// batched request instead of racing to issue one per assignment.
	//
	// Releasing it before the fetch and re-checking afterwards (ordinary
	// double-check locking) would keep the memo correct but lose the
	// coalescing: the executor evaluates block fields in goroutines, so every
	// role assignment whose principal() runs before the first fetch returns
	// would see an unseeded memo and issue its own single-ID request. On a
	// subscription with a few hundred assignments that is a few hundred Graph
	// round trips in place of one, which invites the 429 throttling that
	// batching exists to avoid. The stall this risks instead is bounded by
	// graphRequestTimeout.
	principalsMu   sync.Mutex
	principals     map[string]*graphPrincipal
	principalsMiss map[string]struct{}
	principalsSeed bool
}

// assignmentPrincipalIDs returns the principal IDs named by the subscription's
// role assignments, so the first resolution can seed the memo for the whole
// subscription in one request. A failure to list assignments is not fatal here:
// the caller still resolves the single ID it was asked about.
func (a *mqlAzureSubscriptionAuthorizationService) assignmentPrincipalIDs() []string {
	assignments := a.GetRoleAssignments()
	if assignments.Error != nil {
		return nil
	}
	ids := make([]string, 0, len(assignments.Data))
	for _, item := range assignments.Data {
		assignment, ok := item.(*mqlAzureSubscriptionAuthorizationServiceRoleAssignment)
		if !ok {
			continue
		}
		if assignment.PrincipalId.Data != "" {
			ids = append(ids, assignment.PrincipalId.Data)
		}
	}
	return ids
}

// resolvePrincipal resolves one principal ID against the directory. The first
// call also pulls in every principal the subscription's role assignments name,
// so auditing a whole subscription costs a single Graph round trip; later calls
// are served from the memo. IDs that arrive from another scope (a management
// group's assignment listing, say) are not in that seed, so they are fetched on
// demand rather than being mistaken for deleted principals.
//
// Returns (nil, nil) when Graph does not know the ID, which means the principal
// was deleted and the assignment is an orphaned grant.
func (a *mqlAzureSubscriptionAuthorizationService) resolvePrincipal(principalID string) (*graphPrincipal, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	key := strings.ToLower(principalID)

	a.principalsMu.Lock()
	defer a.principalsMu.Unlock()

	if a.principals == nil {
		a.principals = map[string]*graphPrincipal{}
		a.principalsMiss = map[string]struct{}{}
	}
	if p, ok := a.principals[key]; ok {
		return p, nil
	}
	if _, ok := a.principalsMiss[key]; ok {
		return nil, nil
	}

	wanted := []string{principalID}
	if !a.principalsSeed {
		wanted = append(wanted, a.assignmentPrincipalIDs()...)
		a.principalsSeed = true
	}

	// Deduplicate while preserving the requested ID first, and skip anything
	// already memoized from an earlier batch.
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(wanted))
	for _, id := range wanted {
		k := strings.ToLower(id)
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		if _, done := a.principals[k]; done {
			continue
		}
		if _, done := a.principalsMiss[k]; done {
			continue
		}
		ids = append(ids, id)
	}

	found, err := fetchGraphPrincipals(context.Background(), conn, ids)
	if err != nil {
		return nil, err
	}
	maps.Copy(a.principals, found)
	// Every ID we asked about and did not get back is a principal Graph cannot
	// resolve; record it so a repeat query doesn't re-request it.
	for _, id := range ids {
		k := strings.ToLower(id)
		if _, ok := a.principals[k]; !ok {
			a.principalsMiss[k] = struct{}{}
		}
	}

	if p, ok := a.principals[key]; ok {
		return p, nil
	}
	return nil, nil
}

func (a *mqlAzureSubscriptionAuthorizationServiceRoleAssignment) principal() (*mqlAzureEntraPrincipal, error) {
	if a.PrincipalId.Data == "" {
		a.Principal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	// Route through the subscription's authorization service so every assignment
	// shares one memo and one batched Graph fetch.
	r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + conn.SubId()),
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	iamVal := r.(*mqlAzureSubscription).GetIam()
	if iamVal.Error != nil {
		return nil, iamVal.Error
	}
	if iamVal.Data == nil {
		return nil, errors.New("cannot resolve the authorization service for the subscription")
	}

	p, err := iamVal.Data.resolvePrincipal(a.PrincipalId.Data)
	if err != nil {
		return nil, err
	}
	if p == nil {
		// Graph does not know this object: the principal was deleted and this is
		// an orphaned grant.
		a.Principal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAzureEntraPrincipal,
		map[string]*llx.RawData{
			"__id":                 llx.StringData(p.ID),
			"id":                   llx.StringData(p.ID),
			"displayName":          llx.StringData(p.DisplayName),
			"principalType":        llx.StringData(principalTypeFromODataType(p.ODataType)),
			"userPrincipalName":    llx.StringData(p.UserPrincipalName),
			"appId":                llx.StringData(p.AppID),
			"appOwnerTenantId":     llx.StringData(p.AppOwnerOrganizationID),
			"servicePrincipalType": llx.StringData(p.ServicePrincipalType),
			"accountEnabled":       llx.BoolDataPtr(p.AccountEnabled),
			"isAssignableToRole":   llx.BoolDataPtr(p.IsAssignableToRole),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureEntraPrincipal), nil
}
