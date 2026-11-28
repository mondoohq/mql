// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
)

// Some services have no Go SDK module, or one pinned to an API version that
// predates the properties a check needs. Those are read with requests through
// the azcore ARM pipeline: it keeps the pipeline's authentication, retries,
// and *azcore.ResponseError on a non-2xx, so a listing still goes through
// listPaged and a refused read reports null like every SDK-backed list.

// newRawArmClient returns an ARM client for hand-written requests.
func newRawArmClient(conn *connection.AzureConnection, module string) (*arm.Client, error) {
	return arm.NewClient(module, "v1.0.0", conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
}

// armResourceURL builds the request URL for an ARM path (a resource ID or a
// collection path) at an API version.
func armResourceURL(client *arm.Client, path, apiVersion string) string {
	return runtime.JoinPaths(client.Endpoint(), path) + "?api-version=" + url.QueryEscape(apiVersion)
}

// armSubscriptionCollectionURL builds the URL listing a provider's resources
// of one type across a subscription, for example
// "Microsoft.HealthBot/healthBots".
func armSubscriptionCollectionURL(client *arm.Client, subscriptionID, providerType, apiVersion string) string {
	return armResourceURL(client,
		"/subscriptions/"+url.PathEscape(subscriptionID)+"/providers/"+providerType, apiVersion)
}

// armGet fetches one URL and returns the body of a 200 response. Any other
// status is returned as an *azcore.ResponseError, which the provider's
// classifiers understand.
func armGet(ctx context.Context, client *arm.Client, rawURL string) ([]byte, error) {
	req, err := runtime.NewRequest(ctx, http.MethodGet, rawURL)
	if err != nil {
		return nil, err
	}
	req.Raw().Header["Accept"] = []string{"application/json"}
	resp, err := client.Pipeline().Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return nil, runtime.NewResponseError(resp)
	}
	return runtime.Payload(resp)
}

// armGetJSON fetches one ARM resource and decodes it into out.
func armGetJSON(ctx context.Context, client *arm.Client, path, apiVersion string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, armHTTPTimeout)
	defer cancel()
	body, err := armGet(ctx, client, armResourceURL(client, path, apiVersion))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decoding %s: %w", path, err)
	}
	return nil
}

// armJSONPage is one page of an ARM list response.
type armJSONPage[T any] struct {
	Value    []*T    `json:"value"`
	NextLink *string `json:"nextLink"`
}

// armJSONPager walks an ARM list's nextLink chain, satisfying the pager
// interface listPaged takes.
type armJSONPager[T any] struct {
	client *arm.Client
	what   string
	next   string
	seen   map[string]struct{}
}

func newArmJSONPager[T any](client *arm.Client, what, firstURL string) *armJSONPager[T] {
	return &armJSONPager[T]{client: client, what: what, next: firstURL, seen: map[string]struct{}{}}
}

func (p *armJSONPager[T]) More() bool {
	return p.next != ""
}

func (p *armJSONPager[T]) NextPage(ctx context.Context) (armJSONPage[T], error) {
	var page armJSONPage[T]
	if len(p.seen) >= maxArmPages {
		return page, fmt.Errorf("%s: stopped after %d pages, the service kept returning a nextLink", p.what, maxArmPages)
	}
	// A cursor pointing at a page already fetched would loop forever and
	// duplicate every row it returned.
	if _, dup := p.seen[p.next]; dup {
		return page, fmt.Errorf("%s: pagination cycled back to %s", p.what, p.next)
	}
	p.seen[p.next] = struct{}{}

	body, err := armGet(ctx, p.client, p.next)
	if err != nil {
		return page, err
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return page, fmt.Errorf("decoding %s: %w", p.what, err)
	}
	p.next = convert.ToValue(page.NextLink)
	return page, nil
}

// armIdentity is the common ARM managed service identity block.
type armIdentity struct {
	Type                   *string                    `json:"type"`
	PrincipalID            *string                    `json:"principalId"`
	TenantID               *string                    `json:"tenantId"`
	UserAssignedIdentities map[string]json.RawMessage `json:"userAssignedIdentities"`
}

// armTrackedResource is the envelope every ARM tracked resource shares.
type armTrackedResource struct {
	ID       *string            `json:"id"`
	Name     *string            `json:"name"`
	Location *string            `json:"location"`
	Tags     map[string]*string `json:"tags"`
	Identity *armIdentity       `json:"identity"`
}

// orDefault returns the string p points at, or def when it is nil or empty:
// the value Azure uses for a setting the resource never set.
func orDefault(p *string, def string) string {
	if p == nil || *p == "" {
		return def
	}
	return *p
}

// isUserAssignedIdentityID reports whether id is the ARM ID of a user-assigned
// managed identity, rather than a marker such as "SystemAssigned".
func isUserAssignedIdentityID(id string) bool {
	return strings.Contains(strings.ToLower(id), "/providers/microsoft.managedidentity/userassignedidentities/")
}

// userAssignedIdentityRef resolves the user-assigned identity id names, and
// sets field to null when id names none.
func userAssignedIdentityRef(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlAzureSubscriptionManagedIdentity]) (*mqlAzureSubscriptionManagedIdentity, error) {
	if !isUserAssignedIdentityID(id) {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, ResourceAzureSubscriptionManagedIdentity,
		map[string]*llx.RawData{"__id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

// setArmResourceIdentity publishes an ARM identity block as resourceIdentity.
func setArmResourceIdentity(runtime *plugin.Runtime, args map[string]*llx.RawData, identity *armIdentity) error {
	id := orZero(identity)
	return setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(id.UserAssignedIdentities),
		identityType(id.Type), identityPrincipalId(id.PrincipalID), identityTenantId(id.TenantID))
}
