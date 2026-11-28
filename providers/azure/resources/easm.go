// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// Defender External Attack Surface Management has no Go SDK module, so its
// workspaces are listed with a request through the azcore ARM pipeline. That
// keeps the pipeline's authentication, retries, and *azcore.ResponseError on a
// non-2xx, so the walk goes through listPaged and a refused read reports null
// like every SDK-backed list. The generic resources listing would also find the
// workspaces, but it returns no resource properties, so neither the data plane
// endpoint nor (without an expand) the provisioning state.

// easmAPIVersion is the newest Microsoft.Easm API version.
const easmAPIVersion = "2023-04-01-preview"

// easmWorkspace is one Microsoft.Easm/workspaces row.
type easmWorkspace struct {
	ID         *string            `json:"id"`
	Name       *string            `json:"name"`
	Location   *string            `json:"location"`
	Tags       map[string]*string `json:"tags"`
	Properties *struct {
		ProvisioningState *string `json:"provisioningState"`
		DataPlaneEndpoint *string `json:"dataPlaneEndpoint"`
	} `json:"properties"`
}

// easmWorkspacePage is one page of the workspace listing.
type easmWorkspacePage struct {
	Value    []*easmWorkspace `json:"value"`
	NextLink *string          `json:"nextLink"`
}

// parseEasmWorkspacePage decodes one page of the workspace listing.
func parseEasmWorkspacePage(body []byte) (easmWorkspacePage, error) {
	var page easmWorkspacePage
	if err := json.Unmarshal(body, &page); err != nil {
		return page, fmt.Errorf("decoding Defender EASM workspaces: %w", err)
	}
	return page, nil
}

// easmWorkspacePager walks the workspace listing's nextLink chain, satisfying
// the pager interface listPaged takes.
type easmWorkspacePager struct {
	client *arm.Client
	next   string
	pages  int
}

func (p *easmWorkspacePager) More() bool {
	return p.next != ""
}

func (p *easmWorkspacePager) NextPage(ctx context.Context) (easmWorkspacePage, error) {
	if p.pages >= maxArmPages {
		return easmWorkspacePage{}, fmt.Errorf("Defender EASM workspaces: stopped after %d pages, the service kept returning a nextLink", maxArmPages)
	}
	p.pages++

	req, err := runtime.NewRequest(ctx, http.MethodGet, p.next)
	if err != nil {
		return easmWorkspacePage{}, err
	}
	req.Raw().Header["Accept"] = []string{"application/json"}
	resp, err := p.client.Pipeline().Do(req)
	if err != nil {
		return easmWorkspacePage{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return easmWorkspacePage{}, runtime.NewResponseError(resp)
	}
	body, err := runtime.Payload(resp)
	if err != nil {
		return easmWorkspacePage{}, err
	}
	page, err := parseEasmWorkspacePage(body)
	if err != nil {
		return easmWorkspacePage{}, err
	}
	next := convert.ToValue(page.NextLink)
	if next == p.next {
		return easmWorkspacePage{}, fmt.Errorf("Defender EASM workspaces: pagination cycled back to %s", next)
	}
	p.next = next
	return page, nil
}

func (a *mqlAzureSubscriptionCloudDefenderService) easmWorkspaces() ([]any, error) {
	conn, err := azureConn(a.MqlRuntime)
	if err != nil {
		return nil, err
	}
	client, err := arm.NewClient("mql-azure-easm", "v1.0.0", conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	first := runtime.JoinPaths(client.Endpoint(),
		"/subscriptions/"+url.PathEscape(a.SubscriptionId.Data)+"/providers/Microsoft.Easm/workspaces") +
		"?api-version=" + easmAPIVersion

	return listPaged(a.MqlRuntime, &a.EasmWorkspaces, "Defender EASM workspaces",
		&easmWorkspacePager{client: client, next: first},
		func(page easmWorkspacePage) []*easmWorkspace { return page.Value },
		createEasmWorkspace,
	)
}

// createEasmWorkspace builds the MQL resource for one Defender EASM workspace.
func createEasmWorkspace(runtime *plugin.Runtime, w *easmWorkspace) (plugin.Resource, error) {
	var provisioningState, dataPlaneEndpoint string
	if w.Properties != nil {
		provisioningState = convert.ToValue(w.Properties.ProvisioningState)
		dataPlaneEndpoint = convert.ToValue(w.Properties.DataPlaneEndpoint)
	}
	return CreateResource(runtime, ResourceAzureSubscriptionCloudDefenderServiceEasmWorkspace, map[string]*llx.RawData{
		"__id":              llx.StringDataPtr(w.ID),
		"id":                llx.StringDataPtr(w.ID),
		"name":              llx.StringDataPtr(w.Name),
		"location":          llx.StringDataPtr(w.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(w.Tags), types.String),
		"provisioningState": llx.StringData(provisioningState),
		"dataPlaneEndpoint": llx.StringData(dataPlaneEndpoint),
	})
}

func (a *mqlAzureSubscriptionCloudDefenderServiceEasmWorkspace) id() (string, error) {
	return a.Id.Data, nil
}
