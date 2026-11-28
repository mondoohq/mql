// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type staticToken struct{}

func (staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "t"}, nil
}

func testArmClient(t *testing.T, srv *httptest.Server) *arm.Client {
	t.Helper()
	client, err := arm.NewClient("mql-azure-test", "v1.0.0", staticToken{}, &arm.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Cloud: cloud.Configuration{
				Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
					cloud.ResourceManager: {Endpoint: srv.URL, Audience: "https://management.azure.com"},
				},
			},
			Transport:                       srv.Client(),
			Retry:                           policy.RetryOptions{MaxRetries: -1},
			InsecureAllowCredentialWithHTTP: true,
		},
	})
	require.NoError(t, err)
	return client
}

func TestEasmWorkspacePager(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "":
			_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Easm/workspaces/ws1","name":"ws1","location":"eastus","tags":{"env":"prod"},"properties":{"provisioningState":"Succeeded","dataPlaneEndpoint":"https://eastus.easm.defender.microsoft.com"}}],"nextLink":"` + srv.URL + `/next?page=2"}`))
		case "2":
			_, _ = w.Write([]byte(`{"value":[{"id":"ws2-id","name":"ws2"}]}`))
		}
	}))
	defer srv.Close()

	p := &easmWorkspacePager{client: testArmClient(t, srv), next: srv.URL + "/list"}
	var got []*easmWorkspace
	for p.More() {
		page, err := p.NextPage(context.Background())
		require.NoError(t, err)
		got = append(got, page.Value...)
	}
	require.Len(t, got, 2)
	assert.Equal(t, "ws1", *got[0].Name)
	assert.Equal(t, "Succeeded", *got[0].Properties.ProvisioningState)
	assert.Equal(t, "https://eastus.easm.defender.microsoft.com", *got[0].Properties.DataPlaneEndpoint)
	assert.Equal(t, "prod", *got[0].Tags["env"])
	assert.Nil(t, got[1].Properties)
}

func TestEasmWorkspacePagerDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed","message":"denied"}}`))
	}))
	defer srv.Close()

	p := &easmWorkspacePager{client: testArmClient(t, srv), next: srv.URL + "/list"}
	_, err := p.NextPage(context.Background())
	require.Error(t, err)
	// listPaged reports a refused read as null only when it sees a 403
	// ResponseError, which is what going through the azcore pipeline buys.
	assert.Equal(t, faultDenied, azureFault(err))
}

func TestEasmWorkspacePagerCycle(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[],"nextLink":"` + srv.URL + `/list"}`))
	}))
	defer srv.Close()

	p := &easmWorkspacePager{client: testArmClient(t, srv), next: srv.URL + "/list"}
	_, err := p.NextPage(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycled")
}
