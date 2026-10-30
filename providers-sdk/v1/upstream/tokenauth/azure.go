// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tokenauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// MONDOO_WIF_CLIENT_ID names a user-assigned identity by client id; unset
	// selects the system-assigned identity. MONDOO_WIF_AUDIENCE names the token's
	// aud claim (an app registration URI, e.g. api://example).
	envClientID      = "MONDOO_WIF_CLIENT_ID"
	envTokenAudience = "MONDOO_WIF_AUDIENCE"
	// Injected by Azure on App Service, Functions and Container Apps: the local
	// token endpoint and the secret that authenticates callers to it.
	envIdentityEndpoint  = "IDENTITY_ENDPOINT"
	envIdentityHeader    = "IDENTITY_HEADER"
	appServiceAPIVersion = "2019-08-01"

	// Cloud Shell's token endpoint predates IMDS and always listens here.
	cloudShellTokenURL = "http://localhost:50342/oauth2/token"

	tokenFetchTimeout = 2 * time.Second
)

// AzureTokenProvider fetches an Azure AD access token from whichever managed
// identity endpoint the compute environment exposes: App Service (which also
// covers Functions and Container Apps) or Cloud Shell. VMs and scale sets use
// IMDS and are not supported.
type AzureTokenProvider struct {
	// cloudShellURL overrides the Cloud Shell endpoint; only tests set it.
	cloudShellURL string
}

func (p *AzureTokenProvider) GetToken(ctx context.Context, audience string) (string, error) {
	cloudShell := p.cloudShellURL
	if cloudShell == "" {
		cloudShell = cloudShellTokenURL
	}

	reqs, err := azureTokenRequests(audience, cloudShell)
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: tokenFetchTimeout}
	var errs []error
	for _, req := range reqs {
		token, err := req.RequestToken(ctx, client)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", req, err))
			continue
		}
		return token, nil
	}

	return "", fmt.Errorf("azure managed identity token request failed on all endpoints: %w", errors.Join(errs...))
}

// azureTokenRequest is one managed identity endpoint we know how to ask for a
// token. String labels it in aggregated errors and must not leak the secret.
type azureTokenRequest interface {
	fmt.Stringer
	RequestToken(ctx context.Context, client *http.Client) (string, error)
}

// azureTokenRequests builds the ordered list of endpoints to try, registering
// each only once the environment supplies what it needs.
func azureTokenRequests(audience, cloudShellURL string) ([]azureTokenRequest, error) {
	reqs := make([]azureTokenRequest, 0, 2)

	// App Service announces itself via IDENTITY_ENDPOINT. The header and a resource
	// are then both required; refuse early rather than send a request Azure answers
	// with an opaque 4xx that names nothing.
	if endpoint := os.Getenv(envIdentityEndpoint); endpoint != "" {
		// The header authenticates the caller to the local token service (SSRF
		// defense). Azure injects it alongside the endpoint, so its absence means
		// this is not really App Service.
		header := os.Getenv(envIdentityHeader)
		if header == "" {
			return nil, fmt.Errorf(
				"%s names an azure managed identity endpoint, but %s is unset: the endpoint rejects requests that do not carry it",
				envIdentityEndpoint, envIdentityHeader)
		}

		// Resource to mint for: MONDOO_WIF_AUDIENCE, else the exchange audience.
		resource := os.Getenv(envTokenAudience)
		if resource == "" {
			resource = audience
		}
		if resource == "" {
			return nil, fmt.Errorf(
				"%s names an azure managed identity endpoint, but no resource to mint for: set %s to the app registration URI, or pass an audience",
				envIdentityEndpoint, envTokenAudience)
		}

		reqs = append(reqs, appServiceTokenRequest{
			endpoint: endpoint,
			header:   header,
			resource: resource,
			clientID: os.Getenv(envClientID),
		})
	}

	// Cloud Shell needs nothing from the environment and is always tried, with the
	// caller's audience verbatim — the exact request sent before App Service
	// support, empty audience included, so existing users stay unaffected.
	reqs = append(reqs, cloudShellTokenRequest{
		endpoint: cloudShellURL,
		resource: audience,
	})

	return reqs, nil
}

// appServiceTokenRequest covers App Service, Functions and Container Apps: the
// resource travels in the query string, authenticated by the injected secret.
type appServiceTokenRequest struct {
	endpoint string
	header   string // required secret; the endpoint rejects requests without it
	resource string
	clientID string // user-assigned identity; empty selects system-assigned
}

func (r appServiceTokenRequest) String() string {
	identity := "system-assigned identity"
	if r.clientID != "" {
		identity = "client_id=" + r.clientID
	}
	return fmt.Sprintf("app service (%s, resource=%s, %s)", r.endpoint, r.resource, identity)
}

func (r appServiceTokenRequest) RequestToken(ctx context.Context, client *http.Client) (string, error) {
	q := url.Values{}
	q.Set("api-version", appServiceAPIVersion)
	q.Set("resource", r.resource)
	if r.clientID != "" {
		q.Set("client_id", r.clientID)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint+"?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-IDENTITY-HEADER", r.header)

	return requestAzureToken(client, req)
}

// cloudShellTokenRequest mints for the caller's audience via a form-encoded POST.
// Cloud Shell has no user-assigned identities, so there is no clientID.
type cloudShellTokenRequest struct {
	endpoint string
	resource string
}

func (r cloudShellTokenRequest) String() string {
	return fmt.Sprintf("cloud shell (%s, resource=%s)", r.endpoint, r.resource)
}

func (r cloudShellTokenRequest) RequestToken(ctx context.Context, client *http.Client) (string, error) {
	form := url.Values{}
	form.Set("resource", r.resource)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata", "true")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return requestAzureToken(client, req)
}

// requestAzureToken sends a built request and extracts the access token; both
// endpoints share this JSON response envelope.
func requestAzureToken(client *http.Client, req *http.Request) (string, error) {
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Surface Azure's complaint (invalid resource, no such identity, ...); a
		// bare status is unactionable. An error response never carries a token.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		detail := strings.TrimSpace(string(body))
		if detail == "" {
			detail = "<empty body>"
		}
		return "", fmt.Errorf("endpoint returned non-OK status %d: %s", resp.StatusCode, detail)
	}

	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.AccessToken == "" {
		return "", fmt.Errorf("endpoint returned an empty access_token")
	}
	return result.AccessToken, nil
}
