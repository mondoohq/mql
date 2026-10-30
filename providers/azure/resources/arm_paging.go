// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"go.mondoo.com/mql/providers/azure/connection"
)

// A handful of endpoints in this provider are fetched with a hand-rolled
// request rather than through an SDK client, because the vendored SDK models
// them as a single call or does not ship a client at all. Those requests get
// none of what the azcore pipeline normally provides, so the pieces they still
// need -- a bounded page walk, a request timeout, an honest error on a non-2xx
// -- live here rather than being written out once per call site.

const (
	// maxArmPages bounds a nextLink walk. ARM is not supposed to return a
	// cursor that cycles or never terminates, but nothing in the protocol
	// prevents it, and an unbounded loop would hang the scan while growing the
	// result without limit. A thousand pages is far beyond any real collection.
	maxArmPages = 1000

	// armHTTPTimeout bounds a single request. Without it a hung connection
	// stalls the field forever: these requests do not go through the azcore
	// pipeline, so nothing else imposes a deadline.
	armHTTPTimeout = 60 * time.Second
)

// armHTTPClient is shared by the hand-rolled requests so they all get the
// timeout. http.Client is safe for concurrent use.
var armHTTPClient = &http.Client{Timeout: armHTTPTimeout}

// armTokenFunc adapts a connection's credential to the getter fetchArmPages
// wants, for callers that are not going through armSecurityConn.
func armTokenFunc(conn *connection.AzureConnection) func(context.Context) (azcore.AccessToken, error) {
	return func(ctx context.Context) (azcore.AccessToken, error) {
		return conn.Token().GetToken(ctx, policy.TokenRequestOptions{
			Scopes: []string{"https://management.core.windows.net//.default"},
		})
	}
}

// fetchArmPages walks an ARM collection starting at firstURL, calling decode
// with each page body. decode returns the nextLink to continue with, or "" to
// stop.
//
// The token is fetched per page rather than once up front: a walk over a large
// collection can outlive a bearer token, and the credential caches, so asking
// again is cheap and only refreshes near expiry. getToken takes the walk's
// context so a refresh cannot outlive a cancelled walk.
func fetchArmPages(
	ctx context.Context,
	getToken func(context.Context) (azcore.AccessToken, error),
	firstURL string,
	what string,
	decode func(body []byte) (nextLink string, err error),
) error {
	seen := make(map[string]struct{}, 8)
	next := firstURL

	for page := 0; next != ""; page++ {
		if page >= maxArmPages {
			return fmt.Errorf("%s: stopped after %d pages, the service kept returning a nextLink", what, maxArmPages)
		}
		// A cursor that points at a page already fetched would loop forever and
		// duplicate every row it returned.
		if _, dup := seen[next]; dup {
			return fmt.Errorf("%s: pagination cycled back to %s", what, next)
		}
		seen[next] = struct{}{}

		token, err := getToken(ctx)
		if err != nil {
			return err
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+token.Token)

		resp, err := armHTTPClient.Do(req)
		if err != nil {
			return err
		}

		// Read the status before the body: an error body must surface as an
		// error, never be decoded as a zero-length page. That would report an
		// empty collection as fact.
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return errors.New("failed to fetch " + what + " from " + next + ": " + resp.Status)
		}

		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return err
		}

		next, err = decode(raw)
		if err != nil {
			return err
		}
	}
	return nil
}
