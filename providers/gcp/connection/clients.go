// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/api/transport"
	"google.golang.org/grpc"
)

// scopeCacheKey builds an order-independent cache key from a scope set so that
// Client/Credentials calls with the same scopes (in any order) share a cached
// result.
func scopeCacheKey(scopes []string) string {
	sorted := make([]string, len(scopes))
	copy(sorted, scopes)
	sort.Strings(sorted)
	return strings.Join(sorted, " ")
}

// Credentials returns OAuth credentials for the given scopes, building them
// once per scope set and caching the result on the connection. The credentials
// carry a token source that refreshes internally, so reuse is both correct and
// avoids re-parsing the service account / re-reading ADC on every call.
func (c *GcpConnection) Credentials(scopes ...string) (*googleoauth.Credentials, error) {
	key := scopeCacheKey(scopes)
	if v, ok := c.credsCache.Load(key); ok {
		return v.(*googleoauth.Credentials), nil
	}
	creds, err := c.buildCredentials(scopes...)
	if err != nil {
		return nil, err
	}
	actual, _ := c.credsCache.LoadOrStore(key, creds)
	return actual.(*googleoauth.Credentials), nil
}

func (c *GcpConnection) buildCredentials(scopes ...string) (*googleoauth.Credentials, error) {
	ctx := context.Background()
	credParams := googleoauth.CredentialsParams{
		Scopes:  scopes,
		Subject: c.opts.serviceAccountSubject,
	}
	if c.opts.cred != nil {
		// use service account from secret
		data, err := credsServiceAccountData(c.opts.cred)
		if err != nil {
			return nil, err
		}
		return googleoauth.CredentialsFromJSONWithParams(ctx, data, credParams)
	}

	// otherwise fallback to default google sdk authentication
	log.Debug().Msg("fallback to default google sdk authentication")
	return googleoauth.FindDefaultCredentials(ctx, scopes...)
}

// Client returns an HTTP client authorized for the given scopes, building it
// once per scope set and caching it on the connection. http.Client is safe for
// concurrent use, so the cached instance is shared across all callers.
func (c *GcpConnection) Client(scope ...string) (*http.Client, error) {
	key := scopeCacheKey(scope)
	if v, ok := c.clientCache.Load(key); ok {
		return v.(*http.Client), nil
	}
	client, err := c.buildClient(scope...)
	if err != nil {
		return nil, err
	}
	actual, _ := c.clientCache.LoadOrStore(key, client)
	return actual.(*http.Client), nil
}

// UseHTTPClient installs client as the HTTP client for the given scope set,
// bypassing credential resolution and the auth stack entirely.
//
// This is the provider's test seam. Every google.golang.org/api service here is
// built as
//
//	svc, err := foo.NewService(ctx, option.WithHTTPClient(conn.Client(scopes...)))
//
// so seeding the cache for a scope set points that whole service at whatever
// transport the caller supplies. That is what makes a lister's pagination,
// decoding and error degradation testable without credentials or a network --
// none of which had any coverage before, in a provider whose recurring bug is a
// listing that silently returns less than it should.
//
// The scopes must match the call site's, though the order does not matter:
// Client keys the cache on a sorted scope set.
func (c *GcpConnection) UseHTTPClient(client *http.Client, scopes ...string) {
	c.clientCache.Store(scopeCacheKey(scopes), client)
}

func (c *GcpConnection) buildClient(scope ...string) (*http.Client, error) {
	ctx := context.Background()

	var client *http.Client
	var err error
	// use service account from secret if one is provided
	if c.opts.cred != nil {
		data, dataErr := credsServiceAccountData(c.opts.cred)
		if dataErr != nil {
			return nil, dataErr
		}
		client, err = serviceAccountAuth(ctx, c.opts.serviceAccountSubject, data, scope...)
	} else {
		// otherwise fallback to default google sdk authentication
		log.Debug().Msg("fallback to default google sdk authentication")
		client, err = defaultAuth(ctx, scope...)
	}
	if err != nil {
		return nil, err
	}

	// wrap the transport so every Google API call is traced at Debug level
	client.Transport = newApiTraceTransport(client.Transport)
	return client, nil
}

// apiTraceTransport is an http.RoundTripper that logs every Google API call
// with its method, URL, status code, and duration at Debug level. It is the GCP
// analog of the Azure provider's apiTracePolicy, so that `-v` output reveals
// which APIs are being called (and against which projects/regions/zones) and
// whether they are failing, rather than presenting GCP discovery as a black box.
type apiTraceTransport struct {
	base http.RoundTripper
}

func newApiTraceTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &apiTraceTransport{base: base}
}

func (t *apiTraceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.base.RoundTrip(req)
	elapsed := time.Since(start)

	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	log.Debug().
		Str("method", req.Method).
		// host+path only: the query string can carry signed-URL tokens or
		// access tokens that must not leak into debug logs.
		Str("url", req.URL.Host+req.URL.Path).
		Int("status", status).
		Dur("duration", elapsed).
		Err(err).
		Msg("gcp api call")

	return resp, err
}

// loggingUnaryInterceptor logs every unary gRPC call (method, target, duration,
// and error) at Debug level. It is the gRPC counterpart of apiTraceTransport:
// most cloud.google.com/go client libraries (securitycenter, kms, bigquery,
// etc.) talk gRPC rather than HTTP, so without this their API calls would be
// invisible under `-v`. The read-only list/get/pager calls these resources make
// are all unary, so a unary interceptor covers them.
func loggingUnaryInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	start := time.Now()
	err := invoker(ctx, method, req, reply, cc, opts...)
	log.Debug().
		Str("method", method).
		Str("target", cc.Target()).
		Dur("duration", time.Since(start)).
		Err(err).
		Msg("gcp grpc call")
	return err
}

// GRPCClientTraceOption returns a client option that installs the Debug-level
// gRPC tracing interceptor. Pass it alongside option.WithCredentials when
// constructing a cloud.google.com/go (gRPC) client so its API calls are traced
// the same way HTTP calls are by apiTraceTransport. Example:
//
//	c, err := securitycenter.NewClient(ctx,
//		option.WithCredentials(creds),
//		connection.GRPCClientTraceOption(),
//	)
func GRPCClientTraceOption() option.ClientOption {
	return option.WithGRPCDialOption(grpc.WithChainUnaryInterceptor(loggingUnaryInterceptor))
}

// defaultAuth builds an HTTP client from Application Default Credentials.
// It routes through transport.NewHTTPClient with option.WithCredentials so that
// the quota project (from quota_project_id in the ADC JSON, or the
// GOOGLE_CLOUD_QUOTA_PROJECT env var) is propagated as the X-Goog-User-Project
// header. Going through googleoauth.DefaultClient skips that plumbing and
// causes APIs that bill the caller (apikeys, serviceusage,
// cloudresourcemanager) to fail with 403 against Google's default SDK project.
func defaultAuth(ctx context.Context, scope ...string) (*http.Client, error) {
	creds, err := googleoauth.FindDefaultCredentials(ctx, scope...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find google default credentials")
	}

	client, _, err := transport.NewHTTPClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create google http client")
	}
	return client, nil
}

// serviceAccountAuth implements
func serviceAccountAuth(ctx context.Context, subject string, serviceAccount []byte, scopes ...string) (*http.Client, error) {
	credParams := googleoauth.CredentialsParams{
		Scopes:  scopes,
		Subject: subject,
	}

	credentials, err := googleoauth.CredentialsFromJSONWithParams(ctx, serviceAccount, credParams)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create google credentials")
	}

	cleanCtx := context.WithValue(ctx, oauth2.HTTPClient, cleanhttp.DefaultClient())
	client, _, err := transport.NewHTTPClient(cleanCtx, option.WithTokenSource(credentials.TokenSource))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create google http client")
	}

	return client, nil
}

func credsServiceAccountData(cred *vault.Credential) ([]byte, error) {
	switch cred.Type {
	case vault.CredentialType_json:
		return cred.Secret, nil
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", cred.Type)
	}
}
