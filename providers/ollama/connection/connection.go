// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ollama/ollama/api"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	HostOption  = "host"
	TokenOption = "token"
)

// probeTimeout bounds the unauthenticated probe. It is a single request against
// an instance we already talk to, so a short budget is enough and keeps a
// wedged server from stalling the query.
const probeTimeout = 10 * time.Second

type OllamaConnection struct {
	plugin.Connection
	Conf  *inventory.Config
	asset *inventory.Asset

	client *api.Client
	// baseURL is the parsed host, kept so the scheme and hostname can be
	// inspected without re-parsing and so probes can build their own requests.
	baseURL *url.URL
	// baseTransport carries the TLS settings but never the API token, so an
	// unauthenticated probe can reuse it without leaking credentials.
	baseTransport http.RoundTripper
	// authTransport is what the API client itself sends through, so it carries
	// the API token when one is configured. A probe that has to be answered the
	// way an ordinary call would be reuses it, and every request through it goes
	// to the configured host exactly as the client's own calls do.
	authTransport http.RoundTripper

	versionOnce sync.Once
	version     string
	versionErr  error
}

func NewOllamaConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*OllamaConnection, error) {
	host := conf.Options[HostOption]
	if host == "" {
		host = os.Getenv("OLLAMA_HOST")
	}
	if host == "" {
		host = "http://localhost:11434"
	}

	token := conf.Options[TokenOption]
	if token == "" {
		token = os.Getenv("OLLAMA_API_TOKEN")
	}

	baseURL, err := url.Parse(host)
	if err != nil {
		return nil, err
	}

	var baseTransport http.RoundTripper
	if conf.Insecure {
		baseTransport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	httpClient := &http.Client{Transport: baseTransport}
	if token != "" {
		httpClient.Transport = &tokenTransport{
			token: token,
			base:  baseTransport,
		}
	}

	client := api.NewClient(baseURL, httpClient)

	conn := &OllamaConnection{
		Connection:    plugin.NewConnection(id, asset),
		Conf:          conf,
		asset:         asset,
		client:        client,
		baseURL:       baseURL,
		baseTransport: baseTransport,
		authTransport: httpClient.Transport,
	}

	return conn, nil
}

func (c *OllamaConnection) Name() string {
	return "ollama"
}

func (c *OllamaConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *OllamaConnection) Client() *api.Client {
	return c.client
}

func (c *OllamaConnection) Host() string {
	return c.baseURL.String()
}

// TLS reports whether the instance is reached over an encrypted connection.
func (c *OllamaConnection) TLS() bool {
	return strings.EqualFold(c.baseURL.Scheme, "https")
}

// IsLocal reports whether the configured host is a loopback address, meaning
// the API is only reachable from the machine running the server. Only the
// configured address is inspected; no name resolution is performed, so a
// hostname that happens to resolve to 127.0.0.1 reports false.
func (c *OllamaConnection) IsLocal() bool {
	hostname := c.baseURL.Hostname()
	if ip := net.ParseIP(hostname); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(hostname, "localhost") ||
		strings.HasSuffix(strings.ToLower(hostname), ".localhost")
}

// Version returns the version reported by the instance. The result is fetched
// once and reused, so asset detection and the version field share one call.
func (c *OllamaConnection) Version(ctx context.Context) (string, error) {
	c.versionOnce.Do(func() {
		c.version, c.versionErr = c.client.Version(ctx)
	})
	return c.version, c.versionErr
}

// writeProbeBody is the body of the unauthenticated write probe. It is
// truncated JSON: the object is opened and a key is started, then the bytes
// stop. No JSON decoder can parse it, so no field of a create request, above
// all no model name, can be read out of it. The key names the probe so an
// operator reading their server log can see what sent it.
const writeProbeBody = `{"mondoo_write_auth_probe":`

// AnonymousStatus issues a read-only request with no credentials attached and
// returns the HTTP status code the instance answers with. It deliberately uses
// the model listing endpoint: it is a plain GET that changes nothing, so the
// probe cannot alter the instance it is auditing.
func (c *OllamaConnection) AnonymousStatus(ctx context.Context) (int, error) {
	return c.anonymousStatus(ctx, http.MethodGet, "/api/tags", "")
}

// AnonymousWriteStatus reports the HTTP status an unauthenticated caller gets
// from the model-creation endpoint, which is what decides whether a stranger
// can replace the weights this instance serves.
//
// The probe cannot create, pull, or delete anything. It posts a body that is
// not valid JSON, and /api/create decodes its body before it does anything
// else: a body that fails to decode is answered 400 by the handler's first
// branch, with no model named and no state touched. Deleting and pulling are
// never attempted at all, because both take a model name and there is no
// malformed form of those requests that is safe to send.
//
// A server that gates writes rejects the request before its body is ever
// looked at, so its answer (401, 403, 407) is distinguishable from the 400 a
// server that accepts anonymous writes returns for the unparseable body.
func (c *OllamaConnection) AnonymousWriteStatus(ctx context.Context) (int, error) {
	return c.anonymousStatus(ctx, http.MethodPost, "/api/create", writeProbeBody)
}

// anonymousStatus issues one request with no credentials attached and returns
// the status code the instance answers with.
func (c *OllamaConnection) anonymousStatus(ctx context.Context, method, path, body string) (int, error) {
	var payload io.Reader
	if body != "" {
		payload = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL.JoinPath(path).String(), payload)
	if err != nil {
		return 0, err
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}

	// A fresh client, so the token-bearing transport cannot be reached.
	client := &http.Client{Transport: c.baseTransport, Timeout: probeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to probe %s for anonymous access: %w", c.baseURL.Host, err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// CORSObservation records what the instance answered a cross-origin request
// made on behalf of a web origin it has no relationship with.
type CORSObservation struct {
	// ProbeOrigin is the unrelated web origin the request was made for. It is
	// generated per run, so it cannot coincide with an origin an operator chose
	// to permit.
	ProbeOrigin string
	// AllowOrigin is the Access-Control-Allow-Origin the instance returned for
	// ProbeOrigin, empty when it returned none.
	AllowOrigin string
	// Observed reports whether either answer carried cross-origin headers at
	// all, which is what tells a refusal apart from an instance that does not
	// handle cross-origin requests and therefore says nothing about them.
	Observed bool
}

// corsControlOrigin is a web origin every Ollama build permits: the defaults
// always include an `app://*` pattern, whatever OLLAMA_ORIGINS is set to, since
// the desktop app depends on it. Its answer is the control for the unrelated
// origin's: cross-origin headers here mean the instance handles cross-origin
// requests, so their absence for the unrelated origin is a refusal rather than
// silence.
const corsControlOrigin = "app://mondoo-cors-control"

// CORS asks the instance, once for an unrelated web origin and once for an
// origin it is known to permit, which origin it allows a browser page to use.
// Both are preflight requests, which carry no body and reach no handler, so
// neither can change anything on the instance.
func (c *OllamaConnection) CORS(ctx context.Context) (CORSObservation, error) {
	label, err := randomProbeLabel()
	if err != nil {
		return CORSObservation{}, err
	}
	obs := CORSObservation{ProbeOrigin: "https://" + label + ".example.com"}

	probeAllow, probeObserved, err := c.preflight(ctx, obs.ProbeOrigin)
	if err != nil {
		return CORSObservation{}, err
	}
	obs.AllowOrigin = probeAllow
	obs.Observed = probeObserved

	if obs.Observed {
		return obs, nil
	}

	_, controlObserved, err := c.preflight(ctx, corsControlOrigin)
	if err != nil {
		return CORSObservation{}, err
	}
	obs.Observed = controlObserved

	return obs, nil
}

// preflight sends one cross-origin preflight for the given origin and reports
// the origin the instance allowed along with whether the answer carried any
// cross-origin headers.
func (c *OllamaConnection) preflight(ctx context.Context, origin string) (allowOrigin string, observed bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, c.baseURL.JoinPath("/").String(), nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", "authorization,content-type")

	// A fresh client, so the token-bearing transport cannot be reached: a
	// preflight is answered before any credential is looked at, and sending one
	// would only risk leaking it.
	client := &http.Client{Transport: c.baseTransport, Timeout: probeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return "", false, fmt.Errorf("failed to ask %s which web origins it allows: %w", c.baseURL.Host, err)
	}
	defer resp.Body.Close()

	allowOrigin = resp.Header.Get("Access-Control-Allow-Origin")
	observed = allowOrigin != "" ||
		resp.Header.Get("Access-Control-Allow-Methods") != "" ||
		resp.Header.Get("Access-Control-Allow-Headers") != ""
	return allowOrigin, observed, nil
}

// HostHeaderObservation records how the instance answered the same read-only
// request under its own host name and under one it has no relationship with.
type HostHeaderObservation struct {
	// ForeignHost is the unrelated host name the second request claimed. It is
	// generated per run, so it cannot coincide with a name an operator chose to
	// answer to.
	ForeignHost string
	// ControlStatus is the status for the request under the instance's own host
	// name. Anything but 200 means the pair says nothing, because whatever
	// turned the control away would have turned the other one away too.
	ControlStatus int
	// ForeignStatus is the status for the request under ForeignHost.
	ForeignStatus int
}

// ForeignHostStatus asks the instance for its model listing twice, once under
// its own host name and once under an unrelated one, and reports both answers.
// Both are the plain GET the models field already makes, so neither changes
// anything on the instance.
//
// The requests carry the configured API token, because the question is whether
// the host name alone decides the answer: an instance that gates reads would
// turn an unauthenticated pair away for the wrong reason and the control makes
// that visible.
func (c *OllamaConnection) ForeignHostStatus(ctx context.Context) (HostHeaderObservation, error) {
	label, err := randomProbeLabel()
	if err != nil {
		return HostHeaderObservation{}, err
	}
	obs := HostHeaderObservation{ForeignHost: label + ".example.com"}

	obs.ControlStatus, err = c.tagsStatusForHost(ctx, "")
	if err != nil {
		return HostHeaderObservation{}, err
	}
	obs.ForeignStatus, err = c.tagsStatusForHost(ctx, obs.ForeignHost)
	if err != nil {
		return HostHeaderObservation{}, err
	}

	return obs, nil
}

// tagsStatusForHost issues the model listing request and returns the status the
// instance answered with. An empty host leaves the request's own host name in
// place; anything else claims that name instead. The connection still goes to
// the configured address either way, so the token never reaches another server.
func (c *OllamaConnection) tagsStatusForHost(ctx context.Context, host string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL.JoinPath("/api/tags").String(), nil)
	if err != nil {
		return 0, err
	}
	if host != "" {
		req.Host = host
	}

	client := &http.Client{Transport: c.authTransport, Timeout: probeTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to ask %s whether it answers to another host name: %w", c.baseURL.Host, err)
	}
	defer resp.Body.Close()

	return resp.StatusCode, nil
}

// randomProbeLabel returns an unguessable DNS label. Both host and origin
// probes build their name from one, so a probe cannot accidentally name
// something the operator deliberately allowed and report it as a weakness.
func randomProbeLabel() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("failed to generate a probe name: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

type tokenTransport struct {
	token string
	base  http.RoundTripper
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}
