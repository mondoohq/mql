// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	OptionAPIKey  = "api-key"
	OptionBaseURL = "base-url"
	OptionTimeout = "timeout"

	DefaultTimeoutSeconds = 10

	endpointProbeWorkers = 8
	maxProbeBody         = 64 << 10
	maxVersionBody       = 1 << 20

	corsProbeOrigin  = "https://mondoo.example"
	corsProbeHeaders = "authorization,content-type"
)

type EndpointSpec struct {
	Method   string
	Path     string
	Category string
	Body     string
	// StateChanging marks a route whose documented method mutates the server:
	// it aborts in-flight work, puts the engine to sleep, swaps a LoRA adapter,
	// drops a cache, or cancels a stored response. A probe for such a route must
	// never reach the handler.
	StateChanging bool
	// ProbeMethod is the HTTP method actually put on the wire. State-changing
	// routes set it to a method the route does not accept, so the request is
	// answered by the router with 405 when the route is registered and 404 when
	// it is not, and the handler never runs.
	ProbeMethod string
}

// WireMethod is the HTTP method the probe sends. It differs from Method only
// for state-changing routes, where the probe deliberately uses a method the
// route rejects.
func (s EndpointSpec) WireMethod() string {
	if s.ProbeMethod != "" {
		return strings.ToUpper(s.ProbeMethod)
	}
	return strings.ToUpper(s.Method)
}

type EndpointObservation struct {
	Spec                    EndpointSpec
	AnonymousStatusCode     *int
	AuthenticatedStatusCode *int
	AnonymousError          string
	AuthenticatedError      string
}

type VllmConnection struct {
	plugin.Connection
	Conf    *inventory.Config
	asset   *inventory.Asset
	client  *http.Client
	baseURL string
	apiKey  string

	endpointsOnce sync.Once
	endpoints     []EndpointObservation
	endpointsErr  error

	corsOnce sync.Once
	cors     CORSObservation
	corsErr  error

	versionOnce sync.Once
	version     string
	versionErr  error

	serverInfoOnce sync.Once
	serverInfo     *ServerInfo
	serverInfoErr  error

	tokenizerInfoOnce sync.Once
	tokenizerInfo     *TokenizerInfo
	tokenizerInfoErr  error

	metricsOnce sync.Once
	metrics     *MetricsSnapshot
	metricsErr  error

	storedResponsesOnce sync.Once
	storedResponses     StoredResponseObservation
	storedResponsesErr  error
}

type CORSObservation struct {
	Configured      *bool
	AllowsAnyOrigin *bool
	StatusCode      *int
	AllowOrigin     string
}

func NewVllmConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*VllmConnection, error) {
	baseURL, err := baseURLFromConfig(conf)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(DefaultTimeoutSeconds) * time.Second
	if conf.Options != nil {
		if raw := strings.TrimSpace(conf.Options[OptionTimeout]); raw != "" {
			seconds, err := strconv.Atoi(raw)
			if err != nil || seconds <= 0 {
				return nil, fmt.Errorf("vllm: invalid timeout %q", raw)
			}
			timeout = time.Duration(seconds) * time.Second
		}
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if conf.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // user-controlled flag for lab/test environments
	}

	conn := &VllmConnection{
		Connection: plugin.NewConnection(id, asset),
		Conf:       conf,
		asset:      asset,
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		baseURL: baseURL,
		apiKey:  apiKeyFromConfig(conf),
	}

	return conn, nil
}

func (c *VllmConnection) Name() string {
	return "vllm"
}

func (c *VllmConnection) Asset() *inventory.Asset {
	return c.asset
}

func (c *VllmConnection) Close() {
	if c.client != nil {
		c.client.CloseIdleConnections()
	}
}

func (c *VllmConnection) BaseURL() string {
	return c.baseURL
}

func (c *VllmConnection) HasAPIKey() bool {
	return c.apiKey != ""
}

func (c *VllmConnection) UsesTLS() bool {
	return strings.HasPrefix(c.baseURL, "https://")
}

func (c *VllmConnection) Request(ctx context.Context, method string, path string, authenticated bool, body string) (*http.Response, error) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.urlForPath(path), reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, text/plain, */*")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticated && c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	return c.client.Do(req)
}

func (c *VllmConnection) Reachable(ctx context.Context) bool {
	resp, err := c.Request(ctx, http.MethodGet, "/health", false, "")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	discardProbeBody(resp.Body)
	return resp.StatusCode >= 200 && resp.StatusCode < 400
}

func (c *VllmConnection) Version(ctx context.Context) (string, error) {
	c.versionOnce.Do(func() {
		resp, err := c.Request(ctx, http.MethodGet, "/version", false, "")
		if err != nil {
			c.versionErr = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			c.versionErr = fmt.Errorf("vllm: /version returned HTTP %d", resp.StatusCode)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxVersionBody))
		if err != nil {
			c.versionErr = err
			return
		}
		var parsed struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(raw, &parsed); err == nil && parsed.Version != "" {
			c.version = parsed.Version
			return
		}
	})
	return c.version, c.versionErr
}

type ModelCard struct {
	ID          string            `json:"id"`
	Object      string            `json:"object"`
	Created     int64             `json:"created"`
	OwnedBy     string            `json:"owned_by"`
	Root        string            `json:"root"`
	Parent      string            `json:"parent"`
	MaxModelLen int64             `json:"max_model_len"`
	Permission  []ModelPermission `json:"permission"`
}

// ModelPermission is one entry of the OpenAI-compatible permission array vLLM
// emits per model on /v1/models. Every field is a pointer so a payload that
// omits one resolves to null rather than to the Go zero value, which would
// report a permission the server never stated.
type ModelPermission struct {
	ID                 string  `json:"id"`
	Object             string  `json:"object"`
	Created            int64   `json:"created"`
	AllowCreateEngine  *bool   `json:"allow_create_engine"`
	AllowSampling      *bool   `json:"allow_sampling"`
	AllowLogprobs      *bool   `json:"allow_logprobs"`
	AllowSearchIndices *bool   `json:"allow_search_indices"`
	AllowView          *bool   `json:"allow_view"`
	AllowFineTuning    *bool   `json:"allow_fine_tuning"`
	Organization       *string `json:"organization"`
	Group              *string `json:"group"`
	IsBlocking         *bool   `json:"is_blocking"`
}

func (c *VllmConnection) Models(ctx context.Context) ([]ModelCard, error) {
	resp, err := c.Request(ctx, http.MethodGet, "/v1/models", true, "")
	if err != nil {
		return nil, fmt.Errorf("vllm: failed to list models: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("vllm: /v1/models returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Data []ModelCard `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("vllm: failed to parse /v1/models response: %w", err)
	}
	return parsed.Data, nil
}

func (c *VllmConnection) EndpointObservations(ctx context.Context) ([]EndpointObservation, error) {
	c.endpointsOnce.Do(func() {
		specs := DefaultEndpointSpecs()
		c.endpoints = make([]EndpointObservation, len(specs))
		workers := endpointProbeWorkers
		if len(specs) < workers {
			workers = len(specs)
		}
		jobs := make(chan int)
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				for idx := range jobs {
					c.endpoints[idx] = c.ProbeEndpoint(ctx, specs[idx])
				}
			}()
		}
		for i := range specs {
			select {
			case <-ctx.Done():
				c.endpointsErr = ctx.Err()
				close(jobs)
				wg.Wait()
				return
			case jobs <- i:
			}
		}
		close(jobs)
		wg.Wait()
	})
	return c.endpoints, c.endpointsErr
}

func (c *VllmConnection) ProbeEndpoint(ctx context.Context, spec EndpointSpec) EndpointObservation {
	spec.Method = strings.ToUpper(spec.Method)
	spec.ProbeMethod = strings.ToUpper(spec.ProbeMethod)
	obs := EndpointObservation{Spec: spec}

	status, errText := c.probe(ctx, spec, false)
	obs.AnonymousStatusCode = status
	obs.AnonymousError = errText

	if c.apiKey != "" {
		status, errText = c.probe(ctx, spec, true)
		obs.AuthenticatedStatusCode = status
		obs.AuthenticatedError = errText
	}

	return obs
}

func (c *VllmConnection) CORS(ctx context.Context) (CORSObservation, error) {
	c.corsOnce.Do(func() {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, c.urlForPath("/"), nil)
		if err != nil {
			c.corsErr = err
			return
		}
		req.Header.Set("Origin", corsProbeOrigin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		req.Header.Set("Access-Control-Request-Headers", corsProbeHeaders)

		resp, err := c.client.Do(req)
		if err != nil {
			c.corsErr = err
			return
		}
		defer resp.Body.Close()
		discardProbeBody(resp.Body)

		status := resp.StatusCode
		allowOrigin := resp.Header.Get("Access-Control-Allow-Origin")
		configured := allowOrigin != "" || resp.Header.Get("Access-Control-Allow-Methods") != "" || resp.Header.Get("Access-Control-Allow-Headers") != ""
		allowsAny := allowOrigin == "*"

		c.cors.StatusCode = &status
		c.cors.AllowOrigin = allowOrigin
		c.cors.Configured = &configured
		c.cors.AllowsAnyOrigin = &allowsAny
	})
	return c.cors, c.corsErr
}

func (c *VllmConnection) probe(ctx context.Context, spec EndpointSpec, authenticated bool) (*int, string) {
	method := spec.WireMethod()
	body := ""
	if methodAcceptsBody(method) {
		body = spec.Body
		if body == "" {
			body = NewPostBody()
		}
	}
	resp, err := c.Request(ctx, method, spec.Path, authenticated, body)
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	discardProbeBody(resp.Body)

	status := resp.StatusCode
	return &status, ""
}

func discardProbeBody(body io.Reader) {
	_, _ = io.CopyN(io.Discard, body, maxProbeBody)
}

func (c *VllmConnection) urlForPath(path string) string {
	if path == "" || path == "/" {
		return c.baseURL + "/"
	}
	return c.baseURL + "/" + strings.TrimPrefix(path, "/")
}

func baseURLFromConfig(conf *inventory.Config) (string, error) {
	if conf.Options != nil {
		if raw := strings.TrimSpace(conf.Options[OptionBaseURL]); raw != "" {
			return normalizeBaseURL(raw)
		}
	}

	scheme := conf.Runtime
	if scheme == "" {
		scheme = "http"
	}
	host := conf.Host
	if host == "" {
		return "", fmt.Errorf("vllm: endpoint URL is required")
	}
	if conf.Port > 0 {
		host = net.JoinHostPort(host, strconv.Itoa(int(conf.Port)))
	}
	return normalizeBaseURL(scheme + "://" + host + conf.Path)
}

func normalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("vllm: endpoint must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("vllm: endpoint URL must include a host")
	}
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/"), nil
}

func apiKeyFromConfig(conf *inventory.Config) string {
	apiKey := os.Getenv("VLLM_API_KEY")
	if conf.Options != nil && conf.Options[OptionAPIKey] != "" {
		apiKey = conf.Options[OptionAPIKey]
	}
	for _, cred := range conf.Credentials {
		if cred.Type == vault.CredentialType_password {
			apiKey = string(cred.Secret)
		}
	}
	return strings.TrimSpace(apiKey)
}

func NewPostBody() string {
	return "{}"
}

// methodAcceptsBody reports whether a probe of this method should carry a JSON
// body. State-changing routes are probed with a method they do not accept, and
// those requests are sent without a body so nothing can be parsed as input.
func methodAcceptsBody(method string) bool {
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	default:
		return false
	}
}

// SyntheticResponseID is the stored-response identifier used to probe
// /v1/responses/{id} and its cancel route. vLLM mints stored-response ids as
// "resp_" followed by a random UUID in hex, so an all-zero suffix cannot name a
// real response: the probe can never read or cancel another caller's data.
const SyntheticResponseID = "resp_00000000000000000000000000000000"

// StoredResponsePath is the retrieval route for a single stored response,
// addressed with the synthetic identifier.
const StoredResponsePath = "/v1/responses/" + SyntheticResponseID

// StoredResponseCancelPath is the cancel route for a single stored response.
// It is state-changing, so it is probed with a method it does not accept.
const StoredResponseCancelPath = StoredResponsePath + "/cancel"

// LoRAAdapterPaths are the runtime LoRA management routes. Upstream vLLM
// registers only the /v1-prefixed pair, and only when
// VLLM_ALLOW_RUNTIME_LORA_UPDATING is set. The unprefixed pair is probed as
// well because deployments behind a prefix-stripping reverse proxy, and forks
// that mount the router at the root, expose the same handlers there.
var LoRAAdapterPaths = []string{
	"/v1/load_lora_adapter",
	"/v1/unload_lora_adapter",
	"/load_lora_adapter",
	"/unload_lora_adapter",
}

// AnonymousInferencePaths are the OpenAI-compatible completion routes used for
// the "can a stranger run inference here" roll-up.
var AnonymousInferencePaths = []string{
	"/v1/chat/completions",
	"/v1/completions",
}

// WeightUpdatePaths are the routes that replace the weights a vLLM server is
// running. vLLM registers them only when the server development mode flag is
// set, and its built-in API key guards only the "/v1", "/v2", "/inference" and
// "/cohere" prefixes, so no key configured on the server covers any of them.
// Every path here is state-changing and is probed with a rejected method.
var WeightUpdatePaths = []string{
	"/init_weight_transfer_engine",
	"/start_weight_update",
	"/start_draft_weight_update",
	"/update_weights",
	"/finish_weight_update",
	"/update_weight_version",
}

// DocumentationPaths are the interactive API documentation routes FastAPI
// serves. vLLM enables both by default and disables both together, but a
// reverse proxy in front of the server routinely allows one and blocks the
// other, so the exposure question is answered across the pair.
var DocumentationPaths = []string{
	"/docs",
	"/redoc",
}

// DefaultEndpointSpecs returns the routes probed on every vLLM server. The
// table is shared, not rebuilt per call, because it is looked up once per
// endpoint resource; callers read it and must not modify it. ProbeEndpoint
// takes its spec by value, so its uppercasing of the method stays local.
func DefaultEndpointSpecs() []EndpointSpec {
	return defaultEndpointSpecs
}

var defaultEndpointSpecs = []EndpointSpec{
	{Method: http.MethodGet, Path: "/docs", Category: "documentation"},
	{Method: http.MethodGet, Path: "/redoc", Category: "documentation"},
	{Method: http.MethodGet, Path: "/openapi.json", Category: "documentation"},
	{Method: http.MethodGet, Path: "/version", Category: "metadata"},
	{Method: http.MethodGet, Path: "/health", Category: "utility"},
	{Method: http.MethodGet, Path: "/ping", Category: "utility"},
	{Method: http.MethodGet, Path: "/load", Category: "utility"},
	{Method: http.MethodGet, Path: "/metrics", Category: "metrics"},
	{Method: http.MethodGet, Path: "/tokenizer_info", Category: "utility"},
	{Method: http.MethodPost, Path: "/tokenize", Category: "utility", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/detokenize", Category: "utility", Body: NewPostBody()},
	{Method: http.MethodGet, Path: "/v1/models", Category: "openai"},
	{Method: http.MethodPost, Path: "/v1/chat/completions", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/completions", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/embeddings", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/audio/transcriptions", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/audio/translations", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/messages", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/responses", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/score", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/rerank", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/invocations", Category: "custom-inference", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/inference/v1/generate", Category: "custom-inference", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/pooling", Category: "custom-inference", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/classify", Category: "custom-inference", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/score", Category: "custom-inference", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/rerank", Category: "custom-inference", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/generative_scoring", Category: "custom-inference", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/audio/speech", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/completions/render", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodPost, Path: "/v1/chat/completions/render", Category: "openai", Body: NewPostBody()},
	{Method: http.MethodGet, Path: StoredResponsePath, Category: "responses"},
	{Method: http.MethodPost, Path: StoredResponseCancelPath, Category: "responses", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/v1/load_lora_adapter", Category: "lora", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/v1/unload_lora_adapter", Category: "lora", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/load_lora_adapter", Category: "lora", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/unload_lora_adapter", Category: "lora", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/pause", Category: "operational-control", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/resume", Category: "operational-control", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/abort_requests", Category: "operational-control", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/scale_elastic_ep", Category: "operational-control", StateChanging: true, ProbeMethod: http.MethodGet},
	// is_scaling_elastic_ep and fault_tolerance/status only report state, so
	// they are reached with the method they document. fault_tolerance/apply
	// dispatches a recovery instruction to the engine and is not.
	{Method: http.MethodPost, Path: "/is_scaling_elastic_ep", Category: "operational-control", Body: NewPostBody()},
	{Method: http.MethodGet, Path: "/fault_tolerance/status", Category: "operational-control"},
	{Method: http.MethodPost, Path: "/fault_tolerance/apply", Category: "operational-control", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodGet, Path: "/server_info", Category: "development"},
	{Method: http.MethodPost, Path: "/reset_prefix_cache", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/reset_mm_cache", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/reset_encoder_cache", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/sleep", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/wake_up", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodGet, Path: "/is_sleeping", Category: "development"},
	{Method: http.MethodPost, Path: "/collective_rpc", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	// The weight-transfer routes ride the same development-mode router as
	// /sleep and /collective_rpc. Six of them replace or re-version the weights
	// the server is running, so each is probed with a method the route does not
	// accept and the handler is never reached. The remaining three report state
	// and nothing else, so they are reached with the method they document.
	{Method: http.MethodPost, Path: "/init_weight_transfer_engine", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/start_weight_update", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/start_draft_weight_update", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/update_weights", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/finish_weight_update", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/update_weight_version", Category: "development", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodGet, Path: "/weight_info", Category: "development"},
	{Method: http.MethodGet, Path: "/is_paused", Category: "development"},
	{Method: http.MethodGet, Path: "/get_world_size", Category: "development"},
	{Method: http.MethodPost, Path: "/start_profile", Category: "profiler", StateChanging: true, ProbeMethod: http.MethodGet},
	{Method: http.MethodPost, Path: "/stop_profile", Category: "profiler", StateChanging: true, ProbeMethod: http.MethodGet},
}

func ObservationPresent(obs EndpointObservation) bool {
	code := bestStatus(obs)
	return code != nil && *code != http.StatusNotFound && *code != http.StatusNotImplemented
}

// RoutePresence is the strict presence verdict for a method-mismatch probe.
// Unlike ObservationPresent it never reports a route as present on the strength
// of an authentication rejection: a 401 is produced by middleware that runs
// before routing, so it says nothing about whether the route is registered.
//
// The second return value reports whether the verdict is known at all, so a
// caller can render null instead of a "not present" that was never observed.
func RoutePresence(obs EndpointObservation) (bool, bool) {
	code := bestStatus(obs)
	if code == nil {
		return false, false
	}
	switch *code {
	case http.StatusMethodNotAllowed:
		// The router matched the path and rejected the method: registered.
		return true, true
	case http.StatusNotFound, http.StatusNotImplemented:
		return false, true
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, false
	}
	if *code >= 500 {
		return false, false
	}
	// Any other answer came from the application, so the route is registered.
	return true, true
}

// AnyRoutePresent aggregates RoutePresence across a set of paths, reporting
// true as soon as one is registered, and reporting the verdict as unknown only
// when no path produced one.
func AnyRoutePresent(observations []EndpointObservation, paths ...string) (bool, bool) {
	known := false
	for _, path := range paths {
		for _, obs := range observations {
			if obs.Spec.Path != path {
				continue
			}
			present, ok := RoutePresence(obs)
			if !ok {
				continue
			}
			known = true
			if present {
				return true, true
			}
		}
	}
	return false, known
}

// AnyAnonymousAccessible aggregates the anonymous-access verdict across an
// explicit set of paths.
func AnyAnonymousAccessible(observations []EndpointObservation, paths ...string) (bool, bool) {
	known := false
	for _, path := range paths {
		for _, obs := range observations {
			if obs.Spec.Path != path {
				continue
			}
			accessible, ok := ObservationAnonymousAccessible(obs)
			if !ok {
				continue
			}
			known = true
			if accessible {
				return true, true
			}
		}
	}
	return false, known
}

// AnyRequiresAuth aggregates the authentication-rejection verdict across an
// explicit set of paths.
func AnyRequiresAuth(observations []EndpointObservation, paths ...string) (bool, bool) {
	known := false
	for _, path := range paths {
		for _, obs := range observations {
			if obs.Spec.Path != path {
				continue
			}
			required, ok := ObservationRequiresAuth(obs)
			if !ok {
				continue
			}
			known = true
			if required {
				return true, true
			}
		}
	}
	return false, known
}

func ObservationAnonymousAccessible(obs EndpointObservation) (bool, bool) {
	if obs.AnonymousStatusCode == nil {
		return false, false
	}
	switch *obs.AnonymousStatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, true
	case http.StatusNotFound, http.StatusNotImplemented:
		return false, true
	default:
		if *obs.AnonymousStatusCode >= 500 {
			return false, false
		}
		return true, true
	}
}

// CategoryAnonymousAccessible aggregates the anonymous-access verdict across all
// observations in a functional category. It returns (true, true) as soon as any
// endpoint in the category is anonymously accessible; otherwise it returns
// (false, true) when at least one endpoint had a known verdict, and
// (false, false) when every endpoint in the category was unknown (so the caller
// can report null rather than a misleading "not exposed").
func CategoryAnonymousAccessible(observations []EndpointObservation, category string) (bool, bool) {
	known := false
	for _, obs := range observations {
		if obs.Spec.Category != category {
			continue
		}
		accessible, ok := ObservationAnonymousAccessible(obs)
		if !ok {
			continue
		}
		known = true
		if accessible {
			return true, true
		}
	}
	return false, known
}

func ObservationRequiresAuth(obs EndpointObservation) (bool, bool) {
	if obs.AnonymousStatusCode == nil || *obs.AnonymousStatusCode == http.StatusNotFound || *obs.AnonymousStatusCode >= 500 {
		return false, false
	}
	switch *obs.AnonymousStatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return true, true
	default:
		return false, true
	}
}

func ObservationNotes(obs EndpointObservation) []string {
	notes := []string{}
	if obs.Spec.Path == StoredResponsePath || obs.Spec.Path == StoredResponseCancelPath {
		notes = append(notes, "probed with a synthetic stored-response identifier that cannot name a real response")
	}
	if obs.Spec.StateChanging {
		notes = append(notes, "route changes server state, so presence was probed with an HTTP "+
			obs.Spec.WireMethod()+" the route does not accept and the handler was never invoked")
	}
	if obs.AnonymousError != "" {
		notes = append(notes, "anonymous probe error: "+obs.AnonymousError)
	}
	if obs.AuthenticatedError != "" {
		notes = append(notes, "authenticated probe error: "+obs.AuthenticatedError)
	}
	if obs.AnonymousStatusCode != nil {
		switch *obs.AnonymousStatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			notes = append(notes, "anonymous request was rejected by an authentication-like response")
		case http.StatusNotFound:
			notes = append(notes, "route was not observed")
		case http.StatusNotImplemented:
			notes = append(notes, "route is not implemented by the server")
		case http.StatusMethodNotAllowed:
			notes = append(notes, "route exists but rejected the probed HTTP method")
		case http.StatusBadRequest, http.StatusUnprocessableEntity:
			notes = append(notes, "anonymous request reached route validation")
		default:
			if *obs.AnonymousStatusCode < 400 {
				notes = append(notes, "anonymous request reached route successfully")
			}
		}
	}
	return notes
}

func bestStatus(obs EndpointObservation) *int {
	if obs.AuthenticatedStatusCode != nil && *obs.AuthenticatedStatusCode != http.StatusUnauthorized && *obs.AuthenticatedStatusCode != http.StatusForbidden {
		return obs.AuthenticatedStatusCode
	}
	return obs.AnonymousStatusCode
}
