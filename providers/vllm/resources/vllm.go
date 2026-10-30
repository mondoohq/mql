// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/vllm/connection"
)

type mqlVllmEndpointInternal struct {
	once sync.Once
	obs  connection.EndpointObservation
}

// mqlVllmModelInternal carries the permission array from the /v1/models
// response that produced the model, so reading vllm.model.permissions does not
// re-list the models.
type mqlVllmModelInternal struct {
	once            sync.Once
	permissionCards []connection.ModelPermission
}

func (r *mqlVllm) id() (string, error) {
	conn, err := vllmConnection(r.MqlRuntime)
	if err != nil {
		return "", err
	}
	return conn.BaseURL(), nil
}

func (r *mqlVllm) server() (*mqlVllmServer, error) {
	res, err := CreateResource(r.MqlRuntime, "vllm.server", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlVllmServer), nil
}

func (r *mqlVllm) endpoints() ([]any, error) {
	conn, err := vllmConnection(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	observations, err := conn.EndpointObservations(context.Background())
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(observations))
	for _, obs := range observations {
		endpoint, err := CreateResource(r.MqlRuntime, "vllm.endpoint", map[string]*llx.RawData{
			"path":   llx.StringData(obs.Spec.Path),
			"method": llx.StringData(obs.Spec.Method),
		})
		if err != nil {
			return nil, err
		}
		if e, ok := endpoint.(*mqlVllmEndpoint); ok {
			primed := obs
			e.once.Do(func() {
				e.obs = primed
			})
		}
		res = append(res, endpoint)
	}
	return res, nil
}

func (r *mqlVllm) metrics() (*mqlVllmMetrics, error) {
	res, err := CreateResource(r.MqlRuntime, "vllm.metrics", nil)
	if err != nil {
		return nil, err
	}
	return res.(*mqlVllmMetrics), nil
}

func (r *mqlVllm) version() (string, error) {
	conn, err := vllmConnection(r.MqlRuntime)
	if err != nil {
		return "", err
	}
	version, err := conn.Version(context.Background())
	if err != nil {
		r.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	if version == "" {
		r.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return version, nil
}

func (r *mqlVllm) models() ([]any, error) {
	conn, err := vllmConnection(r.MqlRuntime)
	if err != nil {
		return nil, err
	}

	cards, err := conn.Models(context.Background())
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(cards))
	for _, c := range cards {
		mqlModel, err := CreateResource(r.MqlRuntime, "vllm.model", map[string]*llx.RawData{
			"__id":        llx.StringData(conn.BaseURL() + "/model/" + c.ID),
			"id":          llx.StringData(c.ID),
			"root":        llx.StringData(c.Root),
			"parent":      llx.StringData(c.Parent),
			"maxModelLen": llx.IntData(c.MaxModelLen),
			"created":     llx.TimeDataPtr(modelCreatedTime(c.Created)),
			"ownedBy":     llx.StringData(c.OwnedBy),
		})
		if err != nil {
			return nil, err
		}
		if m, ok := mqlModel.(*mqlVllmModel); ok {
			primed := c.Permission
			m.once.Do(func() {
				m.permissionCards = primed
			})
		}
		res = append(res, mqlModel)
	}

	return res, nil
}

func (m *mqlVllmModel) permissions() ([]any, error) {
	return modelPermissionResources(m.MqlRuntime, m.Id.Data, m.permissionCards)
}

// modelCreatedTime converts a vLLM model card's Unix creation timestamp into a
// time pointer, returning nil when the server did not report one (a zero value)
// so the field resolves to null instead of the Unix epoch.
func modelCreatedTime(unix int64) *time.Time {
	if unix <= 0 {
		return nil
	}
	t := time.Unix(unix, 0)
	return &t
}

func (r *mqlVllmModel) id() (string, error) {
	return r.Id.Data, nil
}

func (s *mqlVllmServer) id() (string, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return "", err
	}
	return conn.BaseURL(), nil
}

func (s *mqlVllmServer) baseUrl() (string, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return "", err
	}
	return conn.BaseURL(), nil
}

func (s *mqlVllmServer) reachable() (bool, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	return conn.Reachable(context.Background()), nil
}

func (s *mqlVllmServer) version() (string, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return "", err
	}
	version, err := conn.Version(context.Background())
	if err != nil || version == "" {
		s.Version.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return version, nil
}

// docsExposed answers across every interactive documentation route, not just
// /docs. A proxy that blocks /docs and forwards /redoc publishes the same API
// surface, and reading /docs alone reported that server as not exposed.
func (s *mqlVllmServer) docsExposed() (bool, error) {
	observations, err := allEndpointObservations(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	accessible, known := connection.AnyAnonymousAccessible(observations, connection.DocumentationPaths...)
	if !known {
		return nullBool(&s.DocsExposed)
	}
	return accessible, nil
}

func (s *mqlVllmServer) openapiExposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(s.MqlRuntime, http.MethodGet, "/openapi.json")
	if err != nil {
		return false, err
	}
	if !known {
		s.OpenapiExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (s *mqlVllmServer) metricsExposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(s.MqlRuntime, http.MethodGet, "/metrics")
	if err != nil {
		return false, err
	}
	if !known {
		s.MetricsExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (s *mqlVllmServer) loadEndpointExposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(s.MqlRuntime, http.MethodGet, "/load")
	if err != nil {
		return false, err
	}
	if !known {
		s.LoadEndpointExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (s *mqlVllmServer) tokenizerInfoExposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(s.MqlRuntime, http.MethodGet, "/tokenizer_info")
	if err != nil {
		return false, err
	}
	if !known {
		s.TokenizerInfoExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (s *mqlVllmServer) devEndpointsExposed() (bool, error) {
	accessible, known, err := categoryAnonymousAccessibleKnown(s.MqlRuntime, "development")
	if err != nil {
		return false, err
	}
	if !known {
		s.DevEndpointsExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (s *mqlVllmServer) profilerEndpointsExposed() (bool, error) {
	accessible, known, err := categoryAnonymousAccessibleKnown(s.MqlRuntime, "profiler")
	if err != nil {
		return false, err
	}
	if !known {
		s.ProfilerEndpointsExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (s *mqlVllmServer) corsConfigured() (bool, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	obs, err := conn.CORS(context.Background())
	if err != nil || obs.Configured == nil {
		s.CorsConfigured.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *obs.Configured, nil
}

func (s *mqlVllmServer) corsAllowsAnyOrigin() (bool, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	obs, err := conn.CORS(context.Background())
	if err != nil || obs.AllowsAnyOrigin == nil {
		s.CorsAllowsAnyOrigin.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *obs.AllowsAnyOrigin, nil
}

func (s *mqlVllmServer) usesTls() (bool, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	return conn.UsesTLS(), nil
}

func (s *mqlVllmServer) anonymousInferenceAllowed() (bool, error) {
	observations, err := allEndpointObservations(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	allowed, known := connection.AnyAnonymousAccessible(observations, connection.AnonymousInferencePaths...)
	if !known {
		return nullBool(&s.AnonymousInferenceAllowed)
	}
	return allowed, nil
}

func (s *mqlVllmServer) apiKeyRequired() (bool, error) {
	observations, err := allEndpointObservations(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	required, known := connection.AnyRequiresAuth(observations, connection.AnonymousInferencePaths...)
	if !known {
		return nullBool(&s.ApiKeyRequired)
	}
	return required, nil
}

func (s *mqlVllmServer) runtimeLoraUpdatingEnabled() (bool, error) {
	observations, err := allEndpointObservations(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	present, known := connection.AnyRoutePresent(observations, connection.LoRAAdapterPaths...)
	if !known {
		return nullBool(&s.RuntimeLoraUpdatingEnabled)
	}
	return present, nil
}

// weightUpdateRoutesExposed reports whether a stranger can reach a route that
// replaces the served weights. The routes are state-changing, so presence is
// read from a rejected-method answer: a 405 means the request passed whatever
// authentication layer exists and reached the router, which is the exposure.
func (s *mqlVllmServer) weightUpdateRoutesExposed() (bool, error) {
	observations, err := allEndpointObservations(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	accessible, known := connection.AnyAnonymousAccessible(observations, connection.WeightUpdatePaths...)
	if !known {
		return nullBool(&s.WeightUpdateRoutesExposed)
	}
	return accessible, nil
}

func (s *mqlVllmServer) storedResponsesExposed() (bool, error) {
	conn, err := vllmConnection(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	obs, err := conn.StoredResponses(context.Background())
	if err != nil || !obs.Known {
		return nullBool(&s.StoredResponsesExposed)
	}
	return obs.Readable, nil
}

func initVllmEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["path"]; !ok {
		return nil, nil, errors.New("vllm.endpoint requires path")
	}
	if _, ok := args["method"]; !ok {
		args["method"] = llx.StringData(http.MethodGet)
	}
	if method, ok := args["method"]; ok {
		raw, isString := method.Value.(string)
		if !isString || raw == "" {
			args["method"] = llx.StringData(http.MethodGet)
		} else {
			args["method"] = llx.StringData(strings.ToUpper(raw))
		}
	}
	return args, nil, nil
}

func (e *mqlVllmEndpoint) id() (string, error) {
	return e.Method.Data + " " + e.Path.Data, nil
}

func (e *mqlVllmEndpoint) category() (string, error) {
	obs, err := e.observation()
	if err != nil {
		return "", err
	}
	return obs.Spec.Category, nil
}

func (e *mqlVllmEndpoint) present() (bool, error) {
	obs, err := e.observation()
	if err != nil {
		return false, err
	}
	return connection.ObservationPresent(obs), nil
}

func (e *mqlVllmEndpoint) anonymousStatusCode() (int64, error) {
	obs, err := e.observation()
	if err != nil {
		return 0, err
	}
	if obs.AnonymousStatusCode == nil {
		e.AnonymousStatusCode.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*obs.AnonymousStatusCode), nil
}

func (e *mqlVllmEndpoint) authenticatedStatusCode() (int64, error) {
	obs, err := e.observation()
	if err != nil {
		return 0, err
	}
	if obs.AuthenticatedStatusCode == nil {
		e.AuthenticatedStatusCode.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*obs.AuthenticatedStatusCode), nil
}

func (e *mqlVllmEndpoint) anonymousAccessible() (bool, error) {
	obs, err := e.observation()
	if err != nil {
		return false, err
	}
	val, known := connection.ObservationAnonymousAccessible(obs)
	if !known {
		e.AnonymousAccessible.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return val, nil
}

func (e *mqlVllmEndpoint) requiresAuth() (bool, error) {
	obs, err := e.observation()
	if err != nil {
		return false, err
	}
	val, known := connection.ObservationRequiresAuth(obs)
	if !known {
		e.RequiresAuth.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return val, nil
}

func (e *mqlVllmEndpoint) notes() ([]any, error) {
	obs, err := e.observation()
	if err != nil {
		return nil, err
	}
	notes := connection.ObservationNotes(obs)
	res := make([]any, len(notes))
	for i := range notes {
		res[i] = notes[i]
	}
	return res, nil
}

func (e *mqlVllmEndpoint) observation() (connection.EndpointObservation, error) {
	var err error
	e.once.Do(func() {
		conn, connErr := vllmConnection(e.MqlRuntime)
		if connErr != nil {
			err = connErr
			return
		}
		spec := endpointSpecFor(e.Method.Data, e.Path.Data)
		e.obs = conn.ProbeEndpoint(context.Background(), spec)
	})
	return e.obs, err
}

func (m *mqlVllmMetrics) id() (string, error) {
	conn, err := vllmConnection(m.MqlRuntime)
	if err != nil {
		return "", err
	}
	return conn.BaseURL() + "/metrics", nil
}

func (m *mqlVllmMetrics) prometheusExposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(m.MqlRuntime, http.MethodGet, "/metrics")
	if err != nil {
		return false, err
	}
	if !known {
		m.PrometheusExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (m *mqlVllmMetrics) loadEndpointExposed() (bool, error) {
	accessible, known, err := endpointAnonymousAccessibleKnown(m.MqlRuntime, http.MethodGet, "/load")
	if err != nil {
		return false, err
	}
	if !known {
		m.LoadEndpointExposed.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return accessible, nil
}

func (m *mqlVllmMetrics) loadTrackingVisible() (bool, error) {
	obs, err := endpointObservation(m.MqlRuntime, http.MethodGet, "/load")
	if err != nil {
		return false, err
	}
	accessible, known := connection.ObservationAnonymousAccessible(obs)
	if !known {
		m.LoadTrackingVisible.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return accessible, nil
}

func (m *mqlVllmMetrics) exposedModelNames() ([]any, error) {
	snapshot := metricsSnapshot(m.MqlRuntime)
	if snapshot == nil || !snapshot.Fetched {
		return stringListField(&m.ExposedModelNames, nil)
	}
	return stringListField(&m.ExposedModelNames, snapshot.ModelNames)
}

func (m *mqlVllmMetrics) exposedLoraAdapters() ([]any, error) {
	snapshot := metricsSnapshot(m.MqlRuntime)
	if snapshot == nil || !snapshot.Fetched {
		return stringListField(&m.ExposedLoraAdapters, nil)
	}
	return stringListField(&m.ExposedLoraAdapters, snapshot.LoraAdapters)
}

func (m *mqlVllmMetrics) cacheConfigExposed() (bool, error) {
	snapshot := metricsSnapshot(m.MqlRuntime)
	if snapshot == nil || !snapshot.Fetched {
		return nullBool(&m.CacheConfigExposed)
	}
	return snapshot.CacheConfigExposed, nil
}

func (m *mqlVllmMetrics) exposedCacheConfig() (map[string]any, error) {
	snapshot := metricsSnapshot(m.MqlRuntime)
	if snapshot == nil || !snapshot.Fetched {
		return stringMapField(&m.ExposedCacheConfig, nil)
	}
	return stringMapField(&m.ExposedCacheConfig, snapshot.CacheConfig)
}

// metricsSnapshot reads the anonymous Prometheus scrape, or nil when the
// endpoint could not be scraped. A failed scrape means the labels were never
// observed, so callers render null rather than an empty list that would read
// as "nothing is disclosed".
func metricsSnapshot(runtime *plugin.Runtime) *connection.MetricsSnapshot {
	conn, err := vllmConnection(runtime)
	if err != nil {
		return nil
	}
	snapshot, err := conn.MetricsSnapshot(context.Background())
	if err != nil {
		return nil
	}
	return snapshot
}

func vllmConnection(runtime *plugin.Runtime) (*connection.VllmConnection, error) {
	conn, ok := runtime.Connection.(*connection.VllmConnection)
	if !ok {
		return nil, errors.New("invalid connection for vllm provider")
	}
	return conn, nil
}

func endpointAnonymousAccessibleKnown(runtime *plugin.Runtime, method string, path string) (bool, bool, error) {
	obs, err := endpointObservation(runtime, method, path)
	if err != nil {
		return false, false, err
	}
	val, known := connection.ObservationAnonymousAccessible(obs)
	return val, known, nil
}

func categoryAnonymousAccessibleKnown(runtime *plugin.Runtime, category string) (bool, bool, error) {
	observations, err := allEndpointObservations(runtime)
	if err != nil {
		return false, false, err
	}
	accessible, known := connection.CategoryAnonymousAccessible(observations, category)
	return accessible, known, nil
}

func allEndpointObservations(runtime *plugin.Runtime) ([]connection.EndpointObservation, error) {
	conn, err := vllmConnection(runtime)
	if err != nil {
		return nil, err
	}
	return conn.EndpointObservations(context.Background())
}

func endpointObservation(runtime *plugin.Runtime, method string, path string) (connection.EndpointObservation, error) {
	conn, err := vllmConnection(runtime)
	if err != nil {
		return connection.EndpointObservation{}, err
	}
	observations, err := conn.EndpointObservations(context.Background())
	if err != nil {
		return connection.EndpointObservation{}, err
	}
	method = strings.ToUpper(method)
	for _, obs := range observations {
		if obs.Spec.Method == method && obs.Spec.Path == path {
			return obs, nil
		}
	}
	return conn.ProbeEndpoint(context.Background(), endpointSpecFor(method, path)), nil
}

func endpointSpecFor(method string, path string) connection.EndpointSpec {
	method = strings.ToUpper(method)
	for _, spec := range connection.DefaultEndpointSpecs() {
		if spec.Method == method && spec.Path == path {
			return spec
		}
	}
	body := ""
	if method == http.MethodPost {
		body = connection.NewPostBody()
	}
	return connection.EndpointSpec{
		Method:   method,
		Path:     path,
		Category: "custom",
		Body:     body,
	}
}
