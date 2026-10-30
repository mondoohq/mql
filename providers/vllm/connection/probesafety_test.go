// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
)

// mutatingRoutes are the vLLM routes whose documented method changes server
// state. Probing any of them with that method has a real effect: /sleep
// offloads the engine, /pause aborts every in-flight request, /abort_requests
// with an empty body aborts everything the engine is tracking,
// /reset_prefix_cache drops the cache, the LoRA routes swap the served
// adapters, and the responses cancel route cancels a caller's response. The
// weight-transfer routes are the worst of them: /update_weights replaces the
// weights the engine is serving, so a probe that used the documented POST
// would swap the model out from under a production server.
var mutatingRoutes = []string{
	"/pause",
	"/resume",
	"/abort_requests",
	"/scale_elastic_ep",
	"/fault_tolerance/apply",
	"/init_weight_transfer_engine",
	"/start_weight_update",
	"/start_draft_weight_update",
	"/update_weights",
	"/finish_weight_update",
	"/update_weight_version",
	"/reset_prefix_cache",
	"/reset_mm_cache",
	"/reset_encoder_cache",
	"/sleep",
	"/wake_up",
	"/collective_rpc",
	"/start_profile",
	"/stop_profile",
	"/v1/load_lora_adapter",
	"/v1/unload_lora_adapter",
	"/load_lora_adapter",
	"/unload_lora_adapter",
	StoredResponseCancelPath,
}

// Every route that changes server state must be marked so, and every marked
// route must be probed with a method it does not accept. This is the invariant
// the whole probe table rests on: a state-changing route the table forgets to
// mark is a scan that mutates the server it is auditing.
func TestEveryMutatingRouteIsProbedWithARejectedMethod(t *testing.T) {
	specs := DefaultEndpointSpecs()

	for _, path := range mutatingRoutes {
		idx := slices.IndexFunc(specs, func(s EndpointSpec) bool { return s.Path == path })
		if idx < 0 {
			t.Fatalf("%s is not in the probe table", path)
		}
		spec := specs[idx]
		if !spec.StateChanging {
			t.Fatalf("%s changes server state but is not marked StateChanging", path)
		}
		if spec.ProbeMethod == "" {
			t.Fatalf("%s is state-changing but has no probe method override", path)
		}
		if spec.WireMethod() == spec.Method {
			t.Fatalf("%s would be probed with its own method %s, which invokes the handler", path, spec.Method)
		}
		if spec.Body != "" {
			t.Fatalf("%s carries a probe body, which a rejected-method probe must never send", path)
		}
	}
}

// The inverse guard: nothing may be marked state-changing without an override,
// so a future route added to the table cannot quietly inherit the POST probe.
func TestStateChangingSpecsAlwaysOverrideTheMethod(t *testing.T) {
	for _, spec := range DefaultEndpointSpecs() {
		if !spec.StateChanging {
			continue
		}
		if spec.ProbeMethod == "" || spec.WireMethod() == spec.Method {
			t.Fatalf("%s %s is state-changing but is probed with its documented method", spec.Method, spec.Path)
		}
	}
}

// The wire behaviour that backs the invariant: a state-changing route is only
// ever reached with the rejected method and with no request body at all, so
// nothing the handler would act on is ever transmitted.
func TestStateChangingProbesNeverSendTheDocumentedMethod(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	bodies := map[string]int{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen[r.URL.Path] = append(seen[r.URL.Path], r.Method)
		bodies[r.URL.Path] += len(body)
		mu.Unlock()
		// Answer the way a FastAPI app does for a registered path reached with
		// a method it does not accept.
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	conn := &VllmConnection{client: server.Client(), baseURL: server.URL, apiKey: "probe-token"}
	if _, err := conn.EndpointObservations(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, path := range mutatingRoutes {
		mu.Lock()
		methods := slices.Clone(seen[path])
		bodyLen := bodies[path]
		mu.Unlock()

		if len(methods) == 0 {
			t.Fatalf("%s was never probed", path)
		}
		for _, method := range methods {
			if method != http.MethodGet {
				t.Fatalf("%s was probed with %s, which invokes the state-changing handler", path, method)
			}
		}
		if bodyLen != 0 {
			t.Fatalf("%s was probed with a %d byte body, which a rejected-method probe must never send", path, bodyLen)
		}
	}
}

// A method-mismatch probe reads presence from the router's answer. An
// authentication rejection arrives from middleware that runs before routing,
// so it says nothing about whether the route exists and must stay unknown.
func TestRoutePresence(t *testing.T) {
	tests := []struct {
		name    string
		anon    *int
		auth    *int
		present bool
		known   bool
	}{
		{name: "method rejected means registered", anon: intPtr(http.StatusMethodNotAllowed), present: true, known: true},
		{name: "not found means absent", anon: intPtr(http.StatusNotFound), present: false, known: true},
		{name: "not implemented means absent", anon: intPtr(http.StatusNotImplemented), present: false, known: true},
		{name: "unauthorized is not evidence of absence", anon: intPtr(http.StatusUnauthorized), present: false, known: false},
		{name: "forbidden is not evidence of absence", anon: intPtr(http.StatusForbidden), present: false, known: false},
		{name: "server error is undetermined", anon: intPtr(http.StatusInternalServerError), present: false, known: false},
		{name: "no answer is undetermined", anon: nil, present: false, known: false},
		{name: "validation answer means registered", anon: intPtr(http.StatusUnprocessableEntity), present: true, known: true},
		{
			name:    "authenticated probe resolves an anonymous rejection",
			anon:    intPtr(http.StatusUnauthorized),
			auth:    intPtr(http.StatusMethodNotAllowed),
			present: true,
			known:   true,
		},
		{
			name:    "authenticated probe can prove absence too",
			anon:    intPtr(http.StatusUnauthorized),
			auth:    intPtr(http.StatusNotFound),
			present: false,
			known:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := EndpointObservation{AnonymousStatusCode: tt.anon, AuthenticatedStatusCode: tt.auth}
			present, known := RoutePresence(obs)
			if present != tt.present || known != tt.known {
				t.Fatalf("got (%v,%v) want (%v,%v)", present, known, tt.present, tt.known)
			}
		})
	}
}

func TestAnyRoutePresent(t *testing.T) {
	observations := []EndpointObservation{
		{Spec: EndpointSpec{Path: "/a"}, AnonymousStatusCode: intPtr(http.StatusNotFound)},
		{Spec: EndpointSpec{Path: "/b"}, AnonymousStatusCode: intPtr(http.StatusMethodNotAllowed)},
		{Spec: EndpointSpec{Path: "/c"}, AnonymousStatusCode: intPtr(http.StatusUnauthorized)},
	}

	if present, known := AnyRoutePresent(observations, "/a", "/b"); !present || !known {
		t.Fatalf("got (%v,%v) want (true,true)", present, known)
	}
	if present, known := AnyRoutePresent(observations, "/a"); present || !known {
		t.Fatalf("got (%v,%v) want (false,true)", present, known)
	}
	// Only unknown answers, so the verdict must stay unknown rather than
	// collapse to "no runtime LoRA loading here".
	if present, known := AnyRoutePresent(observations, "/c"); present || known {
		t.Fatalf("got (%v,%v) want (false,false)", present, known)
	}
	if present, known := AnyRoutePresent(observations, "/missing"); present || known {
		t.Fatalf("got (%v,%v) want (false,false)", present, known)
	}
}

func TestAnyAnonymousAccessibleAndRequiresAuth(t *testing.T) {
	observations := []EndpointObservation{
		{Spec: EndpointSpec{Path: "/v1/chat/completions"}, AnonymousStatusCode: intPtr(http.StatusUnauthorized)},
		{Spec: EndpointSpec{Path: "/v1/completions"}, AnonymousStatusCode: intPtr(http.StatusBadRequest)},
	}

	// One open route is enough to answer "a stranger can run inference here".
	if allowed, known := AnyAnonymousAccessible(observations, AnonymousInferencePaths...); !allowed || !known {
		t.Fatalf("anonymousInferenceAllowed got (%v,%v) want (true,true)", allowed, known)
	}
	if required, known := AnyRequiresAuth(observations, AnonymousInferencePaths...); !required || !known {
		t.Fatalf("apiKeyRequired got (%v,%v) want (true,true)", required, known)
	}

	unreachable := []EndpointObservation{
		{Spec: EndpointSpec{Path: "/v1/chat/completions"}},
		{Spec: EndpointSpec{Path: "/v1/completions"}},
	}
	if allowed, known := AnyAnonymousAccessible(unreachable, AnonymousInferencePaths...); allowed || known {
		t.Fatalf("anonymousInferenceAllowed got (%v,%v) want (false,false)", allowed, known)
	}
	if required, known := AnyRequiresAuth(unreachable, AnonymousInferencePaths...); required || known {
		t.Fatalf("apiKeyRequired got (%v,%v) want (false,false)", required, known)
	}
}

// The new routes named in the coverage review must all be probed.
func TestNewRoutesArePresentInTheProbeTable(t *testing.T) {
	required := []string{
		"/abort_requests",
		"/v1/completions/render",
		"/v1/chat/completions/render",
		"/generative_scoring",
		"/v1/audio/speech",
		StoredResponsePath,
		StoredResponseCancelPath,
	}
	required = append(required, LoRAAdapterPaths...)

	specs := DefaultEndpointSpecs()
	for _, path := range required {
		if !slices.ContainsFunc(specs, func(s EndpointSpec) bool { return s.Path == path }) {
			t.Fatalf("missing probe for %s", path)
		}
	}
}

// The render routes echo the fully-assembled prompt, so they are probed for
// existence with a body the request validator rejects before any template is
// applied, and no rendered prompt is ever read back.
func TestRenderRoutesAreProbedWithARejectedBody(t *testing.T) {
	specs := DefaultEndpointSpecs()
	for _, path := range []string{"/v1/completions/render", "/v1/chat/completions/render"} {
		idx := slices.IndexFunc(specs, func(s EndpointSpec) bool { return s.Path == path })
		if idx < 0 {
			t.Fatalf("missing probe for %s", path)
		}
		if got := specs[idx].Body; got != NewPostBody() {
			t.Fatalf("%s probe body got %q want the empty JSON object", path, got)
		}
	}
}

// The whole probe table must be free of any request that could carry usable
// input to a state-changing handler.
func TestNoStateChangingSpecCarriesABody(t *testing.T) {
	for _, spec := range DefaultEndpointSpecs() {
		if spec.StateChanging && spec.Body != "" {
			t.Fatalf("%s %s carries a body", spec.Method, spec.Path)
		}
	}
}

// The weight-replacement roll-up must be backed by the probe table, and every
// path it names must be one the probe never reaches with its documented
// method. A path added to the list but not to the table reports a silent
// "false" for a route that was never looked at.
func TestWeightUpdatePathsAreAllStateChangingSpecs(t *testing.T) {
	specs := DefaultEndpointSpecs()
	for _, path := range WeightUpdatePaths {
		idx := slices.IndexFunc(specs, func(s EndpointSpec) bool { return s.Path == path })
		if idx < 0 {
			t.Fatalf("%s is named by WeightUpdatePaths but is not probed", path)
		}
		spec := specs[idx]
		if spec.Category != "development" {
			t.Fatalf("%s category got %q want development, so it feeds devEndpointsExposed", path, spec.Category)
		}
		if !spec.StateChanging || spec.WireMethod() != http.MethodGet {
			t.Fatalf("%s is probed with %s; a weight-replacement route must be probed with GET only", path, spec.WireMethod())
		}
	}
	if len(WeightUpdatePaths) != 6 {
		t.Fatalf("WeightUpdatePaths has %d entries; vLLM registers six weight-replacement routes", len(WeightUpdatePaths))
	}
}

// The read-only members of the same routers report state and nothing else, so
// they are reached with the method they document. Probing them with a rejected
// method would answer "the route exists" where the real answer is available.
func TestReadOnlyControlRoutesAreProbedForReal(t *testing.T) {
	readOnly := []string{
		"/weight_info",
		"/is_paused",
		"/get_world_size",
		"/fault_tolerance/status",
		"/is_scaling_elastic_ep",
	}
	specs := DefaultEndpointSpecs()
	for _, path := range readOnly {
		idx := slices.IndexFunc(specs, func(s EndpointSpec) bool { return s.Path == path })
		if idx < 0 {
			t.Fatalf("missing probe for %s", path)
		}
		spec := specs[idx]
		if spec.StateChanging {
			t.Fatalf("%s changes nothing but is marked state-changing", path)
		}
		if spec.WireMethod() != spec.Method {
			t.Fatalf("%s is probed with %s instead of its documented %s", path, spec.WireMethod(), spec.Method)
		}
	}
}

// No probe of a weight-replacement route may ever put POST on the wire, with
// or without an API key configured. This is the assertion the whole change
// rests on: getting it wrong replaces a served model's weights during a scan.
func TestWeightUpdateRoutesAreNeverProbedWithPost(t *testing.T) {
	for _, apiKey := range []string{"", "probe-token"} {
		var mu sync.Mutex
		seen := map[string][]string{}
		bodies := map[string]int{}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			seen[r.URL.Path] = append(seen[r.URL.Path], r.Method)
			bodies[r.URL.Path] += len(body)
			mu.Unlock()
			if slices.Contains(WeightUpdatePaths, r.URL.Path) {
				// A registered FastAPI POST route reached with GET.
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))

		conn := &VllmConnection{client: server.Client(), baseURL: server.URL, apiKey: apiKey}
		observations, err := conn.EndpointObservations(context.Background())
		if err != nil {
			server.Close()
			t.Fatalf("unexpected error: %v", err)
		}
		server.Close()

		for _, path := range WeightUpdatePaths {
			mu.Lock()
			methods := slices.Clone(seen[path])
			bodyLen := bodies[path]
			mu.Unlock()

			if len(methods) == 0 {
				t.Fatalf("apiKey=%q: %s was never probed", apiKey, path)
			}
			for _, method := range methods {
				if method != http.MethodGet {
					t.Fatalf("apiKey=%q: %s was probed with %s, which replaces the served weights", apiKey, path, method)
				}
			}
			if bodyLen != 0 {
				t.Fatalf("apiKey=%q: %s was probed with a %d byte body", apiKey, path, bodyLen)
			}
		}

		// A registered route answering the rejected method is the exposure.
		exposed, known := AnyAnonymousAccessible(observations, WeightUpdatePaths...)
		if !exposed || !known {
			t.Fatalf("apiKey=%q: weightUpdateRoutesExposed got (%v,%v) want (true,true)", apiKey, exposed, known)
		}
	}
}

// The four answers a weight-update probe can produce, and the verdict each one
// must yield. The unknown case is the one that must stay null: a server that
// never answered has not been shown to be safe.
func TestWeightUpdateExposureVerdicts(t *testing.T) {
	observationsWith := func(code *int) []EndpointObservation {
		out := make([]EndpointObservation, 0, len(WeightUpdatePaths))
		for _, path := range WeightUpdatePaths {
			out = append(out, EndpointObservation{
				Spec:                EndpointSpec{Path: path, Category: "development"},
				AnonymousStatusCode: code,
			})
		}
		return out
	}

	tests := []struct {
		name    string
		code    *int
		exposed bool
		known   bool
	}{
		{name: "registered route rejects the method", code: intPtr(http.StatusMethodNotAllowed), exposed: true, known: true},
		{name: "route absent", code: intPtr(http.StatusNotFound), exposed: false, known: true},
		{name: "guarded by an auth layer", code: intPtr(http.StatusUnauthorized), exposed: false, known: true},
		{name: "never answered", code: nil, exposed: false, known: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exposed, known := AnyAnonymousAccessible(observationsWith(tt.code), WeightUpdatePaths...)
			if exposed != tt.exposed || known != tt.known {
				t.Fatalf("got (%v,%v) want (%v,%v)", exposed, known, tt.exposed, tt.known)
			}
		})
	}

	// One open route among five closed ones is still an open route.
	mixed := observationsWith(intPtr(http.StatusNotFound))
	mixed[3].AnonymousStatusCode = intPtr(http.StatusMethodNotAllowed)
	if exposed, known := AnyAnonymousAccessible(mixed, WeightUpdatePaths...); !exposed || !known {
		t.Fatalf("mixed got (%v,%v) want (true,true)", exposed, known)
	}
}

// A proxy that blocks /docs and forwards /redoc publishes the same API
// surface, so the documentation verdict is read across both routes.
func TestDocumentationExposureCoversRedoc(t *testing.T) {
	if !slices.Contains(DocumentationPaths, "/redoc") {
		t.Fatal("/redoc is not part of the documentation exposure verdict")
	}
	observations := []EndpointObservation{
		{Spec: EndpointSpec{Path: "/docs"}, AnonymousStatusCode: intPtr(http.StatusNotFound)},
		{Spec: EndpointSpec{Path: "/redoc"}, AnonymousStatusCode: intPtr(http.StatusOK)},
	}
	if exposed, known := AnyAnonymousAccessible(observations, DocumentationPaths...); !exposed || !known {
		t.Fatalf("docsExposed got (%v,%v) want (true,true)", exposed, known)
	}

	bothAbsent := []EndpointObservation{
		{Spec: EndpointSpec{Path: "/docs"}, AnonymousStatusCode: intPtr(http.StatusNotFound)},
		{Spec: EndpointSpec{Path: "/redoc"}, AnonymousStatusCode: intPtr(http.StatusNotFound)},
	}
	if exposed, known := AnyAnonymousAccessible(bothAbsent, DocumentationPaths...); exposed || !known {
		t.Fatalf("docsExposed got (%v,%v) want (false,true)", exposed, known)
	}
}
