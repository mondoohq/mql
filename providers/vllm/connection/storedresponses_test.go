// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClassifyStoredResponseProbe(t *testing.T) {
	handlerNotFound := []byte(`{"error":{"message":"Response with id 'resp_x' not found.","type":"invalid_request_error","param":"response_id","code":404}}`)
	legacyNotFound := []byte(`{"object":"error","message":"Response with id 'resp_x' not found.","type":"invalid_request_error","param":"response_id","code":404}`)
	routerNotFound := []byte(`{"detail":"Not Found"}`)

	tests := []struct {
		name     string
		status   int
		body     []byte
		readable bool
		known    bool
	}{
		{name: "handler answered anonymously", status: http.StatusNotFound, body: handlerNotFound, readable: true, known: true},
		{name: "legacy flat error shape", status: http.StatusNotFound, body: legacyNotFound, readable: true, known: true},
		{name: "route is not registered", status: http.StatusNotFound, body: routerNotFound, readable: false, known: true},
		{name: "empty body is not a handler answer", status: http.StatusNotFound, body: nil, readable: false, known: true},
		{name: "html body is not a handler answer", status: http.StatusNotFound, body: []byte("<html>404</html>"), readable: false, known: true},
		{name: "authentication rejected", status: http.StatusUnauthorized, readable: false, known: true},
		{name: "forbidden", status: http.StatusForbidden, readable: false, known: true},
		{name: "server error is undetermined", status: http.StatusInternalServerError, readable: false, known: false},
		{name: "not implemented is undetermined", status: http.StatusNotImplemented, readable: false, known: false},
		{name: "method rejected", status: http.StatusMethodNotAllowed, readable: false, known: true},
		{name: "validation reached", status: http.StatusUnprocessableEntity, readable: true, known: true},
		{name: "retrieval succeeded", status: http.StatusOK, readable: true, known: true},
		{name: "bad request reached validation", status: http.StatusBadRequest, readable: true, known: true},
		// None of these show that the retrieval handler answered. A redirect is a
		// proxy sending the caller to a login page, and 408 and 429 are produced
		// in front of the handler. Reporting any of them as readable would claim
		// exposure on a server that never served the route.
		{name: "redirect to a login page is undetermined", status: http.StatusFound, readable: false, known: false},
		{name: "moved permanently is undetermined", status: http.StatusMovedPermanently, readable: false, known: false},
		{name: "request timeout is undetermined", status: http.StatusRequestTimeout, readable: false, known: false},
		{name: "rate limited is undetermined", status: http.StatusTooManyRequests, readable: false, known: false},
		{name: "payment required is undetermined", status: http.StatusPaymentRequired, readable: false, known: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := ClassifyStoredResponseProbe(tt.status, tt.body)
			if obs.Readable != tt.readable || obs.Known != tt.known {
				t.Fatalf("got (readable=%v, known=%v) want (%v, %v): %s", obs.Readable, obs.Known, tt.readable, tt.known, obs.Note)
			}
			if obs.StatusCode == nil || *obs.StatusCode != tt.status {
				t.Fatalf("statusCode got %v want %d", obs.StatusCode, tt.status)
			}
			if obs.Note == "" {
				t.Fatal("every verdict must carry a note explaining it")
			}
		})
	}
}

// The probe must never name a real stored response, and it must never send a
// method that could cancel one.
func TestStoredResponsesProbeIsSafe(t *testing.T) {
	var sawMethod, sawPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawMethod = r.Method
		sawPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"type":"invalid_request_error","param":"response_id"}}`))
	}))
	defer server.Close()

	conn := &VllmConnection{client: server.Client(), baseURL: server.URL}
	obs, err := conn.StoredResponses(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawMethod != http.MethodGet {
		t.Fatalf("method got %s want GET", sawMethod)
	}
	if sawPath != StoredResponsePath {
		t.Fatalf("path got %s want %s", sawPath, StoredResponsePath)
	}
	if !strings.HasSuffix(SyntheticResponseID, strings.Repeat("0", 32)) {
		t.Fatalf("the probe identifier %q must be structurally unable to name a real response", SyntheticResponseID)
	}
	if !obs.Readable || !obs.Known {
		t.Fatalf("got %+v want a readable verdict", obs)
	}
}

// A transport failure leaves the question open. It must not read as "not
// exposed", which would be an assertion the probe never made.
func TestStoredResponsesTransportFailureIsUnknown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	client := server.Client()
	server.Close()

	conn := &VllmConnection{client: client, baseURL: url}
	obs, _ := conn.StoredResponses(context.Background())
	if obs.Known {
		t.Fatalf("got %+v want an undetermined verdict", obs)
	}
}
