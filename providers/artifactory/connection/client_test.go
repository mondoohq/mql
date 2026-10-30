// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetJSONSendsBearerToken(t *testing.T) {
	var gotAuth, gotAPIKey, gotAccept string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("X-JFrog-Art-Api")
		gotAccept = r.Header.Get("Accept")
		w.Write([]byte(`{"version":"7.90.10"}`))
	}))
	defer server.Close()

	conn := testConnection(t, server.URL, "example-token", "")

	var out struct {
		Version string `json:"version"`
	}
	if err := conn.GetJSON(context.Background(), conn.ArtifactoryURL("/api/system/version"), &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if out.Version != "7.90.10" {
		t.Errorf("version = %q, want 7.90.10", out.Version)
	}
	if gotAuth != "Bearer example-token" {
		t.Errorf("Authorization = %q, want a bearer token", gotAuth)
	}
	if gotAPIKey != "" {
		t.Errorf("X-JFrog-Art-Api = %q, want it unset when a token is used", gotAPIKey)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept = %q, want application/json", gotAccept)
	}
}

// An API key travels in its own header. Sending it as a bearer token would be
// rejected, so the two credentials must not be confused.
func TestGetJSONSendsAPIKeyHeader(t *testing.T) {
	var gotAuth, gotAPIKey string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotAPIKey = r.Header.Get("X-JFrog-Art-Api")
		w.Write([]byte(`{}`))
	}))
	defer server.Close()

	conn := testConnection(t, server.URL, "", "example-key")

	if err := conn.GetJSON(context.Background(), conn.ArtifactoryURL("/api/repositories"), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAPIKey != "example-key" {
		t.Errorf("X-JFrog-Art-Api = %q, want the API key", gotAPIKey)
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want it unset when an API key is used", gotAuth)
	}
}

func TestGetXMLDecodesTheConfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<config><security><anonAccessEnabled>true</anonAccessEnabled></security></config>`))
	}))
	defer server.Close()

	conn := testConnection(t, server.URL, "example-token", "")

	var out struct {
		Security struct {
			AnonAccessEnabled bool `xml:"anonAccessEnabled"`
		} `xml:"security"`
	}
	if err := conn.GetXML(context.Background(), conn.ArtifactoryURL("/api/system/configuration"), &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !out.Security.AnonAccessEnabled {
		t.Error("anonAccessEnabled decoded as false, want true")
	}
}

func TestGetTextTrimsTheBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("jfrt@01ab2c3d\n"))
	}))
	defer server.Close()

	conn := testConnection(t, server.URL, "example-token", "")

	got, err := conn.GetText(context.Background(), conn.ArtifactoryURL("/api/system/service_id"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "jfrt@01ab2c3d" {
		t.Errorf("service id = %q, want it trimmed", got)
	}
}

func TestAPIErrorCarriesTheMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors":[{"status":403,"message":"Insufficient permissions"}]}`))
	}))
	defer server.Close()

	conn := testConnection(t, server.URL, "example-token", "")

	err := conn.GetJSON(context.Background(), conn.ArtifactoryURL("/api/system/configuration"), nil)
	if err == nil {
		t.Fatal("expected an error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is not an APIError: %v", err)
	}
	if apiErr.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", apiErr.StatusCode)
	}
	if apiErr.Message != "Insufficient permissions" {
		t.Errorf("message = %q, want the message from the errors array", apiErr.Message)
	}
	if !IsForbidden(err) {
		t.Error("IsForbidden = false, want true")
	}
	if IsNotFound(err) {
		t.Error("IsNotFound = true, want false")
	}
}

func TestIsNotFoundMatchesA404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer server.Close()

	conn := testConnection(t, server.URL, "example-token", "")

	err := conn.GetJSON(context.Background(), conn.ArtifactoryURL("/api/cleanup/packages/policies"), nil)
	if !IsNotFound(err) {
		t.Fatalf("IsNotFound = false for %v, want true", err)
	}
	if IsForbidden(err) {
		t.Error("IsForbidden = true, want false")
	}
}

// A network failure must not be classified as an access decision. If it were,
// a blip would degrade a field to null and an audit would pass on data that
// was never read.
func TestClassifiersIgnoreTransportErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := server.URL
	server.Close()

	conn := testConnection(t, unreachable, "example-token", "")

	err := conn.GetJSON(context.Background(), conn.ArtifactoryURL("/api/repositories"), nil)
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if IsForbidden(err) || IsNotFound(err) {
		t.Errorf("a transport error was classified as an access decision: %v", err)
	}
}

func TestGetJSONReportsADecodeFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer server.Close()

	conn := testConnection(t, server.URL, "example-token", "")

	var out map[string]any
	if err := conn.GetJSON(context.Background(), conn.ArtifactoryURL("/api/repositories"), &out); err == nil {
		t.Fatal("expected a decode error")
	}
}

// Xray is a separate service of the same platform, so its URL must be built
// from the same base rather than from the Artifactory service prefix.
func TestXrayURL(t *testing.T) {
	conn := testConnection(t, "https://artifactory.example.com/artifactory", "token", "")

	if got, want := conn.XrayURL("/api/v2/watches"), "https://artifactory.example.com/xray/api/v2/watches"; got != want {
		t.Errorf("XrayURL = %q, want %q", got, want)
	}
}
