// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "cloud instance", raw: "https://example.jfrog.io", want: "https://example.jfrog.io"},
		{name: "cloud instance with slash", raw: "https://example.jfrog.io/", want: "https://example.jfrog.io"},
		{name: "cloud instance with service prefix", raw: "https://example.jfrog.io/artifactory", want: "https://example.jfrog.io"},
		{name: "self hosted base", raw: "https://artifactory.example.com", want: "https://artifactory.example.com"},
		{name: "self hosted with service prefix", raw: "https://artifactory.example.com/artifactory/", want: "https://artifactory.example.com"},
		{name: "service prefix in mixed case", raw: "https://artifactory.example.com/Artifactory", want: "https://artifactory.example.com"},
		{name: "bare host defaults to https", raw: "artifactory.example.com", want: "https://artifactory.example.com"},
		{name: "explicit port is kept", raw: "http://localhost:8082/artifactory", want: "http://localhost:8082"},
		{name: "context path is kept", raw: "https://example.com/jfrog", want: "https://example.com/jfrog"},
		{name: "surrounding space is ignored", raw: "  https://example.jfrog.io  ", want: "https://example.jfrog.io"},
		{name: "empty", raw: "", wantErr: true},
		{name: "unsupported scheme", raw: "ftp://example.com", wantErr: true},
		{name: "no host", raw: "https://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeBaseURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q, got %q", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Errorf("NormalizeBaseURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// A doubled service prefix is the failure this normalization exists to
// prevent, so the built URLs are asserted rather than only the base.
func TestServiceURLs(t *testing.T) {
	conn := testConnection(t, "https://artifactory.example.com/artifactory", "token", "")

	if got, want := conn.ArtifactoryURL("/api/repositories"), "https://artifactory.example.com/artifactory/api/repositories"; got != want {
		t.Errorf("ArtifactoryURL = %q, want %q", got, want)
	}
	if got, want := conn.AccessURL("/api/v2/users"), "https://artifactory.example.com/access/api/v2/users"; got != want {
		t.Errorf("AccessURL = %q, want %q", got, want)
	}
	if got, want := conn.Host(), "artifactory.example.com"; got != want {
		t.Errorf("Host = %q, want %q", got, want)
	}
}

func TestNewConnectionRequiresURLAndCredential(t *testing.T) {
	t.Setenv("ARTIFACTORY_URL", "")
	t.Setenv("JFROG_URL", "")
	t.Setenv("ARTIFACTORY_TOKEN", "")
	t.Setenv("JFROG_ACCESS_TOKEN", "")
	t.Setenv("ARTIFACTORY_API_KEY", "")

	_, err := NewArtifactoryConnection(1, &inventory.Asset{}, &inventory.Config{Options: map[string]string{}})
	if err == nil {
		t.Fatal("expected an error when no URL is configured")
	}

	_, err = NewArtifactoryConnection(1, &inventory.Asset{}, &inventory.Config{
		Options: map[string]string{OptionURL: "https://example.jfrog.io"},
	})
	if err == nil {
		t.Fatal("expected an error when no credential is configured")
	}
}

// The credential passed on the command line must win over the environment,
// which is what a user overriding a stale variable expects.
func TestCredentialOverridesEnvironment(t *testing.T) {
	t.Setenv("ARTIFACTORY_TOKEN", "from-environment")

	conn := testConnection(t, "https://example.jfrog.io", "from-flag", "")
	if conn.token != "from-flag" {
		t.Errorf("token = %q, want the flag value", conn.token)
	}
}

func testConnection(t *testing.T, rawURL string, token string, apiKey string) *ArtifactoryConnection {
	t.Helper()

	conf := &inventory.Config{Options: map[string]string{OptionURL: rawURL}}
	if token != "" {
		conf.Credentials = append(conf.Credentials, &vault.Credential{
			Type:   vault.CredentialType_bearer,
			Secret: []byte(token),
		})
	}
	if apiKey != "" {
		conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential("", apiKey))
	}

	conn, err := NewArtifactoryConnection(1, &inventory.Asset{}, conf)
	if err != nil {
		t.Fatalf("could not build the connection: %v", err)
	}
	return conn
}
