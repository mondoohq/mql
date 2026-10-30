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
		{name: "adds default scheme", raw: "example.com:8000", want: "http://example.com:8000"},
		{name: "keeps https", raw: "https://example.com", want: "https://example.com"},
		{name: "trims trailing slash", raw: "https://example.com/base/", want: "https://example.com/base"},
		{name: "strips query and fragment", raw: "http://example.com/p?token=secret#frag", want: "http://example.com/p"},
		{name: "trims surrounding whitespace", raw: "  http://example.com  ", want: "http://example.com"},
		{name: "rejects unsupported scheme", raw: "ftp://example.com", wantErr: true},
		{name: "rejects missing host", raw: "http://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeBaseURL(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeBaseURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestBaseURLFromConfig(t *testing.T) {
	tests := []struct {
		name    string
		conf    *inventory.Config
		want    string
		wantErr bool
	}{
		{
			name: "base-url option wins and is normalized",
			conf: &inventory.Config{Options: map[string]string{OptionBaseURL: "https://vllm.example/api/"}},
			want: "https://vllm.example/api",
		},
		{
			name: "builds from host, port, scheme and path",
			conf: &inventory.Config{Host: "example.com", Port: 8000, Runtime: "https", Path: "/api"},
			want: "https://example.com:8000/api",
		},
		{
			name: "defaults scheme to http when runtime empty",
			conf: &inventory.Config{Host: "example.com", Port: 8000},
			want: "http://example.com:8000",
		},
		{
			name:    "missing host is an error",
			conf:    &inventory.Config{Runtime: "https"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := baseURLFromConfig(tt.conf)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("baseURLFromConfig = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAPIKeyFromConfig(t *testing.T) {
	t.Run("reads from environment", func(t *testing.T) {
		t.Setenv("VLLM_API_KEY", "env-key")
		if got := apiKeyFromConfig(&inventory.Config{}); got != "env-key" {
			t.Fatalf("got %q, want env-key", got)
		}
	})

	t.Run("option overrides environment", func(t *testing.T) {
		t.Setenv("VLLM_API_KEY", "env-key")
		conf := &inventory.Config{Options: map[string]string{OptionAPIKey: "option-key"}}
		if got := apiKeyFromConfig(conf); got != "option-key" {
			t.Fatalf("got %q, want option-key", got)
		}
	})

	t.Run("password credential overrides option", func(t *testing.T) {
		t.Setenv("VLLM_API_KEY", "env-key")
		conf := &inventory.Config{
			Options:     map[string]string{OptionAPIKey: "option-key"},
			Credentials: []*vault.Credential{vault.NewPasswordCredential("", "cred-key")},
		}
		if got := apiKeyFromConfig(conf); got != "cred-key" {
			t.Fatalf("got %q, want cred-key", got)
		}
	})

	t.Run("trims surrounding whitespace", func(t *testing.T) {
		t.Setenv("VLLM_API_KEY", "  spaced-key  ")
		if got := apiKeyFromConfig(&inventory.Config{}); got != "spaced-key" {
			t.Fatalf("got %q, want spaced-key", got)
		}
	})

	t.Run("empty when nothing configured", func(t *testing.T) {
		t.Setenv("VLLM_API_KEY", "")
		if got := apiKeyFromConfig(&inventory.Config{}); got != "" {
			t.Fatalf("got %q, want empty", got)
		}
	})
}

func TestCategoryAnonymousAccessible(t *testing.T) {
	obs := func(category string, status *int) EndpointObservation {
		return EndpointObservation{Spec: EndpointSpec{Category: category}, AnonymousStatusCode: status}
	}

	tests := []struct {
		name           string
		observations   []EndpointObservation
		category       string
		wantAccessible bool
		wantKnown      bool
	}{
		{
			name: "any accessible endpoint wins",
			observations: []EndpointObservation{
				obs("development", new(404)),
				obs("development", new(200)),
			},
			category:       "development",
			wantAccessible: true,
			wantKnown:      true,
		},
		{
			name: "all known but not accessible",
			observations: []EndpointObservation{
				obs("development", new(401)),
				obs("development", new(403)),
			},
			category:       "development",
			wantAccessible: false,
			wantKnown:      true,
		},
		{
			name: "all unknown reports not known",
			observations: []EndpointObservation{
				obs("development", new(500)),
				obs("development", nil),
			},
			category:       "development",
			wantAccessible: false,
			wantKnown:      false,
		},
		{
			name: "ignores other categories",
			observations: []EndpointObservation{
				obs("profiler", new(200)),
			},
			category:       "development",
			wantAccessible: false,
			wantKnown:      false,
		},
		{
			name:           "no observations",
			observations:   nil,
			category:       "development",
			wantAccessible: false,
			wantKnown:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessible, known := CategoryAnonymousAccessible(tt.observations, tt.category)
			if accessible != tt.wantAccessible || known != tt.wantKnown {
				t.Fatalf("CategoryAnonymousAccessible = (%v, %v), want (%v, %v)",
					accessible, known, tt.wantAccessible, tt.wantKnown)
			}
		})
	}
}
