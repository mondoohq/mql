// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestDictStr(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"string", "TLSv1.2", "TLSv1.2"},
		{"empty string", "", ""},
		{"nil", nil, ""},
		{"wrong type int", 12, ""},
		{"wrong type slice", []any{"TLSv1.2"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dictStr(c.in); got != c.want {
				t.Errorf("dictStr(%v) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestParamValue(t *testing.T) {
	params := map[string]any{
		"tls-protocols": []any{"TLSv1.2", "TLSv1.3"},
		"tls-ciphers":   "TLS_AES_128",
	}
	cases := []struct {
		name       string
		parameters any
		key        string
		wantNil    bool
	}{
		{"present list key", params, "tls-protocols", false},
		{"present string key", params, "tls-ciphers", false},
		{"missing key", params, "does-not-exist", true},
		{"parameters not a map", "not-a-map", "tls-protocols", true},
		{"nil parameters", nil, "tls-protocols", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := paramValue(c.parameters, c.key)
			if (got == nil) != c.wantNil {
				t.Errorf("paramValue(%v, %q) = %v, wantNil=%v", c.parameters, c.key, got, c.wantNil)
			}
		})
	}
}

// TestTlsParamCoercion covers the string-list normalization the accessors rely
// on: a JSON array (RabbitMQ/OpenSearch shape) and a single string (the Redis
// tls-protocols enum shape) must both yield a stable []any, and absent keys an
// empty list. This is where a wrong-type assertion would silently drop a TLS
// setting from a PQC check.
func TestTlsParamCoercion(t *testing.T) {
	cases := []struct {
		name   string
		params map[string]any
		key    string
		want   []string
	}{
		{
			name:   "json array of protocols",
			params: map[string]any{"tls-protocols": []any{"TLSv1.2", "TLSv1.3"}},
			key:    "tls-protocols",
			want:   []string{"TLSv1.2", "TLSv1.3"},
		},
		{
			name:   "single string protocol (redis enum)",
			params: map[string]any{"tls-protocols": "TLSv1.3"},
			key:    "tls-protocols",
			want:   []string{"TLSv1.3"},
		},
		{
			name:   "missing key yields empty list",
			params: map[string]any{},
			key:    "tls-protocols",
			want:   []string{},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strSlice(dictStrSlice(paramValue(c.params, c.key)))
			if len(got) != len(c.want) {
				t.Fatalf("coercion(%v) = %v, want %v", c.params, got, c.want)
			}
			for i := range got {
				if got[i].(string) != c.want[i] {
					t.Errorf("coercion[%d] = %q, want %q", i, got[i], c.want[i])
				}
			}
		})
	}
}
