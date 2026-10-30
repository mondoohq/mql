// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestScrubConnectionOptions(t *testing.T) {
	t.Run("nil options yield an empty map", func(t *testing.T) {
		got := scrubConnectionOptions(nil)
		if len(got) != 0 {
			t.Fatalf("scrubConnectionOptions(nil) = %v, want empty", got)
		}
	})

	t.Run("keeps the parameters that locate the external system", func(t *testing.T) {
		got := scrubConnectionOptions(map[string]string{
			"host":        "acme.snowflakecomputing.com",
			"port":        "443",
			"user":        "svc_databricks",
			"sfWarehouse": "COMPUTE_WH",
		})
		want := map[string]any{
			"host":        "acme.snowflakecomputing.com",
			"port":        "443",
			"user":        "svc_databricks",
			"sfWarehouse": "COMPUTE_WH",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("scrubConnectionOptions() = %v, want %v", got, want)
		}
	})

	t.Run("drops credential material across connection types", func(t *testing.T) {
		// One key per shape the 27 connection types produce. The API redacts
		// the values, but the keys still disclose the authentication method
		// and a redacted placeholder is not worth surfacing.
		secrets := []string{
			"password",
			"personalAccessToken",
			"client_secret",
			"sasToken",
			"pem_private_key",
			"privateKey",
			"passphrase",
			"apiKey",
			"aws_access_key_id",
			"aws_secret_access_key",
			"OAuthRefreshToken",
			"service_credential",
			"signature",
		}
		for _, key := range secrets {
			got := scrubConnectionOptions(map[string]string{"host": "db.example.com", key: "REDACTED"})
			if _, leaked := got[key]; leaked {
				t.Errorf("scrubConnectionOptions() kept %q, want it dropped", key)
			}
			if got["host"] != "db.example.com" {
				t.Errorf("scrubConnectionOptions() dropped host while scrubbing %q", key)
			}
		}
	})

	t.Run("matching is case-insensitive", func(t *testing.T) {
		got := scrubConnectionOptions(map[string]string{"PASSWORD": "hunter2", "Host": "db.example.com"})
		want := map[string]any{"Host": "db.example.com"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("scrubConnectionOptions() = %v, want %v", got, want)
		}
	})
}
