// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	tlink "github.com/stackitcloud/stackit-sdk-go/services/telemetrylink/v1api"
	trouter "github.com/stackitcloud/stackit-sdk-go/services/telemetryrouter/v1betaapi"
)

// decodeDestinationConfig builds the SDK struct from a payload shaped like the
// ListDestinations response, then runs it through the same toDict marshal the
// provider uses, so the test exercises the exact key names the redaction has
// to know about rather than a hand-built map.
func decodeDestinationConfig(t *testing.T, payload string) map[string]any {
	t.Helper()
	var cfg trouter.DestinationConfig
	if err := json.Unmarshal([]byte(payload), &cfg); err != nil {
		t.Fatalf("decoding destination config: %v", err)
	}
	m, ok := toDict(cfg).(map[string]any)
	if !ok {
		t.Fatalf("toDict(DestinationConfig) = %T, want map", toDict(cfg))
	}
	return m
}

// TestRedactDestinationConfigStripsSecrets pins the leak this guards against:
// the destination config used to be a raw marshal of DestinationConfig, which
// put the OTLP basic-auth password, the bearer token, and the S3 secret key
// into the `config` dict of every stackit.telemetry.router.destination.
func TestRedactDestinationConfigStripsSecrets(t *testing.T) {
	t.Run("open telemetry basic auth keeps the username, drops the password", func(t *testing.T) {
		got := redactDestinationConfig(decodeDestinationConfig(t, `{
			"configType": "OpenTelemetry",
			"openTelemetry": {
				"uri": "https://otel.example.test:4318",
				"basicAuth": {"username": "router", "password": "hunter2"}
			}
		}`)).(map[string]any)
		otel := got["openTelemetry"].(map[string]any)
		auth := otel["basicAuth"].(map[string]any)
		if _, leaked := auth["password"]; leaked {
			t.Fatalf("basicAuth.password survived redaction: %v", auth)
		}
		if auth["username"] != "router" {
			t.Fatalf("basicAuth.username = %v, want router", auth["username"])
		}
		if otel["uri"] != "https://otel.example.test:4318" {
			t.Fatalf("uri = %v, want the endpoint to survive", otel["uri"])
		}
	})

	t.Run("open telemetry bearer token is dropped", func(t *testing.T) {
		got := redactDestinationConfig(decodeDestinationConfig(t, `{
			"configType": "OpenTelemetry",
			"openTelemetry": {"uri": "https://otel.example.test", "bearerToken": "eyJhbGciOi"}
		}`)).(map[string]any)
		otel := got["openTelemetry"].(map[string]any)
		if _, leaked := otel["bearerToken"]; leaked {
			t.Fatalf("bearerToken survived redaction: %v", otel)
		}
	})

	t.Run("s3 access key keeps the id, drops the secret", func(t *testing.T) {
		got := redactDestinationConfig(decodeDestinationConfig(t, `{
			"configType": "S3",
			"s3": {
				"bucket": "telemetry-archive",
				"endpoint": "https://object.storage.example.test",
				"accessKey": {"id": "AKIA-EXAMPLE", "secret": "wJalrXUtnFEMI"}
			}
		}`)).(map[string]any)
		s3 := got["s3"].(map[string]any)
		key := s3["accessKey"].(map[string]any)
		if _, leaked := key["secret"]; leaked {
			t.Fatalf("accessKey.secret survived redaction: %v", key)
		}
		if key["id"] != "AKIA-EXAMPLE" {
			t.Fatalf("accessKey.id = %v, want AKIA-EXAMPLE", key["id"])
		}
		if s3["bucket"] != "telemetry-archive" || s3["endpoint"] != "https://object.storage.example.test" {
			t.Fatalf("bucket/endpoint did not survive: %v", s3)
		}
	})

	t.Run("config without credentials is left intact", func(t *testing.T) {
		got := redactDestinationConfig(decodeDestinationConfig(t, `{
			"configType": "OpenTelemetry",
			"openTelemetry": {"uri": "https://otel.example.test"},
			"filter": {"attributes": [{"key": "env", "level": "resource", "matcher": "equals", "values": ["prod"]}]}
		}`)).(map[string]any)
		if got["configType"] != "OpenTelemetry" {
			t.Fatalf("configType = %v", got["configType"])
		}
		if _, ok := got["filter"].(map[string]any); !ok {
			t.Fatalf("filter was dropped: %v", got)
		}
	})

	t.Run("non-dict input is returned unchanged", func(t *testing.T) {
		if got := redactDestinationConfig(nil); got != nil {
			t.Fatalf("redactDestinationConfig(nil) = %v, want nil", got)
		}
		if got := redactDestinationConfig("opaque"); got != "opaque" {
			t.Fatalf("redactDestinationConfig(string) = %v, want the input back", got)
		}
	})
}

// Synthetic: GetProjectTelemetryLink payloads shaped after the v1 API model; no live link was read.
func TestTelemetryLinkArgsLabels(t *testing.T) {
	decode := func(payload string) map[string]any {
		t.Helper()
		var l tlink.TelemetryLinkResponse
		if err := json.Unmarshal([]byte(payload), &l); err != nil {
			t.Fatalf("decoding telemetry link: %v", err)
		}
		labels, ok := telemetryLinkArgs(&l)["labels"].Value.(map[string]any)
		if !ok {
			t.Fatalf("labels is %T, want map", telemetryLinkArgs(&l)["labels"].Value)
		}
		return labels
	}

	base := `"id":"0b8b5c0e-1111-2222-3333-444455556666","displayName":"prod","enabled":true,` +
		`"regionId":"eu01","status":"active","createTime":"2026-11-20T10:00:00Z","telemetryRouterId":"r1"`

	labels := decode(`{` + base + `,"resourceLabels":{"env":"prod","team":"platform"}}`)
	if labels["env"] != "prod" || labels["team"] != "platform" || len(labels) != 2 {
		t.Fatalf("labels = %v, want env=prod team=platform", labels)
	}

	if labels := decode(`{` + base + `}`); len(labels) != 0 {
		t.Fatalf("labels without resourceLabels = %v, want empty", labels)
	}
}
