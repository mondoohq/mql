// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"reflect"
	"testing"

	alb "github.com/stackitcloud/stackit-sdk-go/services/alb/v2api"
	albwaf "github.com/stackitcloud/stackit-sdk-go/services/albwaf/v1betaapi"
	loadbalancer "github.com/stackitcloud/stackit-sdk-go/services/loadbalancer/v2api"
)

// optionsDict runs an options payload through the SDK model and the same
// toDict marshal the provider stores on the resource, so the readers are
// tested against the dict shape they see at runtime.
func optionsDict(t *testing.T, payload string) any {
	t.Helper()
	var opts loadbalancer.LoadBalancerOptions
	if err := json.Unmarshal([]byte(payload), &opts); err != nil {
		t.Fatalf("decoding options: %v", err)
	}
	return toDict(opts)
}

// TestLbOptionReaders pins the dict paths behind the balancer option fields.
// The ephemeral-address flag has to distinguish absent from false, and the
// observability push URLs have to come out of the nested logs/metrics blocks.
func TestLbOptionReaders(t *testing.T) {
	full := optionsDict(t, `{
		"accessControl": {"allowedSourceRanges": ["10.0.0.0/8", "192.168.0.0/16"]},
		"ephemeralAddress": true,
		"observability": {
			"logs": {"credentialsRef": "cred-1", "pushUrl": "https://logs.example.test/push"},
			"metrics": {"credentialsRef": "cred-2", "pushUrl": "https://metrics.example.test/push"}
		},
		"privateNetworkOnly": false
	}`)

	if got := lbAccessControlRanges(full); !reflect.DeepEqual(got, []string{"10.0.0.0/8", "192.168.0.0/16"}) {
		t.Fatalf("allowedSourceRanges = %v", got)
	}
	if v, ok := lbEphemeralAddress(full); !ok || !v {
		t.Fatalf("ephemeralAddress = (%v, %v), want (true, present)", v, ok)
	}
	if got := lbObservabilityPushUrl(full, "logs"); got != "https://logs.example.test/push" {
		t.Fatalf("logs pushUrl = %q", got)
	}
	if got := lbObservabilityPushUrl(full, "metrics"); got != "https://metrics.example.test/push" {
		t.Fatalf("metrics pushUrl = %q", got)
	}

	empty := optionsDict(t, `{}`)
	if v, ok := lbEphemeralAddress(empty); ok {
		t.Fatalf("absent ephemeralAddress = (%v, present), want not present", v)
	}
	if got := lbObservabilityPushUrl(empty, "logs"); got != "" {
		t.Fatalf("absent logs pushUrl = %q, want empty", got)
	}
	if got := lbAccessControlRanges(empty); len(got) != 0 {
		t.Fatalf("absent allow-list = %v, want empty", got)
	}

	if v, ok := lbEphemeralAddress(optionsDict(t, `{"ephemeralAddress": false}`)); !ok || v {
		t.Fatalf("explicit false = (%v, %v), want (false, present)", v, ok)
	}
	if _, ok := lbEphemeralAddress(nil); ok {
		t.Fatal("nil options must not report a value")
	}
}

// TestPoolHealthCheckTls pins the tri-state reading of the health-check TLS
// flags: a pool without an HTTP health check, or one whose check omits the
// tls block, must read null on both rather than a false that asserts the
// probe validates certificates.
func TestPoolHealthCheckTls(t *testing.T) {
	decode := func(payload string) *loadbalancer.TargetPool {
		var tp loadbalancer.TargetPool
		if err := json.Unmarshal([]byte(payload), &tp); err != nil {
			t.Fatalf("decoding target pool: %v", err)
		}
		return &tp
	}

	t.Run("tls on, validation skipped", func(t *testing.T) {
		enabled, skip := poolHealthCheckTls(decode(`{"name": "p", "activeHealthCheck": {"httpHealthChecks": {"path": "/healthz", "tls": {"enabled": true, "skipCertificateValidation": true}}}}`))
		assertBoolPtr(t, "healthCheckTlsEnabled", enabled, new(true))
		assertBoolPtr(t, "healthCheckSkipCertificateValidation", skip, new(true))
	})
	t.Run("tls block omitted reads null", func(t *testing.T) {
		enabled, skip := poolHealthCheckTls(decode(`{"name": "p", "activeHealthCheck": {"httpHealthChecks": {"path": "/healthz"}}}`))
		assertBoolPtr(t, "healthCheckTlsEnabled", enabled, nil)
		assertBoolPtr(t, "healthCheckSkipCertificateValidation", skip, nil)
	})
	t.Run("no http health check reads null", func(t *testing.T) {
		enabled, skip := poolHealthCheckTls(decode(`{"name": "p", "activeHealthCheck": {"interval": "10s"}}`))
		assertBoolPtr(t, "healthCheckTlsEnabled", enabled, nil)
		assertBoolPtr(t, "healthCheckSkipCertificateValidation", skip, nil)
	})
	t.Run("session persistence", func(t *testing.T) {
		assertBoolPtr(t, "sessionPersistenceSourceIp", poolSessionPersistenceSourceIp(decode(`{"name": "p", "sessionPersistence": {"useSourceIpAddress": true}}`)), new(true))
		assertBoolPtr(t, "sessionPersistenceSourceIp absent", poolSessionPersistenceSourceIp(decode(`{"name": "p"}`)), nil)
	})
	t.Run("nil pool", func(t *testing.T) {
		enabled, skip := poolHealthCheckTls(nil)
		if enabled != nil || skip != nil || poolSessionPersistenceSourceIp(nil) != nil {
			t.Fatal("nil pool must read null everywhere")
		}
	})
}

// TestAlbListenerAndPoolPosture pins the projections over the application
// balancer's listeners and target pools: certificate ids deduplicated across
// HTTPS listeners, plaintext ports from HTTP listeners only, and the names of
// pools whose TLS bridging skips validation.
func TestAlbListenerAndPoolPosture(t *testing.T) {
	var lb alb.LoadBalancer
	if err := json.Unmarshal([]byte(`{
		"name": "web",
		"listeners": [
			{"name": "https-a", "port": 443, "protocol": "PROTOCOL_HTTPS", "https": {"certificateConfig": {"certificateIds": ["cert-2", "cert-1"]}}},
			{"name": "https-b", "port": 8443, "protocol": "PROTOCOL_HTTPS", "https": {"certificateConfig": {"certificateIds": ["cert-1"]}}},
			{"name": "http", "port": 80, "protocol": "PROTOCOL_HTTP"},
			{"name": "http-alt", "port": 8080, "protocol": "PROTOCOL_HTTP"}
		],
		"targetPools": [
			{"name": "secure", "tlsConfig": {"enabled": true, "skipCertificateValidation": false}},
			{"name": "lax", "tlsConfig": {"enabled": true, "skipCertificateValidation": true}},
			{"name": "plain"}
		]
	}`), &lb); err != nil {
		t.Fatalf("decoding alb: %v", err)
	}

	if got := albCertificateIDs(lb.GetListeners()); !reflect.DeepEqual(got, []string{"cert-1", "cert-2"}) {
		t.Fatalf("certificate ids = %v, want deduplicated and sorted [cert-1 cert-2]", got)
	}
	if got := albPlaintextListenerPorts(lb.GetListeners()); !reflect.DeepEqual(got, []int64{80, 8080}) {
		t.Fatalf("plaintext ports = %v, want [80 8080]", got)
	}
	if got := albInsecureTargetPools(lb.GetTargetPools()); !reflect.DeepEqual(got, []string{"lax"}) {
		t.Fatalf("insecure pools = %v, want [lax]", got)
	}

	if got := albCertificateIDs(nil); len(got) != 0 {
		t.Fatalf("no listeners = %v, want empty", got)
	}
	if got := albPlaintextListenerPorts(nil); len(got) != 0 {
		t.Fatalf("no listeners = %v, want empty", got)
	}
	if got := albInsecureTargetPools(nil); len(got) != 0 {
		t.Fatalf("no pools = %v, want empty", got)
	}
}

// TestWafUsageNames pins the usage projections: WAF usage yields balancer
// names deduplicated across listeners, and rule-set/group usage yields sorted
// unique WAF names. A WAF attached to nothing yields an empty list, which is
// the finding the field exists to surface.
func TestWafUsageNames(t *testing.T) {
	var usage albwaf.WAFUsage
	if err := json.Unmarshal([]byte(`{"count": 3, "items": [
		{"loadBalancerName": "web", "listenerNames": ["https"]},
		{"loadBalancerName": "web", "listenerNames": ["https-alt"]},
		{"loadBalancerName": "api", "listenerNames": ["https"]}
	]}`), &usage); err != nil {
		t.Fatalf("decoding usage: %v", err)
	}
	if got := wafUsageLoadBalancers(&usage); !reflect.DeepEqual(got, []string{"api", "web"}) {
		t.Fatalf("waf load balancers = %v, want [api web]", got)
	}
	if got := wafUsageLoadBalancers(&albwaf.WAFUsage{}); len(got) != 0 {
		t.Fatalf("unattached waf = %v, want empty", got)
	}
	if got := wafUsageLoadBalancers(nil); got != nil {
		t.Fatalf("nil usage = %v, want nil", got)
	}
	if got := usageNames([]string{"waf-b", "waf-a", "waf-b", ""}); !reflect.DeepEqual(got, []string{"waf-a", "waf-b"}) {
		t.Fatalf("usageNames = %v, want [waf-a waf-b]", got)
	}
}
