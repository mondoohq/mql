// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"reflect"
	"testing"

	certificates "github.com/stackitcloud/stackit-sdk-go/services/certificates/v2api"
)

// TestCertificateTrustFlagsStayTriState pins isSelfSigned and isCa to the
// pointer path: a certificate whose response omits them must read null, not
// false, since "not self-signed" and "not a CA" are the reassuring answers and
// must only be reported when the service actually said so.
func TestCertificateTrustFlagsStayTriState(t *testing.T) {
	decode := func(payload string) certificates.Data {
		var d certificates.Data
		if err := json.Unmarshal([]byte(payload), &d); err != nil {
			t.Fatalf("decoding certificate data: %v", err)
		}
		return d
	}

	t.Run("flags absent read null", func(t *testing.T) {
		d := decode(`{"subjectCn": "example.test"}`)
		if got := optBool(d.GetIsSelfSignedOk()); got != nil {
			t.Fatalf("isSelfSigned = %v, want null when absent", *got)
		}
		if got := optBool(d.GetIsCaOk()); got != nil {
			t.Fatalf("isCa = %v, want null when absent", *got)
		}
	})

	t.Run("flags present are reported as sent", func(t *testing.T) {
		d := decode(`{"subjectCn": "example.test", "isSelfSigned": true, "isCa": false, "organization": "Example Org"}`)
		if got := optBool(d.GetIsSelfSignedOk()); got == nil || !*got {
			t.Fatalf("isSelfSigned = %v, want true", got)
		}
		if got := optBool(d.GetIsCaOk()); got == nil || *got {
			t.Fatalf("isCa = %v, want false (a real false, not null)", got)
		}
		if d.GetOrganization() != "Example Org" {
			t.Fatalf("organization = %q", d.GetOrganization())
		}
	})
}

func TestCertificateUsage(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("empty usage yields empty slice", func(t *testing.T) {
		got := certificateUsage(certificates.Usage{})
		if got == nil || len(got) != 0 {
			t.Fatalf("expected non-nil empty slice, got %#v", got)
		}
	})

	t.Run("maps load balancers and listeners", func(t *testing.T) {
		listenersA := []string{"https", "http"}
		listenersB := []string{"tls"}
		u := certificates.Usage{
			Items: []certificates.UsageItem{
				{LoadBalancerName: strPtr("lb-a"), ListenerNames: listenersA},
				{LoadBalancerName: strPtr("lb-b"), ListenerNames: listenersB},
			},
		}

		got := certificateUsage(u)
		want := []any{
			map[string]any{"loadBalancerName": "lb-a", "listenerNames": []any{"https", "http"}},
			map[string]any{"loadBalancerName": "lb-b", "listenerNames": []any{"tls"}},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("mismatch\n got: %#v\nwant: %#v", got, want)
		}
	})

	t.Run("item without listeners yields empty listener slice", func(t *testing.T) {
		u := certificates.Usage{
			Items: []certificates.UsageItem{
				{LoadBalancerName: strPtr("lb-c")},
			},
		}

		got := certificateUsage(u)
		entry, ok := got[0].(map[string]any)
		if !ok {
			t.Fatalf("expected map entry, got %T", got[0])
		}
		listeners, ok := entry["listenerNames"].([]any)
		if !ok {
			t.Fatalf("expected []any listeners, got %T", entry["listenerNames"])
		}
		if len(listeners) != 0 {
			t.Fatalf("expected empty listeners, got %#v", listeners)
		}
	})
}
