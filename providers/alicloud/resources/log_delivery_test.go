// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	cloudfwclient "github.com/alibabacloud-go/cloudfw-20171207/v11/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

// TestWafLogDelivering covers the WAF log-status classifier. WAF reports five
// states and only one of them means logs are reaching Log Service; treating a
// transitional or failed state as delivering would report an audit trail for
// an instance that is recording nothing.
func TestWafLogDelivering(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *string
		want   bool
	}{
		{"nil is not delivering", nil, false},
		{"empty is not delivering", new(""), false},
		{"normal is delivering", new("normal"), true},
		{"case insensitive", new("Normal"), true},
		{"surrounding space", new(" normal "), true},
		{"initializing is not delivering", new("initializing"), false},
		{"initialize_failed is not delivering", new("initialize_failed"), false},
		{"releasing is not delivering", new("releasing"), false},
		{"release_failed is not delivering", new("release_failed"), false},
		{"unknown state is not delivering", new("paused"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, wafLogDelivering(tc.status))
		})
	}
}

// TestSasLogEnabled covers the Security Center per-log-type switch. Security
// Center reports enabled/disabled per category, and an unreadable category has
// to read as off so a check on network logs fails rather than inheriting the
// verdict of a category that happened to be on.
func TestSasLogEnabled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status *string
		want   bool
	}{
		{"nil is off", nil, false},
		{"empty is off", new(""), false},
		{"enabled", new("enabled"), true},
		{"case insensitive", new("Enabled"), true},
		{"surrounding space", new(" enabled "), true},
		{"disabled", new("disabled"), false},
		{"unknown state is off", new("pending"), false},
		{"substring must not match", new("not-enabled"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sasLogEnabled(tc.status))
		})
	}
}

// TestCloudfwLogDelivering covers the Cloud Firewall log-analysis predicate.
// Cloud Firewall exposes no boolean for the feature: switching it on provisions
// a Log Service project and logstore, so their presence is the only signal. A
// partial response naming one and not the other is not a provisioned store, and
// must not read as one.
func TestCloudfwLogDelivering(t *testing.T) {
	t.Run("nil is off", func(t *testing.T) {
		assert.False(t, cloudfwLogDelivering(nil))
	})

	t.Run("empty response is off", func(t *testing.T) {
		assert.False(t, cloudfwLogDelivering(&cloudfwclient.DescribeLogStoreInfoResponseBody{}))
	})

	t.Run("project without logstore is off", func(t *testing.T) {
		assert.False(t, cloudfwLogDelivering(&cloudfwclient.DescribeLogStoreInfoResponseBody{
			ProjectName: new("cloudfirewall-project-1234-cn-hangzhou"),
		}))
	})

	t.Run("logstore without project is off", func(t *testing.T) {
		assert.False(t, cloudfwLogDelivering(&cloudfwclient.DescribeLogStoreInfoResponseBody{
			LogStoreName: new("cloudfirewall-logstore"),
		}))
	})

	t.Run("empty strings are off", func(t *testing.T) {
		assert.False(t, cloudfwLogDelivering(&cloudfwclient.DescribeLogStoreInfoResponseBody{
			ProjectName:  new(""),
			LogStoreName: new(""),
		}))
	})

	t.Run("both present is on", func(t *testing.T) {
		assert.True(t, cloudfwLogDelivering(&cloudfwclient.DescribeLogStoreInfoResponseBody{
			ProjectName:  new("cloudfirewall-project-1234-cn-hangzhou"),
			LogStoreName: new("cloudfirewall-logstore"),
		}))
	})

	t.Run("a quota-only response is off", func(t *testing.T) {
		// An account that bought log storage but never switched log analysis on
		// still reports a quota. Quota is not delivery.
		assert.False(t, cloudfwLogDelivering(&cloudfwclient.DescribeLogStoreInfoResponseBody{
			TotalQuota: tea.Int64(50000000),
			Ttl:        tea.Int32(180),
		}))
	})
}
