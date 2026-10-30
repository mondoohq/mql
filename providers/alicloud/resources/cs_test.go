// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	csclient "github.com/alibabacloud-go/cs-20151215/v8/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseCsMasterURL covers the ACK MasterUrl parser, which drives the
// apiServerInternetExposed security signal. A parsing bug would misreport
// whether a cluster's API server is reachable from the internet.
func TestParseCsMasterURL(t *testing.T) {
	t.Run("public and intranet endpoints present", func(t *testing.T) {
		public, intranet := parseCsMasterURL(new(`{"api_server_endpoint":"https://1.2.3.4:6443","intranet_api_server_endpoint":"https://10.0.0.1:6443"}`))
		assert.Equal(t, "https://1.2.3.4:6443", public)
		assert.Equal(t, "https://10.0.0.1:6443", intranet)
		assert.True(t, public != "", "public endpoint present => internet exposed")
	})
	t.Run("private-only cluster has empty public endpoint", func(t *testing.T) {
		public, intranet := parseCsMasterURL(new(`{"api_server_endpoint":"","intranet_api_server_endpoint":"https://10.0.0.1:6443"}`))
		assert.Equal(t, "", public)
		assert.Equal(t, "https://10.0.0.1:6443", intranet)
		assert.False(t, public != "", "no public endpoint => not internet exposed")
	})
	t.Run("nil pointer yields empties", func(t *testing.T) {
		public, intranet := parseCsMasterURL(nil)
		assert.Equal(t, "", public)
		assert.Equal(t, "", intranet)
	})
	t.Run("empty string (initializing cluster) yields empties", func(t *testing.T) {
		public, intranet := parseCsMasterURL(new(""))
		assert.Equal(t, "", public)
		assert.Equal(t, "", intranet)
	})
	t.Run("malformed JSON yields empties, not a panic", func(t *testing.T) {
		public, intranet := parseCsMasterURL(new("not-json"))
		assert.Equal(t, "", public)
		assert.Equal(t, "", intranet)
	})
}

// TestCsControlPlaneLogComponentEnabled covers the control plane log component
// predicate behind the deprecated auditLogEnabled field. The absent-response
// and empty-list cases decide whether a cluster reads as not collecting a
// component at all.
func TestCsControlPlaneLogComponentEnabled(t *testing.T) {
	t.Run("component collected", func(t *testing.T) {
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{new("kube-apiserver"), new("kube-scheduler")},
		}
		assert.True(t, csControlPlaneLogComponentEnabled(body, "kube-apiserver"))
	})
	t.Run("match is case insensitive and ignores padding", func(t *testing.T) {
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{new(" Kube-APIServer ")},
		}
		assert.True(t, csControlPlaneLogComponentEnabled(body, "kube-apiserver"))
	})
	t.Run("component not collected", func(t *testing.T) {
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{new("kube-apiserver"), new("ccm")},
		}
		assert.False(t, csControlPlaneLogComponentEnabled(body, "kube-scheduler"))
	})
	t.Run("audit is not a control plane log component", func(t *testing.T) {
		// The components ACK collects, per the control plane component log
		// documentation. API server auditing is a separate feature, so an
		// audit component never appears in this list.
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{
				new("kube-apiserver"), new("kube-controller-manager"),
				new("kube-scheduler"), new("ccm"), new("controlplane-events"),
			},
		}
		assert.False(t, csControlPlaneLogComponentEnabled(body, "audit"))
	})
	t.Run("empty component list", func(t *testing.T) {
		body := &csclient.CheckControlPlaneLogEnableResponseBody{Components: []*string{}}
		assert.False(t, csControlPlaneLogComponentEnabled(body, "kube-apiserver"))
	})
	t.Run("nil component pointer is skipped, not a panic", func(t *testing.T) {
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{nil, new("ccm")},
		}
		assert.True(t, csControlPlaneLogComponentEnabled(body, "ccm"))
		assert.False(t, csControlPlaneLogComponentEnabled(body, "kube-apiserver"))
	})
	t.Run("absent response", func(t *testing.T) {
		assert.False(t, csControlPlaneLogComponentEnabled(nil, "kube-apiserver"))
	})
}

// TestCsClusterAuditEnabled covers the API server audit setting. The second
// return value separates a measured false from a setting the cluster auditing
// configuration did not report, which must surface as null rather than as a
// cluster that provably has auditing off.
func TestCsClusterAuditEnabled(t *testing.T) {
	t.Run("auditing enabled", func(t *testing.T) {
		enabled, known := csClusterAuditEnabled(&csclient.GetClusterAuditProjectResponseBody{
			AuditEnabled: new(true),
		})
		assert.True(t, known)
		assert.True(t, enabled)
	})
	t.Run("auditing measured off", func(t *testing.T) {
		enabled, known := csClusterAuditEnabled(&csclient.GetClusterAuditProjectResponseBody{
			AuditEnabled: new(false),
		})
		assert.True(t, known)
		assert.False(t, enabled)
	})
	t.Run("setting absent from the response is unknown, not false", func(t *testing.T) {
		enabled, known := csClusterAuditEnabled(&csclient.GetClusterAuditProjectResponseBody{
			SlsProjectName: new("k8s-log-c123"),
		})
		assert.False(t, known, "an absent audit_enabled must read as null")
		assert.False(t, enabled)
	})
	t.Run("absent response is unknown, not false", func(t *testing.T) {
		enabled, known := csClusterAuditEnabled(nil)
		assert.False(t, known, "an absent response must read as null")
		assert.False(t, enabled)
	})
}

// TestCsClusterAuditProjectName covers the Log Service project holding the API
// server audit logs, which resolves to null when it is absent.
func TestCsClusterAuditProjectName(t *testing.T) {
	t.Run("project name present", func(t *testing.T) {
		assert.Equal(t, "k8s-log-c123", csClusterAuditProjectName(&csclient.GetClusterAuditProjectResponseBody{
			SlsProjectName: new("  k8s-log-c123 "),
		}))
	})
	t.Run("auditing off has no project", func(t *testing.T) {
		assert.Empty(t, csClusterAuditProjectName(&csclient.GetClusterAuditProjectResponseBody{
			AuditEnabled: new(false),
		}))
	})
	t.Run("absent response has no project", func(t *testing.T) {
		assert.Empty(t, csClusterAuditProjectName(nil))
	})
}

// TestCsMaintenanceExclusionID covers the cache key for a maintenance
// exclusion. Named exclusions key on the name, which is unique within the
// window; unnamed ones must still get distinct keys, or the second would be
// reported with the first one's values.
func TestCsMaintenanceExclusionID(t *testing.T) {
	assert.Equal(t, "c1/maintenanceExclusion/holiday", csMaintenanceExclusionID("c1", "holiday", 0))
	assert.Equal(t, csMaintenanceExclusionID("c1", "holiday", 0), csMaintenanceExclusionID("c1", "holiday", 3))
	assert.NotEqual(t, csMaintenanceExclusionID("c1", "", 0), csMaintenanceExclusionID("c1", "", 1))
	assert.NotEqual(t, csMaintenanceExclusionID("c1", "holiday", 0), csMaintenanceExclusionID("c2", "holiday", 0))
}

// TestCsMaintenanceWindowExclusionsDecode checks that the cluster list decodes
// the maintenance exclusions and that their RFC 3339 times, which carry a zone
// offset, parse rather than reading as null.
func TestCsMaintenanceWindowExclusionsDecode(t *testing.T) {
	// Synthetic: field names and example values from the SDK model docs; no
	// live cluster was available.
	body := `{"cluster_id":"c1","maintenance_window":{"enable":true,"exclusions":[{"name":"exclusion-holiday","description":"freeze","scope":"NoCVEPatch","start_time":"2026-11-01T00:00:00+08:00","end_time":"2026-11-15T00:00:00+08:00"}]}}`
	var c csclient.DescribeClustersV1ResponseBodyClusters
	require.NoError(t, json.Unmarshal([]byte(body), &c))
	require.NotNil(t, c.MaintenanceWindow)
	require.Len(t, c.MaintenanceWindow.Exclusions, 1)
	ex := c.MaintenanceWindow.Exclusions[0]
	assert.Equal(t, "exclusion-holiday", tea.StringValue(ex.Name))
	assert.Equal(t, "NoCVEPatch", tea.StringValue(ex.Scope))
	start := csParseTime(ex.StartTime)
	end := csParseTime(ex.EndTime)
	require.NotNil(t, start)
	require.NotNil(t, end)
	assert.Equal(t, 14*24*time.Hour, end.Sub(*start))
	assert.Equal(t, "2026-10-31T16:00:00Z", start.UTC().Format(time.RFC3339))
}
