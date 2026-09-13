// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	csclient "github.com/alibabacloud-go/cs-20151215/v8/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
)

// TestParseCsMasterURL covers the ACK MasterUrl parser, which drives the
// apiServerInternetExposed security signal. A parsing bug would misreport
// whether a cluster's API server is reachable from the internet.
func TestParseCsMasterURL(t *testing.T) {
	t.Run("public and intranet endpoints present", func(t *testing.T) {
		public, intranet := parseCsMasterURL(strp(`{"api_server_endpoint":"https://1.2.3.4:6443","intranet_api_server_endpoint":"https://10.0.0.1:6443"}`))
		assert.Equal(t, "https://1.2.3.4:6443", public)
		assert.Equal(t, "https://10.0.0.1:6443", intranet)
		assert.True(t, public != "", "public endpoint present => internet exposed")
	})
	t.Run("private-only cluster has empty public endpoint", func(t *testing.T) {
		public, intranet := parseCsMasterURL(strp(`{"api_server_endpoint":"","intranet_api_server_endpoint":"https://10.0.0.1:6443"}`))
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
		public, intranet := parseCsMasterURL(strp(""))
		assert.Equal(t, "", public)
		assert.Equal(t, "", intranet)
	})
	t.Run("malformed JSON yields empties, not a panic", func(t *testing.T) {
		public, intranet := parseCsMasterURL(strp("not-json"))
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
			Components: []*string{strp("kube-apiserver"), strp("kube-scheduler")},
		}
		assert.True(t, csControlPlaneLogComponentEnabled(body, "kube-apiserver"))
	})
	t.Run("match is case insensitive and ignores padding", func(t *testing.T) {
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{strp(" Kube-APIServer ")},
		}
		assert.True(t, csControlPlaneLogComponentEnabled(body, "kube-apiserver"))
	})
	t.Run("component not collected", func(t *testing.T) {
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{strp("kube-apiserver"), strp("ccm")},
		}
		assert.False(t, csControlPlaneLogComponentEnabled(body, "kube-scheduler"))
	})
	t.Run("audit is not a control plane log component", func(t *testing.T) {
		// The components ACK collects, per the control plane component log
		// documentation. API server auditing is a separate feature, so an
		// audit component never appears in this list.
		body := &csclient.CheckControlPlaneLogEnableResponseBody{
			Components: []*string{
				strp("kube-apiserver"), strp("kube-controller-manager"),
				strp("kube-scheduler"), strp("ccm"), strp("controlplane-events"),
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
			Components: []*string{nil, strp("ccm")},
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
			AuditEnabled: tea.Bool(true),
		})
		assert.True(t, known)
		assert.True(t, enabled)
	})
	t.Run("auditing measured off", func(t *testing.T) {
		enabled, known := csClusterAuditEnabled(&csclient.GetClusterAuditProjectResponseBody{
			AuditEnabled: tea.Bool(false),
		})
		assert.True(t, known)
		assert.False(t, enabled)
	})
	t.Run("setting absent from the response is unknown, not false", func(t *testing.T) {
		enabled, known := csClusterAuditEnabled(&csclient.GetClusterAuditProjectResponseBody{
			SlsProjectName: strp("k8s-log-c123"),
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
			SlsProjectName: strp("  k8s-log-c123 "),
		}))
	})
	t.Run("auditing off has no project", func(t *testing.T) {
		assert.Empty(t, csClusterAuditProjectName(&csclient.GetClusterAuditProjectResponseBody{
			AuditEnabled: tea.Bool(false),
		}))
	})
	t.Run("absent response has no project", func(t *testing.T) {
		assert.Empty(t, csClusterAuditProjectName(nil))
	})
}
