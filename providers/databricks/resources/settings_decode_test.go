// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/databricks/databricks-sdk-go/service/settings"
)

// The settings endpoints each wrap their value in a differently named envelope,
// and this provider reads the value out of that envelope by field. If an SDK
// bump renames one, the value decodes to its zero and an exfiltration toggle
// reads false on a workspace that has it on. These tests decode the documented
// response shape and assert the field this provider actually reads.
//
// A caveat worth knowing: Go's JSON decoder matches field names
// case-insensitively, so a tag that changed only in case would still pass here.
// What these catch is a renamed or restructured envelope, which is the change
// an SDK bump actually makes.

func TestEnableExportNotebookDecode(t *testing.T) {
	t.Run("an enabled setting decodes to true", func(t *testing.T) {
		var v settings.EnableExportNotebook
		mustDecode(t, `{"setting_name":"default","boolean_val":{"value":true}}`, &v)

		got := boolMessageValue(v.BooleanVal)
		if got == nil || !*got {
			t.Fatalf("notebook export = %v, want true", got)
		}
	})

	t.Run("a disabled setting decodes to a real false", func(t *testing.T) {
		var v settings.EnableExportNotebook
		mustDecode(t, `{"setting_name":"default","boolean_val":{"value":false}}`, &v)

		got := boolMessageValue(v.BooleanVal)
		if got == nil {
			t.Fatal("notebook export = null, want a real false")
		}
		if *got {
			t.Fatalf("notebook export = %v, want false", *got)
		}
	})

	// A response with no boolean_val at all must stay null. This is the case
	// that separates "the workspace turned exporting off" from "the setting
	// was never read", and only the first may satisfy an assertion.
	t.Run("an absent value stays null", func(t *testing.T) {
		var v settings.EnableExportNotebook
		mustDecode(t, `{"setting_name":"default"}`, &v)

		if got := boolMessageValue(v.BooleanVal); got != nil {
			t.Fatalf("notebook export = %v, want null", *got)
		}
	})
}

func TestEnableResultsDownloadingDecode(t *testing.T) {
	var v settings.EnableResultsDownloading
	mustDecode(t, `{"setting_name":"default","boolean_val":{"value":true}}`, &v)

	got := boolMessageValue(v.BooleanVal)
	if got == nil || !*got {
		t.Fatalf("results downloading = %v, want true", got)
	}
}

func TestEnableNotebookTableClipboardDecode(t *testing.T) {
	var v settings.EnableNotebookTableClipboard
	mustDecode(t, `{"setting_name":"default","boolean_val":{"value":true}}`, &v)

	got := boolMessageValue(v.BooleanVal)
	if got == nil || !*got {
		t.Fatalf("table clipboard = %v, want true", got)
	}
}

func TestSqlResultsDownloadDecode(t *testing.T) {
	var v settings.SqlResultsDownload
	mustDecode(t, `{"setting_name":"default","boolean_val":{"value":false},"etag":"abc"}`, &v)

	got := boolMessageValue(&v.BooleanVal)
	if got == nil {
		t.Fatal("sql results download = null, want a real false")
	}
	if *got {
		t.Fatalf("sql results download = %v, want false", *got)
	}
}

func TestDashboardEmailSubscriptionsDecode(t *testing.T) {
	var v settings.DashboardEmailSubscriptions
	mustDecode(t, `{"setting_name":"default","boolean_val":{"value":true},"etag":"abc"}`, &v)

	got := boolMessageValue(&v.BooleanVal)
	if got == nil || !*got {
		t.Fatalf("dashboard email subscriptions = %v, want true", got)
	}
}

func TestAibiDashboardEmbeddingDecode(t *testing.T) {
	t.Run("access policy", func(t *testing.T) {
		var v settings.AibiDashboardEmbeddingAccessPolicySetting
		mustDecode(t, `{"aibi_dashboard_embedding_access_policy":{"access_policy_type":"ALLOW_ALL_DOMAINS"},"etag":"abc"}`, &v)

		if got := string(v.AibiDashboardEmbeddingAccessPolicy.AccessPolicyType); got != "ALLOW_ALL_DOMAINS" {
			t.Fatalf("access policy = %q, want ALLOW_ALL_DOMAINS", got)
		}
	})

	t.Run("approved domains", func(t *testing.T) {
		var v settings.AibiDashboardEmbeddingApprovedDomainsSetting
		mustDecode(t, `{"aibi_dashboard_embedding_approved_domains":{"approved_domains":["example.com","reports.example.com"]},"etag":"abc"}`, &v)

		got := v.AibiDashboardEmbeddingApprovedDomains.ApprovedDomains
		if len(got) != 2 || got[0] != "example.com" || got[1] != "reports.example.com" {
			t.Fatalf("approved domains = %v", got)
		}
	})

	t.Run("no approved domains is an empty list, not a nil one", func(t *testing.T) {
		var v settings.AibiDashboardEmbeddingApprovedDomainsSetting
		mustDecode(t, `{"aibi_dashboard_embedding_approved_domains":{},"etag":"abc"}`, &v)

		// strSlice allocates, so a setting that was read but holds no domains
		// reports an empty list rather than null.
		if got := strSlice(v.AibiDashboardEmbeddingApprovedDomains.ApprovedDomains); got == nil || len(got) != 0 {
			t.Fatalf("approved domains = %v, want an empty non-nil list", got)
		}
	})
}

func TestAccountSettingsDecode(t *testing.T) {
	t.Run("account console ip access list enforcement", func(t *testing.T) {
		var v settings.AccountIpAccessEnable
		mustDecode(t, `{"acct_ip_acl_enable":{"value":true},"etag":"abc","setting_name":"default"}`, &v)

		got := boolMessageValue(&v.AcctIpAclEnable)
		if got == nil || !*got {
			t.Fatalf("account ip acl enable = %v, want true", got)
		}
	})

	t.Run("compliance security profile enforcement and standards", func(t *testing.T) {
		var v settings.CspEnablementAccountSetting
		mustDecode(t, `{"csp_enablement_account":{"is_enforced":true,"compliance_standards":["HIPAA","PCI_DSS"]},"etag":"abc"}`, &v)

		if !v.CspEnablementAccount.IsEnforced {
			t.Fatal("is_enforced = false, want true")
		}
		if len(v.CspEnablementAccount.ComplianceStandards) != 2 {
			t.Fatalf("compliance standards = %v", v.CspEnablementAccount.ComplianceStandards)
		}
	})

	t.Run("enhanced security monitoring enforcement", func(t *testing.T) {
		var v settings.EsmEnablementAccountSetting
		mustDecode(t, `{"esm_enablement_account":{"is_enforced":true},"etag":"abc"}`, &v)

		if !v.EsmEnablementAccount.IsEnforced {
			t.Fatal("is_enforced = false, want true")
		}
	})

	t.Run("legacy feature disablement", func(t *testing.T) {
		var v settings.DisableLegacyFeatures
		mustDecode(t, `{"disable_legacy_features":{"value":true},"etag":"abc"}`, &v)

		got := boolMessageValue(&v.DisableLegacyFeatures)
		if got == nil || !*got {
			t.Fatalf("disable legacy features = %v, want true", got)
		}
	})

	t.Run("personal compute access", func(t *testing.T) {
		var v settings.PersonalComputeSetting
		mustDecode(t, `{"personal_compute":{"value":"DELEGATE"},"etag":"abc"}`, &v)

		if got := string(v.PersonalCompute.Value); got != "DELEGATE" {
			t.Fatalf("personal compute = %q, want DELEGATE", got)
		}
	})
}

func mustDecode(t *testing.T, payload string, into any) {
	t.Helper()
	if err := json.Unmarshal([]byte(payload), into); err != nil {
		t.Fatalf("decoding %s: %v", payload, err)
	}
}
