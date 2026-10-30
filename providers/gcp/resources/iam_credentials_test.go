// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	iamrest "google.golang.org/api/iam/v1"
)

// TestServiceAccountKeyArgs pins the REST key mapping. The eight pre-existing
// fields are pinned too, not just the two new ones: this lister moved from the
// admin gRPC client to REST to reach disableReason and extendedStatus, and the
// migration is only safe if the shipped fields keep the same spellings.
func TestServiceAccountKeyArgs(t *testing.T) {
	t.Run("a user-managed key maps every field", func(t *testing.T) {
		args := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{
			Name:            "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/abc",
			KeyAlgorithm:    "KEY_ALG_RSA_2048",
			KeyOrigin:       "USER_PROVIDED",
			KeyType:         "USER_MANAGED",
			ValidAfterTime:  "2026-07-06T05:53:51Z",
			ValidBeforeTime: "2027-07-06T05:53:51Z",
		})

		assert.Equal(t, "projects/p/serviceAccounts/sa@p.iam.gserviceaccount.com/keys/abc", args["name"].Value)
		assert.Equal(t, "KEY_ALG_RSA_2048", args["keyAlgorithm"].Value)
		assert.Equal(t, "USER_PROVIDED", args["keyOrigin"].Value)
		assert.Equal(t, "USER_MANAGED", args["keyType"].Value)
		assert.Equal(t, true, args["userManaged"].Value, "USER_MANAGED must drive userManaged")

		after, ok := args["validAfterTime"].Value.(*time.Time)
		require.True(t, ok)
		require.NotNil(t, after)
		assert.Equal(t, "2026-07-06T05:53:51Z", after.UTC().Format(time.RFC3339))
	})

	t.Run("a system-managed key is not user-managed", func(t *testing.T) {
		args := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{KeyType: "SYSTEM_MANAGED"})
		assert.Equal(t, false, args["userManaged"].Value)
	})

	t.Run("an absent validity window stays null rather than the zero time", func(t *testing.T) {
		args := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{KeyType: "USER_MANAGED"})

		// A zero time here would report 1 January year 1 as a real timestamp and
		// make every key look long expired to an age-based rotation audit.
		assert.Nil(t, args["validAfterTime"].Value)
		assert.Nil(t, args["validBeforeTime"].Value)
	})

	t.Run("an enabled key reports no disable reason", func(t *testing.T) {
		args := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{KeyType: "USER_MANAGED"})
		assert.Equal(t, false, args["disabled"].Value)
		assert.Equal(t, "", args["disableReason"].Value)
		assert.Equal(t, map[string]any{}, args["extendedStatus"].Value)
	})

	t.Run("an exposed key is distinguishable from an operator-disabled one", func(t *testing.T) {
		exposed := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{
			KeyType:       "USER_MANAGED",
			Disabled:      true,
			DisableReason: "SERVICE_ACCOUNT_KEY_DISABLE_REASON_EXPOSED",
		})
		byOperator := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{
			KeyType:       "USER_MANAGED",
			Disabled:      true,
			DisableReason: "SERVICE_ACCOUNT_KEY_DISABLE_REASON_USER_INITIATED",
		})

		// Both are disabled==true; the reason is the only thing that separates
		// "Google found this key published" from routine key hygiene.
		assert.Equal(t, exposed["disabled"].Value, byOperator["disabled"].Value)
		assert.NotEqual(t, exposed["disableReason"].Value, byOperator["disableReason"].Value)
	})

	t.Run("extendedStatus survives a key being re-enabled", func(t *testing.T) {
		args := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{
			KeyType:  "USER_MANAGED",
			Disabled: false,
			ExtendedStatus: []*iamrest.ExtendedStatus{
				{Key: "SERVICE_ACCOUNT_KEY_EXTENDED_STATUS_KEY_EXPOSED", Value: "public GitHub repo"},
			},
		})

		// The key is enabled and carries no disableReason, so extendedStatus is
		// the only remaining evidence that it was ever found published.
		assert.Equal(t, false, args["disabled"].Value)
		assert.Equal(t, "", args["disableReason"].Value)
		assert.Equal(t, map[string]any{
			"SERVICE_ACCOUNT_KEY_EXTENDED_STATUS_KEY_EXPOSED": "public GitHub repo",
		}, args["extendedStatus"].Value)
	})

	t.Run("extendedStatus drops nil and empty keys and keeps the first duplicate", func(t *testing.T) {
		args := serviceAccountKeyArgs(&iamrest.ServiceAccountKey{
			ExtendedStatus: []*iamrest.ExtendedStatus{
				nil,
				{Key: "", Value: "orphan"},
				{Key: "SERVICE_ACCOUNT_KEY_EXTENDED_STATUS_KEY_COMPROMISE_DETECTED", Value: "first"},
				{Key: "SERVICE_ACCOUNT_KEY_EXTENDED_STATUS_KEY_COMPROMISE_DETECTED", Value: "second"},
			},
		})

		assert.Equal(t, map[string]any{
			"SERVICE_ACCOUNT_KEY_EXTENDED_STATUS_KEY_COMPROMISE_DETECTED": "first",
		}, args["extendedStatus"].Value)
	})
}

func TestWifPoolTrustConfig(t *testing.T) {
	anchors := func(n int) iamrest.TrustStore {
		ts := iamrest.TrustStore{}
		for range n {
			ts.TrustAnchors = append(ts.TrustAnchors, &iamrest.TrustAnchor{PemCertificate: "pem"})
		}
		return ts
	}

	t.Run("no inline trust config is an empty set, not an unread value", func(t *testing.T) {
		got := wifPoolTrustConfig(nil)
		assert.Equal(t, []any{}, got.domains)
		assert.Equal(t, int64(0), got.anchorCount)
	})

	t.Run("domains are sorted and anchors counted across bundles", func(t *testing.T) {
		got := wifPoolTrustConfig(&iamrest.InlineTrustConfig{
			AdditionalTrustBundles: map[string]iamrest.TrustStore{
				"zeta.example":  anchors(1),
				"alpha.example": anchors(2),
			},
		})

		assert.Equal(t, []any{"alpha.example", "zeta.example"}, got.domains,
			"an unordered field would compare unequal to itself between two reads")
		assert.Equal(t, int64(3), got.anchorCount)
	})

	t.Run("intermediate CAs are not counted as anchors", func(t *testing.T) {
		store := anchors(1)
		store.IntermediateCas = []*iamrest.IntermediateCA{{PemCertificate: "pem"}, {PemCertificate: "pem"}}
		got := wifPoolTrustConfig(&iamrest.InlineTrustConfig{
			AdditionalTrustBundles: map[string]iamrest.TrustStore{"a.example": store},
		})

		// Intermediates chain up to an anchor; counting them would overstate how
		// many independent authorities the pool trusts.
		assert.Equal(t, int64(1), got.anchorCount)
	})

	t.Run("an empty domain key is dropped", func(t *testing.T) {
		got := wifPoolTrustConfig(&iamrest.InlineTrustConfig{
			AdditionalTrustBundles: map[string]iamrest.TrustStore{"": anchors(1)},
		})
		assert.Equal(t, []any{}, got.domains)
	})
}

func TestWifPoolCertIssuance(t *testing.T) {
	t.Run("no issuance config names no authority and does not use the shared one", func(t *testing.T) {
		got := wifPoolCertIssuance(nil)
		assert.Equal(t, map[string]any{}, got.caPools)
		assert.Equal(t, false, got.usesDefaultSharedCa)
	})

	t.Run("regional CA pools are carried through", func(t *testing.T) {
		got := wifPoolCertIssuance(&iamrest.InlineCertificateIssuanceConfig{
			CaPools: map[string]string{"us-central1": "projects/p/locations/us-central1/caPools/pool"},
		})
		assert.Equal(t, map[string]any{"us-central1": "projects/p/locations/us-central1/caPools/pool"}, got.caPools)
		assert.Equal(t, false, got.usesDefaultSharedCa)
	})

	t.Run("the Google-managed shared authority is reported", func(t *testing.T) {
		got := wifPoolCertIssuance(&iamrest.InlineCertificateIssuanceConfig{UseDefaultSharedCa: true})
		assert.Equal(t, true, got.usesDefaultSharedCa)
		assert.Equal(t, map[string]any{}, got.caPools)
	})
}

func TestFlattenWorkforceProviderConfig(t *testing.T) {
	t.Run("the implicit flow is distinguishable from the authorization code flow", func(t *testing.T) {
		implicit := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{
			Oidc: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidc{
				IssuerUri: "https://idp.example",
				ClientId:  "client",
				WebSsoConfig: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidcWebSsoConfig{
					ResponseType:            "ID_TOKEN",
					AssertionClaimsBehavior: "ONLY_ID_TOKEN_CLAIMS",
				},
			},
		})

		assert.Equal(t, "oidc", implicit.providerType)
		assert.Equal(t, "ID_TOKEN", implicit.webSsoResponseType)
		assert.Equal(t, "ONLY_ID_TOKEN_CLAIMS", implicit.webSsoAssertionClaimsBehavior)
		assert.Equal(t, []any{}, implicit.webSsoAdditionalScopes)
	})

	t.Run("additional scopes are carried through", func(t *testing.T) {
		got := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{
			Oidc: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidc{
				WebSsoConfig: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidcWebSsoConfig{
					ResponseType:     "CODE",
					AdditionalScopes: []string{"groups", "offline_access"},
				},
			},
		})

		assert.Equal(t, "CODE", got.webSsoResponseType)
		assert.Equal(t, []any{"groups", "offline_access"}, got.webSsoAdditionalScopes)
	})

	t.Run("a client secret is reported by presence and never by value", func(t *testing.T) {
		withSecret := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{
			Oidc: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidc{
				ClientSecret: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidcClientSecret{
					Value: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidcClientSecretValue{
						Thumbprint: "abc123",
					},
				},
			},
		})
		assert.Equal(t, true, withSecret.oidcHasClientSecret)

		// A secret struct with no thumbprint is not a configured secret.
		empty := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{
			Oidc: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidc{
				ClientSecret: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidcClientSecret{
					Value: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidcClientSecretValue{},
				},
			},
		})
		assert.Equal(t, false, empty.oidcHasClientSecret)

		// And a nil Value must not panic.
		nilValue := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{
			Oidc: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidc{
				ClientSecret: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidcClientSecret{},
			},
		})
		assert.Equal(t, false, nilValue.oidcHasClientSecret)
	})

	t.Run("an OIDC provider with no web SSO config reports no response type", func(t *testing.T) {
		got := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{
			Oidc: &iamrest.GoogleIamAdminV1WorkforcePoolProviderOidc{IssuerUri: "https://idp.example"},
		})
		assert.Equal(t, "oidc", got.providerType)
		assert.Equal(t, "", got.webSsoResponseType)
	})

	t.Run("a SAML provider carries no OIDC web SSO fields", func(t *testing.T) {
		got := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{
			Saml: &iamrest.GoogleIamAdminV1WorkforcePoolProviderSaml{IdpMetadataXml: "<xml/>"},
		})

		assert.Equal(t, "saml", got.providerType)
		assert.Equal(t, "<xml/>", got.samlMetadata)
		assert.Equal(t, "", got.webSsoResponseType)
		assert.Equal(t, false, got.oidcHasClientSecret)
		assert.Equal(t, []any{}, got.webSsoAdditionalScopes)
	})

	t.Run("a provider with neither protocol set has no type", func(t *testing.T) {
		got := flattenWorkforceProviderConfig(&iamrest.WorkforcePoolProvider{})
		assert.Equal(t, "", got.providerType)
	})
}
