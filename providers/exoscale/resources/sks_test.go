// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/stretchr/testify/assert"
)

func TestSksClusterArgsUnrestrictedAPIServerIsNull(t *testing.T) {
	args := sksClusterArgs("ch-gva-2", v3.SKSCluster{ID: "c1"})
	// An absent allow-list is null, not an empty list that reads as
	// "nothing allowed".
	assert.Nil(t, args["allowedNetworks"].Value)
	assert.Equal(t, false, args["auditEnabled"].Value)
	assert.Equal(t, "", args["oidcIssuerUrl"].Value)
}

func TestSksClusterArgsReadsSecuritySettings(t *testing.T) {
	enabled := true
	nets := v3.SKSClusterAllowedNetworks{"10.0.0.0/8"}
	args := sksClusterArgs("ch-gva-2", v3.SKSCluster{
		ID:              "c1",
		AllowedNetworks: &nets,
		Audit:           &v3.SKSAudit{Enabled: &enabled, Endpoint: "https://audit.example.com"},
		Oidc:            &v3.SKSOidc{IssuerURL: "https://idp.example.com", ClientID: "k8s", RequiredClaim: map[string]string{"aud": "k8s"}},
		AutoUpgrade:     &enabled,
	})
	assert.Equal(t, []any{"10.0.0.0/8"}, args["allowedNetworks"].Value)
	assert.Equal(t, true, args["auditEnabled"].Value)
	assert.Equal(t, "https://audit.example.com", args["auditEndpoint"].Value)
	assert.Equal(t, "https://idp.example.com", args["oidcIssuerUrl"].Value)
	assert.Equal(t, map[string]any{"aud": "k8s"}, args["oidcRequiredClaim"].Value)
	assert.Equal(t, true, args["autoUpgrade"].Value)
	// An unset optional flag is null, not false.
	assert.Nil(t, args["enableKubeProxy"].Value)
}

func TestSksClusterArgsAuditBlockWithoutFlagIsDisabled(t *testing.T) {
	args := sksClusterArgs("ch-gva-2", v3.SKSCluster{ID: "c1", Audit: &v3.SKSAudit{}})
	assert.Equal(t, false, args["auditEnabled"].Value)
}
