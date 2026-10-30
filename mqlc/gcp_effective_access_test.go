// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// The effective-access resources are parameterized: the caller supplies the
// question under test as arguments. mqlc resolves named arguments against a
// resource's FIELDS and never against its init arguments, so a selector declared
// only as an init argument compiles in the positional form and fails in the
// named form that reads naturally and that the doc comments show. These tests
// pin both forms for every selector, so a future edit that drops one of the
// field declarations fails here rather than in a customer's query.
func TestGcpEffectiveAccessQueriesCompile(t *testing.T) {
	gcpSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "gcp"})

	queries := []string{
		// whoCan: both selectors named
		`gcp.project.assetService.whoCan(permission: "storage.objects.get", resource: "//storage.googleapis.com/projects/_/buckets/b").principals`,
		// whoCan: the derived principal sets and the completeness flag
		`gcp.project.assetService.whoCan(permission: "storage.objects.get", resource: "//storage.googleapis.com/projects/_/buckets/b") { principals inheritedPrincipals conditionalPrincipals roles fullyExplored }`,
		// whoCan: positional form must keep working too
		`gcp.project.assetService.whoCan("storage.objects.get", "//storage.googleapis.com/projects/_/buckets/b").principals`,
		// effectiveOrgPolicy: named single selector
		`gcp.project.effectiveOrgPolicy(constraint: "constraints/compute.requireOsLogin").enforced`,
		`gcp.project.effectiveOrgPolicy(constraint: "constraints/compute.vmExternalIpAccess") { allowAll denyAll allowedValues deniedValues spec }`,
		// effectiveOrgPolicy: positional form
		`gcp.project.effectiveOrgPolicy("constraints/compute.requireOsLogin").enforced`,
		// insights collection and its security-relevant fields
		`gcp.project.insights.where(insightType == "google.iam.policy.Insight") { severity content targetResources }`,
		// principal access boundary policies and their bindings
		`gcp.organization.principalAccessBoundaryPolicies { name enforcementVersion rules }`,
		`gcp.organization.policyBindings { name policyKind policyName target condition }`,
		// typed edge: a binding leads to the boundary policy it attaches
		`gcp.organization.policyBindings { policy { name enforcementVersion rules } }`,
		// the inheritance-aware impersonation accessor
		`gcp.project.iam.serviceAccounts { email canBeImpersonated impersonators }`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(gcpSchema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}

// The credential-visibility resources surface credentials and elevation paths
// that no other collection in the provider reaches, so their query shapes are
// pinned here too.
func TestGcpCredentialVisibilityQueriesCompile(t *testing.T) {
	gcpSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "gcp"})

	queries := []string{
		// HMAC keys, including the accessor back to the account they authenticate as
		`gcp.project.storage.hmacKeys { accessId state timeCreated serviceAccountEmail }`,
		`gcp.project.storage.hmacKeys.where(state == "ACTIVE") { serviceAccount { email } }`,
		// Log Router settings at each level of the hierarchy
		`gcp.project.logging.settings { disableDefaultSink storageLocation kmsKeyName }`,
		`gcp.organization.logging.settings.disableDefaultSink`,
		`gcp.folders.where(id == "123").list { logging { settings { disableDefaultSink } } }`,
		// Privileged Access Manager entitlements and grants
		`gcp.project.privilegedAccessManager.entitlements { name state grantedRoles requiresApproval eligiblePrincipals }`,
		`gcp.project.privilegedAccessManager.entitlements.where(requiresApproval == false) { grantedRoles eligiblePrincipals }`,
		`gcp.project.privilegedAccessManager.grants { requester state requestedDuration externallyModified auditTrail }`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(gcpSchema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}

// The network-boundary resources describe connectivity that a per-project
// network review cannot reach: rules enforced from above the project, networks
// owned by another project, and fabrics that join networks without a peering.
func TestGcpNetworkBoundaryQueriesCompile(t *testing.T) {
	gcpSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "gcp"})

	queries := []string{
		// Shared VPC, both directions plus the typed edges
		`gcp.project.compute { isSharedVpcHost isSharedVpcServiceProject }`,
		`gcp.project.compute.sharedVpcHost { id }`,
		`gcp.project.compute.sharedVpcServiceProjects { id }`,
		// hierarchical firewall policies at organization and folder scope
		`gcp.organization.firewallPolicies { shortName parent ruleTupleCount associations }`,
		`gcp.organization.firewallPolicies.where(ruleTupleCount > 0) { rules { action direction srcIpRanges } }`,
		`gcp.folders.where(id == "123").list { firewallPolicies { shortName rules { action } } }`,
		// Network Connectivity Center hubs and spokes
		`gcp.project.networkConnectivity.hubs { name state policyMode routingVpcs spokeSummary }`,
		`gcp.project.networkConnectivity.spokes { name spokeType state hubName linkedVpcNetwork }`,
		// typed edges: spoke to its hub, hub to the networks it routes through
		`gcp.project.networkConnectivity.spokes { hub { name policyMode } }`,
		`gcp.project.networkConnectivity.hubs { routingVpcNetworks { name autoCreateSubnetworks } }`,
		// connectivity tests and their verdicts
		`gcp.project.networkManagement.connectivityTests { name result verifyTime protocol bypassFirewallChecks }`,
		`gcp.project.networkManagement.connectivityTests.where(result == "REACHABLE") { source destination reachabilityDetails }`,
	}

	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(gcpSchema, features))
			require.NoError(t, err, "query %q should compile", query)
		})
	}
}

// A named argument that is not a declared field must be rejected rather than
// silently ignored, which is what makes the field declarations load-bearing.
func TestGcpEffectiveAccessRejectsUnknownArgument(t *testing.T) {
	gcpSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "gcp"})

	_, err := mqlc.Compile(
		`gcp.project.assetService.whoCan(permissions: "storage.objects.get").principals`,
		nil, mqlc.NewConfig(gcpSchema, features))
	require.Error(t, err, "an undeclared named argument should not compile")
}
