// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/filestorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----- export client options -----
//
// This is the decode the whole feature rests on: an export's client options
// are the NFS access control list, and every field in them has a wrong reading
// that looks like a real answer rather than an error.

func TestOciExportOptionFields(t *testing.T) {
	t.Run("a fully specified option is carried through", func(t *testing.T) {
		fields := ociExportOptionFields("ocid1.export.oc1..aaa", 0, filestorage.ClientOptions{
			Source:                      new("10.0.0.0/16"),
			Access:                      filestorage.ClientOptionsAccessOnly,
			IdentitySquash:              filestorage.ClientOptionsIdentitySquashRoot,
			RequirePrivilegedSourcePort: new(true),
			AnonymousUid:                common.Int64(65534),
			AnonymousGid:                common.Int64(65534),
			IsAnonymousAccessAllowed:    new(false),
			AllowedAuth: []filestorage.ClientOptionsAllowedAuthEnum{
				filestorage.ClientOptionsAllowedAuthKrb5p,
			},
		})

		assert.Equal(t, "10.0.0.0/16", fields["source"].Value)
		assert.Equal(t, "READ_ONLY", fields["access"].Value)
		assert.Equal(t, "ROOT", fields["identitySquash"].Value)
		assert.Equal(t, true, fields["requirePrivilegedSourcePort"].Value)
		assert.Equal(t, int64(65534), fields["anonymousUid"].Value)
		assert.Equal(t, int64(65534), fields["anonymousGid"].Value)
		assert.Equal(t, false, fields["isAnonymousAccessAllowed"].Value)
		assert.Equal(t, []any{"KRB5P"}, fields["allowedAuth"].Value)
	})

	t.Run("the open-share shape reads as open", func(t *testing.T) {
		// The finding this feature exists to make expressible: any source,
		// read-write, no squashing. If any of these three decoded wrongly the
		// share would look constrained.
		fields := ociExportOptionFields("ocid1.export.oc1..aaa", 0, filestorage.ClientOptions{
			Source:         new("0.0.0.0/0"),
			Access:         filestorage.ClientOptionsAccessWrite,
			IdentitySquash: filestorage.ClientOptionsIdentitySquashNone,
		})

		assert.Equal(t, "0.0.0.0/0", fields["source"].Value)
		assert.Equal(t, "READ_WRITE", fields["access"].Value)
		assert.Equal(t, "NONE", fields["identitySquash"].Value)
	})

	t.Run("absent booleans stay null rather than becoming false", func(t *testing.T) {
		// requirePrivilegedSourcePort read as false would report an export as
		// accepting unprivileged source ports on the strength of the API not
		// having said anything.
		fields := ociExportOptionFields("ocid1.export.oc1..aaa", 0, filestorage.ClientOptions{
			Source: new("10.0.0.1"),
		})

		assert.Nil(t, fields["requirePrivilegedSourcePort"].Value)
		assert.Nil(t, fields["isAnonymousAccessAllowed"].Value)
	})

	t.Run("an absent anonymous uid stays null rather than becoming root", func(t *testing.T) {
		// 0 is uid root. Reporting an unset anonymousUid as 0 would say
		// squashed identities are remapped to root, which inverts the control.
		fields := ociExportOptionFields("ocid1.export.oc1..aaa", 0, filestorage.ClientOptions{
			Source:         new("10.0.0.1"),
			IdentitySquash: filestorage.ClientOptionsIdentitySquashAll,
		})

		assert.Nil(t, fields["anonymousUid"].Value)
		assert.Nil(t, fields["anonymousGid"].Value)
	})

	t.Run("no allowed auth is an empty list, not null", func(t *testing.T) {
		// An empty list is the honest reading: the API omits allowedAuth when
		// the export does not constrain the flavor, and a null would read as
		// "not known" instead.
		fields := ociExportOptionFields("ocid1.export.oc1..aaa", 0, filestorage.ClientOptions{
			Source: new("10.0.0.1"),
		})

		assert.Equal(t, []any{}, fields["allowedAuth"].Value)
	})

	t.Run("options are keyed by position", func(t *testing.T) {
		// Two rules may name the same source, so the index is the only stable
		// identity. Keying on source would collapse them into one and silently
		// drop a rule from the export.
		first := ociExportOptionFields("ocid1.export.oc1..aaa", 0, filestorage.ClientOptions{
			Source: new("10.0.0.1"),
		})
		second := ociExportOptionFields("ocid1.export.oc1..aaa", 1, filestorage.ClientOptions{
			Source: new("10.0.0.1"),
		})

		assert.Equal(t, "ocid1.export.oc1..aaa/option/0", first["__id"].Value)
		assert.Equal(t, "ocid1.export.oc1..aaa/option/1", second["__id"].Value)
		assert.NotEqual(t, first["__id"].Value, second["__id"].Value)
	})
}

func TestOciExportOptionAllowedAuthValues(t *testing.T) {
	// The flavor names are passed through as the SDK spells them, so a query
	// comparing against "KRB5P" has to match what the API returns. Driven from
	// the SDK's own enum so a renamed or added flavor shows up here.
	values := filestorage.GetClientOptionsAllowedAuthEnumValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; this check would pass vacuously")

	all := make([]filestorage.ClientOptionsAllowedAuthEnum, 0, len(values))
	all = append(all, values...)

	fields := ociExportOptionFields("ocid1.export.oc1..aaa", 0, filestorage.ClientOptions{
		Source:      new("10.0.0.1"),
		AllowedAuth: all,
	})

	got, ok := fields["allowedAuth"].Value.([]any)
	require.True(t, ok)
	require.Len(t, got, len(values))
	for i, value := range values {
		assert.Equal(t, string(value), got[i])
	}
}

// ----- outbound connectors -----

func TestOciOutboundConnectorFields(t *testing.T) {
	t.Run("an LDAP bind account is flattened", func(t *testing.T) {
		fields, err := ociOutboundConnectorFields(filestorage.LdapBindAccountSummary{
			Id:                    new("ocid1.outboundconnector.oc1..aaa"),
			DisplayName:           new("corp-ldap"),
			CompartmentId:         new("ocid1.compartment.oc1..bbb"),
			AvailabilityDomain:    new("Uocm:PHX-AD-1"),
			LifecycleState:        filestorage.OutboundConnectorSummaryLifecycleStateActive,
			BindDistinguishedName: new("cn=fss,ou=service,dc=corp,dc=example"),
			Endpoints: []filestorage.Endpoint{
				{Hostname: new("ldap1.corp.example"), Port: common.Int64(636)},
				{Hostname: new("ldap2.corp.example"), Port: common.Int64(636)},
			},
		})
		require.NoError(t, err)

		assert.Equal(t, "ocid1.outboundconnector.oc1..aaa", fields["id"].Value)
		assert.Equal(t, "corp-ldap", fields["name"].Value)
		assert.Equal(t, "ACTIVE", fields["state"].Value)
		assert.Equal(t, "LDAPBIND", fields["connectorType"].Value)
		assert.Equal(t, "cn=fss,ou=service,dc=corp,dc=example", fields["bindDistinguishedName"].Value)

		endpoints, ok := fields["endpoints"].Value.([]any)
		require.True(t, ok)
		require.Len(t, endpoints, 2)
		first, ok := endpoints[0].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "ldap1.corp.example", first["hostname"])
	})

	t.Run("an unhandled connector type is an error, not a skip", func(t *testing.T) {
		// Dropping one would leave a mount target's ldapOutboundConnectors
		// resolving to nothing, which reads as identity mapping being
		// unconfigured rather than unreadable.
		_, err := ociOutboundConnectorFields(nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unhandled outbound connector type")
	})
}

func TestOciOutboundConnectorUnionMembers(t *testing.T) {
	// ociOutboundConnectorFields asserts LdapBindAccountSummary and errors on
	// anything else, and fetchLdapAccount does the same for the detail type. A
	// second connector kind needs both changed; this fails the build when the
	// SDK grows one.
	handled := map[string]bool{"LDAPBIND": true}

	values := filestorage.GetOutboundConnectorConnectorTypeEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the drift check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, handled[value],
			"filestorage.OutboundConnectorConnectorType %q is not handled by ociOutboundConnectorFields "+
				"or fetchLdapAccount; add it to both", value)
	}
}

// ----- quota rules -----

func TestOciQuotaRuleID(t *testing.T) {
	t.Run("the rule's own OCID is used when it has one", func(t *testing.T) {
		got := ociQuotaRuleID("ocid1.filesystem.oc1..aaa", filestorage.QuotaRuleSummary{
			Id:            new("ocid1.quotarule.oc1..ccc"),
			PrincipalType: filestorage.QuotaRuleSummaryPrincipalTypeIndividualUser,
			PrincipalId:   new(1001),
		})
		assert.Equal(t, "ocid1.quotarule.oc1..ccc", got)
	})

	t.Run("a rule with no OCID is keyed by file system, scope and principal", func(t *testing.T) {
		got := ociQuotaRuleID("ocid1.filesystem.oc1..aaa", filestorage.QuotaRuleSummary{
			PrincipalType: filestorage.QuotaRuleSummaryPrincipalTypeIndividualUser,
			PrincipalId:   new(1001),
		})
		assert.Equal(t, "ocid1.filesystem.oc1..aaa/quotaRule/INDIVIDUAL_USER/1001", got)
	})

	t.Run("rules on different file systems do not collide", func(t *testing.T) {
		// Both file-system-level rules come back without an OCID and without a
		// principal, so without the file system in the key the runtime cache
		// would hand the second file system the first one's rule.
		first := ociQuotaRuleID("ocid1.filesystem.oc1..aaa", filestorage.QuotaRuleSummary{
			PrincipalType: filestorage.QuotaRuleSummaryPrincipalTypeFileSystemLevel,
		})
		second := ociQuotaRuleID("ocid1.filesystem.oc1..bbb", filestorage.QuotaRuleSummary{
			PrincipalType: filestorage.QuotaRuleSummaryPrincipalTypeFileSystemLevel,
		})
		assert.NotEqual(t, first, second)
	})

	t.Run("an absent principal id does not panic", func(t *testing.T) {
		assert.NotPanics(t, func() {
			ociQuotaRuleID("ocid1.filesystem.oc1..aaa", filestorage.QuotaRuleSummary{
				PrincipalType: filestorage.QuotaRuleSummaryPrincipalTypeFileSystemLevel,
			})
		})
	})
}

func TestOciQuotaRulePrincipalTypeCoverage(t *testing.T) {
	// ListQuotaRules takes exactly one principal type per call and offers no
	// "any" value, so a scope missing from ociQuotaRulePrincipalTypes is a set
	// of quota rules that is never asked for and never reported. Driven from
	// the SDK enum so a scope added upstream fails the build.
	asked := map[string]bool{}
	for _, principalType := range ociQuotaRulePrincipalTypes {
		asked[string(principalType)] = true
	}

	values := filestorage.GetListQuotaRulesPrincipalTypeEnumStringValues()
	require.NotEmpty(t, values, "the SDK enum helper returned nothing; the coverage check would pass vacuously")

	for _, value := range values {
		assert.Truef(t, asked[value],
			"quota rules written at scope %q are never listed; add it to ociQuotaRulePrincipalTypes", value)
	}
	assert.Len(t, ociQuotaRulePrincipalTypes, len(values),
		"ociQuotaRulePrincipalTypes asks for a scope the SDK does not define")
}
