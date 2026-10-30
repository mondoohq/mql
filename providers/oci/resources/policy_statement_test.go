// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOciPolicyStatement(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want ociPolicyStatement
	}{
		{
			name: "tenancy-wide administrator grant",
			raw:  "Allow group Administrators to manage all-resources in tenancy",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"Administrators"},
				Verb:         "manage",
				ResourceType: "all-resources",
				ScopeType:    "tenancy",
			},
		},
		{
			name: "compartment scope by name",
			raw:  "Allow group NetworkAdmins to manage virtual-network-family in compartment Production",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"NetworkAdmins"},
				Verb:         "manage",
				ResourceType: "virtual-network-family",
				ScopeType:    "compartment",
				ScopeName:    "Production",
			},
		},
		{
			name: "nested compartment path is one token",
			raw:  "Allow group Devs to use instance-family in compartment Corp:Engineering:Dev",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"Devs"},
				Verb:         "use",
				ResourceType: "instance-family",
				ScopeType:    "compartment",
				ScopeName:    "Corp:Engineering:Dev",
			},
		},
		{
			name: "compartment id form keeps the ocid",
			raw:  "Allow group Auditors to read all-resources in compartment id ocid1.compartment.oc1..aaaaexample",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"Auditors"},
				Verb:         "read",
				ResourceType: "all-resources",
				ScopeType:    "compartment",
				ScopeName:    "ocid1.compartment.oc1..aaaaexample",
			},
		},
		{
			name: "group id form reports ocids as subject names",
			raw:  "Allow group id ocid1.group.oc1..aaaaone,ocid1.group.oc1..aaaatwo to inspect buckets in tenancy",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"ocid1.group.oc1..aaaaone", "ocid1.group.oc1..aaaatwo"},
				Verb:         "inspect",
				ResourceType: "buckets",
				ScopeType:    "tenancy",
			},
		},
		{
			name: "comma separated groups with spaces",
			raw:  "Allow group Alpha, Beta , Gamma to read objects in compartment Data",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"Alpha", "Beta", "Gamma"},
				Verb:         "read",
				ResourceType: "objects",
				ScopeType:    "compartment",
				ScopeName:    "Data",
			},
		},
		{
			name: "any-user names no principal",
			raw:  "Allow any-user to read objects in compartment Public",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "any-user",
				Verb:         "read",
				ResourceType: "objects",
				ScopeType:    "compartment",
				ScopeName:    "Public",
			},
		},
		{
			name: "condition is separated from the body",
			raw:  "Allow any-user to manage objects in compartment Data where request.principal.type = 'instance'",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "any-user",
				Verb:         "manage",
				ResourceType: "objects",
				ScopeType:    "compartment",
				ScopeName:    "Data",
				Condition:    "request.principal.type = 'instance'",
			},
		},
		{
			name: "grouped condition is kept whole",
			raw:  "Allow group Ops to manage buckets in tenancy where all {request.user.id = 'ocid1.user.oc1..aaaa', target.bucket.name = 'logs'}",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"Ops"},
				Verb:         "manage",
				ResourceType: "buckets",
				ScopeType:    "tenancy",
				Condition:    "all {request.user.id = 'ocid1.user.oc1..aaaa', target.bucket.name = 'logs'}",
			},
		},
		{
			name: "dynamic group subject",
			raw:  "Allow dynamic-group InstancePrincipals to use object-family in compartment Prod",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "dynamic-group",
				SubjectNames: []string{"InstancePrincipals"},
				Verb:         "use",
				ResourceType: "object-family",
				ScopeType:    "compartment",
				ScopeName:    "Prod",
			},
		},
		{
			name: "service subject",
			raw:  "Allow service objectstorage-us-phoenix-1 to manage object-family in compartment Backups",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "service",
				SubjectNames: []string{"objectstorage-us-phoenix-1"},
				Verb:         "manage",
				ResourceType: "object-family",
				ScopeType:    "compartment",
				ScopeName:    "Backups",
			},
		},
		{
			name: "endorse crosses into any tenancy",
			raw:  "Endorse group Replicators to manage object-family in any-tenancy",
			want: ociPolicyStatement{
				Effect:       "endorse",
				SubjectType:  "group",
				SubjectNames: []string{"Replicators"},
				Verb:         "manage",
				ResourceType: "object-family",
				ScopeType:    "any-tenancy",
			},
		},
		{
			name: "admit skips the defined tenancy clause",
			raw:  "Admit group Replicators of definedtenancy PartnerCorp to manage object-family in compartment Shared",
			want: ociPolicyStatement{
				Effect:       "admit",
				SubjectType:  "group",
				SubjectNames: []string{"Replicators"},
				Verb:         "manage",
				ResourceType: "object-family",
				ScopeType:    "compartment",
				ScopeName:    "Shared",
			},
		},
		{
			name: "admit with any-user subject",
			raw:  "Admit any-user of definedtenancy PartnerCorp to read buckets in tenancy",
			want: ociPolicyStatement{
				Effect:       "admit",
				SubjectType:  "any-user",
				Verb:         "read",
				ResourceType: "buckets",
				ScopeType:    "tenancy",
			},
		},
		{
			name: "define names a tenancy and grants nothing",
			raw:  "Define tenancy PartnerCorp as ocid1.tenancy.oc1..aaaaexample",
			want: ociPolicyStatement{
				Effect:       "define",
				SubjectType:  "tenancy",
				SubjectNames: []string{"PartnerCorp"},
			},
		},
		{
			name: "define names a group",
			raw:  "Define group Replicators as ocid1.group.oc1..aaaaexample",
			want: ociPolicyStatement{
				Effect:       "define",
				SubjectType:  "group",
				SubjectNames: []string{"Replicators"},
			},
		},
		{
			name: "keywords are case insensitive",
			raw:  "ALLOW GROUP Ops TO MANAGE buckets IN TENANCY",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"Ops"},
				Verb:         "manage",
				ResourceType: "buckets",
				ScopeType:    "tenancy",
			},
		},
		{
			name: "irregular whitespace",
			raw:  "  Allow   group   Ops   to  manage   buckets   in   tenancy  ",
			want: ociPolicyStatement{
				Effect:       "allow",
				SubjectType:  "group",
				SubjectNames: []string{"Ops"},
				Verb:         "manage",
				ResourceType: "buckets",
				ScopeType:    "tenancy",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOciPolicyStatement(tc.raw)

			// Raw always round-trips, so the expectations above do not repeat it.
			assert.Equal(t, tc.raw, got.Raw)
			got.Raw = ""

			assert.Equal(t, tc.want, got)
		})
	}
}

// A statement the parser cannot place must still report its text rather than
// disappearing: the alternative hides a grant an audit is looking for.
func TestParseOciPolicyStatementUnrecognized(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "whitespace only", raw: "   "},
		{name: "not a statement", raw: "this is not a policy statement"},
		{name: "effect only", raw: "Allow"},
		{name: "truncated after subject", raw: "Allow group Ops"},
		{name: "truncated after verb", raw: "Allow group Ops to manage"},
		{name: "unknown subject kind", raw: "Allow wizard Merlin to manage all-resources in tenancy"},
		{name: "unknown scope kind", raw: "Allow group Ops to manage buckets in galaxy Andromeda"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseOciPolicyStatement(tc.raw)
			assert.Equal(t, tc.raw, got.Raw, "raw text must survive an unrecognized statement")
		})
	}
}

// Partial statements must not report a scope or verb they never named, or an
// audit filtering on those fields draws a conclusion from invented data.
func TestParseOciPolicyStatementPartial(t *testing.T) {
	t.Run("truncated after verb reports no resource type or scope", func(t *testing.T) {
		got := parseOciPolicyStatement("Allow group Ops to manage")
		assert.Equal(t, "manage", got.Verb)
		assert.Empty(t, got.ResourceType)
		assert.Empty(t, got.ScopeType)
		assert.Empty(t, got.ScopeName)
	})

	t.Run("missing in clause reports no scope", func(t *testing.T) {
		got := parseOciPolicyStatement("Allow group Ops to manage buckets")
		assert.Equal(t, "buckets", got.ResourceType)
		assert.Empty(t, got.ScopeType)
	})

	t.Run("unknown subject reports no principals", func(t *testing.T) {
		got := parseOciPolicyStatement("Allow wizard Merlin to manage all-resources in tenancy")
		assert.Empty(t, got.SubjectType)
		assert.Empty(t, got.SubjectNames)
		// The rest of the statement is still readable.
		assert.Equal(t, "manage", got.Verb)
		assert.Equal(t, "tenancy", got.ScopeType)
	})

	t.Run("condition survives an unrecognized body", func(t *testing.T) {
		got := parseOciPolicyStatement("something odd where request.user.id = 'ocid1.user.oc1..aaaa'")
		assert.Empty(t, got.Effect)
		assert.Equal(t, "request.user.id = 'ocid1.user.oc1..aaaa'", got.Condition)
	})
}

func TestOciPolicyStatementIsOCID(t *testing.T) {
	assert.True(t, ociPolicyStatementIsOCID("ocid1.group.oc1..aaaaexample"))
	assert.True(t, ociPolicyStatementIsOCID("ocid1.compartment.oc1..aaaaexample"))
	assert.False(t, ociPolicyStatementIsOCID("Administrators"))
	assert.False(t, ociPolicyStatementIsOCID(""))
	assert.False(t, ociPolicyStatementIsOCID("ocid2.group.oc1..aaaa"))
}
