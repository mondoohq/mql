// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

// A dotted path resolves to the longest matching resource name, so a resource
// named `x.y.z` makes a field `z` on `x.y` unreachable through its own path.
// Four schemas shipped that collision (mondoohq/mql#10785): the path compiled,
// ran, and answered about the bare resource instead of the field, with nothing
// reported at author, lint or scan time.
//
// lrcore.validateFieldShadowing now refuses the schema, so this cannot be
// reintroduced. These pin the other half - that each path still reads the field
// it always named, and with the field's own type. Renaming any of the four
// resources back onto a field's path flips the type here and fails.
func TestShadowedFieldPathsResolveToTheField(t *testing.T) {
	cases := []struct {
		provider string
		path     string
		want     types.Type
	}{
		// the user's primary address, not the `emails()` row type
		{"gitlab", "gitlab.user.email", types.String},
		// the group's name, not the permission group resource
		{"mikrotik", "mikrotik.user.group", types.String},
		// the raw mailbox list the CIS Microsoft 365 content reads
		{"ms365", "ms365.exchangeonline.mailbox", types.Array(types.Dict)},
		// current disk usage in bytes, not an attached virtual disk
		{"proxmox", "proxmox.vm.disk", types.Int},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: tc.provider})
			res, err := mqlc.Compile(tc.path, nil, mqlc.NewConfig(schema, features))
			require.NoError(t, err)

			chunks := res.CodeV2.Blocks[0].Chunks
			last := chunks[len(chunks)-1]
			require.NotNil(t, last.Function, "%s compiled to a bare resource, not a field read", tc.path)
			assert.Equal(t, string(tc.want), last.Function.Type,
				"%s must read the field, not the resource that used to shadow it", tc.path)
		})
	}
}

// The checks these collisions actually broke. Every one is shipped content that
// failed to compile against the ms365 provider, which fails the whole bundle
// rather than the single check.
func TestShadowedFieldContentQueriesCompile(t *testing.T) {
	ms365 := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "ms365"})

	// verbatim from cnspec-enterprise-policies: queries/ms365-foundations.mql.yaml
	// and certifications/ms365-3.1.0/cis-microsoft-365.mql.yaml
	queries := []string{
		`ms365.exchangeonline.mailbox.where(RecipientTypeDetails == "UserMailbox" || RecipientTypeDetails == "SharedMailbox").all(AuditEnabled == true)`,
		`ms365.exchangeonline.mailbox.where(AccountDisabled == false && RecipientTypeDetails == "UserMailbox").all(AuditEnabled == true)`,
		`ms365.exchangeonline.mailbox.where(AccountDisabled == false).all(AuditAdmin.containsAll(["Update", "MoveToDeletedItems"]))`,
		// the typed view alongside it, which was never broken and must stay working
		`ms365.exchangeonline.mailboxesWithAudit.all(auditEnabled == true)`,
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			_, err := mqlc.Compile(query, nil, mqlc.NewConfig(ms365, features))
			assert.NoError(t, err)
		})
	}
}
