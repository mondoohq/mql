// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func policyRef(domain, name string) *mqlSnowflakePolicyReference {
	return &mqlSnowflakePolicyReference{
		RefEntityDomain: plugin.TValue[string]{Data: domain, State: plugin.StateIsSet},
		RefEntityName:   plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
	}
}

func authPolicyWithRefs(name string, refs ...*mqlSnowflakePolicyReference) *mqlSnowflakeAuthenticationPolicy {
	data := make([]any, 0, len(refs))
	for _, ref := range refs {
		data = append(data, ref)
	}
	return &mqlSnowflakeAuthenticationPolicy{
		Name:       plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		References: plugin.TValue[[]any]{Data: data, State: plugin.StateIsSet},
	}
}

func TestPolicyReferenceTarget(t *testing.T) {
	domain, name, ok := policyReferenceTarget(policyRef("user", "ALICE"))
	if !ok {
		t.Fatal("policyReferenceTarget reported not ok on a USER row")
	}
	if domain != policyDomainUser {
		t.Errorf("domain = %q, want %q (the column is folded before it is matched)", domain, policyDomainUser)
	}
	if name != "ALICE" {
		t.Errorf("name = %q, want ALICE", name)
	}

	if _, _, ok := policyReferenceTarget(policyRef("", "ALICE")); ok {
		t.Error("a row with no entity domain was accepted")
	}
	if _, _, ok := policyReferenceTarget("not a reference"); ok {
		t.Error("a value that is not a policy reference was accepted")
	}
	if _, _, ok := policyReferenceTarget((*mqlSnowflakePolicyReference)(nil)); ok {
		t.Error("a nil reference was accepted")
	}
}

func TestIndexPolicyAttachments(t *testing.T) {
	references := func(p *mqlSnowflakeAuthenticationPolicy) *plugin.TValue[[]any] { return &p.References }

	strict := authPolicyWithRefs("STRICT",
		policyRef(policyDomainUser, "ALICE"),
		policyRef(policyDomainUser, "bob"),
	)
	baseline := authPolicyWithRefs("BASELINE", policyRef(policyDomainAccount, "ACME"))
	// A policy attached to a table is a governance policy, not an identity one,
	// and must not land in either bucket.
	onTable := authPolicyWithRefs("TABLE_ONLY", policyRef("TABLE", "CUSTOMERS"))
	// A policy that reports nothing at all still has to leave the rest intact.
	empty := authPolicyWithRefs("EMPTY")

	index := indexPolicyAttachments([]any{strict, baseline, onTable, empty}, references, "authentication")

	if got := index.byUser[policyEntityKey("ALICE")]; got != strict {
		t.Errorf("ALICE resolved to %v, want STRICT", got)
	}
	// The entity name arrives folded or not depending on how it was quoted, so
	// a lower-case row still has to match an upper-case user name.
	if got := index.byUser[policyEntityKey("BOB")]; got != strict {
		t.Errorf("BOB resolved to %v, want STRICT", got)
	}
	if len(index.byUser) != 2 {
		t.Errorf("byUser holds %d entries, want 2", len(index.byUser))
	}
	if !index.hasAccount || index.onAccount != baseline {
		t.Errorf("account attachment = (%v, %v), want (true, BASELINE)", index.hasAccount, index.onAccount)
	}
	if _, ok := index.byUser[policyEntityKey("CUSTOMERS")]; ok {
		t.Error("a table attachment was indexed as a user attachment")
	}
}

// TestIndexPolicyAttachmentsSkipsUnreadable pins that one policy whose
// references cannot be read is dropped rather than taking the index down: the
// users the other policies govern still have to resolve.
func TestIndexPolicyAttachmentsSkipsUnreadable(t *testing.T) {
	references := func(p *mqlSnowflakeAuthenticationPolicy) *plugin.TValue[[]any] { return &p.References }

	denied := authPolicyWithRefs("DENIED", policyRef(policyDomainUser, "ALICE"))
	denied.References = plugin.TValue[[]any]{Error: errors.New("access denied"), State: plugin.StateIsSet}
	readable := authPolicyWithRefs("READABLE", policyRef(policyDomainUser, "BOB"))

	index := indexPolicyAttachments([]any{denied, readable}, references, "authentication")

	if _, ok := index.byUser[policyEntityKey("ALICE")]; ok {
		t.Error("a user was indexed from a policy whose references could not be read")
	}
	if got := index.byUser[policyEntityKey("BOB")]; got != readable {
		t.Errorf("BOB resolved to %v, want READABLE", got)
	}
}

// TestIndexPolicyAttachmentsEmpty covers the account with no policies at all,
// where the index has to be usable rather than nil.
func TestIndexPolicyAttachmentsEmpty(t *testing.T) {
	references := func(p *mqlSnowflakeAuthenticationPolicy) *plugin.TValue[[]any] { return &p.References }

	index := indexPolicyAttachments([]any{}, references, "authentication")
	if index.byUser == nil {
		t.Fatal("byUser is nil, a lookup against it would still work but a write would panic")
	}
	if _, ok := index.byUser[policyEntityKey("ALICE")]; ok {
		t.Error("an empty account resolved a user")
	}
	if index.hasAccount {
		t.Error("an empty account reported an account-level attachment")
	}
}
