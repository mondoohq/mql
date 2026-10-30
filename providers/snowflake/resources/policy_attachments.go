// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Policy attachment, in both directions.
//
// INFORMATION_SCHEMA.POLICY_REFERENCES answers "what is this policy attached
// to". The security question is usually the reverse one, "what policy governs
// this user", and Snowflake offers no statement that asks it: a user reports
// neither its authentication policy nor its password or session policy, in
// SHOW USERS or in DESCRIBE USER.
//
// So the reverse is built from the forward direction. Every password, session,
// and authentication policy in the account is asked what it governs once, and
// the answers are inverted into an index keyed by the entity. That is one
// lookup per policy for the whole scan rather than one per user, which matters
// because accounts hold few policies and many users.
//
// The index is memoized on the account, which is a singleton, and it is built
// from the policies' own references field, so a query that reads both a
// policy's references and a user's policy pays for the lookup once.

// Entity domains POLICY_REFERENCES reports in REF_ENTITY_DOMAIN for the
// policies indexed here. A policy attached to a table or a view is not an
// identity control and is not indexed.
const (
	policyDomainUser    = "USER"
	policyDomainAccount = "ACCOUNT"
)

// policyReferenceMemo holds the outcome of one POLICY_REFERENCES lookup.
//
// The failure is memoized with the value. A role that cannot read the table
// function for one policy cannot read it on a second look either, so retrying
// would only multiply statements against an account already refusing them.
type policyReferenceMemo struct {
	lock   sync.Mutex
	loaded bool
	refs   []any
	err    error
}

func (m *policyReferenceMemo) get(runtime *plugin.Runtime, databaseName, schemaName, name string) ([]any, error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if m.loaded {
		return m.refs, m.err
	}
	m.refs, m.err = queryPolicyReferences(runtime, databaseName, schemaName, name)
	m.loaded = true
	return m.refs, m.err
}

// policyAttachment is the inverted view of one policy kind: which policy of
// that kind governs a given user, and which one governs the account.
type policyAttachment[T any] struct {
	byUser     map[string]T
	onAccount  T
	hasAccount bool
}

// policyAttachments holds the inverted view of all three identity policy kinds.
type policyAttachments struct {
	authentication policyAttachment[*mqlSnowflakeAuthenticationPolicy]
	password       policyAttachment[*mqlSnowflakePasswordPolicy]
	session        policyAttachment[*mqlSnowflakeSessionPolicy]
}

// policyEntityKey normalizes an entity name into its index key. Snowflake
// stores unquoted identifiers folded to upper case and reports them that way in
// both SHOW USERS and POLICY_REFERENCES, but a quoted identifier keeps its case
// in one and can arrive quoted in the other, so both sides go through the same
// normalization.
func policyEntityKey(name string) string {
	return strings.ToUpper(strings.Trim(strings.TrimSpace(name), `"`))
}

// policyReferenceTarget reads the entity a POLICY_REFERENCES row names.
func policyReferenceTarget(ref any) (domain string, name string, ok bool) {
	row, isRef := ref.(*mqlSnowflakePolicyReference)
	if !isRef || row == nil {
		return "", "", false
	}
	domain = strings.ToUpper(strings.TrimSpace(row.RefEntityDomain.Data))
	if domain == "" {
		return "", "", false
	}
	return domain, row.RefEntityName.Data, true
}

// indexPolicyAttachments inverts one policy kind.
//
// A policy whose references cannot be read is dropped from the index rather
// than taking the other policies down with it: the whole point of the index is
// to answer for the users that other policies do govern, and one unreadable
// policy would otherwise leave every user unanswered.
func indexPolicyAttachments[T any](entries []any, references func(T) *plugin.TValue[[]any], kind string) policyAttachment[T] {
	out := policyAttachment[T]{byUser: map[string]T{}}
	for _, entry := range entries {
		policy, ok := entry.(T)
		if !ok {
			continue
		}
		refs := references(policy)
		if refs.Error != nil {
			log.Warn().Err(refs.Error).Str("kind", kind).
				Msg("snowflake: could not read the objects a policy is attached to")
			continue
		}
		for _, ref := range refs.Data {
			domain, name, ok := policyReferenceTarget(ref)
			if !ok {
				continue
			}
			switch domain {
			case policyDomainUser:
				key := policyEntityKey(name)
				if key == "" {
					continue
				}
				out.byUser[key] = policy
			case policyDomainAccount:
				out.onAccount = policy
				out.hasAccount = true
			}
		}
	}
	return out
}

// policyAttachmentIndex returns the memoized inverted index for the account.
func (r *mqlSnowflakeAccount) policyAttachmentIndex() (*policyAttachments, error) {
	r.policyAttachmentsOnce.Do(func() {
		r.cachedPolicyAttachments, r.cachedPolicyAttachmentsErr = r.buildPolicyAttachments()
	})
	return r.cachedPolicyAttachments, r.cachedPolicyAttachmentsErr
}

func (r *mqlSnowflakeAccount) buildPolicyAttachments() (*policyAttachments, error) {
	authPolicies := r.GetAuthenticationPolicies()
	if authPolicies.Error != nil {
		return nil, authPolicies.Error
	}
	passwordPolicies := r.GetPasswordPolicies()
	if passwordPolicies.Error != nil {
		return nil, passwordPolicies.Error
	}
	sessionPolicies := r.GetSessionPolicies()
	if sessionPolicies.Error != nil {
		return nil, sessionPolicies.Error
	}

	return &policyAttachments{
		authentication: indexPolicyAttachments(authPolicies.Data,
			func(p *mqlSnowflakeAuthenticationPolicy) *plugin.TValue[[]any] { return p.GetReferences() },
			"authentication"),
		password: indexPolicyAttachments(passwordPolicies.Data,
			func(p *mqlSnowflakePasswordPolicy) *plugin.TValue[[]any] { return p.GetReferences() },
			"password"),
		session: indexPolicyAttachments(sessionPolicies.Data,
			func(p *mqlSnowflakeSessionPolicy) *plugin.TValue[[]any] { return p.GetReferences() },
			"session"),
	}, nil
}

// policyAttachmentsFor reaches the index from a resource other than the account.
func policyAttachmentsFor(runtime *plugin.Runtime) (*policyAttachments, error) {
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	return account.policyAttachmentIndex()
}

func (r *mqlSnowflakeAccount) authenticationPolicy() (*mqlSnowflakeAuthenticationPolicy, error) {
	index, err := r.policyAttachmentIndex()
	if err != nil {
		return nil, err
	}
	if !index.authentication.hasAccount {
		r.AuthenticationPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return index.authentication.onAccount, nil
}

func (r *mqlSnowflakeAccount) passwordPolicy() (*mqlSnowflakePasswordPolicy, error) {
	index, err := r.policyAttachmentIndex()
	if err != nil {
		return nil, err
	}
	if !index.password.hasAccount {
		r.PasswordPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return index.password.onAccount, nil
}

func (r *mqlSnowflakeAccount) sessionPolicy() (*mqlSnowflakeSessionPolicy, error) {
	index, err := r.policyAttachmentIndex()
	if err != nil {
		return nil, err
	}
	if !index.session.hasAccount {
		r.SessionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return index.session.onAccount, nil
}

func (r *mqlSnowflakeUser) authenticationPolicy() (*mqlSnowflakeAuthenticationPolicy, error) {
	index, err := policyAttachmentsFor(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	policy, ok := index.authentication.byUser[policyEntityKey(r.Name.Data)]
	if !ok {
		r.AuthenticationPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return policy, nil
}

func (r *mqlSnowflakeUser) passwordPolicy() (*mqlSnowflakePasswordPolicy, error) {
	index, err := policyAttachmentsFor(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	policy, ok := index.password.byUser[policyEntityKey(r.Name.Data)]
	if !ok {
		r.PasswordPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return policy, nil
}

func (r *mqlSnowflakeUser) sessionPolicy() (*mqlSnowflakeSessionPolicy, error) {
	index, err := policyAttachmentsFor(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	policy, ok := index.session.byUser[policyEntityKey(r.Name.Data)]
	if !ok {
		r.SessionPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return policy, nil
}

func (r *mqlSnowflakePasswordPolicy) references() ([]any, error) {
	return r.refsMemo.get(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
}

func (r *mqlSnowflakeSessionPolicy) references() ([]any, error) {
	return r.refsMemo.get(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
}

func (r *mqlSnowflakeAuthenticationPolicy) references() ([]any, error) {
	return r.refsMemo.get(r.MqlRuntime, r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data)
}
