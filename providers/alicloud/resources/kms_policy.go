// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	kmsclient "github.com/alibabacloud-go/kms-20160120/v4/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/providers/alicloud/connection"
)

// kmsKeyPolicyState memoizes a key's policy document and its parsed statements.
// Five fields read them, so the policy is fetched and decoded once per key.
type kmsKeyPolicyState struct {
	policyOnce sync.Once
	policyDoc  string

	statementsOnce sync.Once
	parsed         []policyStatement
	statementsErr  error
}

// acsAccountID extracts the account id from an ACS resource name of the form
// acs:<service>:<region>:<account>:<relative-id>. An empty string means the
// value names no account, either because it is not an ACS name or because the
// account field is blank or wildcarded.
func acsAccountID(arn string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(arn), "acs:")
	if !ok {
		return ""
	}
	fields := strings.SplitN(rest, ":", 4)
	if len(fields) < 4 {
		return ""
	}
	account := strings.TrimSpace(fields[2])
	if account == "*" {
		return ""
	}
	return account
}

// kmsPolicyPrincipalAccountID reads the account a key-policy principal belongs
// to. KMS writes these either as a bare account id or as an ACS RAM name such
// as acs:ram::123456789:*, so both forms are accepted. The wildcard names no
// account and is reported separately by hasWildcardPrincipal.
func kmsPolicyPrincipalAccountID(principal string) string {
	principal = strings.TrimSpace(principal)
	if principal == "" || principal == "*" {
		return ""
	}
	if strings.HasPrefix(principal, "acs:") {
		return acsAccountID(principal)
	}
	// a bare account id: digits only, anything else is a name we cannot
	// attribute to an account
	for _, r := range principal {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return principal
}

// kmsExternalAccountIDs returns the accounts, other than ownAccount, that the
// allowing statements of a key policy grant use of the key to. Denying
// statements are skipped because they withdraw rather than grant.
//
// When ownAccount is empty the key's own account could not be determined, so no
// principal can be classified as external and the result is empty: guessing
// would report every principal, including the account's own default policy, as
// a cross-account grant.
func kmsExternalAccountIDs(statements []policyStatement, ownAccount string) []string {
	if ownAccount == "" {
		return nil
	}
	seen := map[string]struct{}{}
	for _, s := range statements {
		if !s.isAllow() {
			continue
		}
		for _, entries := range s.Principal {
			for _, p := range entries {
				account := kmsPolicyPrincipalAccountID(p)
				if account == "" || account == ownAccount {
					continue
				}
				seen[account] = struct{}{}
			}
		}
	}
	return sortedKeys(seen)
}

// keyPolicyDocument reads the key's policy once. A key with no policy, or one
// the scan may not read, yields an empty document rather than an error: a
// single unreadable policy must not fail a query over every key in the account.
func (r *mqlAlicloudKmsKey) keyPolicyDocument() string {
	r.policyOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
		client, err := conn.KmsClient(r.region)
		if err != nil {
			log.Debug().Err(err).Str("key", r.keyId).Msg("alicloud> could not reach KMS to read a key policy")
			return
		}
		resp, err := client.GetKeyPolicy(&kmsclient.GetKeyPolicyRequest{
			KeyId: new(r.keyId),
			// "default" is the only policy name KMS supports
			PolicyName: new("default"),
		})
		if err != nil {
			log.Debug().Err(err).Str("key", r.keyId).Msg("alicloud> could not read KMS key policy")
			return
		}
		if resp == nil || resp.Body == nil {
			return
		}
		r.policyDoc = tea.StringValue(resp.Body.Policy)
	})
	return r.policyDoc
}

// parsedKeyPolicy decodes the key policy once, reusing the parser that already
// serves RAM permission policies, RAM trust policies and OSS bucket policies.
func (r *mqlAlicloudKmsKey) parsedKeyPolicy() ([]policyStatement, error) {
	r.statementsOnce.Do(func() {
		r.parsed, r.statementsErr = parsePolicyDocument(r.keyPolicyDocument())
	})
	return r.parsed, r.statementsErr
}

func (r *mqlAlicloudKmsKey) policy() (string, error) {
	return r.keyPolicyDocument(), nil
}

func (r *mqlAlicloudKmsKey) statements() ([]any, error) {
	parsed, err := r.parsedKeyPolicy()
	if err != nil {
		return nil, err
	}
	return newPolicyStatements(r.MqlRuntime, "kms/"+r.region+"/"+r.keyId, parsed)
}

func (r *mqlAlicloudKmsKey) externalPrincipalAccountIds() ([]any, error) {
	parsed, err := r.parsedKeyPolicy()
	if err != nil {
		return nil, err
	}
	return strsToAny(kmsExternalAccountIDs(parsed, acsAccountID(r.Arn.Data))), nil
}

func (r *mqlAlicloudKmsKey) allowsExternalPrincipal() (bool, error) {
	parsed, err := r.parsedKeyPolicy()
	if err != nil {
		return false, err
	}
	if policyGrantsAnonymousAccess(parsed) {
		return true, nil
	}
	return len(kmsExternalAccountIDs(parsed, acsAccountID(r.Arn.Data))) > 0, nil
}

func (r *mqlAlicloudKmsKey) hasWildcardPrincipal() (bool, error) {
	parsed, err := r.parsedKeyPolicy()
	if err != nil {
		return false, err
	}
	return policyGrantsAnonymousAccess(parsed), nil
}
