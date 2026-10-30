// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"strings"

	"go.mondoo.com/mql/providers/aws/connection"
)

// --- IAM role trust exposure ---

// assumableByPublic reports whether the role's trust policy lets any principal
// ("*") assume it without a source-scoping condition. Reuses statementsAllowPublic
// so trust-policy "public" matches the resource-policy definition.
func (a *mqlAwsIamRole) assumableByPublic() (bool, error) {
	stmts := a.GetAssumeRolePolicyStatements()
	if stmts.Error != nil {
		return false, stmts.Error
	}
	return statementsAllowPublic(stmts.Data)
}

// assumableByExternalAccounts returns the AWS account IDs outside this account
// that the trust policy allows to assume the role.
func (a *mqlAwsIamRole) assumableByExternalAccounts() ([]any, error) {
	stmts := a.GetAssumeRolePolicyStatements()
	if stmts.Error != nil {
		return nil, stmts.Error
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ownAccount := conn.AccountId()

	accounts := map[string]struct{}{}
	for _, s := range stmts.Data {
		stmt, ok := s.(*mqlAwsIamPolicyStatement)
		if !ok {
			continue
		}
		effect := stmt.GetEffect()
		if effect.Error != nil {
			return nil, effect.Error
		}
		if !strings.EqualFold(effect.Data, "Allow") {
			continue
		}
		principals := stmt.GetPrincipals()
		if principals.Error != nil {
			return nil, principals.Error
		}
		for _, v := range principals.Data {
			vals, ok := v.([]any)
			if !ok {
				continue
			}
			for _, item := range vals {
				p, ok := item.(string)
				if !ok {
					continue
				}
				if acct := accountIdFromPrincipal(p); acct != "" && acct != ownAccount {
					accounts[acct] = struct{}{}
				}
			}
		}
	}

	res := make([]any, 0, len(accounts))
	for acct := range accounts {
		res = append(res, acct)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].(string) < res[j].(string) })
	return res, nil
}

// accountIdFromPrincipal extracts the 12-digit AWS account ID from a trust
// policy principal value, which may be a bare account ID or an IAM ARN such as
// arn:aws:iam::123456789012:root. Returns "" for the "*" wildcard and for
// service principals (e.g. ec2.amazonaws.com).
func accountIdFromPrincipal(principal string) string {
	if principal == "" || principal == "*" {
		return ""
	}
	if isAwsAccountId(principal) {
		return principal
	}
	if strings.HasPrefix(principal, "arn:") {
		parts := strings.Split(principal, ":")
		if len(parts) >= 5 && isAwsAccountId(parts[4]) {
			return parts[4]
		}
	}
	return ""
}

func isAwsAccountId(s string) bool {
	if len(s) != 12 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// --- Egress exposure ---

// allowsUnrestrictedEgress reports whether any egress rule permits outbound
// traffic to the public internet (0.0.0.0/0 or ::/0, including via a managed
// prefix list). Reuses includesPublicSource, where the rule's CIDRs are the
// destination.
func (a *mqlAwsEc2Securitygroup) allowsUnrestrictedEgress() (bool, error) {
	perms := a.GetIpPermissionsEgress()
	if perms.Error != nil {
		return false, perms.Error
	}
	for _, p := range perms.Data {
		perm, ok := p.(*mqlAwsEc2SecuritygroupIppermission)
		if !ok {
			continue
		}
		public := perm.GetIncludesPublicSource()
		if public.Error != nil {
			return false, public.Error
		}
		if public.Data {
			return true, nil
		}
	}
	return false, nil
}

// --- Embedded-config exposure ---

func (a *mqlAwsEc2Launchtemplate) userDataPresent() (bool, error) {
	userData := a.GetUserData()
	if userData.Error != nil {
		return false, userData.Error
	}
	return strings.TrimSpace(userData.Data) != "", nil
}

// environmentSecretLikeKeys returns the function's environment variable names
// whose names suggest an inline credential rather than benign configuration.
func (a *mqlAwsLambdaFunction) environmentSecretLikeKeys() ([]any, error) {
	env := a.GetEnvironment()
	if env.Error != nil {
		return nil, env.Error
	}
	res := []any{}
	for key := range env.Data {
		if looksLikeSecretKey(key) {
			res = append(res, key)
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].(string) < res[j].(string) })
	return res, nil
}

// looksLikeSecretKey reports whether an environment variable name suggests it
// holds a credential. It matches on substrings specific enough to avoid benign
// names like KMS_KEY_ID (it does not match a bare "key").
func looksLikeSecretKey(key string) bool {
	k := strings.ToLower(key)
	for _, marker := range []string{
		"password", "passwd", "pwd",
		"secret", "token", "credential",
		"apikey", "api_key", "accesskey", "access_key",
		"private_key", "privatekey",
	} {
		if strings.Contains(k, marker) {
			return true
		}
	}
	return false
}
