// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// allSecurityIntegrations is the keyword an authentication policy reports in
// place of a list when it permits every security integration in the account.
const allSecurityIntegrations = "ALL"

type mqlSnowflakeAuthenticationPolicyInternal struct {
	descLock          sync.Mutex
	descLoaded        bool
	descLoadErr       error
	descAuthMethods   []any
	descMfaMethods    []any
	descMfaEnrollment string
	descClientTypes   []any
	descSecIntegs     []any
	descPatPolicy     map[string]any
	descWorkloadIdent map[string]any
	descMfaPolicy     map[string]any
	descClientPolicy  map[string]any
	refsMemo          policyReferenceMemo
}

func (r *mqlSnowflakeAccount) authenticationPolicies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	policies, err := client.AuthenticationPolicies.Show(ctx,
		sdk.NewShowAuthenticationPolicyRequest().WithIn(sdk.ExtendedIn{Account: new(true)}),
	)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(policies))
	for i := range policies {
		mqlPolicy, err := newMqlSnowflakeAuthenticationPolicy(r.MqlRuntime, policies[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlPolicy)
	}

	return list, nil
}

func newMqlSnowflakeAuthenticationPolicy(runtime *plugin.Runtime, policy sdk.AuthenticationPolicy) (*mqlSnowflakeAuthenticationPolicy, error) {
	r, err := CreateResource(runtime, "snowflake.authenticationPolicy", map[string]*llx.RawData{
		"__id":          llx.StringData(policy.ID().FullyQualifiedName()),
		"name":          llx.StringData(policy.Name),
		"databaseName":  llx.StringData(policy.DatabaseName),
		"schemaName":    llx.StringData(policy.SchemaName),
		"owner":         llx.StringData(policy.Owner),
		"ownerRoleType": llx.StringData(policy.OwnerRoleType),
		"comment":       llx.StringData(policy.Comment),
		"options":       llx.StringData(policy.Options),
		"createdAt":     snowflakeTime(policy.CreatedOn),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeAuthenticationPolicy), nil
}

func (r *mqlSnowflakeAuthenticationPolicy) gatherDescribe() error {
	if r.descLoaded {
		return r.descLoadErr
	}
	r.descLock.Lock()
	defer r.descLock.Unlock()
	if r.descLoaded {
		return r.descLoadErr
	}

	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	client := conn.Client()
	ctx := context.Background()

	rows, err := client.AuthenticationPolicies.Describe(ctx,
		sdk.NewSchemaObjectIdentifier(r.DatabaseName.Data, r.SchemaName.Data, r.Name.Data),
	)
	if err != nil {
		r.descLoaded = true
		r.descLoadErr = err
		return err
	}

	for _, row := range rows {
		switch row.Property {
		case "AUTHENTICATION_METHODS":
			r.descAuthMethods = parseAuthPolicyList(row.Value)
		case "MFA_AUTHENTICATION_METHODS":
			r.descMfaMethods = parseAuthPolicyList(row.Value)
		case "MFA_ENROLLMENT":
			r.descMfaEnrollment = strings.TrimSpace(row.Value)
		case "CLIENT_TYPES":
			r.descClientTypes = parseAuthPolicyList(row.Value)
		case "SECURITY_INTEGRATIONS":
			r.descSecIntegs = parseAuthPolicyList(row.Value)
		case "PAT_POLICY":
			r.descPatPolicy = parseAuthPolicyStruct(row.Value)
		case "WORKLOAD_IDENTITY_POLICY":
			r.descWorkloadIdent = parseAuthPolicyStruct(row.Value)
		case "MFA_POLICY":
			r.descMfaPolicy = parseAuthPolicyStruct(row.Value)
		case "CLIENT_POLICY":
			r.descClientPolicy = parseAuthPolicyStruct(row.Value)
		}
	}

	r.descLoaded = true
	return nil
}

// parseAuthPolicyList parses DESCRIBE AUTHENTICATION POLICY list values into an
// []any of strings. Snowflake returns these lists wrapped in square brackets
// (`[ALL]`, `[PASSWORD, SAML]`); older docs show parentheses (`('ALL')`), so
// both wrappers are stripped. Empty list values (`[]`, `()`, or empty string)
// yield an empty slice.
func parseAuthPolicyList(s string) []any {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "()[]")
	if s == "" {
		return []any{}
	}
	parts := strings.Split(s, ",")
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, "'\"")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (r *mqlSnowflakeAuthenticationPolicy) authenticationMethods() ([]any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	return r.descAuthMethods, nil
}

func (r *mqlSnowflakeAuthenticationPolicy) mfaAuthenticationMethods() ([]any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	return r.descMfaMethods, nil
}

func (r *mqlSnowflakeAuthenticationPolicy) mfaEnrollment() (string, error) {
	if err := r.gatherDescribe(); err != nil {
		return "", err
	}
	return r.descMfaEnrollment, nil
}

func (r *mqlSnowflakeAuthenticationPolicy) clientTypes() ([]any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	return r.descClientTypes, nil
}

func (r *mqlSnowflakeAuthenticationPolicy) securityIntegrations() ([]any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	return r.descSecIntegs, nil
}

// securityIntegrationRefs resolves the policy's security integrations.
//
// The property is not always a list of names. A policy that does not restrict
// which integrations may be used reports the single value ALL, which is a
// keyword standing for every integration in the account rather than the name of
// one, and is the value every policy carries until it is narrowed. Resolving it
// as a name finds nothing, so ALL expands to the account's integrations instead.
func (r *mqlSnowflakeAuthenticationPolicy) securityIntegrationRefs() ([]any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}

	names := []string{}
	for _, s := range r.descSecIntegs {
		name, ok := s.(string)
		if !ok || name == "" {
			continue
		}
		if strings.EqualFold(name, allSecurityIntegrations) {
			return r.allSecurityIntegrationRefs()
		}
		names = append(names, name)
	}

	out := []any{}
	for _, name := range names {
		res, err := NewResource(r.MqlRuntime, "snowflake.securityIntegration", map[string]*llx.RawData{
			"name": llx.StringData(name),
		})
		if err != nil {
			// An integration named by the policy but no longer present in the
			// account is reported by dropping it, not by discarding every other
			// integration the policy does resolve.
			log.Warn().Err(err).Str("integration", name).
				Msg("could not resolve security integration referenced by authentication policy")
			continue
		}
		out = append(out, res)
	}
	return out, nil
}

// allSecurityIntegrationRefs returns every security integration in the account,
// which is what a policy means when it reports ALL.
func (r *mqlSnowflakeAuthenticationPolicy) allSecurityIntegrationRefs() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	integrations, err := conn.Client().SecurityIntegrations.Show(context.Background(),
		sdk.NewShowSecurityIntegrationRequest())
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(integrations))
	for i := range integrations {
		res, err := newMqlSnowflakeSecurityIntegration(r.MqlRuntime, integrations[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// parseAuthPolicyStruct parses a structured DESCRIBE AUTHENTICATION POLICY
// value into a dict.
//
// These values are not JSON. Snowflake renders them the way a Java map prints
// itself, which the documented CLIENT_POLICY example shows exactly:
//
//	{GO_DRIVER={MINIMUM_VERSION=3.14.1}}
//
// so a PAT policy arrives as
//
//	{DEFAULT_EXPIRY_IN_DAYS=15, MAX_EXPIRY_IN_DAYS=365, NETWORK_POLICY_EVALUATION=ENFORCED_REQUIRED}
//
// Entries are split at top-level separators only, so a nested map or list is
// carried through whole. A value that is neither is returned as int64 or bool
// where it reads as one, since the point of MAX_EXPIRY_IN_DAYS is to compare it
// against a bound. List members are always left as strings: ALLOWED_AWS_ACCOUNTS
// holds 12-digit account ids, and reading one as a number would drop a leading
// zero.
//
// An unrecognizable value yields an empty map rather than an error. The
// property is reported by newer Snowflake versions only, and one unreadable
// entry must not take the other four properties of the policy down with it.
func parseAuthPolicyStruct(s string) map[string]any {
	out := map[string]any{}
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return out
	}
	for _, entry := range splitTopLevel(s[1 : len(s)-1]) {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = parseAuthPolicyValue(value)
	}
	return out
}

// parseAuthPolicyValue converts one value of a structured DESCRIBE value,
// recursing into nested maps and lists.
func parseAuthPolicyValue(s string) any {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"):
		return parseAuthPolicyStruct(s)
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		out := []any{}
		for _, member := range splitTopLevel(s[1 : len(s)-1]) {
			member = strings.TrimSpace(member)
			member = strings.Trim(member, "'\"")
			if member != "" {
				out = append(out, member)
			}
		}
		return out
	}
	s = strings.Trim(s, "'\"")
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	switch strings.ToUpper(s) {
	case "TRUE":
		return true
	case "FALSE":
		return false
	}
	return s
}

// splitTopLevel splits on commas that sit outside any nested {} or [] group, so
// that {A=[X, Y], B=1} yields "A=[X, Y]" and "B=1" rather than three fragments.
func splitTopLevel(s string) []string {
	out := []string{}
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '{', '[':
			depth++
		case '}', ']':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])

	trimmed := make([]string, 0, len(out))
	for _, part := range out {
		if strings.TrimSpace(part) != "" {
			trimmed = append(trimmed, part)
		}
	}
	return trimmed
}

func (r *mqlSnowflakeAuthenticationPolicy) patPolicy() (any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	if r.descPatPolicy == nil {
		return map[string]any{}, nil
	}
	return r.descPatPolicy, nil
}

func (r *mqlSnowflakeAuthenticationPolicy) workloadIdentityPolicy() (any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	if r.descWorkloadIdent == nil {
		return map[string]any{}, nil
	}
	return r.descWorkloadIdent, nil
}

func (r *mqlSnowflakeAuthenticationPolicy) mfaPolicy() (any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	if r.descMfaPolicy == nil {
		return map[string]any{}, nil
	}
	return r.descMfaPolicy, nil
}

func (r *mqlSnowflakeAuthenticationPolicy) clientPolicy() (any, error) {
	if err := r.gatherDescribe(); err != nil {
		return nil, err
	}
	if r.descClientPolicy == nil {
		return map[string]any{}, nil
	}
	return r.descClientPolicy, nil
}
