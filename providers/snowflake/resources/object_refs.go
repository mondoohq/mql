// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// errRefListingUnavailable reports that the listing a reference resolves
// against could not be read at all, as opposed to being read and not holding
// the name. The two have to stay apart: a listing the scanning role is refused
// leaves the resolved list unknown, while an empty resolved list is the claim
// that the object references nothing, which any assertion over the list would
// then pass on.
var errRefListingUnavailable = errors.New("snowflake: object listing unavailable")

// Resolving the object names Snowflake reports inside other objects.
//
// A network policy names its rules, an external access integration names the
// rules and secrets it permits, and a security integration names a role and a
// network policy. Every one of those arrives as a name, and answering a
// question about what the named object actually allows means joining the two
// listings by hand.
//
// The joins go through an index built from the account's own listing of the
// target kind, not through NewResource. NewResource runs the target's init
// before the runtime cache is consulted, so resolving a rule per integration
// would issue one statement per name; the index is one statement for the whole
// scan, and it is free when the same listing is queried anyway, because the
// resources it holds are the ones the listing already created.

// parseQualifiedName splits a Snowflake object name into its database, schema,
// and object parts.
//
// The same name reaches us in two renderings. The SDK quotes every part
// (`"DB"."SCH"."RULE"`), while a DESCRIBE property lists them bare
// (`DB.SCH.RULE`), so the split has to accept both. It also has to respect the
// quotes rather than splitting on every dot, because a quoted identifier is
// allowed to contain one, and it has to reject anything that is not a
// three-part name instead of indexing past the end of the split.
func parseQualifiedName(raw string) (databaseName string, schemaName string, name string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", false
	}

	parts := []string{}
	current := strings.Builder{}
	quoted := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '"' && quoted && i+1 < len(raw) && raw[i+1] == '"':
			// an escaped quote inside a quoted identifier
			current.WriteByte('"')
			i++
		case c == '"':
			quoted = !quoted
		case c == '.' && !quoted:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	parts = append(parts, current.String())

	if quoted || len(parts) != 3 {
		return "", "", "", false
	}
	for _, p := range parts {
		if strings.TrimSpace(p) == "" {
			return "", "", "", false
		}
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2]), true
}

// qualifiedNameKey normalizes a reported object name into the key its resource
// is indexed under, which is the same string the resource carries as its cache
// key. It reports false for a name that is not a three-part qualified name.
func qualifiedNameKey(raw string) (string, bool) {
	databaseName, schemaName, name, ok := parseQualifiedName(raw)
	if !ok {
		return "", false
	}
	return snowflakeSchemaObjectID(databaseName, schemaName, name), true
}

// networkRuleIndex maps a network rule's qualified name to its resource.
func (r *mqlSnowflakeAccount) networkRuleIndex() (map[string]*mqlSnowflakeNetworkRule, error) {
	return r.cachedNetworkRuleIndex.get(func() (map[string]*mqlSnowflakeNetworkRule, error) {
		rules := r.GetNetworkRules()
		if rules.Error != nil {
			return nil, rules.Error
		}
		index := make(map[string]*mqlSnowflakeNetworkRule, len(rules.Data))
		for _, entry := range rules.Data {
			rule, ok := entry.(*mqlSnowflakeNetworkRule)
			if !ok {
				continue
			}
			index[snowflakeSchemaObjectID(rule.DatabaseName.Data, rule.SchemaName.Data, rule.Name.Data)] = rule
		}
		return index, nil
	})
}

// secretIndex maps a secret's qualified name to its resource.
func (r *mqlSnowflakeAccount) secretIndex() (map[string]*mqlSnowflakeSecret, error) {
	return r.cachedSecretIndex.get(func() (map[string]*mqlSnowflakeSecret, error) {
		secrets := r.GetSecrets()
		if secrets.Error != nil {
			return nil, secrets.Error
		}
		index := make(map[string]*mqlSnowflakeSecret, len(secrets.Data))
		for _, entry := range secrets.Data {
			secret, ok := entry.(*mqlSnowflakeSecret)
			if !ok {
				continue
			}
			index[snowflakeSchemaObjectID(secret.DatabaseName.Data, secret.SchemaName.Data, secret.Name.Data)] = secret
		}
		return index, nil
	})
}

// networkPolicyIndex maps a network policy name to its resource. Network
// policies are account-level objects, so the key is the bare name folded the
// way Snowflake folds an unquoted identifier.
func (r *mqlSnowflakeAccount) networkPolicyIndex() (map[string]*mqlSnowflakeNetworkPolicy, error) {
	return r.cachedNetworkPolicyIndex.get(func() (map[string]*mqlSnowflakeNetworkPolicy, error) {
		policies := r.GetNetworkPolicies()
		if policies.Error != nil {
			return nil, policies.Error
		}
		index := make(map[string]*mqlSnowflakeNetworkPolicy, len(policies.Data))
		for _, entry := range policies.Data {
			policy, ok := entry.(*mqlSnowflakeNetworkPolicy)
			if !ok {
				continue
			}
			index[policyEntityKey(policy.Name.Data)] = policy
		}
		return index, nil
	})
}

// resolveObjectRefs turns a list of reported qualified names into the resources
// they name.
//
// Two things are reported by dropping the entry and logging it rather than by
// failing: a name that is not a three-part qualified name, and a name the
// account listing does not hold. The raw name list stays on the resource
// alongside the resolved one, so a shorter resolved list is visible rather than
// silent. A listing that cannot be read at all is different, and comes back as
// errRefListingUnavailable so the field resolves to null.
func resolveObjectRefs[T any](runtime *plugin.Runtime, names []any, kind string, index func(*mqlSnowflakeAccount) (map[string]T, error)) ([]any, error) {
	if len(names) == 0 {
		return []any{}, nil
	}

	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	lookup, err := index(account)
	if err != nil {
		if !isAccessDenied(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("kind", kind).
			Msg("snowflake: cannot list the objects a reference points at, references will be null")
		return nil, errRefListingUnavailable
	}

	out := make([]any, 0, len(names))
	for _, entry := range names {
		raw, ok := entry.(string)
		if !ok {
			continue
		}
		key, ok := qualifiedNameKey(raw)
		if !ok {
			log.Warn().Str("kind", kind).Str("name", raw).
				Msg("snowflake: reference is not a qualified object name")
			continue
		}
		target, ok := lookup[key]
		if !ok {
			log.Warn().Str("kind", kind).Str("name", raw).
				Msg("snowflake: referenced object is not listed by the account")
			continue
		}
		out = append(out, target)
	}
	return out, nil
}

func networkRuleRefs(runtime *plugin.Runtime, names []any) ([]any, error) {
	return resolveObjectRefs(runtime, names, "network rule",
		func(a *mqlSnowflakeAccount) (map[string]*mqlSnowflakeNetworkRule, error) { return a.networkRuleIndex() })
}

func secretRefs(runtime *plugin.Runtime, names []any) ([]any, error) {
	return resolveObjectRefs(runtime, names, "secret",
		func(a *mqlSnowflakeAccount) (map[string]*mqlSnowflakeSecret, error) { return a.secretIndex() })
}

// networkPolicyByName resolves an account-level network policy name.
//
// A name that the account listing does not hold resolves to nothing rather than
// to an error, because the reason is usually that the scanning role cannot list
// the policy, and the name field beside the reference already reports that a
// policy is set.
func networkPolicyByName(runtime *plugin.Runtime, name string) (*mqlSnowflakeNetworkPolicy, error) {
	key := policyEntityKey(name)
	if key == "" {
		return nil, nil
	}
	account, err := snowflakeAccount(runtime)
	if err != nil {
		return nil, err
	}
	index, err := account.networkPolicyIndex()
	if err != nil {
		if !isAccessDenied(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("policy", name).
			Msg("snowflake: cannot list network policies, the reference will be null")
		return nil, nil
	}
	return index[key], nil
}

// refsFromNameList resolves a source list of reported names into resources,
// carrying the source's null state across. A source list that could not be read
// is unknown, and an empty resolved list would report it as "nothing
// referenced".
func refsFromNameList(source *plugin.TValue[[]any], field *plugin.TValue[[]any], resolve func([]any) ([]any, error)) ([]any, error) {
	if source.Error != nil {
		return nil, source.Error
	}
	if source.State&plugin.StateIsNull != 0 {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	refs, err := resolve(source.Data)
	if errors.Is(err, errRefListingUnavailable) {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return refs, err
}

func (r *mqlSnowflakeNetworkPolicy) allowedNetworkRuleRefs() ([]any, error) {
	return refsFromNameList(r.GetAllowedNetworkRules(), &r.AllowedNetworkRuleRefs,
		func(names []any) ([]any, error) { return networkRuleRefs(r.MqlRuntime, names) })
}

func (r *mqlSnowflakeNetworkPolicy) blockedNetworkRuleRefs() ([]any, error) {
	return refsFromNameList(r.GetBlockedNetworkRules(), &r.BlockedNetworkRuleRefs,
		func(names []any) ([]any, error) { return networkRuleRefs(r.MqlRuntime, names) })
}

func (r *mqlSnowflakeExternalAccessIntegration) allowedNetworkRuleRefs() ([]any, error) {
	return refsFromNameList(r.GetAllowedNetworkRules(), &r.AllowedNetworkRuleRefs,
		func(names []any) ([]any, error) { return networkRuleRefs(r.MqlRuntime, names) })
}

func (r *mqlSnowflakeExternalAccessIntegration) allowedAuthenticationSecretRefs() ([]any, error) {
	return refsFromNameList(r.GetAllowedAuthenticationSecrets(), &r.AllowedAuthenticationSecretRefs,
		func(names []any) ([]any, error) { return secretRefs(r.MqlRuntime, names) })
}
