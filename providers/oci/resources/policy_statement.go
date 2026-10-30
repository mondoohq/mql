// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// ociPolicyStatement is one IAM policy statement split into its grammatical
// parts. Every field is optional: OCI accepts statement text the provider does
// not model, and a policy that mixes a recognized statement with an unusual one
// must still report the recognized parts rather than failing whole.
type ociPolicyStatement struct {
	Raw          string
	Effect       string
	SubjectType  string
	SubjectNames []string
	Verb         string
	ResourceType string
	ScopeType    string
	ScopeName    string
	Condition    string
}

// Statement keywords are matched case-insensitively and reported lowercased, so
// `Allow` and `allow` produce the same value and a query does not have to
// account for how the policy author capitalized them.
var (
	ociPolicyEffects = map[string]bool{
		"allow":   true,
		"endorse": true,
		"admit":   true,
		"define":  true,
	}
	ociPolicySubjectKinds = map[string]bool{
		"group":         true,
		"dynamic-group": true,
		"service":       true,
		"tenancy":       true,
	}
	// Subjects that stand alone and name no principal.
	ociPolicyBareSubjects = map[string]bool{
		"any-user":  true,
		"any-group": true,
	}
)

// parseOciPolicyStatement splits a single IAM policy statement into its parts.
//
// The grammar it recognizes is
//
//	<effect> <subject> to <verb> <resource-type> in <scope> [where <condition>]
//
// plus the `define <kind> <name> as <ocid>` form, which names a principal
// instead of granting access and so reports no verb, resource type, or scope.
//
// It never reports an error. A statement it cannot place leaves the
// corresponding fields empty and keeps the original text in Raw, because the
// alternative - failing the statement - would drop the statements around it and
// make a policy that contains one unusual line look like a policy that grants
// nothing.
func parseOciPolicyStatement(raw string) ociPolicyStatement {
	stmt := ociPolicyStatement{Raw: raw}

	// The condition is free-form and may itself contain the words this parser
	// keys on, so it is removed before tokenizing the rest.
	body, condition := splitOciPolicyCondition(raw)
	stmt.Condition = condition

	tokens := strings.Fields(body)
	if len(tokens) == 0 {
		return stmt
	}

	effect := strings.ToLower(tokens[0])
	if !ociPolicyEffects[effect] {
		// Not a statement shape we recognize. Raw and any condition still stand.
		return stmt
	}
	stmt.Effect = effect
	tokens = tokens[1:]

	if effect == "define" {
		stmt.SubjectType, stmt.SubjectNames = parseOciPolicyDefineSubject(tokens)
		return stmt
	}

	// `admit <subject> of definedtenancy <name> to ...` names the tenancy the
	// subject comes from between the subject and the verb. The subject scan
	// stops at `of` so that name does not get read as another principal.
	subjectTokens, rest := cutOciPolicyTokens(tokens, "to", "of")
	stmt.SubjectType, stmt.SubjectNames = parseOciPolicySubject(subjectTokens)

	// Skip anything between the subject and `to` (the admit clause above).
	if len(rest) > 0 && !strings.EqualFold(rest[0], "to") {
		_, rest = cutOciPolicyTokens(rest, "to")
	}
	if len(rest) == 0 || !strings.EqualFold(rest[0], "to") {
		return stmt
	}
	tokens = rest[1:]

	if len(tokens) == 0 {
		return stmt
	}
	stmt.Verb = strings.ToLower(tokens[0])
	tokens = tokens[1:]

	if len(tokens) == 0 {
		return stmt
	}
	stmt.ResourceType = strings.ToLower(tokens[0])
	tokens = tokens[1:]

	if len(tokens) == 0 || !strings.EqualFold(tokens[0], "in") {
		return stmt
	}
	stmt.ScopeType, stmt.ScopeName = parseOciPolicyScope(tokens[1:])

	return stmt
}

// splitOciPolicyCondition separates the statement body from the text after
// `where`. Only the first top-level `where` counts: the condition grammar
// nests with `any {...}` and `all {...}` but does not reintroduce the keyword
// at a level this parser needs to track.
func splitOciPolicyCondition(raw string) (body, condition string) {
	tokens := strings.Fields(raw)
	for i, tok := range tokens {
		if strings.EqualFold(tok, "where") {
			return strings.Join(tokens[:i], " "), strings.Join(tokens[i+1:], " ")
		}
	}
	return raw, ""
}

// cutOciPolicyTokens splits at the first token matching any of the stop words,
// returning the tokens before it and the tokens from the stop word onward. When
// no stop word appears, everything is returned as the head.
func cutOciPolicyTokens(tokens []string, stops ...string) (head, tail []string) {
	for i, tok := range tokens {
		for _, stop := range stops {
			if strings.EqualFold(tok, stop) {
				return tokens[:i], tokens[i:]
			}
		}
	}
	return tokens, nil
}

// parseOciPolicySubject reads the principal clause of a statement:
//
//	any-user | any-group
//	group <name>[,<name>...] | group id <ocid>[,<ocid>...]
//	dynamic-group <name> | service <name>
func parseOciPolicySubject(tokens []string) (subjectType string, names []string) {
	if len(tokens) == 0 {
		return "", nil
	}

	kind := strings.ToLower(tokens[0])
	if ociPolicyBareSubjects[kind] {
		return kind, nil
	}
	if !ociPolicySubjectKinds[kind] {
		return "", nil
	}

	rest := tokens[1:]
	// The `id` form names principals by OCID. They are reported in the same
	// field: both forms identify the principal, and the accessors match on
	// either, so splitting them would only make queries pick a field.
	if len(rest) > 0 && strings.EqualFold(rest[0], "id") {
		rest = rest[1:]
	}

	return kind, splitOciPolicyNameList(rest)
}

// parseOciPolicyDefineSubject reads `define <kind> <name> as <ocid>`. The OCID
// being bound is left in Raw: a define statement grants nothing, so the useful
// query is which tenancies and groups a policy names, not what they resolve to.
func parseOciPolicyDefineSubject(tokens []string) (subjectType string, names []string) {
	if len(tokens) == 0 {
		return "", nil
	}
	kind := strings.ToLower(tokens[0])
	if !ociPolicySubjectKinds[kind] {
		return "", nil
	}
	nameTokens, _ := cutOciPolicyTokens(tokens[1:], "as")
	return kind, splitOciPolicyNameList(nameTokens)
}

// splitOciPolicyNameList flattens a principal list. OCI accepts the names
// comma-separated with or without spaces around the commas, so the tokens are
// rejoined before splitting.
func splitOciPolicyNameList(tokens []string) []string {
	if len(tokens) == 0 {
		return nil
	}
	var names []string
	for part := range strings.SplitSeq(strings.Join(tokens, " "), ",") {
		if name := strings.TrimSpace(part); name != "" {
			names = append(names, name)
		}
	}
	return names
}

// parseOciPolicyScope reads the clause after `in`:
//
//	tenancy | any-tenancy
//	compartment <name> | compartment id <ocid>
func parseOciPolicyScope(tokens []string) (scopeType, scopeName string) {
	if len(tokens) == 0 {
		return "", ""
	}

	switch kind := strings.ToLower(tokens[0]); kind {
	case "tenancy", "any-tenancy":
		return kind, ""
	case "compartment":
		rest := tokens[1:]
		if len(rest) > 0 && strings.EqualFold(rest[0], "id") {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return kind, ""
		}
		return kind, rest[0]
	default:
		return "", ""
	}
}

// ociPolicyStatementIsOCID reports whether a subject or scope name is an OCID
// rather than a display name, which decides how the accessors resolve it.
func ociPolicyStatementIsOCID(value string) bool {
	return strings.HasPrefix(value, "ocid1.")
}

// parsedStatements splits each line of the policy into its parts. The statement
// text is already on the policy, so this costs no API call.
func (o *mqlOciIdentityPolicy) parsedStatements() ([]any, error) {
	raws := o.GetStatements()
	if raws.Error != nil {
		return nil, raws.Error
	}

	res := make([]any, 0, len(raws.Data))
	for i := range raws.Data {
		text, ok := raws.Data[i].(string)
		if !ok {
			continue
		}
		stmt := parseOciPolicyStatement(text)

		// The cache key is the statement's position in the policy. A policy may
		// repeat a statement verbatim, so the text alone would alias the copies
		// onto one resource and shorten the list.
		id := o.Id.Data + "/statement/" + strconv.Itoa(i)

		mqlStmt, err := CreateResource(o.MqlRuntime, "oci.identity.policy.statement", map[string]*llx.RawData{
			"__id":         llx.StringData(id),
			"raw":          llx.StringData(stmt.Raw),
			"effect":       llx.StringData(stmt.Effect),
			"subjectType":  llx.StringData(stmt.SubjectType),
			"subjectNames": llx.ArrayData(stringsToAny(stmt.SubjectNames), types.String),
			"verb":         llx.StringData(stmt.Verb),
			"resourceType": llx.StringData(stmt.ResourceType),
			"scopeType":    llx.StringData(stmt.ScopeType),
			"scopeName":    llx.StringData(stmt.ScopeName),
			"condition":    llx.StringData(stmt.Condition),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlStmt)
	}

	return res, nil
}

func (a *mqlOciIdentityPolicyStatement) groups() ([]any, error) {
	if a.SubjectType.Data != "group" {
		return []any{}, nil
	}
	items, err := ociServiceCollection(a.MqlRuntime, "oci.identity", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciIdentity).GetGroups()
	})
	if err != nil {
		return nil, err
	}

	return ociMatchPolicyPrincipals(a.SubjectNames.Data, items, func(raw any) (id, name string, ok bool) {
		group, ok := raw.(*mqlOciIdentityGroup)
		if !ok {
			return "", "", false
		}
		return group.Id.Data, group.Name.Data, true
	}), nil
}

func (a *mqlOciIdentityPolicyStatement) dynamicGroups() ([]any, error) {
	if a.SubjectType.Data != "dynamic-group" {
		return []any{}, nil
	}
	items, err := ociServiceCollection(a.MqlRuntime, "oci.identity", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciIdentity).GetDynamicGroups()
	})
	if err != nil {
		return nil, err
	}

	return ociMatchPolicyPrincipals(a.SubjectNames.Data, items, func(raw any) (id, name string, ok bool) {
		group, ok := raw.(*mqlOciIdentityDynamicGroup)
		if !ok {
			return "", "", false
		}
		return group.Id.Data, group.Name.Data, true
	}), nil
}

// ociMatchPolicyPrincipals resolves the names a statement's subject clause
// carries against principals the tenancy already listed.
//
// Matching an already-materialized collection rather than resolving each name
// through NewResource is deliberate: neither group resource has an Init, so
// NewResource would build a husk with every field unset and cache it under the
// real OCID, where a later query would receive it in place of the populated
// instance. Filtering the list also costs no additional API call.
//
// Names are compared case-insensitively because OCI treats IAM principal names
// that way, so a statement may capitalize a group differently than the group
// itself does.
func ociMatchPolicyPrincipals(names []any, items []any, identify func(any) (id, name string, ok bool)) []any {
	res := []any{}
	for _, rawName := range names {
		want, ok := rawName.(string)
		if !ok || want == "" {
			continue
		}
		byOCID := ociPolicyStatementIsOCID(want)

		for _, item := range items {
			id, name, ok := identify(item)
			if !ok {
				continue
			}
			if byOCID {
				if id == want {
					res = append(res, item)
					break
				}
				continue
			}
			if strings.EqualFold(name, want) {
				res = append(res, item)
				break
			}
		}
	}
	return res
}

func (a *mqlOciIdentityPolicyStatement) compartment() (*mqlOciCompartment, error) {
	// A statement scoped to the tenancy names no compartment. The field has to
	// be marked resolved-and-null before returning, or the runtime treats it as
	// never fetched.
	markNull := func() (*mqlOciCompartment, error) {
		a.Compartment.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	if a.ScopeType.Data != "compartment" || a.ScopeName.Data == "" {
		return markNull()
	}
	scope := a.ScopeName.Data

	// The `compartment id <ocid>` form addresses the compartment directly, so it
	// goes through the Init, which reads compartments the tenancy listing may
	// not cover.
	if ociPolicyStatementIsOCID(scope) {
		res, err := NewResource(a.MqlRuntime, "oci.compartment", map[string]*llx.RawData{
			"id": llx.StringData(scope),
		})
		if err != nil {
			return nil, err
		}
		compartment, ok := res.(*mqlOciCompartment)
		if !ok {
			return markNull()
		}
		return compartment, nil
	}

	items, err := ociServiceCollection(a.MqlRuntime, "oci", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOci).GetCompartments()
	})
	if err != nil {
		return nil, err
	}

	// A nested scope is written as a colon-separated path, of which only the
	// last segment is the compartment's own name.
	segments := strings.Split(scope, ":")
	want := segments[len(segments)-1]

	var match *mqlOciCompartment
	for _, item := range items {
		compartment, ok := item.(*mqlOciCompartment)
		if !ok {
			continue
		}
		if !strings.EqualFold(compartment.Name.Data, want) {
			continue
		}
		if match != nil {
			// Compartment names repeat across branches of the tree, so a bare
			// name can be ambiguous. Reporting one of the candidates would
			// attribute the grant to a compartment it may not apply to;
			// scopeName still carries the path the statement named.
			return markNull()
		}
		match = compartment
	}

	if match == nil {
		return markNull()
	}
	return match, nil
}

type mqlOciIdentityPolicyInternal struct {
	ociCompartmentRef
}
