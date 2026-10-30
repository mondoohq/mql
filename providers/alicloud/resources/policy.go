// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// policyStatement is one normalized permission statement out of an Alibaba
// Cloud policy document. RAM policies, RAM role trust policies and OSS bucket
// policies all share this envelope, so one parser serves all three: RAM
// permission policies carry Action plus Resource, trust policies carry
// Principal, and bucket policies carry both.
type policyStatement struct {
	Effect      string
	Action      []string
	NotAction   []string
	Resource    []string
	NotResource []string
	// Principal maps a principal kind (RAM, Service, Federated) to its
	// entries. A bare principal list, as OSS bucket policies write it, is
	// stored under the empty key.
	Principal map[string][]string
	Condition map[string]any
}

// policyDocument is the wire shape of a policy document. Every list-valued
// member may arrive as a single string instead of an array, and Statement
// itself may be a lone object, so each is decoded through json.RawMessage and
// normalized rather than bound directly.
type policyDocument struct {
	Version   string          `json:"Version"`
	Statement json.RawMessage `json:"Statement"`
}

type rawStatement struct {
	Effect      string          `json:"Effect"`
	Action      json.RawMessage `json:"Action"`
	NotAction   json.RawMessage `json:"NotAction"`
	Resource    json.RawMessage `json:"Resource"`
	NotResource json.RawMessage `json:"NotResource"`
	Principal   json.RawMessage `json:"Principal"`
	Condition   map[string]any  `json:"Condition"`
}

// parsePolicyDocument decodes a policy document into its statements. An empty
// document yields no statements and no error, which is the common case for a
// bucket that has no policy attached.
func parsePolicyDocument(doc string) ([]policyStatement, error) {
	if strings.TrimSpace(doc) == "" {
		return nil, nil
	}

	var parsed policyDocument
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil, fmt.Errorf("cannot parse policy document: %w", err)
	}
	if len(parsed.Statement) == 0 {
		return nil, nil
	}

	raws, err := decodeStatementList(parsed.Statement)
	if err != nil {
		return nil, err
	}

	res := make([]policyStatement, 0, len(raws))
	for _, raw := range raws {
		principal, err := decodePrincipal(raw.Principal)
		if err != nil {
			return nil, err
		}
		action, err := decodeStringList(raw.Action)
		if err != nil {
			return nil, err
		}
		notAction, err := decodeStringList(raw.NotAction)
		if err != nil {
			return nil, err
		}
		resource, err := decodeStringList(raw.Resource)
		if err != nil {
			return nil, err
		}
		notResource, err := decodeStringList(raw.NotResource)
		if err != nil {
			return nil, err
		}
		res = append(res, policyStatement{
			Effect:      raw.Effect,
			Action:      action,
			NotAction:   notAction,
			Resource:    resource,
			NotResource: notResource,
			Principal:   principal,
			Condition:   raw.Condition,
		})
	}
	return res, nil
}

// decodeStatementList accepts Statement as either an array of statements or a
// single statement object.
func decodeStatementList(raw json.RawMessage) ([]rawStatement, error) {
	var list []rawStatement
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var single rawStatement
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, fmt.Errorf("cannot parse policy statement: %w", err)
	}
	return []rawStatement{single}, nil
}

// decodeStringList accepts a member written as either a JSON string or an
// array of strings, which the policy grammar allows interchangeably.
func decodeStringList(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var single string
	if err := json.Unmarshal(raw, &single); err != nil {
		return nil, fmt.Errorf("cannot parse policy string list: %w", err)
	}
	return []string{single}, nil
}

// decodePrincipal accepts the three shapes a Principal takes: the keyed object
// a RAM trust policy writes, the bare array an OSS bucket policy writes, and a
// lone string. The latter two land under the empty key.
func decodePrincipal(raw json.RawMessage) (map[string][]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}

	var keyed map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keyed); err == nil {
		res := make(map[string][]string, len(keyed))
		for k, v := range keyed {
			entries, err := decodeStringList(v)
			if err != nil {
				return nil, err
			}
			res[k] = entries
		}
		return res, nil
	}

	entries, err := decodeStringList(raw)
	if err != nil {
		return nil, fmt.Errorf("cannot parse policy principal: %w", err)
	}
	return map[string][]string{"": entries}, nil
}

// isAllow reports whether the statement grants rather than denies. The effect
// is compared case-insensitively because the grammar accepts either casing.
func (s policyStatement) isAllow() bool {
	return strings.EqualFold(strings.TrimSpace(s.Effect), "Allow")
}

// grantsAllActions reports whether the action list covers every action, which
// only the bare "*" does. A service wildcard such as "oss:*" does not.
func grantsAllActions(actions []string) bool {
	for _, a := range actions {
		if strings.TrimSpace(a) == "*" {
			return true
		}
	}
	return false
}

// grantsAllResources reports whether the resource list covers every resource.
// That is either the bare "*" or a fully wildcarded ACS resource name such as
// "acs:*:*:*:*". A resource scoped to one service, such as "acs:oss:*:*:*",
// does not qualify.
func grantsAllResources(resources []string) bool {
	for _, r := range resources {
		r = strings.TrimSpace(r)
		if r == "*" {
			return true
		}
		rest, ok := strings.CutPrefix(r, "acs:")
		if !ok {
			continue
		}
		allStars := true
		for segment := range strings.SplitSeq(rest, ":") {
			if segment != "*" {
				allStars = false
				break
			}
		}
		if allStars {
			return true
		}
	}
	return false
}

// hasWildcardAction reports whether any entry carries a "*", covering both the
// full wildcard and prefix forms such as "ecs:Describe*". A prefix wildcard is
// worth flagging because it also grants actions the service has not shipped yet.
func hasWildcardAction(entries []string) bool {
	for _, e := range entries {
		if strings.Contains(e, "*") {
			return true
		}
	}
	return false
}

// resourceIsUnscoped reports whether an ACS resource name selects everything
// its service offers rather than a named resource.
//
// Only the relative-id, the fifth field of
// acs:<service>:<region>:<account>:<relative-id>, is examined. The region and
// account fields are wildcarded in most real policies, so treating any "*" in
// the name as unscoped would flag nearly every statement ever written:
// "acs:oss:*:*:mybucket/*" names one bucket, while "acs:oss:*:*:*" names all of
// OSS.
func resourceIsUnscoped(resource string) bool {
	resource = strings.TrimSpace(resource)
	if resource == "*" {
		return true
	}
	rest, ok := strings.CutPrefix(resource, "acs:")
	if !ok {
		return false
	}
	// the limit of 4 is deliberate, not an off-by-one: it stops the split at
	// the relative-id so a relative-id that itself contains colons, as in
	// "acs:ram::123:role/admin:extra", stays whole in the final field
	fields := strings.SplitN(rest, ":", 4)
	if len(fields) < 4 {
		// a truncated name such as "acs:*" carries no relative-id to narrow it
		return true
	}
	relativeID := strings.TrimSpace(fields[3])
	return relativeID == "" || relativeID == "*"
}

// hasUnscopedResource reports whether any entry selects a whole service rather
// than a named resource.
func hasUnscopedResource(entries []string) bool {
	return slices.ContainsFunc(entries, resourceIsUnscoped)
}

// policyAllowsAdminAccess reports whether the statements grant every action on
// every resource. A statement narrowed by NotAction or NotResource is skipped
// because it carves an exception out of the grant. A Condition does not
// disqualify a statement: the grant is still unrestricted wherever the
// condition holds.
func policyAllowsAdminAccess(statements []policyStatement) bool {
	for _, s := range statements {
		if !s.isAllow() || len(s.NotAction) > 0 || len(s.NotResource) > 0 {
			continue
		}
		if grantsAllActions(s.Action) && grantsAllResources(s.Resource) {
			return true
		}
	}
	return false
}

// policyHasWildcardAction reports whether any granting statement names an
// action by wildcard rather than in full.
func policyHasWildcardAction(statements []policyStatement) bool {
	for _, s := range statements {
		if s.isAllow() && hasWildcardAction(s.Action) {
			return true
		}
	}
	return false
}

// policyHasUnscopedResource reports whether any granting statement applies to a
// whole service instead of to named resources.
func policyHasUnscopedResource(statements []policyStatement) bool {
	for _, s := range statements {
		if s.isAllow() && hasUnscopedResource(s.Resource) {
			return true
		}
	}
	return false
}

// policyGrantsAnonymousAccess reports whether any granting statement names "*"
// as a principal, which opens the resource to unauthenticated callers.
func policyGrantsAnonymousAccess(statements []policyStatement) bool {
	for _, s := range statements {
		if !s.isAllow() {
			continue
		}
		for _, entries := range s.Principal {
			for _, p := range entries {
				if strings.TrimSpace(p) == "*" {
					return true
				}
			}
		}
	}
	return false
}
