// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/providers/bitwarden/connection"
)

func (r *mqlBitwarden) id() (string, error) {
	return "bitwarden", nil
}

// conn returns the Bitwarden connection backing this runtime.
func (r *mqlBitwarden) conn() *connection.BitwardenConnection {
	return r.MqlRuntime.Connection.(*connection.BitwardenConnection)
}

// policies lists every security policy configured for the organization.
func (r *mqlBitwarden) policies() ([]any, error) {
	conn := r.conn()

	policies, err := conn.Client().ListPolicies(context.Background())
	if err != nil {
		return nil, err
	}

	var all []any
	for _, p := range policies {
		res, err := newMqlBitwardenPolicy(r.MqlRuntime, p)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// members lists every member of the organization.
func (r *mqlBitwarden) members() ([]any, error) {
	conn := r.conn()

	members, err := conn.ListMembersCached(context.Background())
	if err != nil {
		return nil, err
	}

	var all []any
	for _, m := range members {
		res, err := newMqlBitwardenMember(r.MqlRuntime, m)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// collections lists every collection defined in the organization.
func (r *mqlBitwarden) collections() ([]any, error) {
	conn := r.conn()

	collections, err := conn.Client().ListCollections(context.Background())
	if err != nil {
		return nil, err
	}

	var all []any
	for _, c := range collections {
		res, err := newMqlBitwardenCollection(r.MqlRuntime, c)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// groups lists every group defined in the organization.
func (r *mqlBitwarden) groups() ([]any, error) {
	conn := r.conn()

	groups, err := conn.Client().ListGroups(context.Background())
	if err != nil {
		return nil, err
	}

	var all []any
	for _, g := range groups {
		res, err := newMqlBitwardenGroup(r.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
