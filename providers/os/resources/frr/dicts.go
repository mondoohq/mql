// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package frr

// DirectivesAsDicts renders directives as plain maps, for resource fields
// that expose the raw lines of a block.
func DirectivesAsDicts(dirs []Directive) []any {
	out := make([]any, 0, len(dirs))
	for i := range dirs {
		d := &dirs[i]
		args := make([]any, 0, len(d.Args))
		for _, a := range d.Args {
			args = append(args, a)
		}
		out = append(out, map[string]any{
			"name":    d.Name,
			"args":    args,
			"negated": d.Negated,
			"line":    int64(d.Line),
			"file":    d.File,
			"raw":     d.Raw,
		})
	}
	return out
}

// PrefixListEntriesAsDicts renders prefix list entries as plain maps.
func PrefixListEntriesAsDicts(entries []PrefixListEntry) []any {
	out := make([]any, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		out = append(out, map[string]any{
			"seq":    e.Seq,
			"action": e.Action,
			"prefix": e.Prefix,
			"le":     e.Le,
			"ge":     e.Ge,
			"line":   int64(e.Line),
			"raw":    e.Raw,
		})
	}
	return out
}

// VNIsAsDicts renders the VNI blocks of an EVPN address family as plain maps.
func VNIsAsDicts(vnis []VNI) []any {
	out := make([]any, 0, len(vnis))
	for i := range vnis {
		v := &vnis[i]
		out = append(out, map[string]any{
			"vni":                v.ID,
			"routeTargetsImport": toAnySlice(v.RouteTargetsImport),
			"routeTargetsExport": toAnySlice(v.RouteTargetsExport),
		})
	}
	return out
}

func toAnySlice(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	return out
}

// VtyshUsersAsDicts renders vtysh users as plain maps.
func VtyshUsersAsDicts(users []VtyshUser) []any {
	out := make([]any, 0, len(users))
	for i := range users {
		u := &users[i]
		out = append(out, map[string]any{
			"name":       u.Name,
			"nopassword": u.NoPassword,
			"privilege":  u.Privilege,
		})
	}
	return out
}

// PolicyEntriesAsDicts renders the entries of a community list, an access
// list or an AS path access list as plain maps.
func PolicyEntriesAsDicts(entries []PolicyEntry) []any {
	out := make([]any, 0, len(entries))
	for i := range entries {
		e := &entries[i]
		out = append(out, map[string]any{
			"seq":    e.Seq,
			"action": e.Action,
			"value":  e.Value,
			"line":   int64(e.Line),
			"raw":    e.Raw,
		})
	}
	return out
}
