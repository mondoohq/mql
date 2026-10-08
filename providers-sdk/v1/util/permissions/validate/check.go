// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// manifest is the part of a *.permissions.json file the validator reads.
type manifest struct {
	Provider            string   `json:"provider"`
	Permissions         []string `json:"permissions"`
	OrgLevelPermissions []string `json:"org_level_permissions"`
	Details             []detail `json:"details"`
}

// detail is one API call the generator saw: the permission it derived, the
// service it belongs to and the SDK operation that produced it.
type detail struct {
	Permission string `json:"permission"`
	Service    string `json:"service"`
	Action     string `json:"action"`
	SourceFile string `json:"source_file"`
}

func readManifest(path string) (manifest, error) {
	var m manifest
	data, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("%s: %w", path, err)
	}
	if m.Provider == "" || len(m.Permissions) == 0 {
		return m, fmt.Errorf("%s: not a permission manifest", path)
	}
	return m, nil
}

// problem is one finding about one manifest entry.
type problem struct {
	Permission string
	Message    string
}

// result is the outcome of checking one manifest. The question it answers is
// whether the manifest can be used to build a role or policy. Total counts the
// entries and Valid the ones that can be used; the rest have one or more
// Problems (an entry can fail for several reasons, so Problems may have more
// lines than Total-Valid). Notes are entries that can be used but that the
// reader should know about.
type result struct {
	Provider string
	Total    int
	Valid    int
	Problems []problem // why an entry cannot be used: unknown, known as something else, not the action its operation needs
	// Notes are usable entries with a caveat: a GCP permission IAM refuses in
	// custom roles (grantable only through a predefined role), an alias of
	// another name, a deprecated name, an action spelled differently from the
	// reference. A custom role built from the manifest alone is refused for
	// the first kind, so it is called out.
	Notes []problem
}

func (r result) ok() bool {
	return len(r.Problems) == 0
}

// scoped is a manifest entry with the level it is listed at: "project" for the
// main list, "organization" for org_level_permissions. Only GCP distinguishes.
type scoped struct {
	perm, scope string
}

// checkManifest compares every permission in m against cat, and for AWS every
// operation in m against the actions AWS says authorize it.
func checkManifest(m manifest, cat *catalog) result {
	r := result{Provider: m.Provider}
	var entries []scoped
	for _, p := range m.Permissions {
		entries = append(entries, scoped{p, "project"})
	}
	for _, p := range m.OrgLevelPermissions {
		entries = append(entries, scoped{p, "organization"})
	}
	operations := checkOperations(m, cat)
	for _, e := range entries {
		r.Total++
		var msg, note string
		var ok bool
		switch m.Provider {
		case "gcp":
			msg, note, ok = judgeGCP(e, cat)
		case "azure":
			msg, note, ok = judgeAzure(e.perm, cat)
		default:
			msg, note, ok = judgeAWS(e.perm, cat)
		}
		// A real permission that is not the one its operation needs is as
		// unusable as an unknown one; the operation finding says which one is.
		r.Problems = append(r.Problems, operations[e.perm]...)
		switch {
		case ok && len(operations[e.perm]) == 0:
			r.Valid++
			if note != "" {
				r.Notes = append(r.Notes, problem{e.perm, note})
			}
		case ok:
		case msg != "":
			r.Problems = append(r.Problems, problem{e.perm, msg})
		default:
			r.Problems = append(r.Problems, problem{Permission: e.perm, Message: explain(m.Provider, e.perm, cat)})
		}
	}
	sort.Slice(r.Problems, func(i, j int) bool { return r.Problems[i].Permission < r.Problems[j].Permission })
	sort.Slice(r.Notes, func(i, j int) bool { return r.Notes[i].Permission < r.Notes[j].Permission })
	return r
}

// judgeAWS says what the Service Reference says about one action. An action
// spelled differently from the reference still works, IAM matches actions
// case-insensitively, but the manifest is what customers paste into policies,
// so the reference spelling is noted.
func judgeAWS(perm string, cat *catalog) (msg, note string, ok bool) {
	if cat.hasExact(perm) {
		return "", "", true
	}
	if canon, exists := cat.canonical(perm); exists {
		return "", fmt.Sprintf("usable, but the reference spells it %s", canon), true
	}
	return "", "", false
}

// judgeAzure says what the provider operation registry says about one
// operation: registered or not. Azure matches operations case-insensitively,
// and unlike AWS a spelling that differs from the registry's earns no note:
// the registry's own casing is inconsistent (microsoft.app/containerapps/read
// next to Microsoft.Insights/ActionGroups/Read), so 69 of the 362 manifest
// entries would be flagged for following the SDK's spelling instead.
func judgeAzure(perm string, cat *catalog) (msg, note string, ok bool) {
	_, ok = cat.canonical(perm)
	return "", "", ok
}

// judgeGCP says what Google's IAM API says about one manifest entry. ok is
// true when the entry can be used as listed (note then carries a caveat). ok
// false with a message means the name exists but cannot be used as listed;
// ok false with no message means the name is unknown at every scope.
func judgeGCP(e scoped, cat *catalog) (msg, note string, ok bool) {
	p, listed := cat.gcp[e.perm]
	if !listed {
		return "", "", false
	}
	if !p.hasScope(e.scope) {
		other := strings.Join(p.Scopes, " and ")
		switch e.scope {
		case "project":
			return fmt.Sprintf("exists, but only at %s scope: move it to org_level_permissions", other), "", false
		default:
			return fmt.Sprintf("exists, but only at %s scope: it is not an organization-level permission", other), "", false
		}
	}
	var notes []string
	if p.Support == "NOT_SUPPORTED" {
		notes = append(notes, "IAM refuses it in a custom role: grantable only through a predefined role")
	}
	if p.Primary != "" {
		notes = append(notes, "an alias of "+p.Primary)
	}
	if p.Stage == "DEPRECATED" {
		notes = append(notes, "Google marks it DEPRECATED")
	}
	if len(notes) > 0 {
		return "", "usable, but " + strings.Join(notes, "; "), true
	}
	return "", "", true
}

// explain says what is unknown about perm: a name the catalog has under a
// different spelling (GCP is case-sensitive), the whole name, or already its
// service, which usually means a wrong prefix.
func explain(provider, perm string, cat *catalog) string {
	if canon, ok := cat.canonical(perm); ok && canon != perm {
		return fmt.Sprintf("spelled %q in the catalog", canon)
	}
	noun := map[string]string{"aws": "IAM action", "gcp": "IAM permission", "azure": "registered operation"}[provider]
	if !cat.hasService(perm) {
		kind := map[string]string{"aws": "IAM service prefix", "gcp": "service", "azure": "resource provider namespace"}[provider]
		return fmt.Sprintf("not a known %s: %s %q", noun, kind, serviceOf(perm))
	}
	return "not a known " + noun
}

// checkOperations reports manifest entries whose SDK operation the cloud maps
// to a different action than the manifest names. Only AWS publishes such a
// mapping, and only for most operations; an operation the catalog has no
// mapping for is not judged here. A role built from such an entry can be
// created, but does not let the scan make the call.
func checkOperations(m manifest, cat *catalog) map[string][]problem {
	out := map[string][]problem{}
	seen := map[string]bool{}
	for _, d := range m.Details {
		key := d.Service + "/" + d.Action
		authorized, ok := cat.operations[key]
		if !ok || len(authorized) == 0 || seen[key+"="+d.Permission] {
			continue
		}
		seen[key+"="+d.Permission] = true
		match := false
		for _, a := range authorized {
			if a == d.Permission {
				match = true
				break
			}
		}
		if !match {
			out[d.Permission] = append(out[d.Permission], problem{d.Permission, fmt.Sprintf("the %s operation %s is authorized by %s, not by this (%s)",
				d.Service, d.Action, strings.Join(authorized, " and "), d.SourceFile)})
		}
	}
	return out
}
