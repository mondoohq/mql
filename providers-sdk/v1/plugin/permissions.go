// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"encoding/json"
	"path"
	"runtime"
	"sort"
	"sync"
)

// PermissionIndex is the fallback for a refusal whose call site did not name
// the permission it needed (ADR 046 §4). It reads the provider's own
// *.permissions.json, which lists every API call the generator found with the
// source file it is in, so a failure in a known file yields the permissions
// that file calls for.
//
// A provider embeds its manifest and asks the index from its classifier, for
// the file the classifier was called from:
//
//	//go:embed aws.permissions.json
//	var awsPermissionsManifest []byte
//
//	var awsPermissions = plugin.NewPermissionIndex(awsPermissionsManifest)
//
//	func classifyAwsError(err error, permissions ...string) error {
//		...
//		if len(permissions) == 0 {
//			permissions = awsPermissions.LookupCaller(1, operationOf(err))
//		}
//		return llx.Forbidden(err, llx.WithPermissions(permissions...))
//	}
//
// The permissions a call site names always win: the index only knows files,
// and a file can call for many permissions. Naming the operation the error
// reports narrows the set to that call. An empty result is always allowed.
type PermissionIndex struct {
	manifest []byte
	load     func() (map[string][]permissionEntry, error)
}

type permissionEntry struct {
	permission string
	action     string
}

// NewPermissionIndex returns an index over a permissions.json manifest. The
// manifest is parsed on first use, so a provider that never sees a refusal
// never pays for it.
func NewPermissionIndex(manifest []byte) *PermissionIndex {
	idx := &PermissionIndex{manifest: manifest}
	idx.load = sync.OnceValues(idx.parse)
	return idx
}

func (idx *PermissionIndex) parse() (map[string][]permissionEntry, error) {
	var m struct {
		Details []struct {
			Permission string `json:"permission"`
			Action     string `json:"action"`
			SourceFile string `json:"source_file"`
		} `json:"details"`
	}
	if err := json.Unmarshal(idx.manifest, &m); err != nil {
		return nil, err
	}
	byFile := map[string][]permissionEntry{}
	for _, d := range m.Details {
		if d.Permission == "" || d.SourceFile == "" {
			continue
		}
		file := path.Base(d.SourceFile)
		byFile[file] = append(byFile[file], permissionEntry{permission: d.Permission, action: d.Action})
	}
	return byFile, nil
}

// Err reports whether the manifest could be read. Lookups on a manifest that
// could not be read return nothing, which is allowed but hides a build
// problem, so a provider tests this once.
func (idx *PermissionIndex) Err() error {
	if idx == nil {
		return nil
	}
	_, err := idx.load()
	return err
}

// Lookup returns the permissions file calls for, sorted and without
// duplicates. file is matched by its base name. When operation is not empty
// and names an API call in file, only that call's permissions are returned;
// when it names none, all of the file's are, since the call may have been
// missed by the generator or renamed by an override. nil when the file is
// unknown.
func (idx *PermissionIndex) Lookup(file string, operation string) []string {
	if idx == nil {
		return nil
	}
	byFile, err := idx.load()
	if err != nil {
		return nil
	}
	entries := byFile[path.Base(file)]
	if len(entries) == 0 {
		return nil
	}

	var matched []string
	if operation != "" {
		for _, e := range entries {
			if e.action == operation {
				matched = append(matched, e.permission)
			}
		}
	}
	if len(matched) == 0 {
		for _, e := range entries {
			matched = append(matched, e.permission)
		}
	}
	return sortedUnique(matched)
}

// LookupCaller is Lookup for the file of a function on the caller's stack.
// skip 0 is the function calling LookupCaller, 1 its caller, and so on, as in
// runtime.Caller. A classifier called directly from the failing call site
// passes 1.
func (idx *PermissionIndex) LookupCaller(skip int, operation string) []string {
	if idx == nil {
		return nil
	}
	_, file, _, ok := runtime.Caller(skip + 1)
	if !ok {
		return nil
	}
	return idx.Lookup(file, operation)
}

func sortedUnique(s []string) []string {
	sort.Strings(s)
	res := s[:0]
	for i, v := range s {
		if i > 0 && v == s[i-1] {
			continue
		}
		res = append(res, v)
	}
	return res
}
