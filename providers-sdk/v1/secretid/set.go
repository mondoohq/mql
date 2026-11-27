// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package secretid

// Set holds secret ids for membership tests, such as a space's honeytokens or
// the entries of a vault. Ids are compared exactly, version prefix included.
//
// A Set is safe for concurrent reads; Add must not run concurrently with any
// other method.
type Set struct {
	m map[string]struct{}
}

// NewSet returns a set holding ids. Empty strings are ignored.
func NewSet(ids ...string) *Set {
	s := &Set{m: make(map[string]struct{}, len(ids))}
	for _, id := range ids {
		s.Add(id)
	}
	return s
}

// Add adds id to the set. An empty id is ignored, so a failed computation
// never makes every unidentified value a member.
func (s *Set) Add(id string) {
	if id == "" {
		return
	}
	s.m[id] = struct{}{}
}

// Contains reports whether id is in the set. It is false for an empty id and
// for a nil set.
func (s *Set) Contains(id string) bool {
	if s == nil || id == "" {
		return false
	}
	_, ok := s.m[id]
	return ok
}

// ContainsAny reports whether any of ids is in the set. Pass the ids a value
// has under the current and the previous key (IDs) during a rotation window.
func (s *Set) ContainsAny(ids []string) bool {
	for _, id := range ids {
		if s.Contains(id) {
			return true
		}
	}
	return false
}

// Len returns the number of ids in the set.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}
