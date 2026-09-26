// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"google.golang.org/protobuf/proto"
)

// ArgsLookupPrefix is the prefix used to flag a recording IdsLookup key whose
// suffix is a hash of the resource init args rather than a request ID. It lets
// recording consumers tell "looked up by empty id" entries apart from real IDs
// that happen to look hash-shaped.
const ArgsLookupPrefix = "args:"

// HashArgs returns a deterministic hash for the given resource init args. It
// is used to disambiguate recordings of resources created by name + args
// (rather than by ID), so two `file(path: "/a")` and `file(path: "/b")` calls
// don't collide on an empty request ID. Returns an empty string when args is
// empty.
func HashArgs(args map[string]*Primitive) string {
	if len(args) == 0 {
		return ""
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	opts := proto.MarshalOptions{Deterministic: true}
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		raw, err := opts.Marshal(args[k])
		if err != nil {
			// fall back to the type+value bytes; deterministic for primitives,
			// and we never want hashing to error out.
			if v := args[k]; v != nil {
				h.Write([]byte(v.Type))
				h.Write([]byte{0})
				h.Write(v.Value)
			}
		} else {
			h.Write(raw)
		}
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// ArgsLookupID returns the synthetic request-ID used to index a recording
// entry when the resource was created by args with no caller-supplied ID.
// Returns an empty string when args is empty.
func ArgsLookupID(args map[string]*Primitive) string {
	hash := HashArgs(args)
	if hash == "" {
		return ""
	}
	return ArgsLookupPrefix + hash
}
