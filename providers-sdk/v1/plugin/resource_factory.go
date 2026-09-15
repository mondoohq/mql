// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
)

// ResolveResource turns a set of user-provided arguments into a resource,
// running the factory's init function when it has one. It is the shared body of
// the generated NewResource in every provider.
//
// Two concurrent calls that ask for the same resource with the same arguments
// run the init function once and share its result. Without that, both callers
// enter init, both spend the API call, and the loser's freshly built resource is
// thrown away on the way out -- the cache cannot prevent it, because the cache
// key is the resolved resource's MqlID, which is not knowable until init has
// already done the work. The argument set is knowable up front, and two calls
// with identical arguments must by definition produce the same resource, so it
// is a sound key to collapse on.
//
// Failures are shared with everyone waiting on that flight but are never
// cached: the flight is forgotten as soon as it completes, so the next caller
// tries again.
func ResolveResource(runtime *Runtime, name string, args map[string]*llx.RawData, f ResourceFactory) (Resource, error) {
	if f.Init == nil {
		return InstantiateResource(runtime, name, args, f)
	}

	key, ok := initFlightKey(name, args)
	if !ok {
		// The arguments do not reduce to a key we can compare safely, so we
		// resolve without deduplicating. Missing a chance to share work is
		// harmless; merging two different resources would not be.
		return initResource(runtime, name, args, f)
	}

	v, err, _ := runtime.flights().Do(key, func() (any, error) {
		return initResource(runtime, name, args, f)
	})
	// Comma-ok rather than a bare assertion: on the error path the factory may
	// hand back a nil resource, which arrives here as an untyped nil.
	res, _ := v.(Resource)
	return res, err
}

// InstantiateResource creates a resource from arguments that are already
// complete, skipping the factory's init function. It is the shared body of the
// generated CreateResource in every provider, used for resources built from
// lists and from recordings.
func InstantiateResource(runtime *Runtime, name string, args map[string]*llx.RawData, f ResourceFactory) (Resource, error) {
	res, err := f.Create(runtime, args)
	if err != nil {
		return nil, err
	}
	return cacheResource(runtime, name, res), nil
}

func initResource(runtime *Runtime, name string, args map[string]*llx.RawData, f ResourceFactory) (Resource, error) {
	cargs, res, err := f.Init(runtime, args)
	if err != nil {
		// The resource is returned alongside the error on purpose: some inits
		// report a partially resolved resource with a failure attached.
		return res, err
	}

	if res != nil {
		return cacheResource(runtime, name, res), nil
	}

	return InstantiateResource(runtime, name, cargs, f)
}

// cacheResource registers the resource under its id and returns whichever
// instance is canonical for that id. When another caller got there first, its
// instance wins and ours is dropped, so every reference in the graph points at
// one object and the fields memoized on it are visible to everyone.
func cacheResource(runtime *Runtime, name string, res Resource) Resource {
	id := name + "\x00" + res.MqlID()
	canonical, _ := runtime.Resources.GetOrSet(id, res)
	return canonical
}

// initFlightKey builds a comparison key for a resource name and its init
// arguments, reporting false when the arguments cannot be reduced to one.
//
// The key is only ever used to decide that two calls are asking for the same
// thing, so the two failure modes are not symmetric: refusing a key we could
// have built merely costs us a deduplication, while accepting a key that two
// different argument sets share would hand back the wrong resource. Every part
// is therefore length-prefixed, so no value can forge a separator, and any
// argument that is not a plain scalar refuses outright rather than guessing at
// a serialization.
func initFlightKey(name string, args map[string]*llx.RawData) (string, bool) {
	var b strings.Builder
	writeChunk(&b, name)

	if len(args) == 0 {
		return b.String(), true
	}

	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		arg := args[k]
		if arg == nil || arg.Error != nil {
			return "", false
		}
		scalar, ok := scalarKey(arg.Value)
		if !ok {
			return "", false
		}
		writeChunk(&b, k)
		// The type travels with the value so that the string "1" and the
		// integer 1 cannot collapse onto one key.
		writeChunk(&b, string(arg.Type))
		writeChunk(&b, scalar)
	}

	return b.String(), true
}

func writeChunk(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
}

// scalarKey renders the values that llx uses for scalar types. Anything else --
// resources, arrays, maps, dicts -- returns false, because comparing them means
// a deep walk whose cost and correctness are not worth the deduplication.
func scalarKey(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", true
	case string:
		return x, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case int64:
		return strconv.FormatInt(x, 10), true
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64), true
	case *time.Time:
		if x == nil {
			return "", true
		}
		return strconv.FormatInt(x.UnixNano(), 10), true
	default:
		return "", false
	}
}
