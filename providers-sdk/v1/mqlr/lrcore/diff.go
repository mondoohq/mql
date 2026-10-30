// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"fmt"
	"sort"

	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

// typeLabel renders a schema type for a human. Types are stored as a tag byte
// plus a name, so printing one raw gives an unreadable control character where
// the author expects to read "string".
func typeLabel(t string) string {
	if t == "" {
		return "<none>"
	}
	return types.Type(t).Label()
}

// Schema evolution is only safe if someone notices it happening. Codegen is the
// one moment that holds both schemas -- the committed *.resources.json and the
// one just generated from the edited .lr -- so it is where a breaking change can
// be caught in the author's own PR instead of on a customer's older client
// (ADR 040 part 5).
//
// The classification is deliberately conservative: anything that could make a
// name or a type stop resolving the way it did is breaking, and only genuine
// additions are additive. A false "breaking" costs an author one acknowledgment;
// a false "additive" ships silent breakage.

type ChangeKind string

const (
	// ChangeAdditive is a change no existing content can notice.
	ChangeAdditive ChangeKind = "additive"
	// ChangeBreaking is a change that can stop existing content from resolving,
	// or resolve it to something else. In phase 2 these require a migration
	// lens; for now they are reported.
	ChangeBreaking ChangeKind = "breaking"
)

// Change is one classified difference between two schemas.
type Change struct {
	Kind ChangeKind
	// Path is the resource or resource.field the change is about.
	Path string
	// Detail says what changed, in terms an author can act on.
	Detail string
}

func (c Change) String() string {
	return string(c.Kind) + ": " + c.Path + " - " + c.Detail
}

// DiffSchemas classifies every difference between a previously-committed schema
// and a freshly generated one. Results are sorted by path so the output is
// stable across runs and reviewable in a diff.
//
// Documentation-only fields (title, desc), provenance (provider,
// min_provider_version) and presentation (defaults, context) are ignored: they
// change constantly and cannot break content.
func DiffSchemas(old *resources.Schema, nu *resources.Schema) []Change {
	if old == nil || nu == nil {
		return nil
	}

	var changes []Change
	add := func(kind ChangeKind, path string, format string, args ...any) {
		changes = append(changes, Change{Kind: kind, Path: path, Detail: fmt.Sprintf(format, args...)})
	}

	for _, name := range sortedKeys(old.Resources) {
		before := old.Resources[name]
		after, ok := nu.Resources[name]
		if !ok {
			// An alias is a name users can write, so losing one breaks content
			// exactly as losing the resource does.
			if before != nil && before.Id != name {
				add(ChangeBreaking, name, "alias for %q removed", before.Id)
			} else {
				add(ChangeBreaking, name, "resource removed")
			}
			continue
		}
		if before == nil || after == nil {
			continue
		}
		diffResource(before, after, name, add)
	}

	for _, name := range sortedKeys(nu.Resources) {
		if _, ok := old.Resources[name]; ok {
			continue
		}
		after := nu.Resources[name]
		if after != nil && after.Id != name {
			add(ChangeAdditive, name, "alias for %q added", after.Id)
		} else {
			add(ChangeAdditive, name, "resource added")
		}
	}

	sort.SliceStable(changes, func(i, j int) bool {
		if changes[i].Path != changes[j].Path {
			return changes[i].Path < changes[j].Path
		}
		return changes[i].Detail < changes[j].Detail
	})
	return changes
}

type addFunc func(kind ChangeKind, path string, format string, args ...any)

func diffResource(before *resources.ResourceInfo, after *resources.ResourceInfo, name string, add addFunc) {
	if before.ListType != after.ListType {
		add(ChangeBreaking, name, "list type changed from %q to %q",
			typeLabel(before.ListType), typeLabel(after.ListType))
	}
	// Making a resource private takes it out of reach of existing queries.
	if !before.Private && after.Private {
		add(ChangeBreaking, name, "resource became private")
	}
	if before.Private && !after.Private {
		add(ChangeAdditive, name, "resource became public")
	}
	if before.Maturity != after.Maturity {
		add(ChangeAdditive, name, "maturity changed from %q to %q", before.Maturity, after.Maturity)
	}
	if before.ReplacedBy != after.ReplacedBy {
		add(ChangeAdditive, name, "replacement changed from %q to %q", before.ReplacedBy, after.ReplacedBy)
	}

	diffInit(before.Init, after.Init, name, add)

	for _, fname := range sortedKeys(before.Fields) {
		path := name + "." + fname
		bf := before.Fields[fname]
		af, ok := after.Fields[fname]
		if !ok {
			add(ChangeBreaking, path, "field removed")
			continue
		}
		if bf == nil || af == nil {
			continue
		}
		if bf.Type != af.Type {
			// The whole reason this gate exists: a type is baked into the
			// bytecode and folded into the content checksum, so changing one
			// changes the identity of every query that touches the field.
			add(ChangeBreaking, path, "type changed from %q to %q",
				typeLabel(bf.Type), typeLabel(af.Type))
		}
		if !bf.IsPrivate && af.IsPrivate {
			add(ChangeBreaking, path, "field became private")
		}
		if bf.IsPrivate && !af.IsPrivate {
			add(ChangeAdditive, path, "field became public")
		}
		if !bf.IsMandatory && af.IsMandatory {
			add(ChangeBreaking, path, "field became mandatory")
		}
		if bf.IsMandatory && !af.IsMandatory {
			add(ChangeAdditive, path, "field became optional")
		}
		if bf.Maturity != af.Maturity {
			add(ChangeAdditive, path, "maturity changed from %q to %q", bf.Maturity, af.Maturity)
		}
		if bf.ReplacedBy != af.ReplacedBy {
			add(ChangeAdditive, path, "replacement changed from %q to %q", bf.ReplacedBy, af.ReplacedBy)
		}
	}

	for _, fname := range sortedKeys(after.Fields) {
		if _, ok := before.Fields[fname]; !ok {
			add(ChangeAdditive, name+"."+fname, "field added")
		}
	}
}

// diffInit compares init signatures positionally, because that is how callers
// bind them. A new trailing optional arg is additive; anything else that moves
// changes what an existing call means.
func diffInit(before *resources.Init, after *resources.Init, name string, add addFunc) {
	var b, a []*resources.TypedArg
	if before != nil {
		b = before.Args
	}
	if after != nil {
		a = after.Args
	}

	for i := range b {
		if b[i] == nil {
			continue
		}
		path := name + "(" + b[i].Name + ")"
		if i >= len(a) || a[i] == nil {
			add(ChangeBreaking, path, "init argument removed")
			continue
		}
		if b[i].Name != a[i].Name {
			add(ChangeBreaking, path, "init argument renamed to %q", a[i].Name)
		}
		if b[i].Type != a[i].Type {
			add(ChangeBreaking, path, "init argument type changed from %q to %q",
				typeLabel(b[i].Type), typeLabel(a[i].Type))
		}
		if b[i].Optional && !a[i].Optional {
			add(ChangeBreaking, path, "init argument became mandatory")
		}
		if !b[i].Optional && a[i].Optional {
			add(ChangeAdditive, path, "init argument became optional")
		}
	}

	for i := len(b); i < len(a); i++ {
		if a[i] == nil {
			continue
		}
		path := name + "(" + a[i].Name + ")"
		if a[i].Optional {
			add(ChangeAdditive, path, "optional init argument added")
		} else {
			add(ChangeBreaking, path, "mandatory init argument added")
		}
	}
}

// Breaking filters a change list down to the changes that need a decision.
func Breaking(changes []Change) []Change {
	var res []Change
	for _, c := range changes {
		if c.Kind == ChangeBreaking {
			res = append(res, c)
		}
	}
	return res
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
