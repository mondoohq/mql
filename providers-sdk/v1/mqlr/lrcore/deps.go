// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package lrcore

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Peer dependency detection (ADR 042, step 2).
//
// A provider reaches a peer two ways, and a version floor has to account for
// both: as a type in the `.lr` (`[]network.certificate`) and as a string
// literal in Go (`CreateSharedResource("cpe")`). The largest single call group
// -- `os` -> `cpe`, 14 sites -- exists only in Go, so scanning the schema alone
// would compute a floor that misses most of the references.

// PeerRef is one reference from this provider into a peer.
type PeerRef struct {
	// Peer is the pack name the reference resolves to, e.g. "network".
	Peer string
	// Resource is the peer's resource name, unqualified: "certificate", not
	// "network.certificate".
	Resource string
	// Field is set when the reference names a specific field, which is what
	// makes the floor precise -- a resource may be old while the field being
	// used is new.
	Field string
	// Origin describes where the reference was found, for diagnostics.
	Origin string
}

// key is the `.lr.versions` lookup key for this reference.
func (r PeerRef) key() string {
	if r.Field == "" {
		return r.Resource
	}
	return r.Resource + "." + r.Field
}

func (r PeerRef) String() string {
	return r.Peer + "." + r.key() + " (" + r.Origin + ")"
}

// SchemaRefs collects every reference from this schema into a declared peer.
//
// Only pack-qualified names count. A local dotted name (`os.unix.sshd`) is not
// a peer reference, and a qualifier naming no import is a build error raised
// during codegen rather than a reference recorded here.
func SchemaRefs(lr *LR) []PeerRef {
	var refs []PeerRef

	add := func(typeName string, field string, origin string) {
		pack, resource, dotted := strings.Cut(typeName, ".")
		if !dotted {
			return
		}
		if _, ok := lr.imports[pack]; !ok {
			return
		}
		refs = append(refs, PeerRef{Peer: pack, Resource: resource, Field: field, Origin: origin})
	}

	// Every asset root carries `asset`, which core owns (attachAssetToRoots).
	// That reference is created by the schema builder rather than written in
	// the file, so counting only what is written would make a rooted provider
	// look like it imports core for nothing - and the fix a reader would then
	// apply, dropping the import, is the wrong one.
	if _, ok := lr.imports["core"]; ok {
		for _, r := range lr.Resources {
			if r != nil && r.IsRoot {
				refs = append(refs, PeerRef{Peer: "core", Resource: "asset", Origin: "asset root"})
				break
			}
		}
	}

	var walkType func(t Type, origin string)
	walkType = func(t Type, origin string) {
		switch {
		case t.MapType != nil:
			add(t.MapType.Key.Type, "", origin)
			walkType(t.MapType.Value, origin)
		case t.ListType != nil:
			walkType(t.ListType.Type, origin)
		case t.SimpleType != nil:
			add(t.SimpleType.Type, "", origin)
		}
	}

	for _, r := range lr.Resources {
		if r == nil {
			continue
		}

		// A list-type resource -- `parse.certificates { []network.certificate(content, path) }`
		// -- needs no special case here: Parse folds it into a synthetic `list`
		// body field (lr.go:492), so walking the body already covers it.
		//
		// Its args are NOT fields of the peer either way. They name fields on
		// the enclosing resource that feed the computation (`content` and
		// `path` are declared on `parse.certificates` itself), exactly like
		// BasicField.Args. Reading them as peer fields asks the peer's
		// .lr.versions for `certificate.content`, which does not exist.
		if r.Body == nil {
			continue
		}
		for _, f := range r.Body.Fields {
			switch {
			case f.BasicField != nil:
				// BasicField.Args name fields on *this* resource, not on the
				// peer, so they are deliberately not walked here.
				walkType(f.BasicField.Type, r.ID+"."+f.BasicField.ID)
			case f.Embeddable != nil:
				add(f.Embeddable.Type, "", r.ID)
			case f.Init != nil:
				for i := range f.Init.Args {
					walkType(f.Init.Args[i].Type, r.ID+".init")
				}
			}
		}
	}

	return refs
}

var (
	reCreateShared = regexp.MustCompile(`CreateSharedResource\(\s*"([a-zA-Z0-9._]+)"`)
	reGetShared    = regexp.MustCompile(`GetSharedData\(\s*"([a-zA-Z0-9._]+)"\s*,[^,]*,\s*"([a-zA-Z0-9_]+)"`)
)

// GoCall is a CreateSharedResource/GetSharedData call whose resource belongs to
// neither this provider nor any declared peer. It is the "call with no import"
// case: the code reaches for a resource it never declared a dependency on.
type GoCall struct {
	Resource string
	Field    string
	Origin   string
}

// GoRefs collects peer references from Go source, and separately reports calls
// that could not be attributed to a declared peer.
//
// Neither call form names a provider, so the resource name is resolved against
// the declared peers' resource sets and this provider's own resources. What is
// left over is returned rather than dropped: silently ignoring it is how a
// cross-provider call with no declaration stays invisible until it fails at the
// runtime gate.
func GoRefs(lr *LR, filename string, src []byte) ([]PeerRef, []GoCall) {
	var refs []PeerRef
	var unresolved []GoCall

	local := make(map[string]struct{}, len(lr.Resources))
	for _, r := range lr.Resources {
		if r != nil {
			local[r.ID] = struct{}{}
		}
	}

	owner := func(resource string) (string, bool) {
		for pack, resources := range lr.imports {
			if _, ok := resources[resource]; ok {
				return pack, true
			}
		}
		return "", false
	}

	record := func(name, field string) {
		if pack, ok := owner(name); ok {
			refs = append(refs, PeerRef{Peer: pack, Resource: name, Field: field, Origin: filename})
			return
		}
		if _, ok := local[name]; ok {
			return
		}
		unresolved = append(unresolved, GoCall{Resource: name, Field: field, Origin: filename})
	}

	for _, m := range reCreateShared.FindAllSubmatch(src, -1) {
		record(string(m[1]), "")
	}
	for _, m := range reGetShared.FindAllSubmatch(src, -1) {
		record(string(m[1]), string(m[2]))
	}

	return refs, unresolved
}

// MinVersions resolves references to the lowest peer version that satisfies all
// of them, per peer.
//
// versions maps a pack name to that peer's parsed `.lr.versions`. A reference
// with no entry is an error rather than a zero: a namespace-only root such as
// `openpgp` or `pkix` carries no version because it has no fields, and treating
// that as version 0 would let a typo validate.
func MinVersions(refs []PeerRef, versions map[string]LrVersions, cmp func(a, b string) (int, error)) (map[string]string, error) {
	res := map[string]string{}
	var missing []string

	for _, ref := range refs {
		peerVersions, ok := versions[ref.Peer]
		if !ok {
			return nil, fmt.Errorf("no versions loaded for peer %q", ref.Peer)
		}

		v, ok := peerVersions[ref.key()]
		if !ok || v == "" {
			missing = append(missing, ref.String())
			continue
		}

		cur, seen := res[ref.Peer]
		if !seen {
			res[ref.Peer] = v
			continue
		}
		diff, err := cmp(v, cur)
		if err != nil {
			return nil, fmt.Errorf("comparing %q and %q for peer %s: %w", v, cur, ref.Peer, err)
		}
		if diff > 0 {
			res[ref.Peer] = v
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("references with no entry in the peer's .lr.versions: %s",
			strings.Join(missing, ", "))
	}

	return res, nil
}

// DeclaredDep is a `Requires` entry read back out of a provider's config.go.
type DeclaredDep struct {
	ID         string
	Name       string
	MinVersion string
	MaxVersion string
}

// ParseDeclaredRequires extracts the `Requires` entries from a provider's
// config.go.
//
// config.go is the declaration of record for execution, and it is hand-authored
// Go rather than generated, so it is read with go/ast: a regex over a struct
// literal would break on formatting the author is entitled to choose.
func ParseDeclaredRequires(filename string, src []byte) ([]DeclaredDep, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}

	var res []DeclaredDep
	var walkErr error

	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Requires" {
			return true
		}

		lit, ok := kv.Value.(*ast.CompositeLit)
		if !ok {
			return false
		}
		for _, el := range lit.Elts {
			entry, ok := el.(*ast.CompositeLit)
			if !ok {
				continue
			}
			var dep DeclaredDep
			for _, f := range entry.Elts {
				field, ok := f.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				name, ok := field.Key.(*ast.Ident)
				if !ok {
					continue
				}
				val, ok := field.Value.(*ast.BasicLit)
				if !ok || val.Kind != token.STRING {
					continue
				}
				unquoted, err := strconv.Unquote(val.Value)
				if err != nil {
					walkErr = err
					return false
				}
				switch name.Name {
				case "ID":
					dep.ID = unquoted
				case "Name":
					dep.Name = unquoted
				case "MinVersion":
					dep.MinVersion = unquoted
				case "MaxVersion":
					dep.MaxVersion = unquoted
				}
			}
			res = append(res, dep)
		}
		return false
	})

	return res, walkErr
}

// DepAction is what reconciliation concluded about one peer.
type DepAction string

const (
	// DepCreate: referenced, but not declared at all.
	DepCreate DepAction = "create"
	// DepRaise: declared below what the references need. The declaration is
	// wrong -- a call to a field that does not exist at the claimed version is
	// a build error waiting to be a runtime null.
	DepRaise DepAction = "raise"
	// DepAccept: declared at or above the detected minimum. Deliberately
	// over-constraining is legitimate; the author may know something the scan
	// does not.
	DepAccept DepAction = "accept"
	// DepUnused: declared (or imported) but never referenced.
	DepUnused DepAction = "unused"
)

// Reconciliation is the verdict for one peer.
type Reconciliation struct {
	Peer     string
	Action   DepAction
	Detected string
	Declared string
}

func (r Reconciliation) String() string {
	switch r.Action {
	case DepCreate:
		return fmt.Sprintf("%s: not declared, references need >= %s", r.Peer, r.Detected)
	case DepRaise:
		return fmt.Sprintf("%s: declared >= %s but references need >= %s", r.Peer, r.Declared, r.Detected)
	case DepUnused:
		return fmt.Sprintf("%s: declared but never referenced", r.Peer)
	default:
		return fmt.Sprintf("%s: declared >= %s, references need >= %s", r.Peer, r.Declared, r.Detected)
	}
}

// Reconcile compares detected minimums against what the author declared.
//
// `imported` is every declared peer, so an import that nothing references can
// be reported: it is as much a drift signal as a missing one, and it is how the
// old whitelist came to name providers nobody called.
func Reconcile(detected map[string]string, declared []DeclaredDep, imported []string, cmp func(a, b string) (int, error)) ([]Reconciliation, error) {
	byName := map[string]DeclaredDep{}
	for _, d := range declared {
		byName[d.Name] = d
	}

	seen := map[string]bool{}
	var res []Reconciliation

	for peer, min := range detected {
		seen[peer] = true
		d, ok := byName[peer]
		if !ok || d.MinVersion == "" {
			res = append(res, Reconciliation{Peer: peer, Action: DepCreate, Detected: min})
			continue
		}
		diff, err := cmp(d.MinVersion, min)
		if err != nil {
			return nil, fmt.Errorf("comparing declared %q against detected %q for %s: %w", d.MinVersion, min, peer, err)
		}
		action := DepAccept
		if diff < 0 {
			action = DepRaise
		}
		res = append(res, Reconciliation{Peer: peer, Action: action, Detected: min, Declared: d.MinVersion})
	}

	for _, peer := range imported {
		if !seen[peer] {
			res = append(res, Reconciliation{Peer: peer, Action: DepUnused})
		}
	}

	sort.Slice(res, func(i, j int) bool { return res[i].Peer < res[j].Peer })
	return res, nil
}

// PeerNames lists the peers this schema declares. Exposed because
// reconciliation needs to see an import that nothing references. (Reads the
// resolved import map, not the LR.Imports field, which Resolve clears.)
func (lr *LR) PeerNames() []string {
	res := make([]string, 0, len(lr.imports))
	for pack := range lr.imports {
		res = append(res, pack)
	}
	sort.Strings(res)
	return res
}

// SupportedBaseline is the oldest peer version a declared floor is written at.
//
// Detection resolves references against `.lr.versions`, which records when each
// resource and field was *introduced* -- often many majors ago. A literal floor
// of `network >= 9.0.0` is not information: MQL support is retired every two
// majors, so as of v14 nothing older than v13 is in the field, and a v9 provider
// cannot be installed against a v14 engine. Declaring a floor nobody can be
// below says nothing, while making the declaration look precisely researched.
//
// Raise this to the new baseline when the supported window moves (v15 -> 14.0.0).
const SupportedBaseline = "13.0.0"

// RaiseToBaseline lifts any detected minimum below the baseline up to it.
//
// Kept separate from MinVersions so that detection stays a statement of fact --
// what the references actually require -- and this stays a statement of policy
// about what is worth declaring. They answer different questions and move for
// different reasons.
func RaiseToBaseline(mins map[string]string, baseline string, cmp func(a, b string) (int, error)) (map[string]string, error) {
	res := make(map[string]string, len(mins))
	for peer, v := range mins {
		diff, err := cmp(v, baseline)
		if err != nil {
			return nil, fmt.Errorf("comparing detected %q against baseline %q for %s: %w", v, baseline, peer, err)
		}
		if diff < 0 {
			res[peer] = baseline
			continue
		}
		res[peer] = v
	}
	return res, nil
}
