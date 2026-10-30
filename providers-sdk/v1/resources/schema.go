// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/types"
)

type ResourcesSchema interface {
	Lookup(resource string) *ResourceInfo
	LookupField(resource string, field string) (*ResourceInfo, *Field)
	FindField(resource *ResourceInfo, field string) (FieldPath, []*Field, bool)
	AllResources() map[string]*ResourceInfo
	AllDependencies() map[string]*ProviderInfo
	// AllProviderVersions returns the version of every provider that
	// contributed to this schema, keyed by provider id. See
	// Schema.provider_versions.
	AllProviderVersions() map[string]string
	// AllProviderRoots returns the root resource every provider that
	// contributed to this schema declares for its assets, keyed by provider id.
	// See Schema.provider_roots and ADR 031.
	AllProviderRoots() map[string]string
}

// cloneField returns a copy of a field for insertion into an aggregate schema.
//
// The aggregate is built by merging the per-provider schemas the coordinator
// caches, and merging appends to `Others`. Storing the source pointer would make
// that append mutate the cached per-provider schema, so every rebuild of the
// aggregate would append again and `Others` would grow without bound. The copy
// is explicit rather than `*fv` because Field is a protobuf message and its
// internal state must not be copied by value.
func cloneField(fv *Field) *Field {
	if fv == nil {
		return nil
	}
	f := &Field{
		Name:               fv.Name,
		Type:               fv.Type,
		IsMandatory:        fv.IsMandatory,
		Title:              fv.Title,
		Desc:               fv.Desc,
		IsPrivate:          fv.IsPrivate,
		MinProviderVersion: fv.MinProviderVersion,
		Provider:           fv.Provider,
		IsImplicitResource: fv.IsImplicitResource,
		IsEmbedded:         fv.IsEmbedded,
		Maturity:           fv.Maturity,
		ReplacedBy:         fv.ReplacedBy,
	}
	if fv.Refs != nil {
		f.Refs = make([]string, len(fv.Refs))
		copy(f.Refs, fv.Refs)
	}
	if fv.Others != nil {
		f.Others = make([]*Field, len(fv.Others))
		copy(f.Others, fv.Others)
	}
	return f
}

// Add another schema and return yourself. other may be nil.
// The other schema overrides specifications in this schema, unless
// it is trying to extend a resource whose base is already defined.
func (s *Schema) Add(other ResourcesSchema) ResourcesSchema {
	if other == nil {
		return s
	}

	for k, v := range other.AllResources() {
		if existing, ok := s.Resources[k]; ok {
			// If neither resource is an extension, we can't merge them. We store both references.
			if !v.IsExtension && !existing.IsExtension && v.Provider != existing.Provider {
				existing.Others = append(existing.Others, v)
				continue
			}

			// We will merge resources into it until we find one that is not extending.
			// Technically, this should only happen with one resource and one only,
			// i.e. the root resource. In case they are incorrectly specified, the
			// last added resource wins (as is the case with all other fields below).
			if !v.IsExtension || existing.IsExtension {
				existing.IsExtension = v.IsExtension
				existing.Provider = v.Provider
				existing.Init = v.Init
				// A version string only means something relative to the
				// provider that owns it, so it travels with Provider.
				existing.MinProviderVersion = v.MinProviderVersion
			}
			// TODO: clean up any resource that clashes right now. There are a few
			//       implicit extensions that cause this behavior at the moment.
			//       log.Warn().Str("resource", k).Msg("found a resource that is not flagged as `extends` properly")
			// else if !v.IsExtension {}

			if v.Title != "" {
				existing.Title = v.Title
			}
			if v.Name != "" {
				existing.Name = v.Name
			}
			if v.Desc != "" {
				existing.Desc = v.Desc
			}
			if !v.Private {
				existing.Private = false
			}
			if v.Defaults != "" {
				existing.Defaults = v.Defaults
			}
			if v.Context != "" {
				existing.Context = v.Context
			}
			if v.Maturity != "" {
				existing.Maturity = v.Maturity
			}
			if v.ReplacedBy != "" {
				existing.ReplacedBy = v.ReplacedBy
			}
			// Reachability without a root is a property of the resource, not of
			// which schema happened to be merged last, so one contributor
			// claiming it is enough. Dropping it here made `asset` - which os
			// extends - look non-global to a rooted compile. See ADR 031.
			if v.Global {
				existing.Global = true
			}
			if v.Root {
				existing.Root = true
			}

			if existing.Fields == nil {
				existing.Fields = map[string]*Field{}
			}
			for fk, fv := range v.Fields {
				// If the field exists in the current resource, but is from a different provider,
				// we store it as an "other"
				if fExisting, ok := existing.Fields[fk]; ok && fv.Provider != fExisting.Provider {
					fExisting.Others = append(fExisting.Others, fv)
				} else {
					existing.Fields[fk] = cloneField(fv)
				}
			}
		} else {
			ri := &ResourceInfo{
				Id:          v.Id,
				Name:        v.Name,
				Fields:      make(map[string]*Field, len(v.Fields)),
				Init:        v.Init,
				ListType:    v.ListType,
				Title:       v.Title,
				Desc:        v.Desc,
				Private:     v.Private,
				IsExtension: v.IsExtension,
				Defaults:    v.Defaults,
				Context:     v.Context,
				Provider:    v.Provider,
				Maturity:    v.Maturity,
				// The version axis has to survive aggregation: it is the only
				// record of which provider release introduced this resource,
				// and diagnostics and the ADR 040 reconciliation step both read
				// it off the merged schema, not off the per-provider one.
				MinProviderVersion: v.MinProviderVersion,
				// So does reachability without a root, for the same reason: a
				// rooted compile reads it off the merged schema (ADR 031).
				Global: v.Global,
				Root:   v.Root,
				// And so does the replacement pointer, which is what a
				// deprecation notice is rendered from (ADR 040).
				ReplacedBy: v.ReplacedBy,
			}
			for k, v := range v.Fields {
				ri.Fields[k] = cloneField(v)
			}
			s.Resources[k] = ri
		}
	}

	for k, v := range other.AllDependencies() {
		if existing, ok := s.Dependencies[k]; ok {
			if v.Name != "" {
				existing.Name = v.Name
			}
		} else {
			pi := &ProviderInfo{
				Id:   v.Id,
				Name: v.Name,
			}
			if s.Dependencies == nil {
				s.Dependencies = make(map[string]*ProviderInfo)
			}
			s.Dependencies[k] = pi
		}
	}

	for k, v := range other.AllProviderVersions() {
		if v == "" {
			continue
		}
		if s.ProviderVersions == nil {
			s.ProviderVersions = make(map[string]string)
		}
		s.ProviderVersions[k] = v
	}

	for k, v := range other.AllProviderRoots() {
		if v == "" {
			continue
		}
		if s.ProviderRoots == nil {
			s.ProviderRoots = make(map[string]string)
		}
		s.ProviderRoots[k] = v
	}

	return s
}

func (s *Schema) Lookup(name string) *ResourceInfo {
	return s.Resources[name]
}

func (s *Schema) LookupField(resource string, field string) (*ResourceInfo, *Field) {
	res := s.Lookup(resource)
	if res == nil {
		return res, nil
	}

	// The field may live on the primary resource or, when several providers
	// extend the same resource, on one of its "other" instances. Search the
	// primary first, then fall back to the others. (Map iteration during
	// aggregation makes which provider becomes the primary non-deterministic,
	// so we must not assume the field sits on the primary.)
	if f := res.Fields[field]; f != nil {
		return res, f
	}
	for _, o := range res.Others {
		if f := o.Fields[field]; f != nil {
			return o, f
		}
	}
	return res, nil
}

type FieldPath []string

func (s *Schema) FindField(resource *ResourceInfo, field string) (FieldPath, []*Field, bool) {
	fieldInfo, ok := resource.Fields[field]
	if ok {
		return FieldPath{field}, []*Field{fieldInfo}, true
	}

	for _, f := range resource.Fields {
		if f.IsEmbedded {
			typ := types.Type(f.Type)
			nextResource := s.Lookup(typ.ResourceName())
			if nextResource == nil {
				continue
			}
			childFieldPath, childFieldInfos, ok := s.FindField(nextResource, field)
			if ok {
				fp := make(FieldPath, len(childFieldPath)+1)
				fieldInfos := make([]*Field, len(childFieldPath)+1)
				fp[0] = f.Name
				fieldInfos[0] = f
				for i, n := range childFieldPath {
					fp[i+1] = n
				}
				for i, f := range childFieldInfos {
					fieldInfos[i+1] = f
				}
				return fp, fieldInfos, true
			}
		}
	}
	return nil, nil, false
}

func (s *Schema) AllResources() map[string]*ResourceInfo {
	return s.Resources
}

func (s *Schema) AllDependencies() map[string]*ProviderInfo {
	return s.Dependencies
}

func (s *Schema) AllProviderVersions() map[string]string {
	return s.ProviderVersions
}

func (s *Schema) AllProviderRoots() map[string]string {
	if s == nil {
		return nil
	}
	return s.ProviderRoots
}

// ProviderKey reduces a provider id to the stable name people type on the
// command line. All of "go.mondoo.com/mql/providers/aws",
// "go.mondoo.com/mql/v13/providers/aws", "go.mondoo.com/cnquery/v9/providers/aws"
// and "go.mondoo.com/cnquery/providers/aws" become "aws".
//
// Provenance has to key on something that survives an id migration, and the ids
// in the tree have not converged: 45 of 81 providers ship a committed schema
// whose provider id predates the current one, spread over three generations of
// the format. The .lr sources are all current -- codegen writes the .lr's
// `option provider` verbatim -- but a schema is only rewritten when its provider
// is rebuilt, and CI regenerates only the providers a PR touches
// (.github/workflows/pr-test-generated-files.yaml), so an untouched provider
// keeps its old string indefinitely and no diff ever reports it.
//
// Keying version metadata on the raw id would therefore lose the association
// for more than half the providers, silently.
func ProviderKey(id string) string {
	if _, after, ok := strings.CutLast(id, "/"); ok && after != "" {
		return after
	}
	return id
}

// ProviderVersion returns the version of a provider, and whether it is known.
// It accepts either a provider id or a bare name, and matches on the normalized
// key so a legacy id resolves against a current one.
//
// An unknown provider is the normal case for a schema serialized before ADR 040
// provenance existed, so a miss means "no information", never an error.
func (s *Schema) ProviderVersion(id string) (string, bool) {
	if s == nil || s.ProviderVersions == nil {
		return "", false
	}
	if v, ok := s.ProviderVersions[id]; ok && v != "" {
		return v, true
	}
	want := ProviderKey(id)
	for k, v := range s.ProviderVersions {
		if v != "" && ProviderKey(k) == want {
			return v, true
		}
	}
	return "", false
}
