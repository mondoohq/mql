// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

// QueryUsage is the result of analyzing an MQL query. It mirrors the
// provider -> resource -> field hierarchy of the schema and tracks how
// many times each level was referenced by the query, plus the maturity
// status (stable, experimental, preview, deprecated, eol) for resources
// and fields.
type QueryUsage struct {
	// Source is the raw MQL when the query was analyzed via AnalyzeQuery.
	// Empty when the caller passed a pre-compiled bundle to AnalyzeBundle.
	Source string
	// CodeID is bundle.CodeV2.Id, useful for cache/dedup keys.
	CodeID string
	// Providers is keyed by provider id ("aws", "core", ...). Resources whose
	// provider could not be resolved (unknown to the schema, or schema was nil)
	// are bucketed under the empty-string key "".
	Providers map[string]*ProviderUsage
	// Warnings collects non-fatal problems encountered during analysis, e.g.
	// references to resources that the supplied schema does not know about.
	Warnings []string
}

// ProviderUsage aggregates resource references per provider.
type ProviderUsage struct {
	ID string
	// Name is the human-readable provider name from schema.AllDependencies();
	// falls back to ID when no entry exists.
	Name string
	// Resources keyed by full resource name (e.g. "aws.ec2.instance").
	Resources map[string]*ResourceUsage
	// Count is the sum of ResourceUsage.Count across this provider.
	Count int
}

// ResourceUsage tracks a single resource and the fields touched on it.
type ResourceUsage struct {
	Name string
	// Provider is the provider id ("" if unknown).
	Provider string
	// Maturity is the raw ResourceInfo.Maturity ("" means stable).
	Maturity string
	// Count is the number of chunks referencing this resource (each chained
	// access — e.g. `aws.ec2` then `aws.ec2.instance` — is a separate chunk
	// and is counted independently).
	Count  int
	Fields map[string]*FieldUsage
}

// FieldUsage tracks a single field touched on its parent resource.
type FieldUsage struct {
	Name string
	Type types.Type
	// Maturity is the raw Field.Maturity ("" means stable).
	Maturity string
	// EffectiveMaturity combines resource and field maturity using
	// resources.EffectiveFieldMaturity (e.g. a stable field on a deprecated
	// resource is effectively deprecated).
	EffectiveMaturity string
	Count             int
}

// AnalyzeQuery compiles input and returns its usage stats.
// On compile error, the error and a nil bundle are returned along with a
// nil QueryUsage; matching the contract of mqlc.Compile, partial bundles
// that come back with errors are still passed through to the caller.
func AnalyzeQuery(input string, props PropsHandler, conf CompilerConfig) (*QueryUsage, *llx.CodeBundle, error) {
	bundle, err := Compile(input, props, conf)
	if err != nil {
		return nil, bundle, err
	}
	usage, aerr := AnalyzeBundle(bundle, conf.Schema)
	if usage != nil {
		usage.Source = input
	}
	return usage, bundle, aerr
}

// AnalyzeBundle walks an already-compiled CodeBundle and returns its usage
// stats. The schema is required for provider attribution and maturity
// resolution. When schema is nil the function still produces resource counts
// (best-effort) but returns an error noting the missing schema, omits all
// provider/maturity fields, and skips field-level analysis (because field
// vs. builtin cannot be distinguished without the schema).
func AnalyzeBundle(bundle *llx.CodeBundle, schema resources.ResourcesSchema) (*QueryUsage, error) {
	if bundle == nil || bundle.CodeV2 == nil {
		return nil, errors.New("cannot analyze a nil bundle")
	}

	usage := &QueryUsage{
		CodeID:    bundle.CodeV2.Id,
		Providers: map[string]*ProviderUsage{},
	}

	a := &usageAnalyzer{
		bundle:           bundle,
		schema:           schema,
		usage:            usage,
		seenUnknownNames: map[string]struct{}{},
	}
	a.walk()

	if schema == nil {
		return usage, errors.New("analyzing without a schema: provider, maturity, and field-level data are unavailable")
	}
	return usage, nil
}

type usageAnalyzer struct {
	bundle           *llx.CodeBundle
	schema           resources.ResourcesSchema
	usage            *QueryUsage
	seenUnknownNames map[string]struct{}
}

func (a *usageAnalyzer) walk() {
	for _, block := range a.bundle.CodeV2.Blocks {
		for _, chunk := range block.Chunks {
			a.classify(chunk)
		}
	}
}

func (a *usageAnalyzer) classify(chunk *llx.Chunk) {
	if chunk.Call != llx.Chunk_FUNCTION {
		return
	}

	// Bare resource access: `addResource` emits Function == nil for resources
	// without init args (mqlc/mqlc.go::addResource).
	if chunk.Function == nil {
		a.recordResource(chunk.Id)
		return
	}

	// Resource init with args: Function is set, Binding == 0, and the function
	// type is the resource itself.
	if chunk.Function.Binding == 0 {
		ftype := types.Type(chunk.Function.Type)
		if ftype.IsResource() && ftype.ResourceName() == chunk.Id {
			a.recordResource(chunk.Id)
		}
		return
	}

	// Field calls and operators all flow through Function.Binding != 0. We tell
	// them apart by the parent chunk's dereferenced type — operators bind to
	// scalars/arrays, fields bind to a Resource (or Array(Resource) when the
	// language sugars list field access).
	//
	// Without a schema we can't reliably distinguish well-named builtins (like
	// `length` bound to a list-of-resources) from real fields, so skip this
	// path entirely in best-effort mode.
	if a.schema == nil {
		return
	}

	parent := a.bundle.CodeV2.Chunk(chunk.Function.Binding)
	parentType := parent.DereferencedTypeV2(a.bundle.CodeV2)

	var resourceName string
	switch {
	case parentType.IsResource():
		resourceName = parentType.ResourceName()
	case parentType.IsArray() && parentType.Child().IsResource():
		resourceName = parentType.Child().ResourceName()
	default:
		return
	}

	a.recordField(resourceName, chunk.Id)
}

func (a *usageAnalyzer) recordResource(name string) {
	ru := a.getOrCreateResource(name)
	ru.Count++
	// Provider count tracks resource references only — keep it in lockstep
	// with the doc on ProviderUsage.Count ("sum of ResourceUsage.Count").
	a.usage.Providers[ru.Provider].Count++
}

func (a *usageAnalyzer) recordField(resourceName, fieldName string) {
	// Look up the field. If it's not a real field on this resource, the chunk
	// is an operator/builtin bound to a resource (rare: e.g. `==` between two
	// resources) — silently skip, the goal is provider/resource/field stats.
	ri, fi := a.schema.LookupField(resourceName, fieldName)
	if fi == nil {
		return
	}

	ru := a.getOrCreateResource(resourceName)
	fu, ok := ru.Fields[fieldName]
	if !ok {
		fu = &FieldUsage{
			Name:              fieldName,
			Type:              types.Type(fi.GetType()),
			Maturity:          fi.GetMaturity(),
			EffectiveMaturity: resources.EffectiveFieldMaturity(ri, fi),
		}
		ru.Fields[fieldName] = fu
	}
	fu.Count++
}

func (a *usageAnalyzer) getOrCreateResource(name string) *ResourceUsage {
	providerID, maturity := a.resolveResource(name)
	pu := a.getOrCreateProvider(providerID)

	ru, ok := pu.Resources[name]
	if !ok {
		ru = &ResourceUsage{
			Name:     name,
			Provider: providerID,
			Maturity: maturity,
			Fields:   map[string]*FieldUsage{},
		}
		pu.Resources[name] = ru
	}
	return ru
}

// resolveResource returns the provider id and resource maturity for the given
// resource name. If the resource is unknown to the schema (or no schema is
// supplied), returns ("", "") and appends a one-shot warning the first time
// each unknown name is encountered.
func (a *usageAnalyzer) resolveResource(name string) (providerID, maturity string) {
	if a.schema == nil {
		return "", ""
	}
	ri := a.schema.Lookup(name)
	if ri == nil {
		a.warnUnknownResource(name)
		return "", ""
	}
	return ri.GetProvider(), ri.GetMaturity()
}

func (a *usageAnalyzer) warnUnknownResource(name string) {
	if _, ok := a.seenUnknownNames[name]; ok {
		return
	}
	a.seenUnknownNames[name] = struct{}{}
	a.usage.Warnings = append(a.usage.Warnings, "unknown resource: "+name)
}

func (a *usageAnalyzer) getOrCreateProvider(id string) *ProviderUsage {
	if pu, ok := a.usage.Providers[id]; ok {
		return pu
	}
	pu := &ProviderUsage{
		ID:        id,
		Name:      a.providerName(id),
		Resources: map[string]*ResourceUsage{},
	}
	a.usage.Providers[id] = pu
	return pu
}

func (a *usageAnalyzer) providerName(id string) string {
	if a.schema == nil || id == "" {
		return id
	}
	if pi, ok := a.schema.AllDependencies()[id]; ok && pi.GetName() != "" {
		return pi.GetName()
	}
	return id
}
