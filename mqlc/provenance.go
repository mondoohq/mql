// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
	"go.mondoo.com/mql/types"
)

// Compiled content is bound to one exact schema version, and until now it
// recorded nothing about which one (ADR 040). This pass stamps the two version
// axes onto a finished bundle:
//
//   - provider_schemas: which provider release the compiler resolved against.
//     Provenance - what the writer saw.
//   - min_provider_versions: the highest min_provider_version over every
//     resource and field the bundle actually touches. A requirement - the
//     oldest provider that can still resolve every name in it.
//   - deprecated_uses: the deprecated names it reads that say where they moved
//     to. Also what the writer saw, and it rides along on the same walk for the
//     same reason.
//
// Both are derived from the finished bytecode rather than recorded during
// compilation on purpose. Name resolution happens at eighteen call sites spread
// over three files; a walk of the emitted chunks sees the same set by
// construction and cannot drift away from it as those sites change.
func stampProvenance(res *llx.CodeBundle, schema resources.ResourcesSchema) {
	if res == nil || res.CodeV2 == nil || schema == nil {
		return
	}

	p := provenance{
		schema:         schema,
		schemaVersions: &resources.Schema{ProviderVersions: schema.AllProviderVersions()},
		code:           res.CodeV2,
		versions:       semver.Parser{},
		schemas:        map[string]string{},
		minimums:       map[string]string{},
		deprecatedSeen: map[string]struct{}{},
	}
	p.walk()

	if len(p.schemas) > 0 {
		res.ProviderSchemas = p.schemas
	}
	if len(p.minimums) > 0 {
		res.MinProviderVersions = p.minimums
	}
	if len(p.deprecated) > 0 {
		res.DeprecatedUses = p.deprecated
	}
	if v := minMqlVersion(res); v != "" {
		res.MinMondooVersion = v
	}
}

type provenance struct {
	schema resources.ResourcesSchema
	// schemaVersions resolves a provider id to a version tolerantly. It is the
	// aggregate schema when we have the concrete type, and an empty stand-in
	// otherwise, so the lookup never needs a nil check.
	schemaVersions *resources.Schema
	code           *llx.CodeV2
	versions       semver.Parser
	schemas        map[string]string
	minimums       map[string]string
	// deprecated keeps first-use order rather than being sorted at the end, so
	// a notice reads in the order the query does.
	deprecated     []*llx.DeprecatedUse
	deprecatedSeen map[string]struct{}
}

func (p *provenance) walk() {

	for _, block := range p.code.Blocks {
		if block == nil {
			continue
		}
		for _, chunk := range block.Chunks {
			if chunk == nil {
				continue
			}

			// The chunk's own type names a resource whenever it produces one,
			// which covers both `aws.s3.buckets` and a field that returns a
			// resource or a list of them.
			if name := resourceOf(chunk.Type()); name != "" {
				p.recordResource(name)
			}

			// A function chunk bound to a resource is a field access, and
			// chunk.Id is the field name. Fields carry their own
			// min_provider_version when they landed after their resource did,
			// which is the common case and the interesting one.
			if chunk.Call == llx.Chunk_FUNCTION && chunk.Function != nil && chunk.Function.Binding != 0 {
				bound := p.chunkAt(chunk.Function.Binding)
				if bound == nil {
					continue
				}
				if name := resourceOf(bound.Type()); name != "" {
					p.recordField(name, chunk.Id)
				}
			}
		}
	}
}

// chunkAt resolves a ref without the panic CodeV2.Chunk would raise on a ref
// this pass has no business trusting. A stamping pass must never be the reason
// a compile fails.
func (p *provenance) chunkAt(ref uint64) *llx.Chunk {
	blockIdx := int(ref>>32) - 1
	chunkIdx := int(uint32(ref)) - 1
	if blockIdx < 0 || blockIdx >= len(p.code.Blocks) {
		return nil
	}
	block := p.code.Blocks[blockIdx]
	if block == nil || chunkIdx < 0 || chunkIdx >= len(block.Chunks) {
		return nil
	}
	return block.Chunks[chunkIdx]
}

func (p *provenance) recordResource(name string) {
	info := p.schema.Lookup(name)
	if info == nil {
		return
	}
	p.noteReplacement(name, info.ReplacedBy)
	if info.Provider == "" {
		return
	}
	p.noteProvider(info.Provider)
	p.raiseMinimum(info.Provider, info.MinProviderVersion)
}

func (p *provenance) recordField(resource string, field string) {
	info, f := p.schema.LookupField(resource, field)
	if info == nil {
		return
	}
	p.noteProvider(info.Provider)
	p.raiseMinimum(info.Provider, info.MinProviderVersion)

	if f == nil {
		return
	}
	p.noteReplacement(resource+"."+field, f.ReplacedBy)
	// A field's provider differs from its resource's when one provider extends
	// another's resource, and then the version belongs to the extending one.
	owner := f.Provider
	if owner == "" {
		owner = info.Provider
	}
	p.noteProvider(owner)
	p.raiseMinimum(owner, f.MinProviderVersion)
}

// noteReplacement records that the bundle reads a deprecated name which says
// where it went. A deprecation with no target is skipped: there is nothing to
// tell a user beyond "this is old", and 431 of the 444 deprecations in the tree
// carry a target, so the ones that do not are the ones with nothing to say.
//
// This records; it never logs. The compiler runs per keystroke behind
// autocomplete, and a message printed from here lands in the middle of the line
// the user is typing.
func (p *provenance) noteReplacement(from string, to string) {
	if to == "" || from == "" {
		return
	}
	if _, ok := p.deprecatedSeen[from]; ok {
		return
	}
	p.deprecatedSeen[from] = struct{}{}
	p.deprecated = append(p.deprecated, &llx.DeprecatedUse{From: from, To: to})
}

// noteProvider records the writer-schema version for a provider. Both the map
// key and the lookup go through resources.ProviderKey, so a resource carrying a
// legacy provider id still matches the version recorded under the current one,
// and the bundle records the stable name either way.
func (p *provenance) noteProvider(id string) {
	if id == "" {
		return
	}
	if v, ok := p.schemaVersions.ProviderVersion(id); ok {
		p.schemas[resources.ProviderKey(id)] = v
	}
}

// raiseMinimum keeps the highest requirement seen for a provider. A bundle that
// touches a resource from 11.15.2 and a field from 13.52.0 requires 13.52.0.
func (p *provenance) raiseMinimum(id string, version string) {
	if id == "" || version == "" {
		return
	}
	key := resources.ProviderKey(id)
	current, ok := p.minimums[key]
	if !ok {
		p.minimums[key] = version
		return
	}
	diff, err := p.versions.Compare(version, current)
	if err != nil {
		// An unparseable version is not worth failing a compile over, but it
		// must not silently lower the requirement either.
		return
	}
	if diff > 0 {
		p.minimums[key] = version
	}
}

// resourceOf is types.ResourceOf. It stays as a local alias because this file
// reads better with the short name.
func resourceOf(typ types.Type) string { return types.ResourceOf(typ) }
