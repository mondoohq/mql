// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

// ErrFieldNotFound reports a field the reader's schema does not define.
//
// It is typed rather than a bare errors.New because the executor has to tell it
// apart from every other failure: a field the reader has never heard of is the
// signature of version skew, and skew is the one failure that may be degraded
// rather than propagated (see SkewPolicy).
type ErrFieldNotFound struct {
	Resource string
	Field    string
}

func (e *ErrFieldNotFound) Error() string {
	return "cannot find field '" + e.Field + "' in resource '" + e.Resource + "'"
}

// ErrResourceNotFound reports a resource the reader's schema does not define.
// Typed for the same reason ErrFieldNotFound is: a whole resource the reader has
// never heard of is skew in exactly the way a missing field is, and the two have
// to degrade alike or the behaviour depends on how far into a chain the gap
// happens to fall.
type ErrResourceNotFound struct {
	Resource string
}

func (e *ErrResourceNotFound) Error() string {
	return "cannot find resource '" + e.Resource + "' in schema"
}

// errFieldUnavailable marks a field that was dropped because the bundle was
// compiled against a newer provider than the one loaded here.
//
// It is an error rather than a bare null on purpose. The field has to read as
// "not measured", loudly and in place: a plain null would be indistinguishable
// from a field that was read and found empty, which is exactly the confusion
// that lets an audit report a pass over data nobody collected.
type errFieldUnavailable struct {
	resource string
	field    string
	reason   string
}

func (e *errFieldUnavailable) Error() string {
	what := "field '" + e.field + "'"
	if e.field == "" {
		what = "resource '" + e.resource + "'"
	}
	return what + " is unavailable: " + e.reason
}

func (e *errFieldUnavailable) Is(target error) bool { return target == ErrVersionSkew }

// ErrVersionSkew identifies every value that is missing because of version
// skew rather than because of a failure to read it. Match it with errors.Is to
// report "your provider is too old for this content" apart from "this query is
// broken".
//
// The message stays "unavailable": it is what renders and what has shipped.
var ErrVersionSkew = errors.New("unavailable")

// IsUnavailable reports whether a value is missing due to version skew.
func IsUnavailable(err error) bool { return errors.Is(err, ErrVersionSkew) }

// SkewPolicy says which providers the reader is behind on, and why.
//
// It is the evidence that turns an unknown field from a bug into a known
// consequence of version skew. Without it a missing field is a typo or a
// compiler defect and must fail loudly; with it, the same missing field is a
// field this build was never going to have, and dropping it lets the rest of
// the query run.
//
// Keys are the stable provider name, matching CodeBundle.min_provider_versions.
type SkewPolicy struct {
	reasons map[string]string
}

// NewSkewPolicy builds a policy from provider name -> human-readable reason.
// It returns nil when there is nothing to excuse, so the common case costs a
// nil check and no allocation.
func NewSkewPolicy(reasons map[string]string) *SkewPolicy {
	if len(reasons) == 0 {
		return nil
	}
	return &SkewPolicy{reasons: reasons}
}

// Reason returns why the given provider is behind, or "" when it is not. The
// provider is identified the same way anything else identifies it, so a legacy
// module-path id resolves against the stable name.
func (p *SkewPolicy) Reason(provider string) string {
	if p == nil || provider == "" {
		return ""
	}
	return p.reasons[resources.ProviderKey(provider)]
}

// providerOfResource attributes a resource name to the provider that owns its
// namespace, by walking the dotted name back to the longest prefix the reader
// does know. `sshd.futureThing` is attributed to whoever owns `sshd`.
//
// A resource that is missing entirely has no ResourceInfo to read a provider
// from, so the namespace is the only handle left. Attributing it matters:
// degrading every unknown resource whenever any provider is behind would let a
// stale aws version excuse a typo in an os resource.
func providerOfResource(schema resources.ResourcesSchema, name string) string {
	if schema == nil {
		return ""
	}
	for {
		i := strings.LastIndexByte(name, '.')
		if i <= 0 {
			return ""
		}
		name = name[:i]
		if info := schema.Lookup(name); info != nil && info.Provider != "" {
			return info.Provider
		}
	}
}

// degradeUnavailableResource is degradeUnavailableField for a resource that the
// reader does not have at all.
func (e *blockExecutor) degradeUnavailableResource(name string, err error) (*RawData, bool) {
	var notFound *ErrResourceNotFound
	if !errors.As(err, &notFound) {
		return nil, false
	}

	reason := e.ctx.skew.Reason(providerOfResource(e.ctx.runtime.Schema(), notFound.Resource))
	if reason == "" {
		return nil, false
	}

	return &RawData{
		Type: types.Resource(name),
		Error: &errFieldUnavailable{
			resource: notFound.Resource,
			reason:   reason,
		},
	}, true
}

// TranslateChunkID is the chunk a downgrade patch installs in place of a call
// the reader cannot make.
//
// It is `$translate` rather than `map` because the block it runs is bound to the
// *parent*, not to an old value: `process.file` on a reader that has no `file`
// field is reconstructed as `file(path: process.executable)`, from a sibling.
// There is no old value to map from, so naming it `map` would describe a shape
// it does not have -- and `map` already means per-element projection on arrays,
// dicts and maps, which is a different operation on a different binding.
//
// The `$` prefix marks it as compiler-internal, the same convention `$whereNot`
// already uses: nobody writes this in MQL, a patcher installs it.
const TranslateChunkID = "$translate"

// translateHandler runs the translation block against the patched chunk's
// original binding and yields its single value.
//
// The block is built SingleValue, so runBlock already extracts the one
// entrypoint and caches it under this ref - the same path the resource `{}`
// handler takes. The patched chunk keeps its original Function.Type, so
// everything downstream stays compiled against the type it expected.
func runTranslate(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if chunk.Function == nil || len(chunk.Function.Args) == 0 {
		return nil, 0, errors.New("$translate chunk carries no translation block")
	}

	return e.runBlock(bind, chunk.Function.Args[0], nil, ref)
}

// markTranslated tags a value produced by a $translate chunk on its way out.
//
// It happens at emission rather than inside runTranslate because a block's
// value does not come back from runBlock: the block runs asynchronously and
// delivers through the chain, so the synchronous return is usually nil. Every
// path - direct and chained - passes through the callback, so tagging there is
// the one place that catches all of them.
//
// The copy is not optional: handlers hand back shared package-level values
// (NilData, BoolTrue, ...) and tagging one in place would corrupt it for every
// other caller in the process. Same reason shortCircuitNull copies.
func (e *blockExecutor) markTranslated(ref uint64, res *RawData) *RawData {
	if res == nil || res.Translated {
		return res
	}
	chunk := e.ctx.code.Chunk(ref)
	if chunk == nil || chunk.Id != TranslateChunkID {
		return res
	}
	return &RawData{
		Type:           res.Type,
		Value:          res.Value,
		Error:          res.Error,
		CoverageGaps:   res.CoverageGaps,
		ShortCircuited: res.ShortCircuited,
		Translated:     true,
	}
}
