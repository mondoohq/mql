// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/lithammer/fuzzysearch/fuzzy"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/sortx"
)

type ErrIdentifierNotFound struct {
	Identifier string
	Binding    string

	// Provider is the id of the provider whose namespace the identifier falls
	// under, when we can establish one, and ProviderVersion is the version of
	// it that is installed. Together they turn "cannot find field 'x'" into a
	// message that says which component would have to be newer -- the most
	// common cause of the failure by far, and the one the bare message gives
	// no hint of (ADR 040 part 1).
	//
	// We deliberately do not claim which version would be new *enough*: that
	// needs a registry of schemas we do not have, and a guess here would send
	// people chasing an upgrade that does not contain what they want.
	Provider        string
	ProviderVersion string
}

func (e *ErrIdentifierNotFound) Error() string {
	var msg string
	if e.Binding == "" {
		msg = "cannot find resource for identifier '" + e.Identifier + "'"
	} else {
		msg = "cannot find field or resource '" + e.Identifier + "' in block for type '" + e.Binding + "'"
	}
	if hint := e.versionHint(); hint != "" {
		msg += " (" + hint + ")"
	}
	return msg
}

func (e *ErrIdentifierNotFound) versionHint() string {
	if e.Provider == "" || e.ProviderVersion == "" {
		return ""
	}
	what := "resource"
	if e.Binding != "" {
		what = "field"
	}
	return providerLabel(e.Provider) + " provider " + e.ProviderVersion +
		" is installed; this " + what + " may require a newer one"
}

// providerLabel trims a provider id down to the name people use on the command
// line. Ids are module paths ("go.mondoo.com/mql/providers/aws"), which are the
// right key but the wrong thing to print.
func providerLabel(id string) string {
	return resources.ProviderKey(id)
}

// identifierProvider finds the provider that owns the namespace an unresolvable
// identifier sits in, by walking the dotted name back to the longest prefix
// that does resolve. `aws.s3.nope` gets attributed to whoever owns `aws.s3`.
func identifierProvider(schema resources.ResourcesSchema, id string) string {
	if schema == nil {
		return ""
	}
	name := id
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

// bindingProvider attributes a failed field access to the provider that owns
// the resource it was attempted on.
func bindingProvider(schema resources.ResourcesSchema, typ types.Type) string {
	if schema == nil {
		return ""
	}
	name := resourceOf(typ)
	if name == "" {
		return ""
	}
	if info := schema.Lookup(name); info != nil {
		return info.Provider
	}
	return ""
}

// skewHint renders the parenthetical that turns a name-resolution failure into
// a version-skew lead, or "" when we cannot attribute the failure to a provider.
// It is appended to the existing messages rather than replacing them, so a
// caller that has no provenance to work with sees exactly what it saw before.
func (c *compiler) skewHint(provider string, what string) string {
	if provider == "" || c.Schema == nil {
		return ""
	}
	version, ok := (&resources.Schema{
		ProviderVersions: c.Schema.AllProviderVersions(),
	}).ProviderVersion(provider)
	if !ok {
		return ""
	}
	return " (" + providerLabel(provider) + " provider " + version +
		" is installed; this " + what + " may require a newer one)"
}

// rootScopeHint names the roots that do carry a field the current root lacks.
//
// A field missing from an asset root is usually a platform mismatch, not version
// skew: `_.registrykey` on a Linux host fails because the asset is rooted at
// `os.linux` and the registry lives on `os.windows` (ADR 031). Saying "the
// provider may need to be newer" there sends the reader after an upgrade that
// cannot help, so this hint takes precedence over the version-skew lead.
//
// Only roots are offered as alternatives, read from the schema's `@root`
// marking rather than guessed from the shape of a name: `os.date` sits in the
// same namespace and has a `timezone` field, but "timezone is available on
// os.date" answers nothing - no asset is ever rooted there. Membership is
// checked the way resolution checks it, through embeds, so a member inherited
// from a universal root is reported on every root that inherits it.
func (c *compiler) rootScopeHint(typ types.Type, id string) string {
	if c.AssetRoot == "" || c.Schema == nil || !typ.IsResource() {
		return ""
	}
	current := typ.ResourceName()
	if info := c.Schema.Lookup(current); info == nil || !info.GetRoot() {
		// Failing on something other than a root says nothing about platforms.
		return ""
	}

	top := c
	for top.parent != nil {
		top = top.parent
	}

	var found []string
	for _, root := range top.rootIdx().roots {
		if root.Id == current {
			continue
		}
		if _, _, ok := c.Schema.FindField(root, id); ok {
			found = append(found, root.Id)
		}
	}
	if len(found) == 0 {
		return ""
	}
	sort.Strings(found)
	return " (this asset is rooted at " + current + "; " + id + " is available on " +
		strings.Join(found, ", ") + ")"
}

// fieldSkewHint attributes a failed field access to the provider owning the
// resource it was attempted on.
func (c *compiler) fieldSkewHint(typ types.Type) string {
	return c.skewHint(bindingProvider(c.Schema, typ), "field")
}

// resourceFieldSkewHint is fieldSkewHint for the paths that already hold the
// resource info and do not need to look it up again.
func (c *compiler) resourceFieldSkewHint(info *resources.ResourceInfo) string {
	if info == nil {
		return ""
	}
	return c.skewHint(info.Provider, "field")
}

// notFound builds an identifier error already carrying its version context, so
// no construction site can forget to attach it.
func (c *compiler) notFound(id string, binding *variable) *ErrIdentifierNotFound {
	err := &ErrIdentifierNotFound{Identifier: id}

	var provider string
	if binding == nil {
		provider = identifierProvider(c.Schema, id)
	} else {
		// Both of these read the binding the caller passed, not c.Binding.
		// They are the same object today - compileIdentifier's only caller
		// hands it c.Binding - but reading the field here would make the
		// reported type and the resolved provider disagree the moment a caller
		// passes anything else, which is exactly what a nested-block binding
		// would do.
		err.Binding = binding.typ.Label()
		provider = bindingProvider(c.Schema, binding.typ)
	}
	if provider == "" {
		return err
	}

	err.Provider = provider
	if c.Schema != nil {
		if v, ok := (&resources.Schema{
			ProviderVersions: c.Schema.AllProviderVersions(),
		}).ProviderVersion(provider); ok {
			err.ProviderVersion = v
		}
	}
	return err
}

type ErrPropertyNotFound struct {
	Name string
}

func (e *ErrPropertyNotFound) Error() string {
	return "cannot find property '" + e.Name + "', please define it first"
}

type variable struct {
	name string
	ref  uint64
	typ  types.Type
	// callback is run when the variable is used by the compiler.
	// This is particularly useful when dealing with pre-defined
	// variables which may or may not be used in the actual code
	// (like `key` and `value`). One use-case is to tell the
	// block compiler that its bound value has been used.
	callback func()
}

type varmap struct {
	blockref uint64
	parent   *varmap
	vars     map[string]variable
}

func newvarmap(blockref uint64, parent *varmap) *varmap {
	return &varmap{
		blockref: blockref,
		parent:   parent,
		vars:     map[string]variable{},
	}
}

func (vm *varmap) lookup(name string) (variable, bool) {
	if v, ok := vm.vars[name]; ok {
		return v, true
	}
	if vm.parent == nil {
		return variable{}, false
	}
	return vm.parent.lookup(name)
}

func (vm *varmap) add(name string, v variable) {
	vm.vars[name] = v
}

func (vm *varmap) len() int {
	return len(vm.vars)
}

type CompilerConfig struct {
	Schema          resources.ResourcesSchema
	UseAssetContext bool
	Stats           CompilerStats
	Features        mql.Features
	// Strict compiles under ADR 043 strict mode: every link in an access chain
	// must resolve, and `?` is how the author marks one optional. It is
	// deliberately not a feature flag - strictness is a property of the content
	// being compiled (a policy declares it), not of the client running it, so it
	// is set per compile. Off by default, which reproduces today's behavior
	// exactly: nothing is marked and the runtime keeps propagating null.
	Strict bool

	// Translations is the downgrade catalog of the loaded providers, and
	// DowngradeFloor the oldest version of each provider this compile should
	// still serve (ADR 040 part 6). Both are supplied by the caller: mqlc has no
	// dependency on the provider machinery today and must not gain one, so
	// whoever holds the coordinator passes these in exactly as it already
	// passes Schema.
	//
	// With either empty, nothing is emitted and the bundle is what it always
	// was - which is also what happens when the provider binaries are not
	// available to read a catalog from.
	//
	// NewConfigFrom fills both in: the catalog from the runtime, and the floor
	// from DefaultDowngradeFloor. Override DowngradeFloor to reach further back
	// than the default window, or clear it to emit nothing.
	Translations   llx.TranslationSource
	DowngradeFloor map[string]string

	// AssetRoot is the resource that roots the connected asset's tree, which is
	// what `_` resolves to at the top level of a query (ADR 031). Supplied by
	// the caller for the same reason as Schema; NewConfigFrom fills it in from
	// the runtime.
	//
	// Empty leaves `_` failing at the top level, as it always did: there is no
	// root to name, and guessing one would answer with a resource that only
	// partly covers the asset.
	AssetRoot string

	// DeclaredAssetRoot is the root the provider declares statically, which for
	// a multi-platform provider is the union of its roots. Only diagnostics use
	// it: the union is a compile-time receiver, not a platform, so it must not
	// be offered as the place a missing field is available.
	DeclaredAssetRoot string

	// RootedNamespace resolves bare identifiers against the asset root instead
	// of the global namespace, which is the v15 model (ADR 031 point 7). Set
	// from the feature of the same name. With it on, the global namespace is
	// reachable only through resources marked `@global`, and a compile without a
	// root is an error rather than a silent fall back to global resolution.
	RootedNamespace bool
}

func (c *CompilerConfig) EnableStats() {
	c.Stats = newCompilerStats()
}

func (c *CompilerConfig) EnableMultiStats() {
	c.Stats = newCompilerMultiStats()
}

// NewConfigFrom builds a compiler config from a runtime, which is NewConfig plus
// whatever else the runtime can supply - today the downgrade translation catalog
// (ADR 040 part 6).
//
// Prefer this wherever a runtime is in hand. mql is the only compiler there is,
// so any capability that has to reach every compile has to reach it through one
// of these constructors; a caller that assembles CompilerConfig by hand silently
// opts out.
//
// A runtime with no schema yields no DowngradeFloor, so nothing is emitted. That
// is the right outcome - a floor is meaningless without provider versions to
// measure against - but it is silent, so a caller wondering why its floor is
// empty should check the schema first.
func NewConfigFrom(runtime llx.Runtime, features mql.Features) CompilerConfig {
	conf := NewConfig(runtime.Schema(), features)
	if src, ok := runtime.(llx.TranslationSource); ok {
		conf.Translations = src
	}
	if schema := runtime.Schema(); schema != nil {
		conf.DowngradeFloor = DefaultDowngradeFloor(schema.AllProviderVersions())
	}
	if src, ok := runtime.(llx.AssetRootSource); ok {
		conf.AssetRoot = src.AssetRoot()
		conf.DeclaredAssetRoot = src.DeclaredAssetRoot()
	}
	return conf
}

func NewConfig(schema resources.ResourcesSchema, features mql.Features) CompilerConfig {
	return CompilerConfig{
		Schema:          schema,
		UseAssetContext: features.IsActive(mql.MQLAssetContext),
		RootedNamespace: features.IsActive(mql.RootedNamespace),
		Stats:           compilerStatsNull{},
		Features:        features,
	}
}

type PropsHandler interface {
	// Get a property for a given name. In some cases, we may look up
	// indirectly available properties (e.g. via policies).
	Get(name string) *llx.Primitive
	// Available returns the list of available properties. This is typically
	// the list of properties that are associated with a query. This should include
	// properties that are indirectly available AND have been requested via Get.
	Available() map[string]*llx.Primitive
	// All looks up all possible properties, direct or indirectly available ones.
	// This is used to provide users with suggestions.
	All() map[string]*llx.Primitive
}

type emptyPropsHandler struct{}

var EmptyPropsHandler = emptyPropsHandler{}

func (e emptyPropsHandler) Get(name string) *llx.Primitive       { return nil }
func (e emptyPropsHandler) Available() map[string]*llx.Primitive { return map[string]*llx.Primitive{} }
func (e emptyPropsHandler) All() map[string]*llx.Primitive       { return map[string]*llx.Primitive{} }

type SimpleProps map[string]*llx.Primitive

func (s SimpleProps) Get(name string) *llx.Primitive       { return s[name] }
func (s SimpleProps) Available() map[string]*llx.Primitive { return s }
func (s SimpleProps) All() map[string]*llx.Primitive       { return s }

type compiler struct {
	CompilerConfig

	Result    *llx.CodeBundle
	Binding   *variable
	vars      *varmap
	parent    *compiler
	block     *llx.Block
	blockRef  uint64
	blockDeps []uint64
	props     PropsHandler
	comment   string

	// translationBlocks memoizes relocated downgrade blocks so a field read in
	// several places shares one block instead of getting a copy each time. See
	// compiler.translationBlock.
	translationBlocks map[string]uint64

	// compatibleRoots is the running intersection of the asset roots that can
	// execute this code, narrowed by every member read off a root. Nil until the
	// first such read, which is what "no requirement" looks like.
	compatibleRoots map[string]struct{}

	// roots indexes the schema's asset roots for narrowing. Held only on the
	// top-level compiler, where the intersection lives.
	roots *rootIndex

	// a standalone code is one that doesn't call any of its bindings
	// examples:
	//   file(xyz).content          is standalone
	//   file(xyz).content == _     is not
	standalone bool

	// Identifier resolution inside blocks
	// -----------------------------------
	//
	// A block has a binding: the resource (or value) it iterates over. How a
	// bare identifier inside the block resolves depends on whether the user
	// gave that binding an explicit name.
	//
	// Anonymous binding (bindingIsExplicit == false):
	//
	//	processes.list { command }
	//
	// The bound resource (each process) is implicitly in scope. Bare `command`
	// first tries the bound resource's fields (process.command), and only falls
	// back to the global namespace if no field matches. The implicit binding
	// effectively shadows globals.
	//
	// Named binding (bindingIsExplicit == true):
	//
	//	processes.list.map(p: command("echo " + p.command))
	//
	// Once the user supplies a name (`p`), they have signaled that the bound
	// resource is reachable through that name (and through `_`) and nothing
	// else. Bare `command` now resolves against the global namespace, so it
	// picks up the top-level `command` resource. To reach the process field
	// the user writes `p.command` or `_.command`.
	//
	// This rule prevents the trap where a same-named field on the bound
	// resource hides a top-level resource the user wanted to call. Before
	// commit 47cac143d we shadowed even when an explicit name was given, which
	// made some queries impossible to write in MQL.
	//
	// The enforcement points are:
	//   - blockcompileOnResource (this file): registers the explicit name and
	//     `_`, and sets bindingIsExplicit on the inner compiler.
	//   - compileDictQuery / compileMapWhere (builtin_map.go): same, for dict
	//     and map blocks.
	//   - compileIdentifier (this file): skips the bound-field lookup when
	//     bindingIsExplicit is true.
	bindingIsExplicit bool

	// helps chaining of builtin calls like `if (..) else if (..) else ..`
	prevID string

	// overrideTailDataRef is set by `having` so that subsequent chained calls
	// bind to the where-filtered list instead of the $any boolean chunk.
	overrideTailDataRef uint64

	// valueBodyBlocks holds the refs of blocks whose single entrypoint is a
	// value consumed by a parent builtin (the function body of `.map(...)`).
	// postCompile must not display-expand those entrypoints: replacing the real
	// value (e.g. the `[]file` from `.list`) with an anonymous `{}` display
	// block (`[]block`) makes the parent collect `block`-typed elements, which
	// breaks any later field access on the result.
	// See https://github.com/mondoohq/mql/issues/8474
	// The map is shared across the whole compiler tree (allocated once on the
	// root compiler and handed to every newBlockCompiler).
	valueBodyBlocks map[uint64]struct{}
}

func (c *compiler) isInMyBlock(ref uint64) bool {
	return (ref >> 32) == (c.blockRef >> 32)
}

func (c *compiler) addChunk(chunk *llx.Chunk) {
	c.block.AddChunk(c.Result.CodeV2, c.blockRef, chunk)
}

func (c *compiler) popChunk() (prev *llx.Chunk, isEntrypoint bool, isDatapoint bool) {
	return c.block.PopChunk(c.Result.CodeV2, c.blockRef)
}

func (c *compiler) addArgumentPlaceholder(typ types.Type, checksum string) {
	c.block.AddArgumentPlaceholder(c.Result.CodeV2, c.blockRef, typ, checksum)
}

func (c *compiler) tailRef() uint64 {
	return c.block.TailRef(c.blockRef)
}

// linkNullability is the marker a single link in an access chain should carry.
// Only dereferences go through here; operators are compiled elsewhere and stay
// unmarked, which is what keeps `a.f == "no"` returning false on a null `f`
// instead of erroring (ADR 043 §3).
func (c *compiler) linkNullability(optional bool) llx.Function_Nullability {
	if !c.Strict {
		return llx.Function_NULLABILITY_UNSPECIFIED
	}
	if optional {
		return llx.Function_NULLABILITY_OPTIONAL
	}
	return llx.Function_NULLABILITY_REQUIRED
}

// markNullability stamps every chunk emitted after afterRef with a strict-mode
// marker, and refreshes their checksums.
//
// Chunks are checksummed by Block.AddChunk at insertion time, so marking one
// afterwards means recomputing. That is only sound while nothing downstream has
// been added yet - dependents fold this checksum into their own - so callers
// must stamp a link immediately after emitting it and before compiling the next.
// A link can emit more than one chunk (a nested field path), hence the range.
//
// Labels registered inline during compilation are keyed by checksum, so they
// move with it; the bulk of labeling runs as a post-pass over the final
// checksums and needs nothing here.
func (c *compiler) markNullability(afterRef uint64, n llx.Function_Nullability) {
	if n == llx.Function_NULLABILITY_UNSPECIFIED {
		return
	}

	code := c.Result.CodeV2
	tail := c.tailRef()

	// Label moves are collected here and applied after the walk. Two chunks in
	// this range can share a pre-mark checksum, and deleting the old key inline
	// would then drop the label the previous iteration had just written under
	// the new one.
	type rename struct{ from, to string }
	var renames []rename

	for ref := afterRef + 1; ref <= tail; ref++ {
		if !c.isInMyBlock(ref) {
			continue
		}
		chunk := code.Chunk(ref)
		// Primitives have no binding and cannot fail to resolve.
		if chunk == nil || chunk.Function == nil || chunk.Function.Nullability == n {
			continue
		}

		old := code.Checksums[ref]
		chunk.Function.Nullability = n
		nu := chunk.ChecksumV2(c.blockRef, code)
		code.Checksums[ref] = nu

		if old != nu {
			if _, ok := c.Result.Labels.Labels[old]; ok {
				renames = append(renames, rename{from: old, to: nu})
			}
		}
	}

	if len(renames) == 0 {
		return
	}

	// Read every label before writing any: one rename's source may be another
	// rename's target, and interleaving the two would lose it.
	labels := make([]string, len(renames))
	for i, r := range renames {
		labels[i] = c.Result.Labels.Labels[r.from]
	}
	for _, r := range renames {
		delete(c.Result.Labels.Labels, r.from)
	}
	for i, r := range renames {
		c.Result.Labels.Labels[r.to] = labels[i]
	}
}

// tailDataRef returns overrideTailDataRef if set (consuming it),
// otherwise falls back to tailRef. Used after builtin calls like
// `having` where the data continuation point differs from the tail.
func (c *compiler) tailDataRef() uint64 {
	if c.overrideTailDataRef != 0 {
		ref := c.overrideTailDataRef
		c.overrideTailDataRef = 0
		return ref
	}
	return c.tailRef()
}

// Creates a new block and its accompanying compiler.
// It carries a set of variables that apply within the scope of this block.
func (c *compiler) newBlockCompiler(binding *variable) compiler {
	code := c.Result.CodeV2
	block, ref := code.AddBlock()

	vars := map[string]variable{}
	blockDeps := []uint64{}
	if binding != nil {
		vars["_"] = *binding
		blockDeps = append(blockDeps, binding.ref)
	}

	return compiler{
		CompilerConfig:  c.CompilerConfig,
		Result:          c.Result,
		Binding:         binding,
		blockDeps:       blockDeps,
		vars:            newvarmap(ref, c.vars),
		parent:          c,
		block:           block,
		blockRef:        ref,
		props:           c.props,
		standalone:      true,
		valueBodyBlocks: c.valueBodyBlocks,
	}
}

func findFuzzy(name string, names []string) fuzzy.Ranks {
	suggested := fuzzy.RankFind(name, names)

	sort.SliceStable(suggested, func(i, j int) bool {
		a := suggested[i]
		b := suggested[j]
		ha := strings.HasPrefix(a.Target, name)
		hb := strings.HasPrefix(b.Target, name)
		if ha && hb {
			// here it's just going by order, because it has the prefix
			return a.Target < b.Target
		}
		if ha {
			return true
		}
		if hb {
			return false
		}
		// unlike here where we sort by fuzzy distance
		return a.Distance < b.Distance
	})

	return suggested
}

func addResourceSuggestions(schema resources.ResourcesSchema, name string, res *llx.CodeBundle) {
	resourceInfos := schema.AllResources()
	names := make([]string, 0, len(resourceInfos))
	for key, info := range resourceInfos {
		// Aliases are a second name for a resource that is already in this
		// pool under its own name (the schema marks one by a map key that
		// differs from the entry's id), so suggesting both is redundant by
		// construction. It also drowns the pool: a provider that attaches its
		// whole surface to its asset roots (ADR 031) contributes one rooted
		// alias per resource, and the longer names widen every fuzzy match -
		// `ssh` starts suggesting `os.base.apache2`.
		if info != nil && info.Id != "" && info.Id != key {
			continue
		}
		names = append(names, key)
	}

	suggested := findFuzzy(name, names)

	var info *resources.ResourceInfo
	for i := range suggested {
		field := suggested[i].Target
		info = resourceInfos[field]
		if info != nil {
			if info.GetPrivate() {
				continue
			}
			title := info.Title
			if label := resources.MaturityLabel(info.Maturity); label != "" {
				title = "[" + label + "] " + title
			}
			res.Suggestions = append(res.Suggestions, &llx.Documentation{
				Field:    field,
				Title:    title,
				Desc:     info.Desc,
				Provider: info.Provider,
			})
		} else {
			res.Suggestions = append(res.Suggestions, &llx.Documentation{
				Field: field,
			})
		}
	}
}

func addFieldSuggestions(fields map[string]llx.Documentation, fieldName string, res *llx.CodeBundle) {
	names := make([]string, len(fields))
	i := 0
	for key := range fields {
		names[i] = key
		i++
	}

	suggested := findFuzzy(fieldName, names)

	res.Suggestions = make([]*llx.Documentation, len(suggested))
	for i := range suggested {
		info := fields[suggested[i].Target]
		res.Suggestions[i] = &info
	}
}

// func (c *compiler) addAccessor(call *Call, typ types.Type) types.Type {
// 	binding := c.Result.Code.ChunkIndex()
// 	ownerType := c.Result.Code.LastChunk().Type(c.Result.Code)

// 	if call.Accessors != nil {
// 		arg, err := c.compileValue(call.Accessors)
// 		if err != nil {
// 			panic(err.Error())
// 		}

// 		c.Result.Code.AddChunk(&llx.Chunk{
// 			Call: llx.Chunk_FUNCTION,
// 			Id:   "[]",
// 			Function: &llx.Function{
// 				Type:    string(ownerType.Child()),
// 				Binding: binding,
// 				Args:    []*llx.Primitive{arg},
// 			},
// 		})

// 		return ownerType.Child()
// 	}

// 	if call.Params != nil {
// 		panic("We have not yet implemented adding more unnamed function calls")
// 	}

// 	panic("Tried to add accessor calls for a call that has no accessors or params")
// }

// func (c *compiler) addAccessorCalls(calls []*Call, typ types.Type) types.Type {
// 	if calls == nil || len(calls) == 0 {
// 		return typ
// 	}
// 	for i := range calls {
// 		typ = c.addAccessorCall(calls[i], typ)
// 	}
// 	return typ
// }

func blockCallType(typ types.Type, schema resources.ResourcesSchema) types.Type {
	if typ.IsArray() {
		return types.Array(types.Block)
	}

	if !typ.IsResource() {
		return types.Block
	}

	info := schema.Lookup(typ.ResourceName())
	if info != nil && info.ListType != "" {
		return types.Array(types.Block)
	}

	return types.Block
}

// compileBlock on a context
func (c *compiler) compileBlock(expressions []*parser.Expression, typ types.Type, bindingRef uint64) (types.Type, error) {
	// For resource, users may indicate to query all fields. It also works for list of resources.
	// This is a special case which is handled here:
	if len(expressions) == 1 && (typ.IsResource() || (typ.IsArray() && typ.Child().IsResource())) {
		x := expressions[0]

		// Special handling for the glob operation on resource fields. It will
		// try to grab all valid fields and return them.
		if x.Operand != nil && x.Operand.Value != nil && x.Operand.Value.Ident != nil && *(x.Operand.Value.Ident) == "*" {
			var fields map[string]llx.Documentation
			if typ.IsArray() {
				fields = availableGlobFields(c, typ.Child(), false)
			} else {
				fields = availableGlobFields(c, typ, true)
			}

			expressions = []*parser.Expression{}
			keys := sortx.Keys(fields)
			for _, v := range keys {
				name := v
				expressions = append(expressions, &parser.Expression{
					Operand: &parser.Operand{
						Value: &parser.Value{Ident: &name},
					},
				})
			}
		}
	}

	refs, err := c.blockExpressions(expressions, typ, bindingRef, "_")
	if err != nil {
		return types.Nil, err
	}
	if refs.block == 0 {
		return typ, nil
	}

	args := []*llx.Primitive{llx.FunctionPrimitive(refs.block)}
	for _, v := range refs.deps {
		if c.isInMyBlock(v) {
			args = append(args, llx.RefPrimitiveV2(v))
		}
	}
	c.blockDeps = append(c.blockDeps, refs.deps...)

	resultType := blockCallType(typ, c.Schema)
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "{}",
		Function: &llx.Function{
			Type:    string(resultType),
			Binding: refs.binding,
			Args:    args,
		},
	})

	return resultType, nil
}

func (c *compiler) compileIfBlock(expressions []*parser.Expression, chunk *llx.Chunk) (types.Type, error) {
	// if `else { .. }` is called, we reset the prevID to indicate there is no
	// more chaining happening
	if c.prevID == "else" {
		c.prevID = ""
	}

	blockCompiler := c.newBlockCompiler(c.Binding)
	err := blockCompiler.compileExpressions(expressions)
	if err != nil {
		return types.Nil, err
	}
	blockCompiler.updateEntrypoints()

	block := blockCompiler.block

	// we set this to true, so that we can decide how to handle all following expressions
	if block.SingleValue {
		c.block.SingleValue = true
	}

	// insert a body if we are in standalone mode to return a value
	if len(block.Chunks) == 0 && c.standalone {
		blockCompiler.addChunk(&llx.Chunk{
			Call:      llx.Chunk_PRIMITIVE,
			Primitive: llx.NilPrimitive,
		})
		blockCompiler.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   "return",
			Function: &llx.Function{
				Type: string(types.Nil),
				// FIXME: this is gonna crash on c.Binding == nil
				Args: []*llx.Primitive{llx.RefPrimitiveV2(blockCompiler.blockRef | 1)},
			},
		})
		block.SingleValue = true
		block.Entrypoints = []uint64{blockCompiler.blockRef | 2}
	}

	depArgs := []*llx.Primitive{}
	for _, v := range blockCompiler.blockDeps {
		if c.isInMyBlock(v) {
			depArgs = append(depArgs, llx.RefPrimitiveV2(v))
		}
	}

	// the last chunk in this case is the `if` function call
	chunk.Function.Args = append(chunk.Function.Args,
		llx.FunctionPrimitive(blockCompiler.blockRef),
		llx.ArrayPrimitive(depArgs, types.Ref),
	)

	c.blockDeps = append(c.blockDeps, blockCompiler.blockDeps...)

	if len(block.Chunks) != 0 {
		var typeToEnforce types.Type
		if c.block.SingleValue {
			last := block.LastChunk()
			typeToEnforce = last.Type()
		} else {
			typeToEnforce = types.Block
		}

		t, ok := types.Enforce(types.Type(chunk.Function.Type), typeToEnforce)
		if !ok {
			return types.Nil, errors.New("mismatched return type for child block of if-function; make sure all return types are the same")
		}
		chunk.Function.Type = string(t)
	}

	return types.Nil, nil
}

func (c *compiler) compileSwitchCase(expression *parser.Expression, bind *variable, chunk *llx.Chunk) error {
	// for the default case, we get a nil expression. We mark it with an unset
	// primitive (not `BoolPrimitive(true)`) so the runtime can tell the default
	// apart from a real case whose condition happens to be a constant boolean,
	// e.g. `case true:` / `case false:`. See mondoohq/mql#1174.
	if expression == nil {
		chunk.Function.Args = append(chunk.Function.Args, llx.UnsetPrimitive)
		return nil
	}

	prevBind := c.Binding
	c.Binding = bind
	defer func() {
		c.Binding = prevBind
	}()

	argValue, err := c.compileExpression(expression)
	if err != nil {
		return err
	}
	chunk.Function.Args = append(chunk.Function.Args, argValue)
	return nil
}

func (c *compiler) compileSwitchBlock(expressions []*parser.Expression, chunk *llx.Chunk) (types.Type, error) {
	// determine if there is a binding
	// i.e. something inside of those `switch( ?? )` calls
	var bind *variable
	arg := chunk.Function.Args[0]

	// we have to pop the switch chunk from the compiler stack, because it needs
	// to be the last item on the stack. otherwise the last reference (top of stack)
	// will not be pointing to it and an additional entrypoint will be generated

	lastRef := c.block.TailRef(c.blockRef)
	if c.block.LastChunk() != chunk {
		return types.Nil, errors.New("failed to compile switch statement, it wasn't on the top of the compile stack")
	}

	c.block.Chunks = c.block.Chunks[:len(c.block.Chunks)-1]
	c.Result.CodeV2.Checksums[lastRef] = ""

	defer func() {
		c.addChunk(chunk)
	}()

	if types.Type(arg.Type) != types.Unset {
		if types.Type(arg.Type) == types.Ref {
			val, ok := arg.RefV2()
			if !ok {
				return types.Nil, errors.New("could not resolve references of switch argument")
			}
			bind = &variable{
				typ: types.Type(arg.Type),
				ref: val,
			}
		} else {
			c.addChunk(&llx.Chunk{
				Call:      llx.Chunk_PRIMITIVE,
				Primitive: arg,
			})
			ref := c.block.TailRef(c.blockRef)
			bind = &variable{typ: types.Type(arg.Type), ref: ref}
		}
	}

	lastType := types.Unset
	for i := 0; i < len(expressions); i += 2 {
		err := c.compileSwitchCase(expressions[i], bind, chunk)
		if err != nil {
			return types.Nil, err
		}

		// compile the block of this case/default
		if i+1 >= len(expressions) {
			return types.Nil, errors.New("missing block expression in calling `case`/`default` statement")
		}

		block := expressions[i+1]
		if *block.Operand.Value.Ident != "{}" {
			return types.Nil, errors.New("expected block inside case/default statement")
		}

		expressions := block.Operand.Block

		blockCompiler := c.newBlockCompiler(bind)
		// TODO(jaym): Discuss with dom: don't understand what
		// standalone is used for here
		blockCompiler.standalone = true

		err = blockCompiler.compileExpressions(expressions)
		if err != nil {
			return types.Nil, err
		}
		blockCompiler.updateEntrypoints()

		// TODO(jaym): Discuss with dom: v1 seems to hardcore this as
		// single valued
		blockCompiler.block.SingleValue = true

		// Check the types
		lastChunk := blockCompiler.block.LastChunk()
		if lastType == types.Unset {
			lastType = lastChunk.Type()
		} else {
			// If the last type is not the same as the current type, then
			// we set the type to any
			if lastChunk.Type() != lastType {
				lastType = types.Any
			}
			chunk.Function.Type = string(lastType)
		}

		depArgs := []*llx.Primitive{}
		for _, v := range blockCompiler.blockDeps {
			if c.isInMyBlock(v) {
				depArgs = append(depArgs, llx.RefPrimitiveV2(v))
			}
		}

		chunk.Function.Args = append(chunk.Function.Args,
			llx.FunctionPrimitive(blockCompiler.blockRef),
			llx.ArrayPrimitive(depArgs, types.Ref),
		)

		c.blockDeps = append(c.blockDeps, blockCompiler.blockDeps...)

	}

	// FIXME: I'm pretty sure we don't need this ...
	// c.Result.Code.RefreshChunkChecksum(chunk)

	return types.Nil, nil
}

func (c *compiler) compileUnboundBlock(expressions []*parser.Expression, chunk *llx.Chunk) (types.Type, error) {
	switch chunk.Id {
	case "if":
		t, err := c.compileIfBlock(expressions, chunk)
		if err == nil {
			code := c.Result.CodeV2
			code.Checksums[c.tailRef()] = chunk.ChecksumV2(c.blockRef, code)
		}
		return t, err

	case "switch":
		return c.compileSwitchBlock(expressions, chunk)
	default:
		return types.Nil, errors.New("don't know how to compile unbound block on call `" + chunk.Id + "`")
	}
}

type blockRefs struct {
	// reference to the block that was created
	block uint64
	// references to all dependencies of the block
	deps []uint64
	// if it's a standalone bloc
	isStandalone bool
	// any changes to binding that might have occurred during the block compilation
	binding uint64
}

// evaluates the given expressions on a non-array resource (eg: no `[]int` nor `groups`)
// and creates a function, returning the entire block compiler after completion
func (c *compiler) blockcompileOnResource(expressions []*parser.Expression, typ types.Type, binding uint64, bindingName string) (*compiler, error) {
	blockCompiler := c.newBlockCompiler(nil)
	blockCompiler.block.AddArgumentPlaceholder(blockCompiler.Result.CodeV2,
		blockCompiler.blockRef, typ, blockCompiler.Result.CodeV2.Checksums[binding])
	v := variable{
		ref: blockCompiler.blockRef | 1,
		typ: typ,
		callback: func() {
			blockCompiler.standalone = false
		},
	}
	// When the user supplies an explicit name (e.g. `.map(p: ...)`) the bound
	// resource is reachable only through that name and through `_`. We also
	// register `_` so the implicit-call form keeps working alongside the name.
	blockCompiler.vars.add(bindingName, v)
	if bindingName != "_" {
		blockCompiler.vars.add("_", v)
		blockCompiler.bindingIsExplicit = true
	}
	blockCompiler.Binding = &v

	err := blockCompiler.compileExpressions(expressions)
	if err != nil {
		return &blockCompiler, err
	}

	blockCompiler.updateEntrypoints()
	blockCompiler.updateLabels()

	return &blockCompiler, nil
}

// evaluates the given expressions on a non-array resource (eg: no `[]int` nor `groups`)
// and creates a function, returning resource references after completion
func (c *compiler) blockOnResource(expressions []*parser.Expression, typ types.Type, binding uint64, bindingName string) (blockRefs, error) {
	blockCompiler, err := c.blockcompileOnResource(expressions, typ, binding, bindingName)
	return blockRefs{
		block:        blockCompiler.blockRef,
		deps:         blockCompiler.blockDeps,
		isStandalone: blockCompiler.standalone,
		binding:      binding,
	}, err
}

// blockExpressions evaluates the given expressions as if called by a block and
// returns the compiled function reference
func (c *compiler) blockExpressions(expressions []*parser.Expression, typ types.Type, binding uint64, bindingName string) (blockRefs, error) {
	if len(expressions) == 0 {
		return blockRefs{}, nil
	}

	if typ.IsArray() {
		return c.blockOnResource(expressions, typ.Child(), binding, bindingName)
	}

	// A block on an asset reference runs against the root resource of the
	// referenced asset, so the deref happens once here rather than once per
	// field inside the block.
	if typ.IsAsset() {
		rootBinding, err := c.compileAssetRoot(&variable{typ: typ, ref: binding})
		if err != nil {
			return blockRefs{}, err
		}
		if c.Schema.Lookup(rootBinding.typ.ResourceName()) == nil {
			// Without the root's schema there is no type to compile a block
			// against. A single field still works (it defers its type to the
			// executing runtime), a block does not. See ADR 031 decision 2.
			return blockRefs{}, errors.New("cannot open a block on asset root '" +
				rootBinding.typ.ResourceName() + "': its schema is not loaded here")
		}
		typ = rootBinding.typ
		binding = rootBinding.ref
	}

	// when calling a block {} on an array resource, we expand it to all its list
	// items and apply the block to those only
	if typ.IsResource() {
		info := c.Schema.Lookup(typ.ResourceName())
		if info != nil && info.ListType != "" {
			typ = types.Type(info.ListType)
			c.addChunk(&llx.Chunk{
				Call: llx.Chunk_FUNCTION,
				Id:   "list",
				Function: &llx.Function{
					Binding: binding,
					Type:    string(types.Array(typ)),
				},
			})
			binding = c.tailRef()
		}
	}

	return c.blockOnResource(expressions, typ, binding, bindingName)
}

// Returns the singular return type of the given block.
// Error if the block has multiple entrypoints (i.e. non singular)
func (c *compiler) blockType(ref uint64) (types.Type, error) {
	block := c.Result.CodeV2.Block(ref)
	if block == nil {
		return types.Nil, errors.New("cannot find block for block ref " + strconv.Itoa(int(ref>>32)))
	}

	if len(block.Entrypoints) != 1 {
		return types.Nil, errors.New("block should only return 1 value (got: " + strconv.Itoa(len(block.Entrypoints)) + ")")
	}

	ep := block.Entrypoints[0]
	chunk := block.Chunks[(ep&0xFFFFFFFF)-1]
	// TODO: this could be a ref! not sure if we can handle that... maybe dereference?
	return chunk.Type(), nil
}

func (c *compiler) dereferenceType(val *llx.Primitive) (types.Type, error) {
	valType := types.Type(val.Type)
	if types.Type(val.Type) != types.Ref {
		return valType, nil
	}

	ref, ok := val.RefV2()
	if !ok {
		return types.Nil, errors.New("found a reference type that doesn't return a reference value")
	}

	chunk := c.Result.CodeV2.Chunk(ref)
	if chunk.Primitive == val {
		return types.Nil, errors.New("recursive reference connections detected")
	}

	if chunk.Primitive != nil {
		return c.dereferenceType(chunk.Primitive)
	}

	valType = chunk.DereferencedTypeV2(c.Result.CodeV2)
	return valType, nil
}

func (c *compiler) unnamedArgs(callerLabel string, init *resources.Init, args []*parser.Arg) ([]*llx.Primitive, error) {
	if len(args) > len(init.Args) {
		return nil, errors.New("Called " + callerLabel +
			" with too many arguments (expected " + strconv.Itoa(len(init.Args)) +
			" but got " + strconv.Itoa(len(args)) + ")")
	}

	// add all calls to the chunk stack
	// collect all their types and call references.
	// len(args) is bounded by the parsed query, but guard the size computation
	// explicitly so len(args)*2 can never overflow on pathological input.
	if len(args) > math.MaxInt/2 {
		return nil, errors.New("Called " + callerLabel + " with too many arguments")
	}
	res := make([]*llx.Primitive, len(args)*2)

	for idx := range args {
		arg := args[idx]

		v, err := c.compileExpression(arg.Value)
		if err != nil {
			return nil, errors.New("addResourceCall error: " + err.Error())
		}

		vType := types.Type(v.Type)
		if vType == types.Ref {
			vType, err = c.dereferenceType(v)
			if err != nil {
				return nil, err
			}
		}

		expected := init.Args[idx]
		expectedType := types.Type(expected.Type)
		if vType != expectedType && expectedType != types.Any {
			// TODO: We are looking for dict types to see if we can type-cast them
			// This needs massive improvements to dynamically cast them in LLX.
			// For a full description see: https://gitlab.com/mondoolabs/mondoo/-/issues/241
			// This is ONLY a temporary workaround which works in a few cases:
			if vType == types.Dict && expectedType == types.String {
				// we are good, LLX will handle it
			} else {
				return nil, errors.New("Incorrect type on argument " + strconv.Itoa(idx) +
					" in " + callerLabel + ": expected " + expectedType.Label() +
					", got: " + vType.Label())
			}
		}

		res[idx*2] = llx.StringPrimitive(expected.Name)
		res[idx*2+1] = v
	}

	return res, nil
}

func (c *compiler) unnamedResourceArgs(resource *resources.ResourceInfo, args []*parser.Arg) ([]*llx.Primitive, error) {
	if resource.Init == nil {
		return nil, errors.New("cannot find init call for resource " + resource.Id)
	}

	return c.unnamedArgs("resource "+resource.Name, resource.Init, args)
}

// resourceArgs turns the list of arguments for the resource into a list of
// primitives that are used as arguments to initialize that resource
// only works if len(args) > 0 !!
// only works if args are either ALL named or not named !!
func (c *compiler) resourceArgs(resource *resources.ResourceInfo, args []*parser.Arg) ([]*llx.Primitive, error) {
	if args[0].Name == "" {
		return c.unnamedResourceArgs(resource, args)
	}

	// len(args) is bounded by the parsed query, but guard the size computation
	// explicitly so len(args)*2 can never overflow on pathological input.
	if len(args) > math.MaxInt/2 {
		return nil, errors.New("resource " + resource.Name + " called with too many arguments")
	}
	res := make([]*llx.Primitive, len(args)*2)
	for idx := range args {
		arg := args[idx]
		field, ok := resource.Fields[arg.Name]
		if !ok {
			return nil, errors.New("resource " + resource.Name + " does not have a field named " + arg.Name)
		}

		v, err := c.compileExpression(arg.Value)
		if err != nil {
			return nil, errors.New("resourceArgs error: " + err.Error())
		}

		vt, err := c.dereferenceType(v)
		if err != nil {
			return nil, err
		}

		ft := types.Type(field.Type)
		if vt != ft {
			return nil, errors.New("Wrong type for field " + arg.Name + " in resource " + resource.Name + ": expected " + ft.Label() + ", got " + vt.Label())
		}

		res[idx*2] = llx.StringPrimitive(arg.Name)
		res[idx*2+1] = v
	}

	return res, nil
}

func (c *compiler) compileBuiltinFunction(h *compileHandler, id string, binding *variable, call *parser.Call) (types.Type, error) {
	if h.compile != nil {
		return h.compile(c, binding.typ, binding.ref, id, call)
	}

	var args []*llx.Primitive

	if call != nil {
		for idx := range call.Function {
			arg := call.Function[idx]
			x, err := c.compileExpression(arg.Value)
			if err != nil {
				return types.Nil, err
			}
			if x != nil {
				args = append(args, x)
			}
		}
	}

	if err := h.signature.Validate(args, c); err != nil {
		return types.Nil, err
	}

	resType := h.returnType(binding.typ)
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(resType),
			Binding: binding.ref,
			Args:    args,
		},
	})
	return resType, nil
}

func filterTrailingNullArgs(call *parser.Call) *parser.Call {
	if call == nil {
		return call
	}

	res := parser.Call{
		Comments: call.Comments,
		Ident:    call.Ident,
		Function: call.Function,
		Accessor: call.Accessor,
	}

	args := call.Function
	if len(args) == 0 {
		return &res
	}

	lastIdx := len(args) - 1
	x := args[lastIdx]
	if x.Value.IsEmpty() {
		res.Function = args[0:lastIdx]
	}

	return &res
}

func filterEmptyExpressions(expressions []*parser.Expression) []*parser.Expression {
	res := []*parser.Expression{}
	for i := range expressions {
		exp := expressions[i]
		if exp.IsEmpty() {
			continue
		}
		res = append(res, exp)
	}

	return res
}

// compile a bound identifier to its binding
// example: user { name } , where name is compiled bound to the user
// it will return false if it cannot bind the identifier
func (c *compiler) compileBoundIdentifier(id string, binding *variable, call *parser.Call) (bool, types.Type, error) {
	return c.compileBoundIdentifierWithMqlCtx(id, binding, call)
}

func (c *compiler) compileBoundIdentifierWithMqlCtx(id string, binding *variable, call *parser.Call) (bool, types.Type, error) {
	typ := binding.typ

	if typ.IsResource() {
		resource, _ := c.Schema.LookupField(typ.ResourceName(), id)
		if resource == nil {
			return true, types.Nil, errors.New("cannot find resource that is called by '" + id + "' of type " + typ.Label())
		}

		fieldPath, fieldinfos, ok := c.Schema.FindField(resource, id)
		if ok {
			c.narrowRoots(resource, id)
			fieldinfo := fieldinfos[len(fieldinfos)-1]
			c.Stats.CallField(resource.Name, fieldinfo)

			if call != nil && len(call.Function) > 0 && !fieldinfo.IsImplicitResource {
				return true, types.Nil, errors.New("cannot call field '" + resource.Name + "." + id + "' with arguments yet (it is a field, not a resource)")
			}

			// this only happens when we call a field of a bridging resource,
			// in which case we don't call the field (since there is nothing to do)
			// and instead we call the resource directly:
			typ := types.Type(fieldinfo.Type)
			if fieldinfo.IsImplicitResource {
				name := typ.ResourceName()

				if binding.ref == 0 {
					c.addChunk(&llx.Chunk{
						Call: llx.Chunk_FUNCTION,
						Id:   name,
					})
				} else {
					f := &llx.Function{
						Type: string(types.Resource(name)),
						Args: []*llx.Primitive{
							llx.RefPrimitiveV2(binding.ref),
						},
					}
					if call != nil && len(call.Function) > 0 {
						realResource := c.Schema.Lookup(typ.ResourceName())
						if realResource == nil {
							// Classified rather than bare (ADR 046): downstream
							// this means the asset went away mid-scan, and
							// cnspec reads it today by matching the message
							// prefix. The message is unchanged so that match
							// keeps working until it reads the kind instead.
							return true, types.Nil, llx.AssetVanished(
								errors.New("could not find resource " + typ.ResourceName()))
						}
						args, err := c.resourceArgs(realResource, call.Function)
						if err != nil {
							return true, types.Nil, err
						}
						f.Args = append(f.Args, args...)
					}

					c.addChunk(&llx.Chunk{
						Call:     llx.Chunk_FUNCTION,
						Id:       "createResource",
						Function: f,
					})
				}

				// the new ID is now the full resource call, which is not what the
				// field is originally labeled when we get it, so we have to fix it
				checksum := c.Result.CodeV2.Checksums[c.tailRef()]
				c.Result.Labels.Labels[checksum] = id
				return true, typ, nil
			}

			lastRef := binding.ref
			for i, p := range fieldPath {
				c.addChunk(&llx.Chunk{
					Call: llx.Chunk_FUNCTION,
					Id:   p,
					Function: &llx.Function{
						Type:    fieldinfos[i].Type,
						Binding: lastRef,
					},
				})
				lastRef = c.tailRef()
				// Downgrade fallbacks for this field (ADR 040 part 6). Field
				// chunks are emitted from two places; both have to offer them,
				// or whether a fallback exists would depend on how the field
				// was reached rather than on what the field is.
				c.emitTranslations(resource.Id, p, lastRef, types.Type(fieldinfos[i].Type))
			}

			return true, typ, nil
		}
	}

	h, _ := builtinFunction(typ, id)
	if h != nil {
		call = filterTrailingNullArgs(call)
		typ, err := c.compileBuiltinFunction(h, id, binding, call)
		return true, typ, err
	}

	// `asset<root>.field` chains into the referenced asset's tree. Tried after
	// the builtins, so the nil comparisons registered on the asset type keep
	// winning over a same-named field of the root.
	if typ.IsAsset() {
		return c.compileAssetRootField(id, binding, call)
	}

	return false, types.Nil, nil
}

// compileAssetRootField compiles a field read on the resource that roots the
// asset a typed `asset<root>` value points at (ADR 031).
//
// The asset is dereferenced into its root resource by its own chunk, so
// everything above it is an ordinary resource chain: blocks, `where`, labels and
// recording all see a resource and need to know nothing about assets.
func (c *compiler) compileAssetRootField(id string, binding *variable, call *parser.Call) (bool, types.Type, error) {
	rootBinding, err := c.compileAssetRoot(binding)
	if err != nil {
		return true, types.Nil, err
	}

	if c.Schema.Lookup(rootBinding.typ.ResourceName()) == nil {
		// The root's schema is not loaded here, so the member cannot be checked.
		// This is the compile-here / run-there case (a bundle compiled where the
		// referenced provider is not installed), so the field is emitted untyped
		// and its type resolves from the executing runtime's schema. See ADR 031
		// decision 2.
		// Arguments would have to be checked against an init signature this
		// compile cannot see, so they are refused rather than passed on
		// unchecked.
		if call != nil && len(call.Function) > 0 {
			return true, types.Nil, errors.New("cannot call '" + id + "' with arguments: the schema for asset root '" +
				rootBinding.typ.ResourceName() + "' is not loaded")
		}

		log.Debug().
			Str("root", rootBinding.typ.ResourceName()).
			Str("field", id).
			Msg("mqlc> cannot type-check a field of an asset root that no loaded schema defines; deferring it to runtime")

		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   id,
			Function: &llx.Function{
				Type:    string(types.Any),
				Binding: rootBinding.ref,
			},
		})
		return true, types.Any, nil
	}

	return c.compileBoundIdentifierWithMqlCtx(id, rootBinding, call)
}

// compileAssetRoot emits the chunk that turns an `asset<root>` value into the
// root resource of the asset it points at, and returns the binding for it.
func (c *compiler) compileAssetRoot(binding *variable) (*variable, error) {
	root := binding.typ.AssetRootName()
	if root == "" {
		return nil, errors.New("cannot resolve into an asset reference that declares no root type")
	}

	typ := types.Resource(root)
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   llx.AssetRootChunkID,
		Function: &llx.Function{
			Type:    string(typ),
			Binding: binding.ref,
		},
	})
	return &variable{typ: typ, ref: c.tailRef()}, nil
}

// prefersFieldOverResource reports whether the dotted path `owner`.`field`
// should be compiled as a field read on owner instead of being extended into the
// resource of the same name.
//
// The path extension is greedy, so a resource name always used to win over a
// field of the same name. That is wrong for private resources: private means the
// resource cannot stand on its own, and a bare instance skips the owner's
// accessor. For resources whose fields are only filled by that accessor every
// field then reads null, which combined with MQL's asymmetric null comparisons
// turns a check into a confidently wrong verdict rather than an error. See
// windows.deviceGuard, windows.lsa.ntlm, aws.emr.cluster.encryptionConfiguration
// and friends.
//
// Only redirect when the owner really does expose the value under that name and
// with exactly that type, so nothing that used to compile becomes unreachable.
// Implicit fields are excluded: those are the singular accessors lr generates for
// every `x.y` resource, they are not backed by an accessor on the owner, so
// routing through them would break paths that work today.
func (c *compiler) prefersFieldOverResource(owner *resources.ResourceInfo, target *resources.ResourceInfo, field string) bool {
	if !target.GetPrivate() {
		return false
	}
	_, f := c.Schema.LookupField(owner.Name, field)
	if f == nil || f.GetIsImplicitResource() {
		return false
	}
	return types.Type(f.Type) == types.Resource(target.Name)
}

// compile a resource from an identifier, trying to find the longest matching resource
// and execute all call functions if there are any
// compileRootMember resolves an identifier as a member of the connected asset's
// root, which is what makes a query behave like `assetRoot { ... }` (ADR 031
// point 7). It emits the root resource and then the member on top of it, so
// `hostname` compiles exactly as `os.linux.hostname` would.
//
// Reports false when there is no root, or the root does not carry the member, so
// the caller falls through to its own not-found handling and the message stays
// about the identifier the user typed.
func (c *compiler) compileRootMember(id string, calls []*parser.Call) (bool, []*parser.Call, types.Type, error) {
	if c.AssetRoot == "" {
		return false, nil, types.Nil, nil
	}
	root := c.Schema.Lookup(c.AssetRoot)
	if root == nil {
		return false, nil, types.Nil, nil
	}
	// FindField walks embedded resources, which is how a member of `os.base`
	// is reachable on the `os.linux` root.
	_, fields, ok := c.Schema.FindField(root, id)
	if !ok {
		return false, nil, types.Nil, nil
	}

	// A call with arguments that this member cannot serve is not a member read
	// at all: it names the resource of the same name. `tls` is a member of
	// `network.host` *and* a resource you construct with a target, so
	// `tls("example.com")` has to reach the resource while a bare `tls` reads
	// the member. Declining here is the same move a type conversion makes when
	// it is called with no arguments - the identifier goes back for the other
	// interpretation rather than failing on this one.
	if len(calls) > 0 && calls[0].Function != nil && len(calls[0].Function) > 0 &&
		!c.rootMemberTakesArgs(fields) {
		return false, nil, types.Nil, nil
	}

	rootType, err := c.addResource(c.AssetRoot, root, nil)
	if err != nil {
		return true, nil, types.Nil, err
	}
	binding := &variable{typ: rootType, ref: c.tailRef()}

	var call *parser.Call
	if len(calls) > 0 && calls[0].Function != nil {
		call = calls[0]
		calls = calls[1:]
	}

	found, typ, err := c.compileBoundIdentifier(id, binding, call)
	if !found && err == nil {
		err = errors.New("cannot find field '" + id + "' in " + c.AssetRoot)
	}
	return true, calls, typ, err
}

// rootMemberTakesArgs reports whether a root member can be called with
// arguments. Only one shape can: an *implicit* member, the kind an alias
// creates, which constructs its resource and so passes the arguments to that
// resource's init. `_.file("/etc/hosts")` is that shape.
//
// A field that merely *returns* a resource cannot, even though its type has an
// init: reading it runs the provider's accessor, which takes no arguments.
// `network.host.tls` is that shape - it hands back the TLS endpoint of the
// connected host - so `tls("example.com")` has to mean the resource instead.
// And a plain field cannot either, whatever dependencies it declares:
// `path(env)` names what the compiler resolves first, not something a user
// passes.
func (c *compiler) rootMemberTakesArgs(fields []*resources.Field) bool {
	if len(fields) == 0 {
		return false
	}
	field := fields[len(fields)-1]
	if field == nil || !field.IsImplicitResource {
		return false
	}
	name := types.ResourceOf(types.Type(field.Type))
	if name == "" {
		return false
	}
	info := c.Schema.Lookup(name)
	if info == nil || info.Init == nil {
		return false
	}
	return len(info.Init.Args) > 0
}

func (c *compiler) compileResource(id string, calls []*parser.Call) (bool, []*parser.Call, types.Type, error) {
	resource := c.Schema.Lookup(id)
	if resource == nil {
		return false, nil, types.Nil, nil
	}
	// Checked on the name that entered the namespace, before the dotted walk
	// below: `sshd.config.params` reaches the namespace as `sshd`, and whether
	// *that* hangs off the root is the question. The leaf never does - a root
	// carries `sshd`, not `sshd.config`.
	c.noteIfUnrooted(resource)

	for len(calls) > 0 && calls[0].Ident != nil {
		field := *calls[0].Ident
		nuID := id + "." + field
		nuResource := c.Schema.Lookup(nuID)
		if nuResource == nil {
			break
		}
		if c.prefersFieldOverResource(resource, nuResource, field) {
			break
		}
		// Extending a root by one segment is a member read off that root, the
		// same as a field access: `_.iptables` reaches the resource by its
		// rooted name because the alias made one, and it narrows what can run
		// this bundle just as `_ { iptables }` does.
		c.narrowRoots(resource, field)
		resource, id = nuResource, nuID
		calls = calls[1:]
	}

	c.Stats.CallResource(resource.Name)

	var call *parser.Call
	if len(calls) > 0 && calls[0].Function != nil {
		call = calls[0]
		calls = calls[1:]
	}

	typ, err := c.addResource(id, resource, call)
	return true, calls, typ, err
}

// narrowRoots keeps track of which asset roots can execute this bundle, by
// intersecting - for every member read off a root - the roots that carry it
// (ADR 031 point 4).
//
// A query reading only universal members stays satisfied by every root; one
// reading `iptables` narrows to the Linux root and the union above it. That is
// applicability derived from what the code reads, rather than declared next to
// it by hand.
//
// Only members read off a *root* count. A member of an ordinary resource says
// nothing about which asset can run the query, and the global namespace says
// nothing either - which is why a v14 bundle that never touches a root records
// no requirement and runs everywhere, exactly as before.
func (c *compiler) narrowRoots(resource *resources.ResourceInfo, field string) {
	if resource == nil || !resource.GetRoot() || c.Schema == nil {
		return
	}

	// Blocks compile in their own compiler, so the intersection - and the index
	// the carriers come from - live on the one at the top: a member read inside
	// `_ { ... }` narrows the same bundle as one read outside it.
	top := c
	for top.parent != nil {
		top = top.parent
	}

	carriers := top.rootIdx().carriersOf(c.Schema, field)
	if len(carriers) == 0 {
		return
	}

	if top.compatibleRoots == nil {
		// Copied, not aliased: the intersection below mutates this map, and
		// carriers comes from the index, where it is answering for every other
		// read of the same member.
		top.compatibleRoots = make(map[string]struct{}, len(carriers))
		for name := range carriers {
			top.compatibleRoots[name] = struct{}{}
		}
		return
	}
	// Intersecting can empty the set, and an empty *non-nil* set is meaningful:
	// members were read off a root, and no single root carries all of them. It
	// stays distinct from nil (nothing was read off a root at all) only until
	// recordCompatibleRoots, which deliberately treats both as "no requirement".
	// Do not add a `!= nil` test to that decision without reading the reasoning
	// there first - the two states differ in provenance, not in verdict.
	for name := range top.compatibleRoots {
		if _, ok := carriers[name]; !ok {
			delete(top.compatibleRoots, name)
		}
	}
}

// recordCompatibleRoots writes the narrowed set onto the bundle.
//
// An empty intersection is recorded as no requirement rather than as
// "unsatisfiable". A query that reads a Linux-only and a Windows-only member is
// usually a deliberately cross-platform one - `if ... else ...` over both - and
// it should still run, with each member degrading on the platform that lacks
// it. Refusing it, or marking it runnable nowhere, would break that pattern.
func (c *compiler) recordCompatibleRoots() {
	if len(c.compatibleRoots) == 0 {
		return
	}
	roots := make([]string, 0, len(c.compatibleRoots))
	for name := range c.compatibleRoots {
		roots = append(roots, name)
	}
	sort.Strings(roots)
	c.Result.CompatibleRoots = roots
}

// rootIndex answers "which asset roots carry this member" without walking the
// schema for every read.
//
// Finding the roots means scanning every resource the schema knows - hundreds
// in a two-provider schema, many thousands with a full set installed - so doing
// it per field access made narrowing cost O(fields x resources). Both halves are
// stable for the length of a compile: the roots do not change, and neither does
// which of them carries a given member.
type rootIndex struct {
	roots    []*resources.ResourceInfo
	carriers map[string]map[string]struct{}
}

func (c *compiler) rootIdx() *rootIndex {
	if c.roots != nil {
		return c.roots
	}

	// The provider's declared root is the union of its roots, a compile-time
	// receiver no connection ever reports. It carries every member by
	// construction, so counting it would make every intersection non-empty and
	// leave deliberately cross-platform content narrowed to a root no asset has.
	unions := c.Schema.AllProviderRoots()

	idx := &rootIndex{carriers: map[string]map[string]struct{}{}}
	for name, info := range c.Schema.AllResources() {
		if info == nil || !info.GetRoot() || name != info.Id {
			continue
		}
		if unions[info.GetProvider()] == name {
			continue
		}
		idx.roots = append(idx.roots, info)
	}
	c.roots = idx
	return idx
}

func (idx *rootIndex) carriersOf(schema resources.ResourcesSchema, field string) map[string]struct{} {
	if known, ok := idx.carriers[field]; ok {
		return known
	}

	carriers := map[string]struct{}{}
	for _, root := range idx.roots {
		if _, _, ok := schema.FindField(root, field); ok {
			carriers[root.Id] = struct{}{}
		}
	}
	idx.carriers[field] = carriers
	return carriers
}

// noteIfUnrooted records a resource that this bundle reaches through the global
// namespace and that has no home in an asset's tree (ADR 031 point 7).
//
// Recorded on the bundle and never logged. Compilation runs on every keystroke
// behind shell autocomplete, so anything the compiler prints lands in the middle
// of the terminal UI - typing `os` was enough to garble it. What to show a user,
// and when, is the caller's decision to make from `unrooted_resources`.
//
// Three ways to be fine: the resource says `@global`, its provider declares no
// root yet (nothing to be outside of, so the question is not answerable), or it
// is reachable from that provider's root and the global name is just the other
// spelling. What is left is what stops resolving when the root becomes the
// namespace, which is exactly what is worth counting before that happens.
func (c *compiler) noteIfUnrooted(resource *resources.ResourceInfo) {
	if resource == nil || resource.GetGlobal() || c.Schema == nil || c.Result == nil {
		return
	}

	root := c.Schema.AllProviderRoots()[resource.GetProvider()]
	if root == "" {
		return
	}
	// A root is what everything else hangs off; it does not hang off itself.
	if resource.Id == root || resource.Id == c.AssetRoot {
		return
	}
	// Bridging nodes (`os` for `os.linux`) are namespace segments the schema
	// builder creates, not resources anything resolves to, so they are not a
	// thing that can be inside or outside a tree.
	if resource.GetIsExtension() {
		return
	}
	rootInfo := c.Schema.Lookup(root)
	if rootInfo == nil {
		return
	}
	if _, _, ok := c.Schema.FindField(rootInfo, resource.Id); ok {
		return
	}

	for _, existing := range c.Result.UnrootedResources {
		if existing == resource.Id {
			return
		}
	}
	c.Result.UnrootedResources = append(c.Result.UnrootedResources, resource.Id)
}

func (c *compiler) addResource(id string, resource *resources.ResourceInfo, call *parser.Call) (types.Type, error) {
	var function *llx.Function
	var err error
	typ := types.Resource(id)

	if call != nil && len(call.Function) > 0 {
		function = &llx.Function{Type: string(typ)}
		function.Args, err = c.resourceArgs(resource, call.Function)
		if err != nil {
			return types.Nil, err
		}
	}

	c.addChunk(&llx.Chunk{
		Call:     llx.Chunk_FUNCTION,
		Id:       id,
		Function: function,
	})
	return typ, nil
}

// compileIdentifier within a context of a binding
// 1. global f(): 			expect, ...
// 2. global resource: 	sshd, sshd.config
// 3. bound field: 			user { name }
// x. called field: 		user.name <= not in this scope
func (c *compiler) compileIdentifier(id string, callBinding *variable, calls []*parser.Call) ([]*parser.Call, types.Type, error) {
	var call *parser.Call
	restCalls := calls
	if len(calls) > 0 && calls[0].Function != nil {
		call = calls[0]
		restCalls = calls[1:]
	}

	var typ types.Type
	var err error
	var found bool
	if callBinding != nil {
		// special handling for the `self` operator
		if id == "_" {
			c.standalone = false

			if len(restCalls) == 0 {
				return restCalls, callBinding.typ, nil
			}

			nextCall := restCalls[0]

			if nextCall.Ident != nil {
				calls = restCalls[1:]
				call = nil
				if len(calls) > 0 && calls[0].Function != nil {
					call = calls[0]
				}

				found, typ, err = c.compileBoundIdentifier(*nextCall.Ident, callBinding, call)
				if found {
					if call != nil {
						return restCalls[2:], typ, err
					}
					return restCalls[1:], typ, err
				}
				return nil, types.Nil, errors.New("could not find call _." + (*nextCall.Ident))
			}

			if nextCall.Accessor != nil {
				// turn accessor into a regular function and call that
				fCall := &parser.Call{Function: []*parser.Arg{{Value: nextCall.Accessor}}}

				// accessors are always builtin functions
				h, _ := builtinFunction(callBinding.typ.Underlying(), "[]")

				if h == nil {
					// this is the case when we deal with special resources that expand
					// this type of builtin function
					var bind *variable
					h, bind, err = c.compileImplicitBuiltin(callBinding.typ, "[]")
					if err != nil || h == nil {
						return nil, types.Nil, errors.New("cannot find '[]' function on type " + callBinding.typ.Label())
					}
					callBinding = bind
				}

				typ, err = c.compileBuiltinFunction(h, "[]", callBinding, fCall)
				if err != nil {
					return nil, types.Nil, err
				}

				return restCalls[1:], typ, nil
			}

			return nil, types.Nil, errors.New("not sure how to handle implicit calls around `_`")
		}

		// When the block has an explicit named binding (e.g. `.map(p: ...)`),
		// bare identifiers do NOT shadow the global namespace with the bound
		// resource's fields. The user must write `p.foo` or `_.foo` to reach a
		// field of the binding. This avoids the trap where a process field
		// (e.g. `command`) hides a same-named top-level resource.
		if !c.bindingIsExplicit {
			found, typ, err = c.compileBoundIdentifier(id, callBinding, call)
			if found {
				c.standalone = false
				return restCalls, typ, err
			}
		}
	} // end bound functions

	// `_` at the top level of a query is the connected asset's root resource
	// (ADR 031 decision 6). Inside a block it is the block's binding, handled
	// above; at the top level there is no binding, so before roots existed this
	// fell through to the resource lookup and failed with "cannot find resource
	// for identifier '_'".
	//
	// Compiled by name, as if the user had typed the root resource: everything
	// that works on that resource - fields, blocks, `where` - then works on `_`
	// with no further wiring.
	if id == "_" && callBinding == nil {
		if c.AssetRoot == "" || c.AssetRoot == "_" {
			return nil, types.Nil, errors.New("cannot resolve `_`: this connection declares no root resource")
		}
		// Compiled as the root resource itself, not by feeding its name back
		// through identifier resolution: under a rooted namespace that would ask
		// whether the root is a member of itself, and answer no.
		found, restCalls, typ, err := c.compileResource(c.AssetRoot, calls)
		if !found {
			return nil, types.Nil, errors.New("cannot resolve `_`: this connection declares the root '" +
				c.AssetRoot + "', which is not in the schema")
		}
		return restCalls, typ, err
	}

	if id == "props" {
		return c.compileProps(call, restCalls, c.Result)
	}

	f := operatorsCompilers[id]
	if f != nil {
		typ, err := f(c, id, call)
		return restCalls, typ, err
	}

	variable, ok := c.vars.lookup(id)
	if ok {
		if variable.name == "" {
			c.standalone = false
		}

		if variable.callback != nil {
			variable.callback()
		}

		c.blockDeps = append(c.blockDeps, variable.ref)
		c.addChunk(&llx.Chunk{
			Call:      llx.Chunk_PRIMITIVE,
			Primitive: llx.RefPrimitiveV2(variable.ref),
		})

		checksum := c.Result.CodeV2.Checksums[c.tailRef()]
		c.Result.Labels.Labels[checksum] = variable.name
		return restCalls, variable.typ, nil
	}

	f = typeConversions[id]
	if f != nil {
		typ, err := f(c, id, call)
		// If it works or is some random error, we are done. However, we
		// try to toss this fish back in the sea if it's not a conversion.
		// For example: regex.ipv4 can be handled below, since it's not a conversion
		if err == nil || err != errNotConversion {
			return restCalls, typ, err
		}
	}

	// Rooted namespace (ADR 031 point 7): the root is the namespace, so a bare
	// identifier resolves as a member of it and the global namespace is left to
	// what marks itself `@global`. This is the v15 model; the fallback below is
	// what v14 keeps.
	if c.RootedNamespace && callBinding == nil {
		if c.AssetRoot == "" {
			return nil, types.Nil, errors.New("cannot resolve '" + id +
				"': rooted compilation needs an asset root, and none was supplied")
		}
		if found, restCalls, typ, err := c.compileRootMember(id, calls); found {
			return restCalls, typ, err
		}
		if info := c.Schema.Lookup(id); info != nil && !info.GetGlobal() {
			addFieldSuggestions(availableFields(c, types.Resource(c.AssetRoot)), id, c.Result)
			return nil, types.Nil, errors.New("cannot find '" + id + "' in " + c.AssetRoot +
				"; it is not part of this asset's tree and is not a global resource")
		}
	}

	// Kept out of restCalls: compileResource reports a miss as `false, nil, ...`,
	// and assigning that into restCalls threw away the rest of the chain for
	// every branch below - `params { a.b.c }` compiled to `params["a"]` and
	// answered with the whole subtree under "a".
	var resourceCalls []*parser.Call
	found, resourceCalls, typ, err = c.compileResource(id, calls)
	if found {
		return resourceCalls, typ, err
	}

	// Support easy accessors for dicts and maps, e.g:
	// json.params { A.B.C } => json.params { _["A"]["B"]["C"] }
	if callBinding != nil && callBinding.typ == types.Dict {
		// Optionality is carried by Function.nullability, which compileOperand
		// stamps onto this chunk once it returns. The old `[]?` spelling was
		// unreachable from here anyway: it keyed off a Function call's
		// IsConditional, which the parser never sets.
		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   "[]",
			Function: &llx.Function{
				Type:    string(callBinding.typ),
				Binding: callBinding.ref,
				Args:    []*llx.Primitive{llx.StringPrimitive(id)},
				// This is a key lookup even though it reads like a field, so it
				// is a dereference and carries the marker. Set in the literal
				// rather than stamped afterwards because compileOperand only
				// stamps roots that the author marked optional.
				Nullability: c.linkNullability(false),
			},
		})
		c.standalone = false
		return restCalls, callBinding.typ, err
	}

	// A bare identifier that is not a global resource may still be a member of
	// the asset root: a query is a block on that root, so `hostname` means
	// `assetRoot.hostname` (ADR 031 point 7). Tried after the global namespace,
	// so nothing that compiles today compiles differently - only names that used
	// to fail start resolving. Under RootedNamespace the root was already tried,
	// first.
	if callBinding == nil && !c.RootedNamespace {
		if found, restCalls, typ, err := c.compileRootMember(id, calls); found {
			return restCalls, typ, err
		}
	}

	// suggestions
	if callBinding == nil {
		addResourceSuggestions(c.Schema, id, c.Result)
		// A bare name can also be a member of the asset root (`hostname`), so
		// the root's members are offered alongside the global resources. Without
		// this the shell suggests a different set of names than it accepts.
		if c.AssetRoot != "" {
			addFieldSuggestions(availableFields(c, types.Resource(c.AssetRoot)), id, c.Result)
		}
		return nil, types.Nil, c.notFound(id, nil)
	}
	addFieldSuggestions(availableFields(c, callBinding.typ), id, c.Result)
	return nil, types.Nil, c.notFound(id, callBinding)
}

// compileProps handles built-in properties for this code
// we will use any properties defined at the compiler-level as type-indicators
func (c *compiler) compileProps(call *parser.Call, calls []*parser.Call, res *llx.CodeBundle) ([]*parser.Call, types.Type, error) {
	if call != nil && len(call.Function) != 0 {
		return nil, types.Nil, errors.New("'props' is not a function")
	}

	if len(calls) == 0 {
		return nil, types.Nil, errors.New("called 'props' without a property, please provide the name you are trying to access")
	}

	nextCall := calls[0]
	restCalls := calls[1:]

	if nextCall.Ident == nil {
		return nil, types.Nil, errors.New("please call 'props' with the name of the property you are trying to access")
	}

	name := *nextCall.Ident
	prim := c.props.Get(name)
	if prim == nil {
		props := c.props.All()
		keys := make(map[string]llx.Documentation, len(props))
		for key, prim := range props {
			keys[key] = llx.Documentation{
				Field: key,
				Title: key + " (" + types.Type(prim.Type).Label() + ")",
			}
		}

		addFieldSuggestions(keys, name, res)
		return nil, types.Nil, &ErrPropertyNotFound{Name: name}
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_PROPERTY,
		Id:   name,
		Primitive: &llx.Primitive{
			Type: prim.Type,
		},
	})

	res.Props[name] = string(prim.Type)

	return restCalls, types.Type(prim.Type), nil
}

// compileValue takes an AST value and compiles it
func (c *compiler) compileValue(val *parser.Value) (*llx.Primitive, error) {
	if val.Bool != nil {
		return llx.BoolPrimitive(bool(*val.Bool)), nil
	}

	if val.Int != nil {
		return llx.IntPrimitive(int64(*val.Int)), nil
	}

	if val.Float != nil {
		return llx.FloatPrimitive(float64(*val.Float)), nil
	}

	if val.String != nil {
		return llx.StringPrimitive(*val.String), nil
	}

	if val.Regex != nil {
		re := string(*val.Regex)
		_, err := regexp.Compile(re)
		if err != nil {
			return nil, errors.New("failed to compile regular expression '" + re + "': " + err.Error())
		}
		return llx.RegexPrimitive(re), nil
	}

	if val.Array != nil {
		arr := make([]*llx.Primitive, len(val.Array))
		var err error
		for i := range val.Array {
			e := val.Array[i]
			arr[i], err = c.compileExpression(e)
			if err != nil {
				return nil, err
			}
		}

		return &llx.Primitive{
			Type:  string(llx.ArrayTypeV2(arr, c.Result.CodeV2)),
			Array: arr,
		}, nil
	}

	if val.Map != nil {
		mapRes := make(map[string]*llx.Primitive, len(val.Map))
		var resType types.Type

		for k, v := range val.Map {
			vv, err := c.compileExpression(v)
			if err != nil {
				return nil, err
			}
			if types.Type(vv.Type) != resType {
				if resType == "" {
					resType = types.Type(vv.Type)
				} else if resType != types.Any {
					resType = types.Any
				}
			}
			mapRes[k] = vv
		}

		if resType == "" {
			resType = types.Unset
		}
		// TODO: improve this by adding types to refs
		if resType == types.Ref {
			resType = types.Any
		}

		return &llx.Primitive{
			Type: string(types.Map(types.String, resType)),
			Map:  mapRes,
		}, nil
	}

	return llx.NilPrimitive, nil
}

func (c *compiler) compileOperand(operand *parser.Operand) (*llx.Primitive, error) {
	var err error
	var res *llx.Primitive
	var typ types.Type
	var ref uint64

	calls := operand.Calls
	c.comment = operand.Comments

	// Anything the root value emits sits after this point. Captured up front so
	// the root can be marked with the same range walk the links use.
	rootStart := c.tailRef()

	// value:        bool | string | regex | number | array | map | ident
	// so all simple values are compiled into primitives and identifiers
	// into function calls
	if operand.Value.Ident == nil {
		res, err = c.compileValue(operand.Value)
		if err != nil {
			return nil, err
		}
		typ = types.Type(res.Type)

		if len(calls) > 0 {
			c.addChunk(&llx.Chunk{
				Call: llx.Chunk_PRIMITIVE,
				// no ID for standalone
				Primitive: res,
			})
			ref = c.tailRef()
			res = llx.RefPrimitiveV2(ref)
		}
	} else if *operand.Value.Ident == "empty" {
		// special case for empty: there's no ref for an empty value
		// since we're not really referencing anything
		res = llx.EmptyPrimitive
	} else {
		id := *operand.Value.Ident
		orgcalls := calls
		calls, typ, err = c.compileIdentifier(id, c.Binding, calls)
		if err != nil {
			return nil, err
		}

		ref = c.tailRef()
		// A bare `_` in a block adds no chunk of its own - it *is* the binding -
		// so the operand's value is the binding's ref. At the top level there is
		// no binding: `_` compiled to the asset's root resource, which did emit
		// a chunk, so the tail ref is already the right answer (ADR 031).
		if id == "_" && len(orgcalls) == 0 && c.Binding != nil {
			ref = c.Binding.ref
		}

		res = llx.RefPrimitiveV2(ref)
	}

	// `a?` / `a?.b`: the mark guards the root value, so it lands on whatever
	// chunk the value produced.
	//
	// Only optional is ever stamped here. Required is applied per link inside the
	// loop below, and must not be applied to a root, because ProcessOperators
	// rewrites `a == b` into an operand whose root value *is* the operator
	// (parser/operators.go:165-175). Marking roots required would mark every
	// comparison, and a null operand would start erroring instead of returning
	// false - the opposite of ADR 043 §3. The one root that genuinely is a
	// dereference, the bare-word dict accessor inside a block, is marked at its
	// own emission site in compileIdentifier.
	if operand.ValueIsConditional {
		c.markNullability(rootStart, llx.Function_NULLABILITY_OPTIONAL)
	}

	// operand:      value [ call | accessor | '.' ident ]+ [ block ]
	// dealing with all call types
	for len(calls) > 0 {
		call := calls[0]
		if call.Function != nil {
			return nil, errors.New("don't know how to compile chained functions just yet")
		}

		if call.Comments != "" {
			c.comment = call.Comments
		}

		// Everything emitted from here until the next iteration belongs to this
		// link, and carries this link's nullability. A link can emit several
		// chunks (a nested field path), which is why this is a starting point
		// rather than a single ref.
		linkStart := c.tailRef()
		linkNullability := c.linkNullability(call.IsConditional)

		if call.Accessor != nil {
			// turn accessor into a regular function and call that
			fCall := &parser.Call{Function: []*parser.Arg{{Value: call.Accessor}}}
			relBinding := &variable{typ: typ, ref: ref}

			// accessors are always builtin functions
			h, _ := builtinFunction(typ.Underlying(), "[]")

			if h == nil {
				// this is the case when we deal with special resources that expand
				// this type of builtin function
				var bind *variable
				h, bind, err = c.compileImplicitBuiltin(typ, "[]")
				if err != nil || h == nil {
					return nil, errors.New("cannot find '[]' function on type " + typ.Label())
				}
				relBinding = bind
			}

			typ, err = c.compileBuiltinFunction(h, "[]", relBinding, fCall)
			if err != nil {
				return nil, err
			}

			if call != nil && len(calls) > 0 {
				calls = calls[1:]
			}
			c.markNullability(linkStart, linkNullability)
			ref = c.tailRef()
			res = llx.RefPrimitiveV2(ref)
			continue
		}

		if call.Ident != nil {
			var found bool
			var resType types.Type
			id := *call.Ident

			if id == "." {
				// We get this from the parser if the user called the dot-accessor
				// but didn't provide any values at all. It equates a not found and
				// we can now just suggest all fields
				addFieldSuggestions(availableFields(c, typ), "", c.Result)
				return nil, errors.New("missing field name in accessing " + typ.Label())
			}

			calls = calls[1:]
			call = nil
			if len(calls) > 0 && calls[0].Function != nil {
				call = calls[0]
			}

			found, resType, err = c.compileBoundIdentifier(id, &variable{typ: typ, ref: ref}, call)
			if err != nil {
				return nil, err
			}
			if !found {
				// we add simple accessors for maps and dicts, but this also requires
				// the `id` to look like a regular accessor (to avoid matching against more
				// native internal operators)
				if (typ != types.Dict && !typ.IsMap()) || !reAccessor.MatchString(id) {
					addFieldSuggestions(availableFields(c, typ), id, c.Result)
					msg := "cannot find field '" + id + "' in " + typ.Label()
					if scope := c.rootScopeHint(typ, id); scope != "" {
						// The field exists - on other roots. That makes this a
						// statement about which assets the query targets, not a
						// failure, and a caller running over many assets should
						// skip this one rather than abort (ADR 031).
						return nil, &rootScopeError{msg: msg + scope}
					}
					return nil, errors.New(msg + c.fieldSkewHint(typ))
				}

				// Support easy accessors for dicts and maps, e.g:
				// json.params.A.B.C => json.params["A"]["B"]["C"]
				//
				// Optionality used to be spelled here as a separate `[]?` chunk
				// id. It now rides on Function.nullability like every other link,
				// so this emits a plain `[]`. The `[]?` handler stays registered
				// in llx for bundles that were compiled before the switch.
				c.addChunk(&llx.Chunk{
					Call: llx.Chunk_FUNCTION,
					Id:   "[]",
					Function: &llx.Function{
						Type:    string(typ.Child()),
						Binding: ref,
						Args:    []*llx.Primitive{llx.StringPrimitive(id)},
					},
				})
				typ = typ.Child()
			} else {
				typ = resType
			}

			if call != nil && len(calls) > 0 {
				calls = calls[1:]
			}
			c.markNullability(linkStart, linkNullability)
			ref = c.tailDataRef()
			res = llx.RefPrimitiveV2(ref)

			continue
		}

		return nil, errors.New("processed a call without any data")
	}

	if operand.Block != nil {
		// The block binds to this operand's value, so that value has to exist as a
		// chunk on the stack. ref is still 0 when the value compiled to a bare
		// primitive that nothing pushed (i.e. no calls followed it).
		//
		// This has to test the operand's own ref, not whether the stack is empty.
		// An array literal whose elements are resources compiles those elements
		// into chunks, so the stack is non-empty while the array itself was never
		// pushed. Binding the block to a chunk that is not on the stack made
		// checksumming panic ("doesn't seem to reference a function on the stack"),
		// which Compile only recovers in order to re-panic -- taking the caller
		// down. A scalar array pushes nothing, so it kept working.
		if ref == 0 && res != nil {
			// res is the already-compiled primitive for this value. Recompiling it
			// here would emit a second copy of every chunk its elements produced.
			c.addChunk(&llx.Chunk{
				Call: llx.Chunk_PRIMITIVE,
				// no ID for standalone
				Primitive: res,
			})
			ref = c.tailRef()
		}

		if typ == types.Nil {
			_, err = c.compileUnboundBlock(operand.Block, c.block.LastChunk())
		} else {
			_, err = c.compileBlock(operand.Block, typ, ref)
		}
		if err != nil {
			return nil, err
		}
		ref = c.tailRef()
		res = llx.RefPrimitiveV2(ref)
	}

	return res, nil
}

func (c *compiler) compileExpression(expression *parser.Expression) (*llx.Primitive, error) {
	if len(expression.Operations) > 0 {
		panic("ran into an expression that wasn't pre-compiled. It has more than 1 value attached to it")
	}
	return c.compileOperand(expression.Operand)
}

func (c *compiler) compileAndAddExpression(expression *parser.Expression) (uint64, error) {
	valc, err := c.compileExpression(expression)
	if err != nil {
		return 0, err
	}

	if types.Type(valc.Type) == types.Ref {
		ref, _ := valc.RefV2()
		return ref, nil
		// nothing to do, the last call was added to the compiled chain
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_PRIMITIVE,
		// no id for standalone values
		Primitive: valc,
	})

	return c.tailRef(), nil
}

func (c *compiler) compileExpressions(expressions []*parser.Expression) error {
	var err error
	code := c.Result.CodeV2

	// we may have comment-only expressions
	expressions = filterEmptyExpressions(expressions)

	for idx := range expressions {
		if err = expressions[idx].ProcessOperators(); err != nil {
			return err
		}
	}

	var ident string
	var prev string
	for idx := range expressions {
		expression := expressions[idx]
		prev = ident
		ident = ""
		if expression.Operand != nil && expression.Operand.Value != nil && expression.Operand.Value.Ident != nil {
			ident = *expression.Operand.Value.Ident
		}

		if prev == "else" && ident != "if" && c.block.SingleValue {
			// if the previous id is else and its single valued, the following
			// expressions cannot be executed
			return errors.New("single valued block followed by expressions")
		}

		if prev == "if" && ident != "else" && c.block.SingleValue {
			// all following expressions need to be compiled in a block which is
			// conditional to this if-statement unless we're already doing
			// if-else chaining

			c.prevID = "else"
			rest := expressions[idx:]
			_, err := c.compileUnboundBlock(rest, c.block.LastChunk())
			return err
		}

		if ident == "return" {
			// A return statement can only be followed by max 1 more expression
			max := len(expressions)
			if idx+2 < max {
				return errors.New("return statement is followed by too many expressions")
			}

			// if idx+1 == max: nothing else coming after this, return nil

			c.block.SingleValue = true
			continue
		}

		// for all other expressions, just compile
		ref, err := c.compileAndAddExpression(expression)
		if err != nil {
			return err
		}

		if prev == "return" {
			prevChunk := code.Chunk(ref)

			c.addChunk(&llx.Chunk{
				Call: llx.Chunk_FUNCTION,
				Id:   "return",
				Function: &llx.Function{
					Type:    string(prevChunk.Type()),
					Binding: 0,
					Args: []*llx.Primitive{
						llx.RefPrimitiveV2(ref),
					},
				},
			})

			c.block.Entrypoints = []uint64{c.block.TailRef(c.blockRef)}
			c.block.SingleValue = true

			return nil
		}

		l := len(c.block.Entrypoints)
		// if the last entrypoint already points to this ref, skip it
		if l != 0 && c.block.Entrypoints[l-1] == ref {
			continue
		}

		c.block.Entrypoints = append(c.block.Entrypoints, ref)

		if code.Checksums[ref] == "" {
			return errors.New("failed to compile expression, ref returned empty checksum ID for ref " + strconv.FormatInt(int64(ref), 10))
		}
	}

	return nil
}

func (c *compiler) postCompile() {
	code := c.Result.CodeV2
	// Use index-based loop instead of range so that blocks appended by
	// expandResourceFields (nested @defaults) are visited in the same pass.
	for i := 0; i < len(code.Blocks); i++ {
		block := code.Blocks[i]

		// Skip blocks whose entrypoint is a value consumed by a parent builtin
		// (e.g. a `.map(...)` body). Display-expanding such an entrypoint would
		// replace the collected value with an anonymous `{}` block and strip its
		// resource type. See https://github.com/mondoohq/mql/issues/8474
		if _, ok := c.valueBodyBlocks[uint64(i+1)<<32]; ok {
			continue
		}

		eps := block.Entrypoints

		for _, ref := range eps {
			chunk := code.Chunk(ref)

			if chunk.Call != llx.Chunk_FUNCTION {
				continue
			}

			chunk, typ, ref := c.expandListResource(chunk, ref)
			switch chunk.Id {
			case "$one", "$all", "$none", "$any":
				// default fields
				ref = chunk.Function.Binding
				chunk := code.Chunk(ref)
				if chunk.Function == nil {
					// nothing to expand
					continue
				}
				typ = types.Type(chunk.Function.Type)
				expanded := c.expandResourceFields(chunk, typ, ref)
				// when no defaults are defined or query isn't about a resource, no block was added
				if expanded {
					autoExpandRef := block.TailRef(ref)
					block.Datapoints = append(block.Datapoints, autoExpandRef)
					c.addValueFieldChunks(ref, autoExpandRef)
				}
			default:
				c.expandResourceFields(chunk, typ, ref)
			}
		}
	}
}

// addValueFieldChunks takes the value fields of the assessment and adds them to the
// block for the default fields
// This way, the actual data of the assessment automatically shows up in the output
// of the assessment that failed the assessment
func (c *compiler) addValueFieldChunks(ref uint64, autoExpandRef uint64) {
	var whereChunk *llx.Chunk

	// find chunk with where/whereNot function
	// it holds the reference to the block with the predicate(s) for the assessment
	for {
		chunk := c.Result.CodeV2.Chunk(ref)
		if chunk.Function == nil {
			// this is a safe guard for some cases
			// e.g. queries with .none() are totally valid and will not have a where block,
			// because they do not check a specific field
			log.Debug().Msg("failed to find where function for assessment, this can happen with empty assessments")
			return
		}
		if chunk.Id == "$whereNot" || chunk.Id == "where" {
			whereChunk = chunk
			break
		}

		ref = chunk.Function.Binding

		// If we have no binding left, we have moved as far back as we can.
		// e.g. queries with .all() without a valid body
		if ref == 0 {
			log.Debug().Msg("failed to find where function for assessment in the entire chain, this can happen with empty assessments")
			return
		}
	}

	type fieldTreeNode struct {
		id       string
		chunk    *llx.Chunk
		chunkIdx int
		children map[string]*fieldTreeNode
	}

	type fieldTree struct {
		nodes []*fieldTreeNode
	}

	blockToFieldTree := func(block *llx.Block, filter func(chunkIdx int, chunk *llx.Chunk) bool) fieldTree {
		// This function assumes the chunks are topologically sorted such
		// that any dependency is always before the chunk that depends on it
		nodes := make([]*fieldTreeNode, len(block.Chunks))
		for i := range block.Chunks {
			chunk := block.Chunks[i]
			if !filter(i, chunk) {
				continue
			}
			nodes[i] = &fieldTreeNode{
				id:       chunk.Id,
				chunk:    chunk,
				chunkIdx: i + 1,
				children: map[string]*fieldTreeNode{},
			}

			if chunk.Function != nil && chunk.Function.Binding != 0 {
				chunkIdx := llx.ChunkIndex(chunk.Function.Binding)
				parent := nodes[chunkIdx-1]
				if parent != nil {
					nodes[chunkIdx-1].children[chunk.Id] = nodes[i]
				}
			}
		}

		return fieldTree{
			nodes: nodes,
		}
	}

	addToTree := func(tree *fieldTree, parentPath []string, blockRef uint64, block *llx.Block, chunk *llx.Chunk) bool {
		// add a chunk to the tree. If the path already exists, do nothing
		// return true if the chunk was added, false if it already existed
		if len(tree.nodes) != len(block.Chunks) {
			panic("tree and block chunks do not match")
		}

		parent := tree.nodes[0]
		for _, id := range parentPath[1:] {
			child := parent.children[id]
			parent = child
		}

		if parent.children[chunk.Id] != nil {
			return false
		}

		newChunk := chunk
		if chunk.Function != nil {
			newChunk = &llx.Chunk{
				Call: chunk.Call,
				Id:   chunk.Id,
				Function: &llx.Function{
					Binding: (blockRef & 0xFFFFFFFF00000000) | uint64(parent.chunkIdx),
					Type:    chunk.Function.Type,
					Args:    chunk.Function.Args,
				},
			}
		}

		parent.children[chunk.Id] = &fieldTreeNode{
			id:       chunk.Id,
			chunk:    newChunk,
			chunkIdx: len(tree.nodes) + 1,
			children: map[string]*fieldTreeNode{},
		}
		tree.nodes = append(tree.nodes, parent.children[chunk.Id])
		block.AddChunk(c.Result.CodeV2, blockRef, newChunk)

		return true
	}

	var visitTreeNodes func(tree *fieldTree, node *fieldTreeNode, path []string, visit func(tree *fieldTree, node *fieldTreeNode, path []string))
	visitTreeNodes = func(tree *fieldTree, node *fieldTreeNode, path []string, visit func(tree *fieldTree, node *fieldTreeNode, path []string)) {
		if node == nil {
			return
		}
		path = append(path, node.id)
		keys := []string{}
		for k := range node.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child := node.children[k]
			visit(tree, child, path)
			visitTreeNodes(tree, child, path, visit)
		}
	}

	// This block holds all the data and function chunks used
	// for the predicate(s) of the .all()/.none()/... function
	var assessmentBlock *llx.Block
	// find the referenced block for the where function
	for i := len(whereChunk.Function.Args) - 1; i >= 0; i-- {
		arg := whereChunk.Function.Args[i]
		if types.Type(arg.Type).Underlying() == types.FunctionLike {
			raw := arg.RawData()
			blockRef := raw.Value.(uint64)
			assessmentBlock = c.Result.CodeV2.Block(blockRef)
			break
		}
	}
	assessmentBlockTree := blockToFieldTree(assessmentBlock, func(chunkIdx int, chunk *llx.Chunk) bool {
		if chunk.Id == "$whereNot" || chunk.Id == "where" {
			return false
		} else if _, comparable := llx.ComparableLabel(chunk.Id); comparable {
			return false
		} else if chunk.Function != nil && len(chunk.Function.Args) > 0 {
			// filter out nested function block that require other blocks
			// This at least makes https://github.com/mondoohq/mql/issues/1339
			// not panic
			for _, arg := range chunk.Function.Args {
				if types.Type(arg.Type).Underlying() == types.Ref {
					return false
				}
			}
		}
		return true
	})

	// The default-fields block is the one referenced by the auto-expand `{}`
	// chunk we just created for this list — NOT necessarily the last block.
	// A resource with a `@context` annotation appends a further nested block
	// (the context expansion), so `Blocks[len-1]` would wrongly target the
	// context block and bind the predicate's value fields to the context
	// resource (e.g. `file.context.criteria`), yielding an untyped/empty field
	// that breaks the failing-resource list. Resolve the block from the chunk.
	autoExpandChunk := c.Result.CodeV2.Chunk(autoExpandRef)
	if autoExpandChunk == nil || autoExpandChunk.Function == nil || len(autoExpandChunk.Function.Args) == 0 {
		return
	}
	defaultFieldsBlockRef, ok := autoExpandChunk.Function.Args[0].RawData().Value.(uint64)
	if !ok {
		return
	}
	defaultFieldsBlock := c.Result.CodeV2.Block(defaultFieldsBlockRef)
	defaultFieldsRef := defaultFieldsBlock.HeadRef(defaultFieldsBlockRef)
	defaultFieldsBlockTree := blockToFieldTree(defaultFieldsBlock, func(chunkIdx int, chunk *llx.Chunk) bool {
		return true
	})

	visitTreeNodes(&assessmentBlockTree, assessmentBlockTree.nodes[0], make([]string, 0, 16), func(tree *fieldTree, node *fieldTreeNode, path []string) {
		// add the node to the assessment block tree
		chunkAdded := addToTree(&defaultFieldsBlockTree, path, defaultFieldsRef, defaultFieldsBlock, node.chunk)
		if chunkAdded && node.chunk.Function != nil {
			defaultFieldsBlock.Entrypoints = append(defaultFieldsBlock.Entrypoints, (defaultFieldsRef&0xFFFFFFFF00000000)|uint64(len(defaultFieldsBlock.Chunks)))
		}
	})
}

func (c *compiler) expandListResource(chunk *llx.Chunk, ref uint64) (*llx.Chunk, types.Type, uint64) {
	typ := chunk.Type()
	if !typ.IsResource() {
		return chunk, typ, ref
	}

	info := c.Schema.Lookup(typ.ResourceName())
	if info == nil || info.ListType == "" {
		return chunk, typ, ref
	}

	block := c.Result.CodeV2.Block(ref)
	newType := types.Array(types.Type(info.ListType))
	newChunk := &llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "list",
		Function: &llx.Function{
			Binding: ref,
			Type:    string(newType),
		},
	}
	block.AddChunk(c.Result.CodeV2, ref, newChunk)
	newRef := block.TailRef(ref)
	block.ReplaceEntrypoint(ref, newRef)

	return newChunk, newType, newRef
}

func (c *compiler) expandResourceFields(chunk *llx.Chunk, typ types.Type, ref uint64) bool {
	c.Stats.SetAutoExpand(true)
	defer c.Stats.SetAutoExpand(false)

	resultType := types.Block
	if typ.IsArray() {
		resultType = types.Array(types.Block)
		typ = typ.Child()
	}
	if !typ.IsResource() {
		return false
	}

	info := c.Schema.Lookup(typ.ResourceName())
	if info == nil {
		return false
	}
	if info.Defaults == "" {
		return false
	}

	ast, err := parser.Parse(info.Defaults)
	if ast == nil || len(ast.Expressions) == 0 {
		log.Error().Err(err).Msg("failed to parse defaults for " + info.Name)
		return false
	}

	blockCompiler, err := c.blockcompileOnResource(ast.Expressions, types.Resource(info.Name), ref, "_")
	if err != nil {
		log.Error().Err(err).Msg("failed to compile default for " + info.Name)
	}
	if len(blockCompiler.blockDeps) != 0 {
		log.Warn().Msg("defaults somehow included external dependencies for resource " + info.Name)
	}

	if c.Features.IsActive(mql.ResourceContext) && info.Context != "" {
		// (Dom) Note: This is the very first expansion block implementation, so there are some
		// serious limitations while we figure things out.
		// 1. We can only expand a resource that has defaults defined. As soon as you add
		//    a resource without defaults that needs an expansion, please adjust the above code to
		//    provide a function block we can attach to AND don't exit early on defaults==empty.
		//    One way could be to just create a new defaults code and add context to it.
		// 2. The `context` field may be part of defaults and the actual `@context`. Obviously we
		//    only ever need and want one. This needs fixing in LR.

		ctxType := types.Resource(info.Context)
		blockCompiler.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   "context",
			Function: &llx.Function{
				Type:    string(ctxType),
				Binding: blockCompiler.block.HeadRef(blockCompiler.blockRef),
				Args:    []*llx.Primitive{},
			},
		})
		blockCompiler.expandResourceFields(blockCompiler.block.LastChunk(), ctxType, blockCompiler.tailRef())
		blockCompiler.block.Entrypoints = append(blockCompiler.block.Entrypoints, blockCompiler.tailRef())
	}

	args := []*llx.Primitive{llx.FunctionPrimitive(blockCompiler.blockRef)}
	block := c.Result.CodeV2.Block(ref)
	block.AddChunk(c.Result.CodeV2, ref, &llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "{}",
		Function: &llx.Function{
			Type:    string(resultType),
			Binding: ref,
			Args:    args,
		},
	})
	ep := block.TailRef(ref)
	block.ReplaceEntrypoint(ref, ep)
	ref = ep

	c.Result.AutoExpand[c.Result.CodeV2.Checksums[ref]] = blockCompiler.blockRef
	return true
}

func (c *compiler) updateLabels() {
	for _, v := range c.vars.vars {
		if v.name == "" {
			continue
		}

		c.Result.Vars[v.ref] = v.name
	}
}

func (c *compiler) updateEntrypoints() {
	code := c.Result.CodeV2

	// 1. efficiently remove variable definitions from entrypoints
	varsByRef := make(map[uint64]variable, c.vars.len())
	for name, v := range c.vars.vars {
		if name == "_" {
			// We need to filter this out. It wasn't an assignment declared by the
			// user. We will re-introduce it conceptually once we tackle context
			// information for blocks.
			continue
		}
		varsByRef[v.ref] = v
	}

	max := len(c.block.Entrypoints)
	for i := 0; i < max; {
		ref := c.block.Entrypoints[i]
		if _, ok := varsByRef[ref]; ok {
			c.block.Entrypoints[i], c.block.Entrypoints[max-1] = c.block.Entrypoints[max-1], c.block.Entrypoints[i]
			max--
		} else {
			i++
		}
	}
	if max != len(c.block.Entrypoints) {
		c.block.Entrypoints = c.block.Entrypoints[:max]
	}

	// 2. potentially clean up all inherited entrypoints
	// TODO: unclear if this is necessary because the condition may never be met
	entrypoints := map[uint64]struct{}{}
	for _, ref := range c.block.Entrypoints {
		entrypoints[ref] = struct{}{}
		chunk := code.Chunk(ref)
		if chunk.Function != nil {
			delete(entrypoints, chunk.Function.Binding)
		}
	}

	datapoints := map[uint64]struct{}{}
	// 3. resolve operators
	for ref := range entrypoints {
		dps := code.RefDatapoints(ref)
		for i := range dps {
			datapoints[dps[i]] = struct{}{}
		}
	}

	// done
	res := make([]uint64, len(datapoints))
	var idx int
	for ref := range datapoints {
		res[idx] = ref
		idx++
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i] < res[j]
	})
	c.block.Datapoints = append(c.block.Datapoints, res...)
	// E.g. in the case of .all(...)/.none(...)/... queries, we have two datapoints bound to the list of resources:
	// - one with the resource ids
	// - one with the default values
	// We only want to keep the datapoint for the default values.
	updatedDatapoints := make([]uint64, 0, len(c.block.Datapoints))
	for _, ref := range c.block.Datapoints {
		chunk := code.Chunk(ref)
		if chunk.Function != nil {
			found := false
			for i := range c.block.Datapoints {
				if c.block.Datapoints[i] == chunk.Function.Binding {
					found = true
					break
				}
			}
			if found {
				updatedDatapoints = append(updatedDatapoints, ref)
			}
		}
	}
	if len(updatedDatapoints) > 0 {
		c.block.Datapoints = updatedDatapoints
	}
}

// CompileParsed AST into an executable structure
func (c *compiler) CompileParsed(ast *parser.AST) error {
	err := c.compileExpressions(ast.Expressions)
	if err != nil {
		return err
	}

	c.postCompile()
	c.Result.CodeV2.UpdateID()
	c.updateEntrypoints()
	c.updateLabels()

	return c.failIfNoEntrypoints()
}

func (c *compiler) failIfNoEntrypoints() error {
	if c.Features.IsActive(mql.FailIfNoEntryPoints) {
		for _, b := range c.Result.CodeV2.Blocks {
			if len(b.Datapoints) == 0 && len(b.Entrypoints) == 0 {
				return errors.New("failed to compile: received an empty code structure. this is a bug with the query compilation")
			}
		}
	}
	return nil
}

// CompileAST with a schema into a chunky code
func CompileAST(ast *parser.AST, props PropsHandler, conf CompilerConfig) (*llx.CodeBundle, error) {
	if conf.Schema == nil {
		return nil, errors.New("mqlc> please provide a schema to compile this code")
	}

	if props == nil {
		props = EmptyPropsHandler
	}

	codeBundle := &llx.CodeBundle{
		CodeV2: &llx.CodeV2{
			Checksums: map[uint64]string{},
			// we are initializing it with the first block, which is empty
			Blocks: []*llx.Block{{}},
		},
		Labels: &llx.Labels{
			Labels: map[string]string{},
		},
		Props:      map[string]string{},
		Version:    mql.APIVersion(),
		AutoExpand: map[string]uint64{},
		Vars:       map[uint64]string{},
	}

	c := compiler{
		CompilerConfig:  conf,
		Result:          codeBundle,
		vars:            newvarmap(1<<32, nil),
		parent:          nil,
		blockRef:        1 << 32,
		block:           codeBundle.CodeV2.Blocks[0],
		props:           props,
		standalone:      true,
		valueBodyBlocks: map[uint64]struct{}{},
	}

	err := c.CompileParsed(ast)
	c.recordCompatibleRoots()
	return c.Result, err
}

// Compile a code piece against a schema into chunky code
func compile(input string, props PropsHandler, compilerConf CompilerConfig) (*llx.CodeBundle, error) {
	// remove leading whitespace; we are re-using this later on
	input = Dedent(input)

	conf := compilerConf
	conf.Stats = compilerConf.Stats.CompileQuery(input)

	ast, err := parser.Parse(input)
	if ast == nil {
		return nil, err
	}

	// Special handling for parser errors: We still try to compile it because
	// we want to get any compiler suggestions for auto-complete / fixing it.
	// That said, we must return an error either way.
	if err != nil {
		res, _ := CompileAST(ast, props, conf)
		return res, err
	}

	res, err := CompileAST(ast, props, conf)
	if err != nil {
		return res, err
	}

	res.AssetRoot = conf.AssetRoot

	err = UpdateLabels(res, conf.Schema)
	if err != nil {
		return res, err
	}
	if len(res.Labels.Labels) == 0 {
		res.Labels.Labels = nil
	}

	err = UpdateAssertions(res)
	if err != nil {
		return res, err
	}

	res.Source = input

	// ADR 040 part 1: the bundle records which schema it was compiled against
	// and what it needs to run. Stamped after labels and assertions so it sees
	// the finished chunk list.
	stampProvenance(res, conf.Schema)

	return res, nil
}

func Compile(input string, props PropsHandler, conf CompilerConfig) (*llx.CodeBundle, error) {
	// Note: we do not check the conf because it will get checked by the
	// first CompileAST call. Do not use it earlier or add a check.
	defer func() {
		if r := recover(); r != nil {
			errNew := fmt.Errorf("panic compiling %q: %v", input, r)
			panic(errNew)
		}
	}()

	res, err := compile(input, props, conf)
	if err != nil {
		return res, err
	}

	if res.CodeV2 == nil || res.CodeV2.Id == "" {
		return res, errors.New("failed to compile: received an unspecified empty code structure")
	}

	return res, nil
}
