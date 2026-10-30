// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bicep/connection"
	"go.mondoo.com/mql/types"
)

// mqlBicepParameterInternal carries the owning file's symbol resolver so the
// lazy resolvedType() accessor can resolve the declared `type` name to the
// same-file `bicep.type` it names.
type mqlBicepParameterInternal struct {
	stampOnce sync.Once
	resolver  *symbolResolver
}

func createMqlParameters(runtime *plugin.Runtime, filePath string, params []parsedParameter, resolver *symbolResolver) ([]any, error) {
	var mqlParams []any
	for _, p := range params {
		allowed := sliceToAny(p.allowed)
		decorators := sliceToAny(p.decorators)

		ctx, err := newBicepContext(runtime, filePath, p.startLine, p.endLine)
		if err != nil {
			return nil, err
		}
		args := map[string]*llx.RawData{
			"__id":         llx.StringData("bicep.parameter:" + filePath + ":" + p.name),
			"name":         llx.StringData(p.name),
			"type":         llx.StringData(p.typ),
			"defaultValue": llx.StringData(p.defaultValue),
			"description":  llx.StringData(p.description),
			"secure":       llx.BoolData(p.secure),
			"allowed":      llx.ArrayData(allowed, types.String),
			"minLength":    llx.IntDataPtr(p.minLength),
			"maxLength":    llx.IntDataPtr(p.maxLength),
			"minValue":     llx.IntDataPtr(p.minValue),
			"maxValue":     llx.IntDataPtr(p.maxValue),
			"decorators":   llx.ArrayData(decorators, types.String),
		}
		contextArg(args, ctx)
		res, err := CreateResource(runtime, "bicep.parameter", args)
		if err != nil {
			return nil, err
		}
		// CreateResource returns the CACHED instance when this __id is already
		// in the runtime cache, and the same declaration is reached
		// concurrently from bicep.file.parameters and the symbol resolver.
		// stampOnce keeps the write race-free and happens-before any reader.
		mqlP := res.(*mqlBicepParameter)
		mqlP.stampOnce.Do(func() { mqlP.resolver = resolver })
		mqlParams = append(mqlParams, res)
	}
	return mqlParams, nil
}

// resolvedType resolves the parameter's declared `type` name to the same-file
// `bicep.type` it references, or null for a built-in type or an unresolvable
// name.
func (p *mqlBicepParameter) resolvedType() (*mqlBicepType, error) {
	t, err := p.resolver.typ(p.MqlRuntime, p.Type.Data)
	if err != nil {
		return nil, err
	}
	if t == nil {
		p.ResolvedType.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return t, nil
}

// mqlBicepVariableInternal carries the owning file's symbol resolver so the
// lazy expressionTree() accessor can resolve the root identifiers its nodes
// reference to same-file declarations.
type mqlBicepVariableInternal struct {
	stampOnce sync.Once
	resolver  *symbolResolver
}

func createMqlVariables(runtime *plugin.Runtime, filePath string, vars []parsedVariable, resolver *symbolResolver) ([]any, error) {
	var mqlVars []any
	for _, v := range vars {
		ctx, err := newBicepContext(runtime, filePath, v.startLine, v.endLine)
		if err != nil {
			return nil, err
		}
		args := map[string]*llx.RawData{
			"__id":        llx.StringData("bicep.variable:" + filePath + ":" + v.name),
			"name":        llx.StringData(v.name),
			"expression":  llx.StringData(v.expression),
			"description": llx.StringData(v.description),
		}
		addLoopArgs(args, v.loop)
		contextArg(args, ctx)
		res, err := CreateResource(runtime, "bicep.variable", args)
		if err != nil {
			return nil, err
		}
		mqlV := res.(*mqlBicepVariable)
		mqlV.stampOnce.Do(func() { mqlV.resolver = resolver })
		mqlVars = append(mqlVars, res)
	}
	return mqlVars, nil
}

// mqlBicepResourceInternal caches the parsed nested child resources so the
// lazy `resources()` accessor can materialize them without re-parsing. Each
// child carries a parent-qualified `__id` (`<parentId>/<childSymbolicName>`)
// so nested resources under different parents never collide in the cache.
// The resolver carries the owning file's symbol table so the lazy
// name/location/condition expression-tree accessors can resolve referenced
// root identifiers to same-file declarations. Nested child resources inherit
// the same resolver since symbols stay file-scoped regardless of nesting.
type mqlBicepResourceInternal struct {
	stampOnce sync.Once
	nested    []parsedResource
	resolver  *symbolResolver
	// propertiesBody is the raw text of the resource's `properties: { ... }`
	// block (between the outer braces), kept so propertyExpressions() can
	// re-walk it with quoting intact — the parsed `properties` dict has already
	// stripped quotes, losing the literal-vs-expression distinction.
	propertiesBody string
	// rawName is the resource's name expression with quotes intact, kept so
	// nameTree() can classify it (literal vs interpolation vs functionCall)
	// even though the public `name` field strips surrounding literal quotes.
	rawName string
}

func createMqlResources(runtime *plugin.Runtime, filePath string, resources []parsedResource, resolver *symbolResolver) ([]any, error) {
	var mqlResources []any
	for _, r := range resources {
		ctx, err := newBicepContext(runtime, filePath, r.startLine, r.endLine)
		if err != nil {
			return nil, err
		}
		res, err := newMqlBicepResource(runtime, bicepResourceID(filePath, r), r, resolver, ctx)
		if err != nil {
			return nil, err
		}
		mqlResources = append(mqlResources, res)
	}
	return mqlResources, nil
}

// resourceBodyInner returns the content between a resource declaration's outer
// braces. `parsedResource.body` is the full `resource <name> '<type>' = { ... }`
// text (braces included), so this drops everything up to and including the
// first `{` and the final `}`, leaving the top-level field block that
// parseBicepObject expects. Returns "" when no braces are present.
func resourceBodyInner(body string) string {
	_, after, ok := strings.Cut(body, "{")
	if !ok {
		return ""
	}
	inner := after
	if before, _, ok := strings.CutLast(inner, "}"); ok {
		inner = before
	}
	return inner
}

// newMqlBicepResource builds a single bicep.resource from a parsedResource.
// The id is supplied by the caller: top-level resources use
// `bicep.resource:<file>:<symbolicName>`, while nested resources use a
// parent-qualified `<parentId>/<childSymbolicName>`. The parsed nested
// declarations are cached on the Internal struct for the lazy `resources()`
// accessor to materialize, recursively.
func newMqlBicepResource(runtime *plugin.Runtime, id string, r parsedResource, resolver *symbolResolver, ctx *mqlBicepContext) (*mqlBicepResource, error) {
	dependsOn := sliceToAny(r.dependsOn)
	decorators := sliceToAny(r.decorators)

	// Surface the resource's `properties: { ... }` sub-block as a
	// structured dict so audits can query individual keys directly
	// (e.g., `bicepResource.properties["accessTier"]`). When the
	// resource has no `properties` block the field is an empty
	// map rather than nil so the shape stays consistent across
	// resources.
	var properties any = map[string]any{}
	propertiesBody := ""
	if r.body != "" {
		if raw := extractFieldBlock(r.body, "properties"); raw != "" {
			properties = parseBicepObject(raw)
			propertiesBody = raw
		}
	}

	// Surface the entire resource body as a dict so audits can reach
	// top-level fields the `properties` sub-block doesn't carry — `identity`,
	// `sku`, `kind`, … — and Microsoft Graph resources, whose config lives at
	// the top level with no `properties:` wrapper. `r.body` is the full
	// `resource <name> '<type>' = { ... }` declaration, so strip the header up
	// to the opening brace and the trailing close brace before parsing the
	// top-level fields. Nested `resource` declarations carry no top-level
	// `key: value` colon and are skipped by parseBicepObject; reach them
	// through `resources` instead.
	var body any = map[string]any{}
	if inner := resourceBodyInner(r.body); inner != "" {
		body = parseBicepObject(inner)
	}

	args := map[string]*llx.RawData{
		"__id":         llx.StringData(id),
		"symbolicName": llx.StringData(r.symbolicName),
		"type":         llx.StringData(r.typ),
		"apiVersion":   llx.StringData(r.apiVersion),
		"name":         llx.StringData(stripLiteralQuotes(r.name)),
		"location":     llx.StringData(r.location),
		"existing":     llx.BoolData(r.existing),
		"condition":    llx.StringData(r.condition),
		"parent":       llx.StringData(r.parent),
		"scope":        llx.StringData(r.scope),
		"properties":   llx.DictData(properties),
		"body":         llx.DictData(body),
		"dependsOn":    llx.ArrayData(dependsOn, types.String),
		"decorators":   llx.ArrayData(decorators, types.String),
	}
	if r.tags == nil {
		args["tags"] = llx.NilData
	} else {
		tags := make(map[string]any, len(r.tags))
		for k, v := range r.tags {
			tags[k] = v
		}
		args["tags"] = llx.MapData(tags, types.String)
	}
	addLoopArgs(args, r.loop)
	contextArg(args, ctx)

	res, err := CreateResource(runtime, "bicep.resource", args)
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlBicepResource)
	mqlRes.stampOnce.Do(func() {
		mqlRes.nested = r.nested
		mqlRes.resolver = resolver
		mqlRes.propertiesBody = propertiesBody
		mqlRes.rawName = r.name
	})
	return mqlRes, nil
}

// bicepResourceID builds the cache id of a top-level resource declaration.
// The declaration's start line is part of the key because a symbolic name is
// not guaranteed unique within a file: two `resource sa ...` declarations are
// invalid Bicep the compiler rejects, but on that input a name-only id made
// both list entries alias the first declaration's data. The line makes the id
// collision-proof at no cost.
func bicepResourceID(filePath string, r parsedResource) string {
	return "bicep.resource:" + filePath + ":" + r.symbolicName + ":" + strconv.Itoa(r.startLine)
}

// resources materializes this resource's nested child resources. Each child
// gets a parent-qualified `__id` so nested resources under different parents
// don't collide; children may themselves declare further nested resources,
// resolved recursively by the same accessor.
func (r *mqlBicepResource) resources() ([]any, error) {
	out := make([]any, 0, len(r.nested))
	for _, child := range r.nested {
		childID := r.__id + "/" + child.symbolicName
		// Nested resources are re-parsed from the parent body without absolute
		// line offsets, so they carry no source context.
		mqlChild, err := newMqlBicepResource(r.MqlRuntime, childID, child, r.resolver, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlChild)
	}
	return out, nil
}

// mqlBicepModuleInternal carries the owning file's symbol resolver so the
// lazy scope/condition expression-tree accessors can resolve referenced root
// identifiers to same-file declarations. owningFilePath is the path of the
// file that declared this module; a relative `source` is resolved against its
// directory by the target() accessor.
type mqlBicepModuleInternal struct {
	stampOnce      sync.Once
	resolver       *symbolResolver
	owningFilePath string
	// paramsBody is the raw text of the module's `params: { ... }` block,
	// kept so paramExpressions() can re-walk it with quoting intact.
	paramsBody string
}

func createMqlModules(runtime *plugin.Runtime, filePath string, modules []parsedModule, resolver *symbolResolver) ([]any, error) {
	var mqlModules []any
	for _, m := range modules {
		// Same shape as bicep.resource.properties: parse the module's
		// `params: { ... }` block as a structured dict so audits can
		// pluck individual parameter values.
		var params any = map[string]any{}
		paramsBody := ""
		if m.body != "" {
			if raw := extractFieldBlock(m.body, "params"); raw != "" {
				params = parseBicepObject(raw)
				paramsBody = raw
			}
		}

		decorators := sliceToAny(m.decorators)

		ctx, err := newBicepContext(runtime, filePath, m.startLine, m.endLine)
		if err != nil {
			return nil, err
		}
		args := map[string]*llx.RawData{
			"__id":           llx.StringData("bicep.module:" + filePath + ":" + m.name),
			"name":           llx.StringData(m.name),
			"source":         llx.StringData(m.source),
			"scope":          llx.StringData(m.scope),
			"params":         llx.DictData(params),
			"condition":      llx.StringData(m.condition),
			"isRegistry":     llx.BoolData(m.isRegistry),
			"isTemplateSpec": llx.BoolData(m.isTemplateSpec),
			"description":    llx.StringData(m.description),
			"decorators":     llx.ArrayData(decorators, types.String),
		}
		addLoopArgs(args, m.loop)
		contextArg(args, ctx)
		res, err := CreateResource(runtime, "bicep.module", args)
		if err != nil {
			return nil, err
		}
		mqlMod := res.(*mqlBicepModule)
		mqlMod.stampOnce.Do(func() {
			mqlMod.resolver = resolver
			mqlMod.owningFilePath = filePath
			mqlMod.paramsBody = paramsBody
		})
		mqlModules = append(mqlModules, res)
	}
	return mqlModules, nil
}

// mqlBicepExpressionInternal caches the parsed child nodes of an expression
// so the lazy `args()` and `segments()` accessors can materialize their
// child resources without re-parsing. The synthetic `__id` of each child is
// derived from its parent's id (`<exprId>/arg[<i>]`, `<exprId>/seg[<i>]`).
type mqlBicepExpressionInternal struct {
	stampOnce sync.Once
	node      *exprNode
	// resolver is the owning file's symbol table, threaded down from the
	// declaration whose value this expression is. It lets referenceKind and
	// the referenced*() accessors resolve `target` (the root identifier of a
	// symbolicRef or propertyAccess) to the same-file declaration it names.
	// Child nodes (args, segments) inherit the same resolver so nested refs
	// resolve too.
	resolver *symbolResolver
}

// newMqlBicepExpression turns a parsed exprNode into a bicep.expression
// resource. Scalar fields are set immediately; child nodes (args, segments)
// are cached on the Internal struct and materialized lazily. The resolver is
// the owning file's symbol table, propagated to children so symbol resolution
// works at every depth.
func newMqlBicepExpression(runtime *plugin.Runtime, parentID string, node *exprNode, resolver *symbolResolver) (*mqlBicepExpression, error) {
	res, err := CreateResource(runtime, "bicep.expression", map[string]*llx.RawData{
		"__id":         llx.StringData(parentID),
		"kind":         llx.StringData(node.kind),
		"raw":          llx.StringData(node.raw),
		"functionName": llx.StringData(node.functionName),
		"target":       llx.StringData(node.target),
		"path":         llx.ArrayData(sliceToAny(node.path), types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlExpr := res.(*mqlBicepExpression)
	mqlExpr.stampOnce.Do(func() {
		mqlExpr.node = node
		mqlExpr.resolver = resolver
	})
	return mqlExpr, nil
}

func (e *mqlBicepExpression) args() ([]any, error) {
	if e.node == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(e.node.args))
	for i, child := range e.node.args {
		childID := e.__id + "/arg[" + strconv.Itoa(i) + "]"
		mqlChild, err := newMqlBicepExpression(e.MqlRuntime, childID, child, e.resolver)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlChild)
	}
	return out, nil
}

func (e *mqlBicepExpression) segments() ([]any, error) {
	if e.node == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(e.node.segments))
	for i, child := range e.node.segments {
		childID := e.__id + "/seg[" + strconv.Itoa(i) + "]"
		mqlChild, err := newMqlBicepExpression(e.MqlRuntime, childID, child, e.resolver)
		if err != nil {
			return nil, err
		}
		out = append(out, mqlChild)
	}
	return out, nil
}

// referenceKind reports which same-file declaration this node's `target` root
// identifier names — one of "parameter", "variable", "resource", "module", or
// "type" — or "" when `target` is empty or doesn't match a same-file
// declaration (a built-in like `resourceGroup`, or an imported symbol, which
// is resolved by a separate later layer). At most one referenced*() accessor
// is non-null, matching this kind.
func (e *mqlBicepExpression) referenceKind() (string, error) {
	target := ""
	if e.node != nil {
		target = e.node.target
	}
	return e.resolver.kind(target), nil
}

func (e *mqlBicepExpression) target_() string {
	if e.node != nil {
		return e.node.target
	}
	return e.Target.Data
}

func (e *mqlBicepExpression) referencedParameter() (*mqlBicepParameter, error) {
	p, err := e.resolver.parameter(e.MqlRuntime, e.target_())
	if err != nil {
		return nil, err
	}
	if p == nil {
		e.ReferencedParameter.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return p, nil
}

func (e *mqlBicepExpression) referencedVariable() (*mqlBicepVariable, error) {
	v, err := e.resolver.variable(e.MqlRuntime, e.target_())
	if err != nil {
		return nil, err
	}
	if v == nil {
		e.ReferencedVariable.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return v, nil
}

func (e *mqlBicepExpression) referencedResource() (*mqlBicepResource, error) {
	r, err := e.resolver.resource(e.MqlRuntime, e.target_())
	if err != nil {
		return nil, err
	}
	if r == nil {
		e.ReferencedResource.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r, nil
}

func (e *mqlBicepExpression) referencedModule() (*mqlBicepModule, error) {
	m, err := e.resolver.module(e.MqlRuntime, e.target_())
	if err != nil {
		return nil, err
	}
	if m == nil {
		e.ReferencedModule.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return m, nil
}

func (e *mqlBicepExpression) referencedType() (*mqlBicepType, error) {
	t, err := e.resolver.typ(e.MqlRuntime, e.target_())
	if err != nil {
		return nil, err
	}
	if t == nil {
		e.ReferencedType.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return t, nil
}

// expressionTreeFor parses a raw Bicep expression string and returns it as a
// bicep.expression resource. The suffix is appended to the parent's __id so
// distinct expression fields under the same parent (e.g. nameTree vs
// locationTree on one resource) get distinct, non-colliding cache keys. An
// empty raw string parses to an `unknown` node with empty `raw`, mirroring the
// existing variable/output expressionTree() behavior.
func expressionTreeFor(runtime *plugin.Runtime, parentID, suffix, raw string, resolver *symbolResolver) (*mqlBicepExpression, error) {
	node := parseExpression(raw)
	return newMqlBicepExpression(runtime, parentID+suffix, node, resolver)
}

func (v *mqlBicepVariable) expressionTree() (*mqlBicepExpression, error) {
	return expressionTreeFor(v.MqlRuntime, v.__id, "/expr", v.Expression.Data, v.resolver)
}

func (o *mqlBicepOutput) expressionTree() (*mqlBicepExpression, error) {
	return expressionTreeFor(o.MqlRuntime, o.__id, "/expr", o.Expression.Data, o.resolver)
}

func (r *mqlBicepResource) nameTree() (*mqlBicepExpression, error) {
	return expressionTreeFor(r.MqlRuntime, r.__id, "/nameTree", r.rawName, r.resolver)
}

func (r *mqlBicepResource) locationTree() (*mqlBicepExpression, error) {
	return expressionTreeFor(r.MqlRuntime, r.__id, "/locationTree", r.Location.Data, r.resolver)
}

func (r *mqlBicepResource) conditionTree() (*mqlBicepExpression, error) {
	return expressionTreeFor(r.MqlRuntime, r.__id, "/conditionTree", r.Condition.Data, r.resolver)
}

func (m *mqlBicepModule) scopeTree() (*mqlBicepExpression, error) {
	return expressionTreeFor(m.MqlRuntime, m.__id, "/scopeTree", m.Scope.Data, m.resolver)
}

func (m *mqlBicepModule) conditionTree() (*mqlBicepExpression, error) {
	return expressionTreeFor(m.MqlRuntime, m.__id, "/conditionTree", m.Condition.Data, m.resolver)
}

// mqlBicepPropertyExpressionInternal carries the raw leaf value and the owning
// file's symbol resolver so the lazy expression() accessor can parse the value
// into a bicep.expression with symbol resolution intact (the same resolver the
// owning resource/module's scalar expression trees thread through).
type mqlBicepPropertyExpressionInternal struct {
	stampOnce sync.Once
	raw       string
	resolver  *symbolResolver
}

// propertyExpressionEntry is one flattened string leaf of a properties/params
// object: its dotted/indexed path and the raw Bicep value text at that path.
type propertyExpressionEntry struct {
	path string
	raw  string
}

// flattenObjectExpressions walks the raw body text of a Bicep object (the text
// between the outer braces, as captured by extractFieldBlock) and returns one
// entry per scalar leaf, paired with its dotted/indexed path. It re-walks the
// raw text rather than the already-parsed dict so the leaf value keeps its
// original quoting: `'Hot'` (a literal), `resourceGroup().location` (a function
// call), and `'${adminPassword}'` (an interpolation) stay distinguishable when
// parsed into an expression. Map keys are sorted so output is deterministic;
// array element order is preserved. Nested objects (`{`) and arrays (`[`)
// recurse; every other value is a leaf and is emitted with its raw text intact.
func flattenObjectExpressions(body, prefix string) []propertyExpressionEntry {
	var out []propertyExpressionEntry

	type kv struct{ key, value string }
	var pairs []kv
	for _, entry := range splitTopLevelEntries(body) {
		key, value, ok := splitFirstColon(entry)
		if !ok {
			continue
		}
		pairs = append(pairs, kv{strings.TrimSpace(key), strings.TrimSpace(value)})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].key < pairs[j].key })

	for _, p := range pairs {
		child := p.key
		if prefix != "" {
			child = prefix + "." + p.key
		}
		out = append(out, flattenValueExpressions(p.value, child)...)
	}
	return out
}

// flattenValueExpressions emits entries for a single value at the given path:
// it recurses into objects and arrays and emits a leaf for everything else,
// keeping the raw (still-quoted) value text.
func flattenValueExpressions(value, path string) []propertyExpressionEntry {
	if value == "" {
		return nil
	}
	switch value[0] {
	case '{':
		return flattenObjectExpressions(stripOuter(value, '{', '}'), path)
	case '[':
		var out []propertyExpressionEntry
		elems := splitTopLevelEntries(stripOuter(value, '[', ']'))
		for i, elem := range elems {
			out = append(out, flattenValueExpressions(strings.TrimSpace(elem), path+"["+strconv.Itoa(i)+"]")...)
		}
		return out
	}
	return []propertyExpressionEntry{{path: path, raw: value}}
}

// newMqlBicepPropertyExpressions builds the flattened []bicep.propertyExpression
// for a properties/params object. The parentID is the owning resource/module's
// __id; each entry gets a synthetic, parent-qualified `__id`
// (`<parentId>/<accessor>/<path>`) and carries the raw leaf value plus the
// resolver so its expression() resolves references the same way the scalar
// trees do.
func newMqlBicepPropertyExpressions(runtime *plugin.Runtime, parentID, accessor, body string, resolver *symbolResolver) ([]any, error) {
	entries := flattenObjectExpressions(body, "")
	out := make([]any, 0, len(entries))
	for _, e := range entries {
		res, err := CreateResource(runtime, "bicep.propertyExpression", map[string]*llx.RawData{
			"__id": llx.StringData(parentID + "/" + accessor + "/" + e.path),
			"path": llx.StringData(e.path),
		})
		if err != nil {
			return nil, err
		}
		mqlPE := res.(*mqlBicepPropertyExpression)
		mqlPE.stampOnce.Do(func() {
			mqlPE.raw = e.raw
			mqlPE.resolver = resolver
		})
		out = append(out, mqlPE)
	}
	return out, nil
}

func (r *mqlBicepResource) propertyExpressions() ([]any, error) {
	return newMqlBicepPropertyExpressions(r.MqlRuntime, r.__id, "propertyExpressions", r.propertiesBody, r.resolver)
}

func (m *mqlBicepModule) paramExpressions() ([]any, error) {
	return newMqlBicepPropertyExpressions(m.MqlRuntime, m.__id, "paramExpressions", m.paramsBody, m.resolver)
}

// expression parses this leaf's raw Bicep value into a bicep.expression,
// threading the owning file's resolver so referenceKind / referenced*()
// resolve property values to their same-file declarations.
func (p *mqlBicepPropertyExpression) expression() (*mqlBicepExpression, error) {
	return expressionTreeFor(p.MqlRuntime, p.__id, "/expr", p.raw, p.resolver)
}

// resolveScannedBicepFile resolves a relative `source` (e.g. './shared.bicep')
// declared in the file at owningFilePath to the bicep.file it references,
// returning the SAME cached bicep.file instance the scan already discovered, or
// nil when no in-tree file matches.
//
// This is the shared, security-critical resolver behind both
// bicep.module.target() and bicep.import.targetFile(). We never read an
// arbitrary path from disk: `source` comes from the (potentially untrusted)
// Bicep file, so an on-demand read of the resolved path would let a crafted
// reference (e.g. '../../../../etc/passwd') disclose arbitrary file contents
// via bicep.file.content. The scan already loads every .bicep under the root
// recursively, so any legitimate in-tree target — including ones reached via a
// relative '../' path — is present in conn.BicepFiles(); anything not found
// (out-of-root or absolute references) resolves to nil. Callers are responsible
// for setting StateIsNull on their singular field when nil is returned.
func resolveScannedBicepFile(runtime *plugin.Runtime, owningFilePath, source string) (*mqlBicepFile, error) {
	if source == "" || owningFilePath == "" {
		return nil, nil
	}

	conn, ok := runtime.Connection.(*connection.BicepConnection)
	if !ok {
		return nil, nil
	}

	resolved := filepath.Clean(filepath.Join(filepath.Dir(owningFilePath), source))
	for _, f := range conn.BicepFiles() {
		if filepath.Clean(f.Path) == resolved {
			return newMqlBicepFile(runtime, f)
		}
	}
	return nil, nil
}

// target resolves a local module `source` to the bicep.file it references.
//
// Only local sources are resolved: a registry (`br:`) or template-spec (`ts:`)
// source returns null. The source path is computed relative to the directory
// of the file that declared the module. The resolved path must match one of
// the connection's already-discovered files, in which case the same cached
// bicep.file is returned (reusing its __id) so the runtime serves the existing
// instance and the caller can traverse into its resources/params/outputs. A
// path that resolves outside the scanned root — or is otherwise unresolvable —
// returns null; target() never reads an arbitrary path from disk (it shares the
// scan-only resolveScannedBicepFile helper).
func (m *mqlBicepModule) target() (*mqlBicepFile, error) {
	source := m.Source.Data
	// Registry and template-spec references are not local files.
	if m.IsRegistry.Data || m.IsTemplateSpec.Data ||
		strings.HasPrefix(source, "br:") || strings.HasPrefix(source, "br/") ||
		strings.HasPrefix(source, "ts:") || strings.HasPrefix(source, "ts/") {
		m.Target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	f, err := resolveScannedBicepFile(m.MqlRuntime, m.owningFilePath, source)
	if err != nil {
		return nil, err
	}
	if f == nil {
		m.Target.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return f, nil
}

// mqlBicepOutputInternal carries the owning file's symbol resolver so the
// lazy expressionTree() accessor can resolve referenced root identifiers to
// same-file declarations.
type mqlBicepOutputInternal struct {
	stampOnce sync.Once
	resolver  *symbolResolver
}

func createMqlOutputs(runtime *plugin.Runtime, filePath string, outputs []parsedOutput, resolver *symbolResolver) ([]any, error) {
	var mqlOutputs []any
	for _, o := range outputs {
		ctx, err := newBicepContext(runtime, filePath, o.startLine, o.endLine)
		if err != nil {
			return nil, err
		}
		args := map[string]*llx.RawData{
			"__id":        llx.StringData("bicep.output:" + filePath + ":" + o.name),
			"name":        llx.StringData(o.name),
			"type":        llx.StringData(o.typ),
			"expression":  llx.StringData(o.expression),
			"description": llx.StringData(o.description),
		}
		addLoopArgs(args, o.loop)
		contextArg(args, ctx)
		res, err := CreateResource(runtime, "bicep.output", args)
		if err != nil {
			return nil, err
		}
		mqlO := res.(*mqlBicepOutput)
		mqlO.stampOnce.Do(func() { mqlO.resolver = resolver })
		mqlOutputs = append(mqlOutputs, res)
	}
	return mqlOutputs, nil
}

// resolvedType resolves the output's declared `type` name to the same-file
// `bicep.type` it references, or null for a built-in type or an unresolvable
// name.
func (o *mqlBicepOutput) resolvedType() (*mqlBicepType, error) {
	t, err := o.resolver.typ(o.MqlRuntime, o.Type.Data)
	if err != nil {
		return nil, err
	}
	if t == nil {
		o.ResolvedType.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return t, nil
}

// mqlBicepTypeInternal caches the parsed object-type properties so the lazy
// properties() accessor can materialize them without re-parsing the raw
// definition.
type mqlBicepTypeInternal struct {
	stampOnce       sync.Once
	cacheProperties []parsedTypeProperty
}

func createMqlTypes(runtime *plugin.Runtime, filePath string, types_ []parsedType) ([]any, error) {
	var mqlTypes []any
	for _, t := range types_ {
		decorators := sliceToAny(t.decorators)
		unionMembers := sliceToAny(t.unionMembers)
		res, err := CreateResource(runtime, "bicep.type", map[string]*llx.RawData{
			"__id":          llx.StringData("bicep.type:" + filePath + ":" + t.name),
			"name":          llx.StringData(t.name),
			"definition":    llx.StringData(t.definition),
			"kind":          llx.StringData(t.kind),
			"unionMembers":  llx.ArrayData(unionMembers, types.String),
			"discriminator": llx.StringData(t.discriminator),
			"description":   llx.StringData(t.description),
			"exported":      llx.BoolData(t.exported),
			"decorators":    llx.ArrayData(decorators, types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlT := res.(*mqlBicepType)
		mqlT.stampOnce.Do(func() { mqlT.cacheProperties = t.properties })
		mqlTypes = append(mqlTypes, res)
	}
	return mqlTypes, nil
}

// properties materializes the object type's `name: type` members. Each gets a
// synthetic parent-qualified `__id` (`<typeId>/properties/<name>`); the value
// is empty for non-object types.
func (t *mqlBicepType) properties() ([]any, error) {
	out := make([]any, 0, len(t.cacheProperties))
	for _, p := range t.cacheProperties {
		res, err := CreateResource(t.MqlRuntime, "bicep.type.property", map[string]*llx.RawData{
			"__id": llx.StringData(t.__id + "/properties/" + p.name),
			"name": llx.StringData(p.name),
			"type": llx.StringData(p.typ),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func createMqlFunctions(runtime *plugin.Runtime, filePath string, functions []parsedFunction) ([]any, error) {
	var mqlFunctions []any
	for _, fn := range functions {
		decorators := sliceToAny(fn.decorators)

		params := make(map[string]any, len(fn.parameters))
		for k, v := range fn.parameters {
			params[k] = v
		}

		res, err := CreateResource(runtime, "bicep.function", map[string]*llx.RawData{
			"__id":        llx.StringData("bicep.function:" + filePath + ":" + fn.name),
			"name":        llx.StringData(fn.name),
			"parameters":  llx.MapData(params, types.String),
			"returnType":  llx.StringData(fn.returnType),
			"expression":  llx.StringData(fn.expression),
			"description": llx.StringData(fn.description),
			"decorators":  llx.ArrayData(decorators, types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlFunctions = append(mqlFunctions, res)
	}
	return mqlFunctions, nil
}

// mqlBicepImportInternal carries the path of the file that declared this
// import; a relative `source` is resolved against its directory by the
// targetFile() accessor.
type mqlBicepImportInternal struct {
	stampOnce      sync.Once
	owningFilePath string
}

func createMqlImports(runtime *plugin.Runtime, filePath string, imports []parsedImport) ([]any, error) {
	var mqlImports []any
	for i, imp := range imports {
		symbols := sliceToAny(imp.symbols)
		// A file can import the same source twice (e.g. a named import and a
		// wildcard import of './shared.bicep'), so the index disambiguates
		// the synthetic id.
		res, err := CreateResource(runtime, "bicep.import", map[string]*llx.RawData{
			"__id":      llx.StringData("bicep.import:" + filePath + ":" + strconv.Itoa(i) + ":" + imp.source),
			"source":    llx.StringData(imp.source),
			"symbols":   llx.ArrayData(symbols, types.String),
			"namespace": llx.StringData(imp.namespace),
			"wildcard":  llx.BoolData(imp.wildcard),
		})
		if err != nil {
			return nil, err
		}
		mqlImp := res.(*mqlBicepImport)
		mqlImp.stampOnce.Do(func() { mqlImp.owningFilePath = filePath })
		mqlImports = append(mqlImports, res)
	}
	return mqlImports, nil
}

// targetFile resolves a local import `source` to the bicep.file it pulls from.
//
// A bare provider import (e.g. `az@2.0.0`) is not a local file: imports never
// set isRegistry, so a provider import is detected as one whose `source` is not
// a relative path (it has no `./`/`../` prefix and no `.bicep` extension) — it
// resolves to null. Otherwise the relative source is resolved against the
// declaring file's directory via the shared scan-only resolver: only a file the
// scan already discovered is returned (the same cached bicep.file instance),
// and an out-of-root or otherwise unresolvable path returns null. The resolved
// path is never read directly from disk.
func (i *mqlBicepImport) targetFile() (*mqlBicepFile, error) {
	source := i.Source.Data

	// A provider import like `az@2.0.0` is not a relative local file path.
	isRelative := strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")
	if !isRelative || !strings.HasSuffix(source, ".bicep") {
		i.TargetFile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	f, err := resolveScannedBicepFile(i.MqlRuntime, i.owningFilePath, source)
	if err != nil {
		return nil, err
	}
	if f == nil {
		i.TargetFile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return f, nil
}

// cachedTargetFile reads the resolved target file through the generated
// GetTargetFile getter so resolvedTypes() and resolvedFunctions() share a
// single resolution (and its connection scan) instead of each re-running
// targetFile().
func (i *mqlBicepImport) cachedTargetFile() (*mqlBicepFile, error) {
	tv := i.GetTargetFile()
	if tv.Error != nil {
		return nil, tv.Error
	}
	return tv.Data, nil
}

// resolvedTypes returns the user-defined types this import brings in from its
// target file: the named subset (filtered by `symbols`) for a named import, or
// all of the target file's types for a wildcard import. Empty when there is no
// resolvable target file.
func (i *mqlBicepImport) resolvedTypes() ([]any, error) {
	target, err := i.cachedTargetFile()
	if err != nil {
		return nil, err
	}
	if target == nil {
		return []any{}, nil
	}
	all, err := target.types()
	if err != nil {
		return nil, err
	}
	if i.Wildcard.Data {
		return all, nil
	}
	wanted := importSymbolSet(i.Symbols.Data)
	out := make([]any, 0, len(all))
	for _, t := range all {
		if wanted[t.(*mqlBicepType).Name.Data] {
			out = append(out, t)
		}
	}
	return out, nil
}

// resolvedFunctions returns the user-defined functions this import brings in
// from its target file: the named subset (filtered by `symbols`) for a named
// import, or all of the target file's functions for a wildcard import. Empty
// when there is no resolvable target file.
func (i *mqlBicepImport) resolvedFunctions() ([]any, error) {
	target, err := i.cachedTargetFile()
	if err != nil {
		return nil, err
	}
	if target == nil {
		return []any{}, nil
	}
	all, err := target.functions()
	if err != nil {
		return nil, err
	}
	if i.Wildcard.Data {
		return all, nil
	}
	wanted := importSymbolSet(i.Symbols.Data)
	out := make([]any, 0, len(all))
	for _, fn := range all {
		if wanted[fn.(*mqlBicepFunction).Name.Data] {
			out = append(out, fn)
		}
	}
	return out, nil
}

// importSymbolSet turns the `symbols` list (an []any of strings) into a lookup
// set for filtering a target file's types/functions on a named import.
//
// A `{ ... }` import element may rename what it pulls in
// (`import { sku as skuAlias } from './shared.bicep'`), and the parser stores
// the element verbatim, so the entry arrives as "sku as skuAlias". What the
// target file declares is the name before the alias, so that is what has to be
// matched; without the split an aliased import resolves to nothing at all.
//
// The alias is split here rather than at parse time because the parser is
// being changed concurrently on another branch. Splitting it in the parser
// would be cleaner, and would also let `symbols` report the imported names
// without their aliases.
func importSymbolSet(symbols []any) map[string]bool {
	set := make(map[string]bool, len(symbols))
	for _, s := range symbols {
		name, ok := s.(string)
		if !ok {
			continue
		}
		if idx := strings.Index(name, " as "); idx >= 0 {
			name = strings.TrimSpace(name[:idx])
		}
		set[name] = true
	}
	return set
}

// addLoopArgs sets the four flattened `for`-loop fields shared by
// bicep.resource, bicep.module, bicep.output, and bicep.variable. For a
// non-loop declaration isLoop is false and the string fields are empty.
func addLoopArgs(args map[string]*llx.RawData, loop loopInfo) {
	args["isLoop"] = llx.BoolData(loop.isLoop)
	args["loopIterator"] = llx.StringData(loop.iterator)
	args["loopIndexVar"] = llx.StringData(loop.indexVar)
	args["loopExpression"] = llx.StringData(loop.expression)
}

func sliceToAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// Ensure all leaf resources satisfy the plugin interface.
var (
	_ plugin.Resource = (*mqlBicepParameter)(nil)
	_ plugin.Resource = (*mqlBicepVariable)(nil)
	_ plugin.Resource = (*mqlBicepResource)(nil)
	_ plugin.Resource = (*mqlBicepModule)(nil)
	_ plugin.Resource = (*mqlBicepOutput)(nil)
	_ plugin.Resource = (*mqlBicepExpression)(nil)
	_ plugin.Resource = (*mqlBicepPropertyExpression)(nil)
	_ plugin.Resource = (*mqlBicepType)(nil)
	_ plugin.Resource = (*mqlBicepTypeProperty)(nil)
	_ plugin.Resource = (*mqlBicepFunction)(nil)
	_ plugin.Resource = (*mqlBicepImport)(nil)
	_ plugin.Resource = (*mqlBicepParamFile)(nil)
	_ plugin.Resource = (*mqlBicepTemplateParameter)(nil)
	_ plugin.Resource = (*mqlBicepTemplateVariable)(nil)
	_ plugin.Resource = (*mqlBicepTemplateOutput)(nil)
	_ plugin.Resource = (*mqlBicepTemplateResource)(nil)
)
