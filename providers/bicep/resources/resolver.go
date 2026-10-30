// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Reference kinds returned by symbolResolver.kind and exposed as
// bicep.expression.referenceKind.
const (
	refKindParameter = "parameter"
	refKindVariable  = "variable"
	refKindResource  = "resource"
	refKindModule    = "module"
	refKindType      = "type"
)

// symbolResolver is a per-file symbol table. Bicep symbols are file-scoped:
// a root identifier in an expression (the `target` of a symbolicRef or
// propertyAccess) resolves to exactly one declaration in the same file among
// the parameters, variables, resources, modules, and user-defined types.
// The resolver indexes those declarations by the name they're referenced by
// (parameters/variables/modules/types by name, resources by symbolic name)
// and builds the matching typed resource on demand, reusing the same __id the
// declaration was originally created with so the runtime returns the cached
// instance instead of a duplicate.
//
// Cross-file `import` resolution is intentionally out of scope here — a target
// that names an imported symbol (or a built-in like `resourceGroup`) simply
// doesn't match and resolves to the empty kind.
type symbolResolver struct {
	filePath   string
	parameters map[string]parsedParameter
	variables  map[string]parsedVariable
	resources  map[string]parsedResource
	modules    map[string]parsedModule
	types      map[string]parsedType
}

// newSymbolResolver builds the per-file symbol index from a parsed file. Only
// top-level declarations participate in symbol resolution — nested child
// resources are addressed through their parent and never referenced by a bare
// root identifier, so they're not indexed here.
func newSymbolResolver(filePath string, parsed *parsedBicepFile) *symbolResolver {
	r := &symbolResolver{
		filePath:   filePath,
		parameters: make(map[string]parsedParameter, len(parsed.parameters)),
		variables:  make(map[string]parsedVariable, len(parsed.variables)),
		resources:  make(map[string]parsedResource, len(parsed.resources)),
		modules:    make(map[string]parsedModule, len(parsed.modules)),
		types:      make(map[string]parsedType, len(parsed.types)),
	}
	for _, p := range parsed.parameters {
		r.parameters[p.name] = p
	}
	for _, v := range parsed.variables {
		r.variables[v.name] = v
	}
	for _, res := range parsed.resources {
		r.resources[res.symbolicName] = res
	}
	for _, m := range parsed.modules {
		r.modules[m.name] = m
	}
	for _, t := range parsed.types {
		r.types[t.name] = t
	}
	return r
}

// kind reports which declaration category `target` names within the file, or
// the empty string when `target` is empty or doesn't match a same-file
// declaration (e.g. a built-in like `resourceGroup` or an imported symbol).
func (r *symbolResolver) kind(target string) string {
	if r == nil || target == "" {
		return ""
	}
	if _, ok := r.parameters[target]; ok {
		return refKindParameter
	}
	if _, ok := r.variables[target]; ok {
		return refKindVariable
	}
	if _, ok := r.resources[target]; ok {
		return refKindResource
	}
	if _, ok := r.modules[target]; ok {
		return refKindModule
	}
	if _, ok := r.types[target]; ok {
		return refKindType
	}
	return ""
}

// parameter builds (or returns the cached) bicep.parameter the target names,
// or nil when it doesn't name a parameter in this file.
func (r *symbolResolver) parameter(runtime *plugin.Runtime, target string) (*mqlBicepParameter, error) {
	if r == nil {
		return nil, nil
	}
	p, ok := r.parameters[target]
	if !ok {
		return nil, nil
	}
	out, err := createMqlParameters(runtime, r.filePath, []parsedParameter{p}, r)
	if err != nil {
		return nil, err
	}
	return out[0].(*mqlBicepParameter), nil
}

// variable builds (or returns the cached) bicep.variable the target names, or
// nil when it doesn't name a variable in this file.
func (r *symbolResolver) variable(runtime *plugin.Runtime, target string) (*mqlBicepVariable, error) {
	if r == nil {
		return nil, nil
	}
	v, ok := r.variables[target]
	if !ok {
		return nil, nil
	}
	out, err := createMqlVariables(runtime, r.filePath, []parsedVariable{v}, r)
	if err != nil {
		return nil, err
	}
	return out[0].(*mqlBicepVariable), nil
}

// resource builds (or returns the cached) bicep.resource the target names, or
// nil when it doesn't name a resource in this file.
func (r *symbolResolver) resource(runtime *plugin.Runtime, target string) (*mqlBicepResource, error) {
	if r == nil {
		return nil, nil
	}
	res, ok := r.resources[target]
	if !ok {
		return nil, nil
	}
	ctx, err := newBicepContext(runtime, r.filePath, res.startLine, res.endLine)
	if err != nil {
		return nil, err
	}
	return newMqlBicepResource(runtime, bicepResourceID(r.filePath, res), res, r, ctx)
}

// module builds (or returns the cached) bicep.module the target names, or nil
// when it doesn't name a module in this file.
func (r *symbolResolver) module(runtime *plugin.Runtime, target string) (*mqlBicepModule, error) {
	if r == nil {
		return nil, nil
	}
	m, ok := r.modules[target]
	if !ok {
		return nil, nil
	}
	out, err := createMqlModules(runtime, r.filePath, []parsedModule{m}, r)
	if err != nil {
		return nil, err
	}
	return out[0].(*mqlBicepModule), nil
}

// typ builds (or returns the cached) bicep.type the target names, or nil when
// it doesn't name a user-defined type in this file.
func (r *symbolResolver) typ(runtime *plugin.Runtime, target string) (*mqlBicepType, error) {
	if r == nil {
		return nil, nil
	}
	t, ok := r.types[target]
	if !ok {
		return nil, nil
	}
	out, err := createMqlTypes(runtime, r.filePath, []parsedType{t})
	if err != nil {
		return nil, err
	}
	return out[0].(*mqlBicepType), nil
}
