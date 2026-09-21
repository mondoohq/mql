// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

type compileHandler struct {
	typ        types.Type
	typHandler *typeHandler
	signature  FunctionSignature
	compile    func(*compiler, types.Type, uint64, string, *parser.Call) (types.Type, error)
	desc       string
	// maturity is one of the resources.Maturity* values; empty means stable,
	// which is what every builtin that does not set it is. It travels out
	// through BuiltinDocs on the field, the same channel a schema field uses.
	maturity string
}

func (c compileHandler) returnType(t types.Type) types.Type {
	if c.typHandler != nil {
		return c.typHandler.f(t)
	}
	return c.typ
}

type typeHandler struct {
	name string
	f    func(t types.Type) types.Type
}

var (
	arrayBlockType  = types.Array(types.Map(types.Int, types.Block))
	boolType        = types.Bool
	intType         = types.Int
	stringType      = types.String
	stringArrayType = types.Array(types.String)
	dictType        = types.Dict
	blockType       = types.Block
	dictArrayType   = types.Array(types.Dict)
	// conditional types:
	childType = typeHandler{
		name: "ChildType",
		f:    func(t types.Type) types.Type { return t.Child() },
	}
	sameType = typeHandler{
		name: "SameType",
		f:    func(t types.Type) types.Type { return t },
	}
)

var builtinFunctions map[types.Type]map[string]compileHandler

func init() {
	builtinFunctions = map[types.Type]map[string]compileHandler{
		types.Int: {
			"inRange": {typ: boolType, compile: compileNumberInRange},
		},
		types.Float: {
			"inRange": {typ: boolType, compile: compileNumberInRange},
		},
		types.String: {
			"contains": {
				typ: boolType, compile: compileStringContains, signature: FunctionSignature{Required: 1, Args: []types.Type{types.String}},
				desc: "Checks if this string contains another string",
			},
			"in": {
				typ: boolType, compile: compileStringInOrNotIn,
				desc: "Checks if this string is contained in an array of strings",
			},
			"notIn": {
				typ: boolType, compile: compileStringInOrNotIn,
				desc: "Checks if this string is not contained in an array of strings",
			},
			"inRange": {
				typ: boolType, compile: compileNumberInRange,
				desc: "Checks if the number is in range of a min and max",
			},
			"find": {
				typ: stringArrayType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Regex}},
				desc: "Find a regular expression in a string and return all matches as an array",
			},
			"length": {
				typ: intType, signature: FunctionSignature{},
				desc: "Get the length of this string in bytes",
			},
			"camelcase": {
				typ: stringType, signature: FunctionSignature{},
				desc: "Turns the string into a camelCaseString",
			},
			"downcase": {
				typ: stringType, signature: FunctionSignature{},
				desc: "Turns all characters in this string into lowercase",
			},
			"upcase": {
				typ: stringType, signature: FunctionSignature{},
				desc: "Turns all characters in this string into uppercase",
			},
			"lines": {
				typ: stringArrayType, signature: FunctionSignature{},
				desc: "Split the string into lines and return them in an array",
			},
			"split": {
				typ: stringArrayType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.String}},
				desc: "Split a string into an array of substrings separated by the given character",
			},
			"trim": {
				typ: stringType, signature: FunctionSignature{Required: 0, Args: []types.Type{types.String}},
				desc: "Remove all surrounding whitespaces (including newlines and tabs)",
			},
			"json": {
				typ: dictType, signature: FunctionSignature{},
				desc:     "Experimental. Decode this string as a JSON document and return it as a traversable dict",
				maturity: resources.MaturityExperimental,
			},
		},
		types.Time: {
			"seconds": {typ: intType, signature: FunctionSignature{}},
			"minutes": {typ: intType, signature: FunctionSignature{}},
			"hours":   {typ: intType, signature: FunctionSignature{}},
			"days":    {typ: intType, signature: FunctionSignature{}},
			"unix":    {typ: intType, signature: FunctionSignature{}},
			"inRange": {typ: boolType, compile: compileTimeInRange},
		},
		types.Dict: {
			"[]": {typ: dictType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Any}}},
			"{}": {typ: blockType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			// number-ish
			"inRange": {typ: boolType, compile: compileNumberInRange},
			// string-ish
			"find":      {typ: stringArrayType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Regex}}},
			"length":    {typ: intType, signature: FunctionSignature{}},
			"camelcase": {typ: stringType, signature: FunctionSignature{}},
			"downcase":  {typ: stringType, signature: FunctionSignature{}},
			"upcase":    {typ: stringType, signature: FunctionSignature{}},
			"lines":     {typ: stringArrayType, signature: FunctionSignature{}},
			"split":     {typ: stringArrayType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.String}}},
			"trim":      {typ: stringType, signature: FunctionSignature{Required: 0, Args: []types.Type{types.String}}},
			"json": {
				typ: dictType, signature: FunctionSignature{},
				desc:     "Experimental. Decode this string as a JSON document and return it as a traversable dict",
				maturity: resources.MaturityExperimental,
			},
			// string / array
			"in":    {typ: boolType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Array(types.String), types.Array(types.Dict)}}},
			"notIn": {typ: boolType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Array(types.String), types.Array(types.Dict)}}},
			// array- or map-ish
			"first":   {typ: dictType, signature: FunctionSignature{}},
			"last":    {typ: dictType, signature: FunctionSignature{}},
			"where":   {compile: compileDictWhere, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"sample":  {typHandler: &sameType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Int}}},
			"recurse": {compile: compileDictRecurse, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"contains": {
				compile: compileDictContains, typ: boolType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}},
				desc: "When dealing with strings, check if it contains another string. When dealing with maps or arrays, check if any entry matches the given condition.",
			},
			"containsOnly": {compile: compileDictContainsOnly, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"containsAll":  {compile: compileDictContainsAll, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"containsNone": {compile: compileDictContainsNone, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"all": {
				compile: compileDictAll, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}},
				desc: "Check if all entries in this array or map satisfy a given condition",
			},
			"any": {
				compile: compileDictAny, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}},
				desc: "Check if any entry in this array or map satisfies a given condition",
			},
			"one": {
				compile: compileDictOne, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}},
				desc: "Check if exactly one entry in this array or map satisfies a given condition",
			},
			"none": {
				compile: compileDictNone, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}},
				desc: "Check if no entry in this array or map satisfies a given condition",
			},
			"having": {compile: compileDictHaving, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"map":    {compile: compileArrayMap, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"flat":   {compile: compileDictFlat, signature: FunctionSignature{}},
			// map-ish
			"keys":   {typ: stringArrayType, signature: FunctionSignature{}},
			"values": {typ: dictArrayType, signature: FunctionSignature{}},
		},
		types.Version: {
			"epoch":   {typ: intType, signature: FunctionSignature{}},
			"inRange": {typ: intType, compile: compileVersionInRange},
		},
		types.IP: {
			"address":       {typ: stringType, signature: FunctionSignature{}},
			"cidr":          {typ: stringType, signature: FunctionSignature{}},
			"inRange":       {typ: intType, compile: compileIpInRange},
			"isPublic":      {typ: boolType, signature: FunctionSignature{}},
			"isUnspecified": {typ: boolType, signature: FunctionSignature{}},
			"prefix":        {typ: stringType, signature: FunctionSignature{}},
			"prefixLength":  {typ: intType, signature: FunctionSignature{}},
			"subnet":        {typ: stringType, signature: FunctionSignature{}},
			"suffix":        {typ: stringType, signature: FunctionSignature{}},
			"version":       {typ: stringType, signature: FunctionSignature{}},
		},
		types.ArrayLike: {
			"[]":           {typHandler: &childType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Int}}},
			"first":        {typHandler: &childType, signature: FunctionSignature{}},
			"last":         {typHandler: &childType, signature: FunctionSignature{}},
			"{}":           {typ: arrayBlockType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"length":       {typ: intType, signature: FunctionSignature{}},
			"where":        {compile: compileArrayWhere, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"sample":       {typHandler: &sameType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Int}}},
			"duplicates":   {compile: compileArrayDuplicates, signature: FunctionSignature{Required: 0, Args: []types.Type{types.String}}},
			"unique":       {compile: compileArrayUnique, signature: FunctionSignature{Required: 0}},
			"in":           {typ: boolType, compile: compileStringInOrNotIn, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Array(types.String)}}},
			"notIn":        {typ: boolType, compile: compileStringInOrNotIn, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Array(types.String)}}},
			"contains":     {compile: compileArrayContains, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"containsOnly": {compile: compileArrayContainsOnly, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"containsAll":  {compile: compileArrayContainsAll, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"containsNone": {compile: compileArrayContainsNone, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"all":          {compile: compileArrayAll, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"any":          {compile: compileArrayAny, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"one":          {compile: compileArrayOne, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"none":         {compile: compileArrayNone, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"having":       {compile: compileArrayHaving, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"map":          {compile: compileArrayMap, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"flat":         {compile: compileArrayFlat, signature: FunctionSignature{}},
			"reverse":      {typHandler: &sameType, signature: FunctionSignature{}},
			"join":         {compile: compileArrayJoin, signature: FunctionSignature{Args: []types.Type{types.String}}},
		},
		types.MapLike: {
			"[]":       {typHandler: &childType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.String}}},
			"{}":       {typ: blockType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"length":   {typ: intType, signature: FunctionSignature{}},
			"keys":     {typ: stringArrayType, signature: FunctionSignature{}},
			"values":   {compile: compileMapValues, signature: FunctionSignature{}},
			"where":    {compile: compileMapWhere, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"sample":   {typHandler: &sameType, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Int}}},
			"contains": {compile: compileMapContains, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"all":      {compile: compileMapAll, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"one":      {compile: compileMapOne, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"none":     {compile: compileMapNone, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"having":   {compile: compileMapHaving, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
		},
		types.ResourceLike: {
			"first":                    {compile: compileResourceChildAccess, signature: FunctionSignature{}},
			"last":                     {compile: compileResourceChildAccess, signature: FunctionSignature{}},
			"length":                   {compile: compileResourceLength, signature: FunctionSignature{}},
			"where":                    {compile: compileResourceWhere, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"sample":                   {compile: compileResourceSample, signature: FunctionSignature{Required: 1, Args: []types.Type{types.Int}}},
			"contains":                 {compile: compileResourceContains, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"all":                      {compile: compileResourceAll, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"any":                      {compile: compileResourceAny, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"one":                      {compile: compileResourceOne, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"none":                     {compile: compileResourceNone, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"having":                   {compile: compileResourceHaving, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"map":                      {compile: compileResourceMap, signature: FunctionSignature{Required: 1, Args: []types.Type{types.FunctionLike}}},
			"==" + string(types.Empty): {compile: compileResourceCmpEmpty},
			"!=" + string(types.Empty): {compile: compileResourceCmpEmpty},
		},
		// TODO: [#32] unique builtin fields that need a long-term support in LR
		types.Resource("parse"): {
			"date":     {compile: compileResourceParseDate, signature: FunctionSignature{Required: 1, Args: []types.Type{types.String, types.String}}},
			"duration": {compile: compileResourceParseDuration, signature: FunctionSignature{Required: 1, Args: []types.Type{types.String}}},
		},
	}
}

// Note: Call it with the full type, not just the underlying type
func builtinFunction(typ types.Type, id string) (*compileHandler, error) {
	// TODO: [#32] special handlers for specific types, which are builtin and should
	// be removed long-term, one the resource is native in LR
	fh, ok := builtinFunctions[typ]
	if ok {
		c, ok := fh[id]
		if ok {
			return &c, nil
		}
	}

	fh, ok = builtinFunctions[typ.Underlying()]
	if ok {
		c, ok := fh[id]
		if ok {
			return &c, nil
		}
	} else {
		return nil, errors.New("cannot find any functions for type '" + typ.Label() + "' during compile")
	}

	return nil, errors.New("cannot find function '" + id + "' for type '" + typ.Label() + "' during compile")
}

// Compile calls to builtin type handlers, that aren't mapped via builtin
// functions above. Typically only used if we need to go deeper into the given
// type to figure out what to do. For example: list resources are just
// resource types, so we can't tell if there are builtin functions without
// detecting that we are looking at a list resource.
func (c *compiler) compileImplicitBuiltin(typ types.Type, id string) (*compileHandler, *variable, error) {
	if !typ.IsResource() {
		return nil, nil, nil
	}

	r := typ.ResourceName()
	resource := c.Schema.Lookup(r)
	if resource == nil || resource.ListType == "" {
		return nil, nil, nil
	}

	ch, ok := builtinFunctions[types.ArrayLike][id]
	if !ok {
		return nil, nil, nil
	}

	resType := types.Array(types.Type(resource.ListType))
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "list",
		Function: &llx.Function{
			Type:    string(resType),
			Binding: c.tailRef(),
		},
	})
	return &ch, &variable{
		typ: resType,
		ref: c.tailRef(),
	}, nil
}

func publicFieldsInfo(c *compiler, resourceInfo *resources.ResourceInfo) map[string]llx.Documentation {
	return publicFieldsInfoFlat(c, resourceInfo, c.UseAssetContext)
}

// publicFieldsInfoFlat is publicFieldsInfo with control over whether embedded
// resources are flattened into the answer.
//
// An asset root always flattens, regardless of the asset-context feature: its
// embed chain (`os.linux` -> `os.unix` -> `os.base`) is the taxonomy, so not
// descending it hides `hostname` and most of the surface - names that compile
// fine, which is what made the shell suggest a different set than it accepts.
func publicFieldsInfoFlat(c *compiler, resourceInfo *resources.ResourceInfo, flattenEmbedded bool) map[string]llx.Documentation {
	res := map[string]llx.Documentation{}
	for k, v := range resourceInfo.Fields {
		if v.IsPrivate {
			continue
		}
		if v.IsEmbedded && !flattenEmbedded {
			continue
		}

		if v.IsEmbedded && flattenEmbedded {
			name := types.Type(v.Type).ResourceName()
			child := c.Schema.Lookup(name)
			if child == nil {
				continue
			}
			childFields := publicFieldsInfoFlat(c, child, flattenEmbedded)
			for k, v := range childFields {
				res[k] = v
			}
			continue
		}

		if v.IsImplicitResource {
			name := types.Type(v.Type).ResourceName()
			child := c.Schema.Lookup(name)
			if !child.HasEmptyInit() {
				continue
			}

			// implicit resources don't have their own metadata, so we grab it from
			// the resource itself
			title := child.Title
			if label := resources.MaturityLabel(resources.EffectiveFieldMaturity(resourceInfo, v)); label != "" {
				title = "[" + label + "] " + title
			}
			res[k] = llx.Documentation{
				Field: k,
				Title: title,
				Desc:  child.Desc,
			}
			continue
		}

		title := v.Title
		if label := resources.MaturityLabel(resources.EffectiveFieldMaturity(resourceInfo, v)); label != "" {
			title = "[" + label + "] " + title
		}
		res[k] = llx.Documentation{
			Field: k,
			Title: title,
			Desc:  v.Desc,
		}
	}

	return res
}

// Glob {*} all fields for a given type. Note, that this descends into
// list elements of array resources if permitted.
func availableGlobFields(c *compiler, typ types.Type, descend bool) map[string]llx.Documentation {
	var res map[string]llx.Documentation

	if !typ.IsResource() {
		return res
	}

	resourceInfo := c.Schema.Lookup(typ.ResourceName())
	if descend && resourceInfo.ListType != "" {
		base := types.Type(resourceInfo.ListType).ResourceName()
		if info := c.Schema.Lookup(base); info != nil {
			resourceInfo = info
		}
	}

	return publicFieldsInfo(c, resourceInfo)
}

func availableFields(c *compiler, typ types.Type) map[string]llx.Documentation {
	var res map[string]llx.Documentation

	// An asset reference offers the fields of the resource that roots the
	// referenced asset, since that is what chaining off it reaches. Nothing is
	// offered when that schema is not loaded here — the root is known by name
	// only, so there are no fields to name (ADR 031).
	if typ.IsAsset() {
		if root := typ.AssetRootName(); root != "" {
			if info := c.Schema.Lookup(root); info != nil {
				return publicFieldsInfo(c, info)
			}
		}
		return nil
	}

	// resources maintain their own fields and may be list resources
	if typ.IsResource() {
		resourceInfo := c.Schema.Lookup(typ.ResourceName())
		res = publicFieldsInfoFlat(c, resourceInfo,
			c.UseAssetContext || typ.ResourceName() == c.AssetRoot)

		_, err := listResource(c, typ)
		if err == nil {
			m := builtinFunctions[typ.Underlying()]
			for k := range m {
				if !parser.IsOperator(k) {
					res[k] = llx.Documentation{
						Field: k,
					}
				}
			}
		}

	}

	// We first try to auto-complete the full type. This is important for
	// more complex types, like resource types (eg `parse`).
	builtins := builtinFunctions[typ]
	if builtins == nil && res == nil {
		// Only if we fail to find the full resource AND if we couldn't look
		// up the resource definition either, will we look for additional
		// methods. Otherwise we stick to the directly defined methods, not any
		// potentially "shared" methods (which aren't actually shared).
		builtins = builtinFunctions[typ.Underlying()]
		if builtins == nil {
			return res
		}
	}

	// the non-resource use-case:
	if res == nil {
		res = make(map[string]llx.Documentation, len(builtins))
	}

	for k := range builtins {
		res[k] = llx.Documentation{
			Field: k,
		}
	}

	return res
}

// BuiltinSchema captures all internal types and their metadata.
// We could have just as well used the `resources.Schema` here.
// However, semantically we are documenting types and not resources here.
// The difference may not matter to an end-user (everything looks like types),
// but it matters internally since they are handled differently.
type BuiltinSchema struct {
	Types map[string]*resources.ResourceInfo
}

func BuiltinDocs() *BuiltinSchema {
	var res BuiltinSchema
	res.Types = make(map[string]*resources.ResourceInfo, len(builtinFunctions))
	for typ, fields := range builtinFunctions {
		label := typ.Label()
		resource := &resources.ResourceInfo{
			Id:     label,
			Fields: make(map[string]*resources.Field, len(fields)),
		}
		res.Types[label] = resource

		for field, v := range fields {
			res := &resources.Field{
				Name:     field,
				Desc:     v.desc,
				Maturity: v.maturity,
			}

			if v.typHandler != nil {
				res.Type = v.typHandler.name
			} else {
				res.Type = string(v.typ)
			}

			resource.Fields[field] = res
		}
	}

	return &res
}
