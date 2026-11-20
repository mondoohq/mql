// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"
	"strconv"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc/parser"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

func compileResourceDefault(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	name := typ.ResourceName()
	resource := c.Schema.Lookup(name)
	if resource == nil {
		return types.Nil, errors.New("cannot find resource '" + name + "' when compiling field '" + id + "'")
	}

	// special case that we can optimize: the previous call was a resource
	// without any call arguments + the combined type is a resource itself
	// in that case save the outer call and go for the resource directly
	prevRef := c.tailRef()
	prev := c.Result.CodeV2.Chunk(prevRef)
	if prev.Call == llx.Chunk_FUNCTION && prev.Function == nil {
		name := prev.Id + "." + id
		resourceinfo := c.Schema.Lookup(name)
		if resourceinfo != nil {
			c.popChunk()
			return c.addResource(name, resourceinfo, call)
		}
	}

	fieldPath, fieldinfos, ok := c.Schema.FindField(resource, id)
	if !ok {
		addFieldSuggestions(publicFieldsInfo(c, resource), id, c.Result)
		return "", errors.New("cannot find field '" + id + "' in resource " + resource.Name +
			c.resourceFieldSkewHint(resource))
	}

	lastRef := ref
	for i, p := range fieldPath {
		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   p,
			Function: &llx.Function{
				Type:    fieldinfos[i].Type,
				Binding: lastRef,
				// no Args for field calls yet
			},
		})
		lastRef = c.tailRef()
		// Attach downgrade fallbacks for this field, if the provider knows how
		// to rebuild it for readers that predate it (ADR 040 part 6). Done here,
		// right after the chunk exists, because the translation has to point at
		// that chunk's ref.
		c.emitTranslations(resource.Id, p, lastRef, types.Type(fieldinfos[i].Type))
	}

	return types.Type(fieldinfos[len(fieldinfos)-1].Type), nil
}

// FunctionSignature of any function type
type FunctionSignature struct {
	Required int
	Args     []types.Type
}

func (f *FunctionSignature) expected2string() string {
	if f.Required == len(f.Args) {
		return strconv.Itoa(f.Required)
	}
	return strconv.Itoa(f.Required) + "-" + strconv.Itoa(len(f.Args))
}

// Validate the field call against the signature. Returns nil if valid and
// an error message otherwise
func (f *FunctionSignature) Validate(args []*llx.Primitive, c *compiler) error {
	max := len(f.Args)
	given := len(args)

	if given == 0 {
		if f.Required > 0 {
			return errors.New("no arguments given (expected " + f.expected2string() + ")")
		}
		return nil
	}

	if given < f.Required {
		return errors.New("not enough arguments (expected " + f.expected2string() + ", got " + strconv.Itoa(given) + ")")
	}
	if given > max {
		return errors.New("too many arguments (expected " + f.expected2string() + ", got " + strconv.Itoa(given) + ")")
	}

	for i := range args {
		req := f.Args[i]
		argT := types.Type(args[i].Type)

		var err error
		if argT == types.Ref {
			argT, err = c.dereferenceType(args[i])
			if err != nil {
				return multierr.Wrap(err, "failed to dereference argument in validating function signature")
			}
		}

		// TODO: find out the real type from these REF types
		if argT == req || req == types.Any {
			continue
		}

		return errors.New("incorrect argument " + strconv.Itoa(i) + ": expected " + req.Label() + " got " + argT.Label())
	}
	return nil
}

func listResource(c *compiler, typ types.Type) (*resources.ResourceInfo, error) {
	name := typ.ResourceName()
	resource := c.Schema.Lookup(name)
	if resource == nil {
		return nil, errors.New("cannot find resource '" + name + "'")
	}
	if resource.ListType == "" {
		return nil, errors.New("resource '" + name + "' is not a list type")
	}
	return resource, nil
}

func compileResourceWhere(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	resource, err := listResource(c, typ)
	if err != nil {
		return types.Nil, multierr.Wrap(err, "failed to compile "+id)
	}

	if call == nil {
		return types.Nil, errors.New("missing filter argument for calling '" + id + "'")
	}
	// if the where function is called without arguments, we don't have to do anything
	// so we just return the caller type as no additional step in the compiler is necessary
	if len(call.Function) == 0 {
		return typ, nil
	}
	if len(call.Function) > 1 {
		return types.Nil, errors.New("too many arguments when calling '" + id + "', only 1 is supported")
	}

	arg := call.Function[0]
	bindingName := "_"
	if arg.Name != "" {
		bindingName = arg.Name
	}

	refs, err := c.blockExpressions([]*parser.Expression{arg.Value}, types.Array(types.Type(resource.ListType)), ref, bindingName)
	if err != nil {
		return types.Nil, err
	}
	if refs.isStandalone && !c.EditorMode {
		log.Warn().Str("resource", resource.Name).Msg("Detected a standalone function in a WHERE clause! This is probably unintended. Be sure to filter the list.")
	}
	if refs.block == 0 {
		return types.Nil, errors.New("called '" + id + "' clause without a function block")
	}
	ref = refs.binding

	resourceRef := c.tailRef()

	listType, err := compileResourceDefault(c, typ, ref, "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	args := []*llx.Primitive{
		llx.RefPrimitiveV2(listRef),
		llx.FunctionPrimitive(refs.block),
	}
	for _, v := range refs.deps {
		if c.isInMyBlock(v) {
			args = append(args, llx.RefPrimitiveV2(v))
		}
	}
	c.blockDeps = append(c.blockDeps, refs.deps...)

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(types.Resource(resource.Name)),
			Binding: resourceRef,
			Args:    args,
		},
	})
	return typ, nil
}

func compileResourceSample(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	resource, err := listResource(c, typ)
	if err != nil {
		return types.Nil, multierr.Wrap(err, "failed to compile "+id)
	}

	if call == nil || len(call.Function) == 0 {
		return types.Nil, errors.New("missing argument for calling '" + id + "'")
	}
	if len(call.Function) > 1 {
		return types.Nil, errors.New("too many arguments when calling '" + id + "', only 1 is supported")
	}

	resourceRef := ref

	listType, err := compileResourceDefault(c, typ, ref, "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	arg := call.Function[0]
	if arg.Value == nil || arg.Value.Operand == nil {
		return types.Nil, errors.New("function '" + id + "' needs one argument")
	}
	val, err := c.compileOperand(arg.Value.Operand)
	if err != nil {
		return types.Nil, err
	}

	args := []*llx.Primitive{
		llx.RefPrimitiveV2(listRef),
		val,
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(types.Array(types.Resource(resource.Name))),
			Binding: resourceRef,
			Args:    args,
		},
	})
	return typ, nil
}

func compileResourceMap(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	resource, err := listResource(c, typ)
	if err != nil {
		return types.Nil, multierr.Wrap(err, "failed to compile "+id)
	}

	if call == nil {
		return types.Nil, errors.New("missing filter argument for calling '" + id + "'")
	}
	if len(call.Function) > 1 {
		return types.Nil, errors.New("too many arguments when calling '" + id + "', only 1 is supported")
	}

	// if the where function is called without arguments, we don't have to do anything
	// so we just return the caller type as no additional step in the compiler is necessary
	if len(call.Function) == 0 {
		return typ, nil
	}

	arg := call.Function[0]
	bindingName := "_"
	if arg.Name != "" {
		bindingName = arg.Name
	}

	resourceRef := ref

	refs, err := c.blockExpressions([]*parser.Expression{arg.Value}, types.Array(types.Type(resource.ListType)), ref, bindingName)
	if err != nil {
		return types.Nil, err
	}
	if refs.block == 0 {
		return types.Nil, errors.New("called '" + id + "' clause without a function block")
	}
	ref = refs.binding

	mappedType, err := c.blockType(refs.block)
	if err != nil {
		return types.Nil, multierr.Wrap(err, "called '"+id+"' with a bad function block, types don't match")
	}

	// The map body's entrypoint is the value this map collects, not something
	// that gets rendered on its own. Mark the block so postCompile won't
	// display-expand a resource(-list) entrypoint into an anonymous `{}` block,
	// which would otherwise make the mapped elements lose their resource type.
	// See https://github.com/mondoohq/mql/issues/8474
	c.valueBodyBlocks[refs.block] = struct{}{}

	listType, err := compileResourceDefault(c, typ, ref, "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	args := []*llx.Primitive{
		llx.RefPrimitiveV2(listRef),
		llx.FunctionPrimitive(refs.block),
	}
	for _, v := range refs.deps {
		if c.isInMyBlock(v) {
			args = append(args, llx.RefPrimitiveV2(v))
		}
	}
	c.blockDeps = append(c.blockDeps, refs.deps...)

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(types.Array(mappedType)),
			Binding: resourceRef,
			Args:    args,
		},
	})

	return types.Array(mappedType), nil
}

func compileResourceContains(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	// resource.where
	_, err := compileResourceWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	resourceRef := c.tailRef()

	// .list
	t, err := compileResourceDefault(c, typ, resourceRef, "list", nil)
	if err != nil {
		return t, err
	}
	listRef := c.tailRef()

	// .length
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "length",
		Function: &llx.Function{
			Type:    string(types.Int),
			Binding: listRef,
		},
	})

	// > 0
	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string(">" + types.Int),
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: c.tailRef(),
			Args: []*llx.Primitive{
				llx.IntPrimitive(0),
			},
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = typ.ResourceName() + ".contains()"

	return types.Bool, nil
}

func compileResourceAll(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	// resource.$whereNot
	_, err := compileResourceWhere(c, typ, ref, "$whereNot", call)
	if err != nil {
		return types.Nil, err
	}
	whereRef := c.tailRef()

	listType, err := compileResourceDefault(c, typ, c.tailRef(), "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, listType, whereRef-1, listRef, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$all",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = typ.ResourceName() + ".all()"

	return types.Bool, nil
}

func compileResourceAny(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	// resource.where
	_, err := compileResourceWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	whereRef := c.tailRef()

	listType, err := compileResourceDefault(c, typ, whereRef, "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, listType, whereRef-1, whereRef-1, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$any",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = typ.ResourceName() + ".any()"

	return types.Bool, nil
}

func compileResourceOne(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	// resource.where
	_, err := compileResourceWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	whereRef := c.tailRef()

	listType, err := compileResourceDefault(c, typ, c.tailRef(), "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, listType, whereRef-1, listRef, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$one",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = typ.ResourceName() + ".one()"

	return types.Bool, nil
}

func compileResourceNone(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	// resource.where
	_, err := compileResourceWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	whereRef := c.tailRef()

	listType, err := compileResourceDefault(c, typ, c.tailRef(), "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, listType, whereRef-1, listRef, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$none",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = typ.ResourceName() + ".none()"

	return types.Bool, nil
}

func compileResourceHaving(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	// resource.where
	_, err := compileResourceWhere(c, typ, ref, "where", call)
	if err != nil {
		return types.Nil, err
	}
	whereRef := c.tailRef()

	listType, err := compileResourceDefault(c, typ, whereRef, "list", nil)
	if err != nil {
		return listType, err
	}
	listRef := c.tailRef()

	if err := compileListAssertionMsg(c, listType, whereRef-1, whereRef-1, listRef); err != nil {
		return types.Nil, err
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   "$any",
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
		},
	})
	anyRef := c.tailRef()

	checksum := c.Result.CodeV2.Checksums[anyRef]
	c.Result.Labels.Labels[checksum] = typ.ResourceName() + ".having()"

	c.block.Entrypoints = append(c.block.Entrypoints, anyRef)
	c.block.Datapoints = append(c.block.Datapoints, whereRef)

	c.overrideTailDataRef = whereRef

	return typ, nil
}

func compileResourceChildAccess(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call != nil && len(call.Function) > 0 {
		return types.Nil, errors.New("function " + id + " does not take arguments")
	}

	_, err := listResource(c, typ)
	if err != nil {
		return types.Nil, multierr.Wrap(err, "failed to compile "+id)
	}

	t, err := compileResourceDefault(c, typ, ref, "list", nil)
	if err != nil {
		return t, err
	}
	listRef := c.tailRef()

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(t.Child()),
			Binding: listRef,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2(listRef),
			},
		},
	})
	return t.Child(), nil
}

func compileResourceLength(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call != nil && len(call.Function) > 0 {
		return types.Nil, errors.New("function " + id + " does not take arguments")
	}

	_, err := listResource(c, typ)
	if err != nil {
		return types.Nil, multierr.Wrap(err, "failed to compile "+id)
	}

	resourceRef := ref

	t, err := compileResourceDefault(c, typ, ref, "list", nil)
	if err != nil {
		return t, err
	}
	listRef := c.tailRef()

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(types.Int),
			Binding: resourceRef,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2(listRef),
			},
		},
	})
	return typ, nil
}

func compileResourceParseDate(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call == nil {
		return types.Nil, errors.New("missing arguments to parse date")
	}

	functionID := string(typ) + "." + id

	init := &resources.Init{
		Args: []*resources.TypedArg{
			{Name: "value", Type: string(types.String)},
			{Name: "format", Type: string(types.String)},
		},
	}
	args, err := c.unnamedArgs("parse."+id, init, call.Function)
	if err != nil {
		return types.Nil, err
	}

	rawArgs := make([]*llx.Primitive, len(call.Function))
	for i := range call.Function {
		rawArgs[i] = args[i*2+1]
	}

	if len(rawArgs) == 0 {
		return types.Nil, errors.New("missing arguments to parse date")
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   functionID,
		Function: &llx.Function{
			Type:    string(types.Time),
			Binding: ref,
			Args:    rawArgs,
		},
	})
	return types.Time, nil
}

func compileResourceParseDuration(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call == nil {
		return types.Nil, errors.New("missing arguments to parse duration")
	}

	functionID := string(typ) + "." + id

	init := &resources.Init{
		Args: []*resources.TypedArg{
			{Name: "value", Type: string(types.String)},
		},
	}
	args, err := c.unnamedArgs("parse."+id, init, call.Function)
	if err != nil {
		return types.Nil, err
	}

	rawArgs := make([]*llx.Primitive, len(call.Function))
	for i := range call.Function {
		rawArgs[i] = args[i*2+1]
	}

	if len(rawArgs) == 0 {
		return types.Nil, errors.New("missing arguments to parse duration")
	}

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   functionID,
		Function: &llx.Function{
			Type:    string(types.Time),
			Binding: ref,
			Args:    rawArgs,
		},
	})
	return types.Time, nil
}

// compileFilePermissionsMask compiles file.permissions.atMost(mask) and
// file.permissions.atLeast(mask). MQL has no bitwise operators, so the mask
// test runs in the executor against the resource's `mode` field, which is
// read first and passed as the first argument.
func compileFilePermissionsMask(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	if call == nil || len(call.Function) != 1 {
		return types.Nil, errors.New("function " + id + " expects one argument, the octal mask (e.g. 0640)")
	}
	if call.Function[0].Name != "" {
		return types.Nil, errors.New("function " + id + " does not take named arguments")
	}

	mask, err := c.compileExpression(call.Function[0].Value)
	if err != nil {
		return types.Nil, err
	}
	sig := FunctionSignature{Required: 1, Args: []types.Type{types.Int}}
	if err := sig.Validate([]*llx.Primitive{mask}, c); err != nil {
		return types.Nil, errors.New("function " + id + ": " + err.Error())
	}
	if types.Type(mask.Type) == types.Int {
		if v, ok := mask.RawData().Value.(int64); ok && (v < 0 || v > 0o7777) {
			return types.Nil, errors.New("function " + id + ": mask 0" + strconv.FormatInt(v, 8) + " is outside the permission bits 0-07777")
		}
	}

	if _, err := compileResourceDefault(c, typ, ref, "mode", nil); err != nil {
		return types.Nil, err
	}
	modeRef := c.tailRef()

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   string(typ) + "." + id,
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: ref,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2(modeRef),
				mask,
			},
		},
	})
	return types.Bool, nil
}

func compileResourceCmpEmpty(c *compiler, typ types.Type, ref uint64, id string, call *parser.Call) (types.Type, error) {
	var label string
	switch id {
	case "==" + string(types.Empty):
		label = "== empty"
	case "!=" + string(types.Empty):
		label = "!= empty"
	default:
		label = "?= empty"
	}

	_, err := listResource(c, typ)
	if err != nil {
		// not a list resource, we do the simple empty comparison
		c.addChunk(&llx.Chunk{
			Call: llx.Chunk_FUNCTION,
			Id:   id,
			Function: &llx.Function{
				Type:    string(types.Bool),
				Binding: ref,
				Args: []*llx.Primitive{
					{
						Type: string(types.Empty),
					},
				},
			},
		})
		checksum := c.Result.CodeV2.Checksums[c.tailRef()]
		c.Result.Labels.Labels[checksum] = label
		return types.Bool, nil
	}

	t, err := compileResourceDefault(c, typ, ref, "list", nil)
	if err != nil {
		return t, err
	}
	listRef := c.tailRef()

	c.addChunk(&llx.Chunk{
		Call: llx.Chunk_FUNCTION,
		Id:   id,
		Function: &llx.Function{
			Type:    string(types.Bool),
			Binding: listRef,
			Args: []*llx.Primitive{
				{
					Type: string(types.Empty),
				},
			},
		},
	})

	checksum := c.Result.CodeV2.Checksums[c.tailRef()]
	c.Result.Labels.Labels[checksum] = label

	return types.Bool, nil
}
