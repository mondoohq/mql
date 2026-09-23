// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"math/rand"
	"strconv"
	"strings"

	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

var arrayBlockType = types.Array(types.Block)

// arrayFunctions are all the handlers for builtin array methods
var arrayFunctions map[string]chunkHandlerV2 //nolint:unused

func arrayGetFirstIndexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type[1:]}, 0, nil
	}

	arr, ok := bind.Value.([]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into array")
	}

	if len(arr) == 0 {
		return &RawData{Type: bind.Type[1:]}, 0, nil
	}

	return &RawData{
		Type:  bind.Type[1:],
		Value: arr[0],
	}, 0, nil
}

func arrayGetLastIndexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type[1:]}, 0, nil
	}

	arr, ok := bind.Value.([]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into array")
	}

	if len(arr) == 0 {
		return &RawData{Type: bind.Type[1:]}, 0, nil
	}

	return &RawData{
		Type:  bind.Type[1:],
		Value: arr[len(arr)-1],
	}, 0, nil
}

func arrayGetIndexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type[1:]}, 0, nil
	}

	args := chunk.Function.Args
	// TODO: all this needs to go into the compile phase
	if len(args) < 1 {
		return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	if len(args) > 1 {
		return nil, 0, errors.New("called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	t := types.Type(args[0].Type)
	if t != types.Int {
		return nil, 0, errors.New("called [] with wrong type " + t.Label())
	}
	// ^^ TODO

	key := int(bytes2int(args[0].Value))

	arr, ok := bind.Value.([]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into array")
	}

	if key < 0 {
		if -key > len(arr) {
			return nil, 0, errors.New("array index out of bound (trying to access element " + strconv.Itoa(key) + ", max: " + strconv.Itoa(len(arr)-1) + ")")
		}
		key = len(arr) + key
	}
	if key >= len(arr) {
		return nil, 0, errors.New("array index out of bound (trying to access element " + strconv.Itoa(key) + ", max: " + strconv.Itoa(len(arr)-1) + ")")
	}

	return &RawData{
		Type:  bind.Type[1:],
		Value: arr[key],
	}, 0, nil
}

func arrayBlockListV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type[1:]}, 0, nil
	}

	arr, ok := bind.Value.([]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into array")
	}

	if len(arr) == 0 {
		return &RawData{
			Type:  arrayBlockType,
			Value: []any{},
		}, 0, nil
	}

	prim := chunk.Function.Args[0]
	if !types.Type(prim.Type).IsFunction() {
		return nil, 0, errors.New("called block with wrong function type")
	}
	fref, ok := prim.RefV2()
	if !ok {
		return nil, 0, errors.New("cannot retrieve function reference on block call")
	}
	block := e.ctx.code.Block(fref)
	if block == nil {
		return nil, 0, errors.New("block function is nil")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[1:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	argList := make([][]*RawData, len(arr))
	for i := range arr {
		argList[i] = []*RawData{
			{
				Type:  bind.Type.Child(),
				Value: arr[i],
			},
		}
	}

	err = e.runFunctionBlocks(argList, fref, ref, func(results []arrayBlockCallResult, errs []error) {
		// This is quite heavy handed. If any of the block calls have an error, the whole
		// thing becomes errored. If we don't do this, then we can have more fine grained
		// errors. For example, if only one item in the list has errors, the block for that
		// item will have an entrypoint with an error
		var anyError multierr.Errors
		anyError.Add(errs...)

		allResults := make([]any, len(arr))
		for i, rd := range results {
			allResults[i] = rd.toRawData().Value
		}

		data := &RawData{
			Type:  arrayBlockType,
			Value: allResults,
			Error: anyError.Deduplicate(),
		}
		e.cache.Store(ref, &stepCache{
			Result:   data,
			IsStatic: true,
		})
		e.triggerChain(ref, data)
	})
	if err != nil {
		return nil, 0, err
	}

	return nil, 0, nil
}

func arrayBlockV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	prim := chunk.Function.Args[0]
	if !types.Type(prim.Type).IsFunction() {
		return nil, 0, errors.New("called block with wrong function type")
	}
	return e.runBlock(bind, prim, chunk.Function.Args[1:], ref)
}

func arrayLengthV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int, Error: bind.Error}, 0, nil
	}

	arr, ok := bind.Value.([]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into array")
	}
	return IntData(int64(len(arr))), 0, nil
}

func arrayNotEmptyV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}

	arr, ok := bind.Value.([]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into array")
	}

	if len(arr) == 0 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func _arrayWhereV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, invert bool) (*RawData, uint64, error) {
	// where(array, function)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: items.Type}, 0, nil
	}

	list := items.Value.([]any)
	if len(list) == 0 {
		return items, 0, nil
	}

	arg1 := chunk.Function.Args[1]
	if types.Type(arg1.Type).Underlying() != types.FunctionLike {
		right := arg1.RawData().Value
		res := make([]any, 0)
		for i := range list {
			left := list[i]
			if left == right {
				res = append(res, left)
			}
		}

		return &RawData{
			Type:  items.Type,
			Value: res,
		}, 0, nil
	}

	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'where' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	ct := items.Type.Child()

	argsList := make([][]*RawData, len(list))
	for i := range list {
		argsList[i] = []*RawData{
			{
				Type:  ct,
				Value: list[i],
			},
		}
	}
	err = e.runFunctionBlocks(argsList, fref, ref, func(results []arrayBlockCallResult, errors []error) {
		resList := []any{}
		for i, res := range results {
			isTruthy := res.isTruthy()
			if isTruthy == !invert {
				resList = append(resList, list[i])
			}
		}

		data := &RawData{
			Type:  bind.Type,
			Value: resList,
		}
		e.cache.Store(ref, &stepCache{
			Result:   data,
			IsStatic: false,
		})
		e.triggerChain(ref, data)
	})
	if err != nil {
		return nil, 0, err
	}

	return nil, 0, nil
}

func arrayWhereV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _arrayWhereV2(e, bind, chunk, ref, false)
}

func arrayWhereNotV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _arrayWhereV2(e, bind, chunk, ref, true)
}

func _arraySample(array []any, cnt int64) []any {
	res := make([]any, 0)
	// Note: we still go through the list, even if more items are requested than the list contains.
	// In that case we only return what we have, but in random order.
	for i := 0; i < int(cnt) && len(array) > 0; i++ {
		candidate := rand.Intn(len(array))
		res = append(res, array[candidate])
		// TODO: this approach can be heavily optimized, instead of stitching the slice together over again...
		array = append(array[0:candidate], array[candidate+1:]...)
	}
	return res
}

func arraySample(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return NilData, 0, nil
	}

	list, ok := bind.Value.([]any)
	if !ok {
		return nil, 0, errors.New("can't run sample on data, it's not a list")
	}

	cntRef := chunk.Function.Args[0]
	cntRaw, rref, err := e.resolveValue(cntRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}
	cnt, ok := cntRaw.Value.(int64)
	if !ok {
		return nil, 0, errors.New("failed to get count for sample, incorrect type of value")
	}

	res := _arraySample(list, cnt)
	return ArrayData(res, bind.Type.Child()), 0, nil
}

func arrayAllV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// A null receiver (e.g. a missing map key resolving to a typed null
		// array, like secpol.privilegerights["SeMissing"]) propagates as a
		// null bool rather than erroring. The check then resolves to a clean
		// pass/fail instead of crashing the whole scan with an error. This
		// mirrors the dict variants (dictAllV2 etc.) and arrayLengthV2, which
		// already null-propagate. A genuine upstream error is preserved.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.([]any)

	if len(filteredList) != 0 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func arrayNoneV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// See arrayAllV2: a null receiver propagates as a null bool so the
		// check fails cleanly instead of erroring the whole scan.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.([]any)

	if len(filteredList) != 0 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func arrayAnyV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// See arrayAllV2: a null receiver propagates as a null bool so the
		// check fails cleanly instead of erroring the whole scan.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.([]any)

	if len(filteredList) == 0 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func arrayOneV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// See arrayAllV2: a null receiver propagates as a null bool so the
		// check fails cleanly instead of erroring the whole scan.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.([]any)

	if len(filteredList) != 1 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func arrayMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// map(array, function)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: types.Type(chunk.Function.Type)}, 0, nil
	}

	list := items.Value.([]any)
	if len(list) == 0 {
		// Note: We have to set the type to be the child taype here. The array is
		// now technically an any-typed, i.e. it cannot just be cast into a
		// []T if that is requested down the line. Without carrying types around,
		// we won't be able to do that easily.
		return &RawData{Type: types.Type(chunk.Function.Type), Value: []any{}}, 0, nil
	}

	arg1 := chunk.Function.Args[1]
	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'map' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	ct := items.Type.Child()

	argsList := make([][]*RawData, len(list))
	for i := range list {
		argsList[i] = []*RawData{
			{
				Type:  ct,
				Value: list[i],
			},
		}
	}

	err = e.runFunctionBlocks(argsList, fref, ref, func(results []arrayBlockCallResult, errs []error) {
		var anyError multierr.Errors
		anyError.Add(errs...)

		mappedType := types.Unset
		resList := []any{}
		f := e.ctx.code.Block(fref)

		epChecksum := e.ctx.code.Checksums[f.Entrypoints[0]]

		for _, res := range results {
			if epValIface, ok := res.entrypoints[epChecksum]; ok {
				epVal := epValIface.(*RawData)
				mappedType = epVal.Type
				resList = append(resList, epVal.Value)
			}
		}

		data := &RawData{
			Type:  types.Array(mappedType),
			Value: resList,
			Error: anyError.Deduplicate(),
		}
		e.cache.Store(ref, &stepCache{
			Result:   data,
			IsStatic: false,
		})
		e.triggerChain(ref, data)
	})
	if err != nil {
		return nil, 0, err
	}

	return nil, 0, nil
}

func flatten(v any) []any {
	list, ok := v.([]any)
	if !ok {
		return []any{v}
	}

	res := make([]any, 0)
	for i := range list {
		res = append(res, flatten(list[i])...)
	}
	return res
}

func arrayFlat(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	list, ok := bind.Value.([]any)
	// this should not happen at this point
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("incorrect type, no array data found")}, 0, nil
	}

	res := make([]any, 0)
	for i := range list {
		res = append(res, flatten(list[i])...)
	}

	typ := bind.Type
	for typ.IsArray() {
		typ = typ.Child()
		if typ.NotSet() {
			typ = types.Any
			break
		}
	}

	return &RawData{Type: types.Array(typ), Value: res}, 0, nil
}

func arrayReverse(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	list, ok := bind.Value.([]any)
	// this should not happen at this point
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("incorrect type, no array data found")}, 0, nil
	}

	res := make([]any, len(list))
	for i := range list {
		res[len(res)-1-i] = list[i]
	}

	return &RawData{Type: bind.Type, Value: res}, 0, nil
}

func arrayJoin(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.String, Error: bind.Error}, 0, nil
	}

	list, ok := bind.Value.([]any)
	// this should not happen at this point
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("incorrect type, no array data found")}, 0, nil
	}

	if len(list) == 0 {
		return StringData(""), 0, nil
	}

	var sep string
	if len(chunk.Function.Args) == 1 {
		item, rref, err := e.resolveValue(chunk.Function.Args[0], ref)
		if err != nil || rref > 0 {
			return nil, rref, err
		}
		sep, ok = item.Value.(string)
		if !ok {
			return nil, rref, errors.New("separator provided to join() must be a string")
		}
	}

	typHint := types.Any
	if bind.Type.IsArray() {
		typHint = bind.Type.Child()
	}

	var res strings.Builder
	for i := range list {
		if sep != "" && i > 0 {
			res.WriteString(sep)
		}
		res.WriteString(StringifyValue(list[i], typHint))
	}

	return &RawData{Type: types.String, Value: res.String()}, 0, nil
}

// Take an array and separate it into a list of unique entries and another
// list of only duplicates. The latter list only has every entry appear only
// once.
func detectDupes(array any, typ types.Type) ([]any, []any, error) {
	if array == nil {
		return nil, nil, nil
	}
	arr, ok := array.([]any)
	if !ok {
		return nil, nil, errors.New("failed to typecast " + typ.Label() + " into array")
	}

	ct := typ.Child()
	equalFunc, ok := types.Equal[ct]
	if !ok {
		return nil, nil, errors.New("cannot extract duplicates from array, must be a basic type, try using a field argument")
	}

	existing := []any{}
	duplicates := []any{}
	var found bool
	for i := 0; i < len(arr); i++ {
		left := arr[i]

		for j := range existing {
			if equalFunc(left, existing[j]) {
				found = true
				break
			}
		}

		if !found {
			existing = append(existing, left)
			continue
		}

		found = false
		for j := range duplicates {
			if equalFunc(left, duplicates[j]) {
				found = true
				break
			}
		}

		if found {
			found = false
		} else {
			duplicates = append(duplicates, left)
		}
	}

	return existing, duplicates, nil
}

// Takes an array of resources and a field, identify duplicates of that field value
// Result list is every resource that has duplicates
// (there will be at least resources 2 if there is a duplicate field value)
func arrayFieldDuplicatesV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// where(array, function)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: items.Type}, 0, nil
	}

	list := items.Value.([]any)
	if len(list) == 0 {
		return items, 0, nil
	}

	arg1 := chunk.Function.Args[1]
	if types.Type(arg1.Type).Underlying() != types.FunctionLike {
		return nil, 0, errors.New("Expected resource field, unable to get field value from " + types.Type(arg1.Type).Label())
	}

	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'field duplicates' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	ct := items.Type.Child()

	argsList := make([][]*RawData, len(list))
	for i := range list {
		argsList[i] = []*RawData{
			{
				Type:  ct,
				Value: list[i],
			},
		}
	}

	err = e.runFunctionBlocks(argsList, fref, ref, func(results []arrayBlockCallResult, errs []error) {
		f := e.ctx.code.Block(fref)
		epChecksum := e.ctx.code.Checksums[f.Entrypoints[0]]
		filteredList := map[int]*RawData{}

		for i, res := range results {
			rd := res.toRawData()
			if rd.Error != nil {
				filteredList[i] = &RawData{
					Error: rd.Error,
				}
			} else {
				epVal := res.entrypoints[epChecksum].(*RawData)
				filteredList[i] = epVal
			}
		}

		resList := []any{}

		equalFunc, ok := types.Equal[filteredList[0].Type]
		if !ok {
			data := &RawData{
				Type:  items.Type,
				Error: errors.New("cannot extract duplicates from array, field must be a basic type"),
			}
			e.cache.Store(ref, &stepCache{
				Result:   data,
				IsStatic: false,
			})
			e.triggerChain(ref, data)
			return
		}

		arr := make([]*RawData, len(list))
		for k, v := range filteredList {
			arr[k] = v
		}

		// to track values of fields
		existing := make(map[int]any)
		// to track index of duplicate resources
		duplicateIndices := []int{}
		var found bool
		var added bool
		for i := 0; i < len(arr); i++ {
			left := arr[i].Value

			for j, v := range existing {
				if equalFunc(left, v) {
					found = true
					// Track the index so that we can get the whole resource
					duplicateIndices = append(duplicateIndices, i)
					// check if j was already added to our list of indices
					for di := range duplicateIndices {
						if j == duplicateIndices[di] {
							added = true
						}
					}
					if !added {
						duplicateIndices = append(duplicateIndices, j)
					}
					break
				}
			}

			// value not found so we add it to list of things to check for dupes
			if !found {
				existing[i] = left
			}
		}

		// Once we collect duplicate indices, make a list of resources
		for i := range duplicateIndices {
			idx := duplicateIndices[i]
			resList = append(resList, list[idx])
		}

		data := &RawData{
			Type:  bind.Type,
			Value: resList,
		}
		e.cache.Store(ref, &stepCache{
			Result:   data,
			IsStatic: false,
		})
		e.triggerChain(ref, data)
	})
	if err != nil {
		return nil, 0, err
	}

	return nil, 0, nil
}

func arrayDuplicatesV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	_, dupes, err := detectDupes(bind.Value, bind.Type)
	if err != nil {
		return nil, 0, err
	}

	return &RawData{Type: bind.Type, Value: dupes}, 0, nil
}

func arrayUniqueV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	unique, _, err := detectDupes(bind.Value, bind.Type)
	if err != nil {
		return nil, 0, err
	}

	return &RawData{Type: bind.Type, Value: unique}, 0, nil
}

func arrayDifferenceV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	args := chunk.Function.Args
	// TODO: all this needs to go into the compile phase
	if len(args) < 1 {
		return nil, 0, errors.New("Called `difference` with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	if len(args) > 1 {
		return nil, 0, errors.New("called `difference` with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	// ^^ TODO

	argRef := args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	// A null argument (e.g. a missing map key resolving to a typed null
	// array) propagates as null, mirroring the receiver-nil guard above.
	// Without this the `arg.Value.([]any)` assertion below panics, which
	// crashes the whole scan rather than failing the single check.
	if arg.Value == nil {
		return &RawData{Type: bind.Type, Error: arg.Error}, 0, nil
	}

	t := types.Type(arg.Type)
	if t != bind.Type {
		return nil, 0, errors.New("called `difference` with wrong type (got: " + t.Label() + ", expected:" + bind.Type.Label() + ")")
	}

	ct := bind.Type.Child()
	equalFunc, ok := types.Equal[ct]
	if !ok {
		return nil, 0, errors.New("cannot compare array entries")
	}

	org := bind.Value.([]any)
	filters := arg.Value.([]any)

	res := make([]any, 0)
	var skip bool
	for i := range org {
		skip = false
		for j := range filters {
			if equalFunc(org[i], filters[j]) {
				skip = true
				break
			}
		}

		if !skip {
			res = append(res, org[i])
		}
	}

	return &RawData{Type: bind.Type, Value: res}, 0, nil
}

func anyArrayInStringArray(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	anyArray := bind.Value.([]any)
	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	for b := range anyArray {
		binds, ok := anyArray[b].(string)
		if !ok {
			return BoolFalse, 0, nil
		}

		arr := arg.Value.([]any)
		found := false
		for i := range arr {
			v := arr[i].(string)
			if binds == v {
				found = true
				break
			}
		}
		if !found {
			return BoolFalse, 0, nil
		}
	}

	return BoolTrue, 0, nil
}

func anyArrayNotInStringArray(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// mildly inefficient, but reduces complexity
	res, ref, err := anyArrayInStringArray(e, bind, chunk, ref)
	if res == BoolTrue {
		return BoolFalse, ref, err
	}
	if res == BoolFalse {
		return BoolTrue, ref, err
	}
	return res, ref, err
}

func arrayContainsAll(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	args := chunk.Function.Args
	// TODO: all this needs to go into the compile phase
	if len(args) < 1 {
		return nil, 0, errors.New("Called `arrayContainsNone` with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	if len(args) > 1 {
		return nil, 0, errors.New("called `arrayContainsNone` with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	// ^^ TODO

	argRef := args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	// A null argument (e.g. a missing map key resolving to a typed null
	// array) propagates as null, mirroring the receiver-nil guard above.
	// Without this the `arg.Value.([]any)` assertion below panics, which
	// crashes the whole scan rather than failing the single check.
	if arg.Value == nil {
		return &RawData{Type: bind.Type, Error: arg.Error}, 0, nil
	}

	t := types.Type(arg.Type)
	if t != bind.Type {
		return nil, 0, errors.New("called `arrayNone` with wrong type (got: " + t.Label() + ", expected:" + bind.Type.Label() + ")")
	}

	ct := bind.Type.Child()
	equalFunc, ok := types.Equal[ct]
	if !ok {
		return nil, 0, errors.New("cannot compare array entries")
	}

	org := bind.Value.([]any)
	argFilters := arg.Value.([]any)
	filters := make([]any, len(argFilters))
	copy(filters, argFilters)

	for i := range org {
		for j := range filters {
			if equalFunc(org[i], filters[j]) {
				filters = append(filters[0:j], filters[j+1:]...)
				break
			}
		}
		if len(filters) == 0 {
			filters = nil
			break
		}
	}

	return &RawData{Type: bind.Type, Value: filters}, 0, nil
}

func arrayContainsNone(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type, Error: bind.Error}, 0, nil
	}

	args := chunk.Function.Args
	// TODO: all this needs to go into the compile phase
	if len(args) < 1 {
		return nil, 0, errors.New("Called `arrayContainsNone` with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	if len(args) > 1 {
		return nil, 0, errors.New("called `arrayContainsNone` with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	// ^^ TODO

	argRef := args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	// A null argument (e.g. a missing map key resolving to a typed null
	// array) propagates as null, mirroring the receiver-nil guard above.
	// Without this the `arg.Value.([]any)` assertion below panics, which
	// crashes the whole scan rather than failing the single check.
	if arg.Value == nil {
		return &RawData{Type: bind.Type, Error: arg.Error}, 0, nil
	}

	t := types.Type(arg.Type)
	if t != bind.Type {
		return nil, 0, errors.New("called `arrayNone` with wrong type (got: " + t.Label() + ", expected:" + bind.Type.Label() + ")")
	}

	ct := bind.Type.Child()
	equalFunc, ok := types.Equal[ct]
	if !ok {
		return nil, 0, errors.New("cannot compare array entries")
	}

	org := bind.Value.([]any)
	filters := arg.Value.([]any)

	res := make([]any, 0)
	for i := range org {
		for j := range filters {
			if equalFunc(org[i], filters[j]) {
				res = append(res, org[i])
			}
		}
	}

	return &RawData{Type: bind.Type, Value: res}, 0, nil
}

func compileArrayOpArray(op string) func(types.Type, types.Type) (string, error) {
	return func(left types.Type, right types.Type) (string, error) {
		name := string(left.Child()) + op + string(right)
		af := BuiltinFunctionsV2[types.ArrayLike]
		if _, ok := af[name]; ok {
			return name, nil
		}

		if right.IsArray() {
			return op, nil
		}

		if right == types.Nil {
			return op + string(types.Nil), nil
		}

		return "", errors.New("don't know how to compile " + left.Label() + " " + op + " " + right.Label())
	}
}

func compileLogicalArrayOp(underlying types.Type, op string) func(types.Type, types.Type) (string, error) {
	return func(left types.Type, right types.Type) (string, error) {
		name := string(types.Any) + op + string(right.Underlying())
		af := BuiltinFunctionsV2[underlying]
		if _, ok := af[name]; ok {
			return name, nil
		}

		return "", errors.New("cannot find operation for " + left.Label() + " " + op + " " + right.Label())
	}
}

func cmpArrays(left *RawData, right *RawData, f func(any, any) bool) bool {
	if left.Value == nil {
		return right.Value == nil
	}
	if right == nil || right.Value == nil {
		return false
	}

	l := left.Value.([]any)
	r := right.Value.([]any)

	if len(l) != len(r) {
		return false
	}

	for i := range l {
		if !f(l[i], r[i]) {
			return false
		}
	}

	return true
}

func cmpArrayOne(leftArray *RawData, right *RawData, f func(any, any) bool) bool {
	if leftArray == nil || leftArray.Value == nil {
		return false
	}
	l, ok := leftArray.Value.([]any)
	if !ok || len(l) != 1 {
		return false
	}
	return f(l[0], right.Value)
}

// []T -- []T

func tArrayCmp(left *RawData, right *RawData) func(any, any) bool {
	return func(a any, b any) bool {
		if left.Type.Child() != right.Type.Child() {
			return false
		}
		return a == b
	}
}

func tarrayCmpTarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, tArrayCmp(left, right))
	})
}

func tarrayNotTarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, tArrayCmp(left, right))
	})
}

func tarrayConcatTarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	// Either side may be empty or null, and either side may be the one carrying
	// the element type, since `[]` resolves to []unset. Resolving the type from
	// both operands keeps the result usable regardless of operand order.
	resType := types.CoalesceArrays(bind.Type, items.Type)

	// A null operand contributes no items, the same as an empty one. Treating it
	// as empty keeps the other operand's items instead of discarding them or
	// failing the whole query.
	left, _ := bind.Value.([]any)
	right, _ := items.Value.([]any)

	res := make([]any, 0, len(left)+len(right))
	res = append(res, left...)
	res = append(res, right...)

	return &RawData{
		Type:  resType,
		Value: res,
	}, 0, nil
}

func tarrayDeleteTarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: items.Type}, 0, nil
	}

	v, _ := bind.Value.([]any)
	if v == nil {
		if items.Value == nil {
			return &RawData{Type: bind.Type}, 0, nil
		}
		return nil, 0, errors.New("cannot add arrays to null")
	}

	list := items.Value.([]any)
	if len(list) == 0 {
		return items, 0, nil
	}

	// TODO: We can optimize the way the deletion works, but need to map to
	// recognized types to do so. Common example: strings an numbers.

	res := []any{}
	for i := range v {
		found := false
		for j := range list {
			if v[i] == list[j] {
				found = true
				break
			}
		}

		if !found {
			res = append(res, v[i])
		}
	}

	return &RawData{
		Type:  bind.Type,
		Value: res,
	}, 0, nil
}

func boolarrayCmpBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opBoolCmpBool)
	})
}

func intarrayCmpIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opIntCmpInt)
	})
}

func floatarrayCmpFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opFloatCmpFloat)
	})
}

func stringarrayCmpStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opStringCmpString)
	})
}

func boolarrayNotBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opBoolCmpBool)
	})
}

func intarrayNotIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opIntCmpInt)
	})
}

func floatarrayNotFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opFloatCmpFloat)
	})
}

func stringarrayNotStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrays(left, right, opStringCmpString)
	})
}

// []T -- T

func arrayCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}
	v := bind.Value.([]any)
	if v == nil {
		return BoolTrue, 0, nil
	}
	return BoolFalse, 0, nil
}

func arrayNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	v := bind.Value.([]any)
	if v == nil {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func arrayCmpEmpty(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}
	v := bind.Value.([]any)
	if v == nil {
		return BoolTrue, 0, nil
	}
	return BoolData(len(v) == 0), 0, nil
}

func arrayNotEmpty(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	v := bind.Value.([]any)
	if v == nil {
		return BoolFalse, 0, nil
	}
	return BoolData(len(v) != 0), 0, nil
}

func boolarrayCmpBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opBoolCmpBool)
	})
}

func boolarrayNotBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opBoolCmpBool)
	})
}

func intarrayCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpInt)
	})
}

func intarrayNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpInt)
	})
}

func floatarrayCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpFloat)
	})
}

func floatarrayNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpFloat)
	})
}

func stringarrayCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpString)
	})
}

func stringarrayNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpString)
	})
}

// T -- []T

func boolCmpBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opBoolCmpBool)
	})
}

func boolNotBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opBoolCmpBool)
	})
}

func intCmpIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpInt)
	})
}

func intNotIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpInt)
	})
}

func floatCmpFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpFloat)
	})
}

func floatNotFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpFloat)
	})
}

func stringCmpStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpString)
	})
}

func stringNotStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpString)
	})
}

// int/float -- []T

func intCmpFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpInt)
	})
}

func intNotFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpInt)
	})
}

func floatCmpIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpFloat)
	})
}

func floatNotIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpFloat)
	})
}

func intarrayCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpFloat)
	})
}

func intarrayNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpFloat)
	})
}

func floatarrayCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpInt)
	})
}

func floatarrayNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpInt)
	})
}

// string -- []T

func stringCmpBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opBoolCmpString)
	})
}

func stringNotBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opBoolCmpString)
	})
}

func boolarrayCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opBoolCmpString)
	})
}

func boolarrayNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opBoolCmpString)
	})
}

func stringCmpIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpString)
	})
}

func stringNotIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpString)
	})
}

func intarrayCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpString)
	})
}

func intarrayNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpString)
	})
}

func stringCmpFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpString)
	})
}

func stringNotFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpString)
	})
}

func floatarrayCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpString)
	})
}

func floatarrayNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpString)
	})
}

// bool -- []string

func boolCmpStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpBool)
	})
}

func boolNotStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpBool)
	})
}

func stringarrayCmpBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpBool)
	})
}

func stringarrayNotBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpBool)
	})
}

// int -- []string

func intCmpStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpInt)
	})
}

func intNotStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpInt)
	})
}

func stringarrayCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpInt)
	})
}

func stringarrayNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpInt)
	})
}

// float -- []string

func floatCmpStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpFloat)
	})
}

func floatNotStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpFloat)
	})
}

func stringarrayCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpFloat)
	})
}

func stringarrayNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpFloat)
	})
}

// regex -- []T

func regexCmpStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpRegex)
	})
}

func regexNotStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opStringCmpRegex)
	})
}

func stringarrayCmpRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpRegex)
	})
}

func stringarrayNotRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opStringCmpRegex)
	})
}

func regexCmpIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpRegex)
	})
}

func regexNotIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opIntCmpRegex)
	})
}

func intarrayCmpRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpRegex)
	})
}

func intarrayNotRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opIntCmpRegex)
	})
}

func regexCmpFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpRegex)
	})
}

func regexNotFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(right, left, opFloatCmpRegex)
	})
}

func floatarrayCmpRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpRegex)
	})
}

func floatarrayNotRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, func(left *RawData, right *RawData) bool {
		return cmpArrayOne(left, right, opFloatCmpRegex)
	})
}
