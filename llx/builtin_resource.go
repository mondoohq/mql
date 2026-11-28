// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/timex"
	"google.golang.org/protobuf/proto"
)

type Resource interface {
	// Name of the resource
	MqlName() string
	// ID of this resource
	MqlID() string
}

type MockResource struct {
	Name string
	ID   string
}

func (m *MockResource) MqlName() string {
	return m.Name
}

func (m *MockResource) MqlID() string {
	return m.ID
}

// resourceFunctions are all the shared handlers for resource calls
var resourceFunctionsV2 map[string]chunkHandlerV2 //nolint:unused

func _resourceWhereV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, invert bool) (*RawData, uint64, error) {
	// where(resource.list, function)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}
	list, ok := items.Value.([]any)
	if !ok || len(list) == 0 {
		return bind, 0, nil
	}

	// Comma-ok, not a bare assertion: a panic in a builtin runs on an executor
	// goroutine and takes down the whole scan, not just this query. A null bind
	// reaches here whenever the list resolved but the resource behind it did not.
	resource, ok := bind.Value.(Resource)
	if !ok {
		return nil, 0, errors.New("cannot call 'where' on a non-resource value")
	}

	arg1 := chunk.Function.Args[1]
	blockRef, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'where' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	blockId := e.ctx.code.Id + strconv.FormatUint(blockRef>>32, 10)

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

	err = e.runFunctionBlocks(argsList, blockRef, ref, func(results []arrayBlockCallResult, errs []error) {
		resList := []*Primitive{}
		for i, res := range results {
			isTruthy := res.isTruthy()
			if isTruthy == !invert {
				prim := (&RawData{Value: list[i], Type: ct}).Result().Data
				resList = append(resList, prim)
			}
		}

		// get all mandatory args
		resourceInfo := e.ctx.runtime.Schema().Lookup(resource.MqlName())
		copyFields := []string{}
		for k, v := range resourceInfo.Fields {
			if k != "list" && v.IsMandatory {
				copyFields = append(copyFields, k)
			}
		}
		filtered := ArrayPrimitive(resList, ct)
		args := map[string]*Primitive{
			"list": filtered,
		}

		resResource, err := filterResultResource(e.ctx.runtime, resource, blockId, copyFields, args, filtered)

		var data *RawData
		if err != nil {
			data = &RawData{
				Error: errors.New("Failed to create filter result resource: " + err.Error()),
			}
			e.cache.Store(ref, &stepCache{
				Result: data,
			})
		} else {
			data = &RawData{
				Type:  bind.Type,
				Value: resResource,
			}
			e.cache.Store(ref, &stepCache{
				Result:   data,
				IsStatic: false,
			})
		}

		e.triggerChain(ref, data)
	})
	if err != nil {
		return nil, 0, err
	}

	return nil, 0, nil
}

// filterResultResource stores the result of a where/whereNot call as a clone
// of the filtered resource. The clone's id must name its content, not only the
// filter block: the same block runs once per element when it sits inside
// another block (`list { files.find(from: _).where(...) }`), and each run
// filters a different source or keeps different items. With an id shared by
// every run, each clone replaced the previous one in the provider, and any
// cached field of the first clone answered for all of them. So the id adds
// the source resource's id (the mandatory fields are copied from it) and a
// digest of the filtered list to the block id.
func filterResultResource(runtime Runtime, src Resource, blockId string, copyFields []string, args map[string]*Primitive, filtered *Primitive) (Resource, error) {
	listBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(filtered)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(src.MqlID()))
	h.Write([]byte{0})
	h.Write(listBytes)
	id := blockId + "/" + hex.EncodeToString(h.Sum(nil))

	return runtime.CloneResource(src, id, copyFields, args)
}

func resourceWhereV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _resourceWhereV2(e, bind, chunk, ref, false)
}

func resourceWhereNotV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _resourceWhereV2(e, bind, chunk, ref, true)
}

func resourceSample(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// sample(resource.list)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}
	list, ok := items.Value.([]any)
	if !ok || len(list) == 0 {
		return bind, 0, nil
	}

	cntRef := chunk.Function.Args[1]
	cntRaw, rref, err := e.resolveValue(cntRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}
	cnt, ok := cntRaw.Value.(int64)
	if !ok {
		return nil, 0, errors.New("failed to get count for sample, incorrect type of value")
	}

	res := _arraySample(list, cnt)
	return ArrayData(res, bind.Type), 0, nil
}

func resourceMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// map(resource.list, function)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}
	list, ok := items.Value.([]any)
	if !ok || len(list) == 0 {
		// When the input list is empty or not an array(e.g. embedding), return an empty array
		// so downstream array operations (e.g., $all) can execute without error.
		// It is an empty list of what the block gives, which the compiler
		// announced for this call: what follows is looked up by that type.
		typ := types.Array(types.Unset)
		if announced := types.Type(chunk.Function.Type); announced != "" && announced.IsArray() {
			typ = announced
		}
		return &RawData{Type: typ, Value: []any{}}, 0, nil
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
		}

		e.cache.Store(ref, &stepCache{
			Result: data,
		})

		e.triggerChain(ref, data)
	})
	if err != nil {
		return nil, 0, err
	}

	return nil, 0, nil
}

func resourceLengthV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// length(resource.list)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	list := items.Value.([]any)
	return IntData(int64(len(list))), 0, nil
}

func resourceDateV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	args, rref, err := primitive2array(e, ref, chunk.Function.Args)
	if err != nil || rref != 0 {
		return nil, rref, err
	}

	timestamp, ok := args[0].(string)
	if !ok {
		return nil, 0, errors.New("failed to parse time, timestamp needs to be a string")
	}

	var format string
	if len(args) >= 2 {
		format, ok = args[1].(string)
		if !ok {
			return nil, 0, errors.New("provided time format is not provided as string")
		}
		format = strings.ToLower(format)
	}

	res, err := timex.Parse(timestamp, format)
	if err != nil {
		return nil, 0, errors.New("failed to parse time: " + err.Error())
	}
	return TimeData(res), 0, nil
}

var durationRegex = regexp.MustCompile(`^(\d+|[.])(\w*)$`)

func resourceDuration(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	args, rref, err := primitive2array(e, ref, chunk.Function.Args)
	if err != nil || rref != 0 {
		return nil, rref, err
	}

	// Note: Using the regex is slower than parsing it step by step, so this code can be improved
	m := durationRegex.FindStringSubmatch(args[0].(string))
	if m == nil {
		return nil, 0, errors.New("failed to parse duration")
	}

	num, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return nil, 0, errors.New("failed to parse duration numeric value")
	}

	var t time.Time
	scalar := strings.ToLower(m[2])
	switch scalar {
	case "s", "", "sec", "second", "seconds":
		t = DurationToTime(int64(num))
	case "m", "min", "minute", "minutes":
		t = DurationToTime(int64(num * 60))
	case "h", "hour", "hours":
		t = DurationToTime(int64(num * 60 * 60))
	case "d", "day", "days":
		t = DurationToTime(int64(num * 60 * 60 * 24))
	case "y", "year", "years":
		t = DurationToTime(int64(num * 60 * 60 * 24 * 365))
	default:
		return nil, 0, errors.New("failed to parsee duration (only supports: s/m/h/d/y)")
	}

	return TimeData(t), 0, nil
}

// permissionBits are the bits file.permissions.mode carries: the nine
// rwx bits plus setuid, setgid and sticky.
const permissionBits = 0o7777

// permissionsAtMost reports whether mode sets no bit outside mask.
func permissionsAtMost(mode int64, mask int64) bool {
	return mode&permissionBits&^mask == 0
}

// permissionsAtLeast reports whether mode sets every bit of mask.
func permissionsAtLeast(mode int64, mask int64) bool {
	return mode&permissionBits&mask == mask
}

func filePermissionsAtMost(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return filePermissionsMask(e, chunk, ref, permissionsAtMost)
}

func filePermissionsAtLeast(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return filePermissionsMask(e, chunk, ref, permissionsAtLeast)
}

// filePermissionsMask evaluates a mask test against the mode the compiler
// passes as the first argument. A null mode (no file, or no permissions read)
// stays null, so the check fails instead of passing.
func filePermissionsMask(e *blockExecutor, chunk *Chunk, ref uint64, test func(mode int64, mask int64) bool) (*RawData, uint64, error) {
	if len(chunk.Function.Args) != 2 {
		return nil, 0, errors.New("file.permissions mask test needs the mode and a mask")
	}
	args, rref, err := primitive2array(e, ref, chunk.Function.Args)
	if err != nil || rref != 0 {
		return nil, rref, err
	}

	mask, ok := args[1].(int64)
	if !ok {
		return nil, 0, errors.New("file.permissions mask must be an int")
	}
	if mask < 0 || mask > permissionBits {
		return nil, 0, errors.New("file.permissions mask 0" + strconv.FormatInt(mask, 8) + " is outside the permission bits 0-07777")
	}

	mode, ok := args[0].(int64)
	if !ok {
		return &RawData{Type: types.Bool}, 0, nil
	}
	return BoolData(test(mode, mask)), 0, nil
}

// RuntimeBoundResource is a resource that names the runtime which answers its
// fields, instead of leaving that to the executor's own runtime.
//
// Everything in one asset's tree is answered by the runtime executing the
// query, so almost no resource needs this. A resource reached by resolving into
// *another* asset does (ADR 031): its fields live on that asset's runtime, and
// nothing else about it is special - blocks, `where`, labels and recording see
// an ordinary resource.
type RuntimeBoundResource interface {
	Resource
	// MqlRuntime returns the runtime that answers this resource's fields. A nil
	// return means the executor's own runtime, so a wrapper is never obliged to
	// have one.
	MqlRuntime() Runtime
}

// BoundResource pins a resource to the runtime that can answer it.
type BoundResource struct {
	Resource
	runtime Runtime
}

func (b *BoundResource) MqlRuntime() Runtime {
	return b.runtime
}

// BindResource pins a resource to a runtime, unwrapping any binding it already
// carries so the pin does not stack. Returns the resource untouched when there
// is no runtime to bind to.
func BindResource(resource Resource, runtime Runtime) Resource {
	if resource == nil || runtime == nil {
		return resource
	}
	if bound, ok := resource.(*BoundResource); ok {
		resource = bound.Resource
	}
	return &BoundResource{Resource: resource, runtime: runtime}
}

// bindResourceValues pins every resource in a field's value to runtime. A field
// read on a foreign asset can answer with a resource (or a list of them) that
// lives in that same foreign tree, and the next chunk in the chain binds to that
// value - so without this, a chain crosses into another asset and silently falls
// back to the local runtime one hop later.
func bindResourceValues(value any, runtime Runtime) any {
	if value == nil || runtime == nil {
		return value
	}
	switch v := value.(type) {
	case Resource:
		return BindResource(v, runtime)
	case []any:
		res := make([]any, len(v))
		for i := range v {
			res[i] = bindResourceValues(v[i], runtime)
		}
		return res
	case map[string]any:
		res := make(map[string]any, len(v))
		for k := range v {
			res[k] = bindResourceValues(v[k], runtime)
		}
		return res
	default:
		return value
	}
}
