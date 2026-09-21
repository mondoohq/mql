// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/types"
)

// mapFunctions are all the handlers for builtin array methods
var mapFunctions map[string]chunkHandlerV2 //nolint:unused

// errMissingKey reports a key lookup that named something the map does not
// contain. Only produced under strict mode; see ADR 043.
type errMissingKey struct {
	key string
}

func (e *errMissingKey) Error() string {
	return "cannot find key \"" + e.key + "\""
}

func (e *errMissingKey) Is(target error) bool { return target == ErrStrict }

// missingKey applies the strict-mode rule for a key that is not in the map.
//
// Absence is the one failure a map lookup has that a field access does not: a
// field is declared and always resolves, while naming a key is a claim that may
// simply be false. Under strict mode that claim is checked, which is what turns
// a mistyped `params.PermitRootLogn == "no"` into an error instead of a silent
// false. A key that is present but holds null does not come through here - that
// is a resolved value, and only dereferencing it errors.
func missingKey(chunk *Chunk, key string, typ types.Type) (*RawData, uint64, error) {
	switch chunk.Function.GetNullability() {
	case Function_NULLABILITY_REQUIRED:
		return nil, 0, &errMissingKey{key: key}
	case Function_NULLABILITY_OPTIONAL:
		return &RawData{Type: typ, ShortCircuited: true}, 0, nil
	default:
		return &RawData{Type: typ}, 0, nil
	}
}

// dictPathState is an in-progress walk towards a key that contains dots.
type dictPathState struct {
	root     map[string]any // container the walk is anchored at
	segments []string       // segments taken since
	anchor   *Chunk         // chunk that reports the absence if the walk ends empty
}

// maxDictPathProbes bounds one walk. The search is exponential in the worst
// case - keys "a", "a.a", "a.a.a" keep every prefix alive as a branch - and the
// documents walked are files read off the scanned host.
const maxDictPathProbes = 4096

// dictWalk reaches a key that itself contains dots.
//
// MQL compiles `params.a.b.c` into one lookup per segment, so a managed
// preferences plist - which keys its settings by preference domain - sends the
// chain walking a "com" that does not exist, and every profile-managed CIS
// macOS check read null. A lookup that misses therefore anchors a walk, and
// each later link retries the whole path from that anchor.
//
// It runs here rather than folding the path in mqlc because whether
// "com.apple.MCX" is one key or three is a fact about the document, not about
// the query; folding also mis-compiles a chain that leaves a dict for a map, a
// resource or a scalar. The bytecode is unchanged as a result, which cuts both
// ways: no checksum moves, but neither does anything announce that the same
// query id now answers differently.
//
// handled is false when there is nothing to walk and the caller does what it
// always did. A walk anchors where it first missed, not at the document root,
// so `{"com": {...}, "com.apple.x": 1}` still reads null for
// `params.com.apple.x` - as it does today.
func dictWalk(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, key string, typ types.Type) (*RawData, error, bool) {
	// Whether another key lookup is waiting to read this one. It decides all of:
	// whether a path is worth walking, whether a resolved value carries the walk
	// on, and whether an empty walk is over.
	continues := chainContinues(e, ref)

	if bind.dictPath == nil && !continues {
		return nil, nil, false
	}

	here, _ := bind.Value.(map[string]any)

	root, taken, anchor := here, []string(nil), chunk
	if bind.dictPath != nil {
		root, taken, anchor = bind.dictPath.root, bind.dictPath.segments, bind.dictPath.anchor
	}

	segments := make([]string, len(taken), len(taken)+1)
	copy(segments, taken)
	segments = append(segments, key)

	// The plain key wins wherever it is present, which keeps `params["a.b"]`
	// meaning the key spelled "a.b".
	if here != nil {
		if v, ok := here[key]; ok {
			return dictWalkValue(v, root, segments, anchor, continues, typ), nil, true
		}
	}

	probes := maxDictPathProbes
	v, found, reached := resolveDictPath(root, segments, &probes)
	switch {
	case found:
		return dictWalkValue(v, root, segments, anchor, continues, typ), nil, true
	case continues:
		return &RawData{Type: typ, dictPath: &dictPathState{root: root, segments: segments, anchor: anchor}}, nil, true
	}

	// Nothing answered and nothing follows, so the key is absent and says so as
	// it always did - reported against the chunk the walk started on, since a
	// `?` on the last link must not excuse a key missing at the first. Named for
	// the first segment no prefix reached, so a typo in the leaf of a domain
	// that did resolve is blamed on the leaf.
	name := segments[0]
	if reached > 0 && reached < len(segments) {
		name = segments[reached]
	}
	res, _, err := missingKey(anchor, name, typ)
	return res, err, true
}

// dictWalkValue wraps a resolved value, carrying the walk on only while another
// lookup is waiting to read it. A value that kept its anchor would answer by how
// it was reached: `params.a.b` in a block or a variable would go on resolving
// siblings of the document root that `params["a.b"]` does not hold and its own
// `keys` does not list. A key resolving to null holds a value, so reading
// through it stays a null dereference (ADR 043) and ends the walk too.
func dictWalkValue(v any, root map[string]any, segments []string, anchor *Chunk, continues bool, typ types.Type) *RawData {
	res := &RawData{Type: typ, Value: v}
	if v != nil && continues {
		res.dictPath = &dictPathState{root: root, segments: segments, anchor: anchor}
	}
	return res
}

// chainContinues reports whether the next chunk is another key lookup reading
// from this one - the only thing a partly-walked path needs to know, and
// something the compiled code already holds.
//
// Asking the document instead, by scanning its keys for one continuing the
// path, costs O(keys) per missed lookup (315us on a 50k-key document against
// 50ns for the miss) and, bounded to contain that, stops being deterministic:
// Go randomizes map iteration, so a partial scan answers from a different draw
// each run. Non-consecutive chunks fall through to false, which is what this
// answered before.
func chainContinues(e *blockExecutor, ref uint64) bool {
	if e == nil || e.block == nil {
		return false
	}

	// Refs count from one, so masking the block off indexes the next chunk.
	idx := int(ref & 0xFFFFFFFF)
	if idx <= 0 || idx >= len(e.block.Chunks) {
		return false
	}

	next := e.block.Chunks[idx]
	if next.Id != "[]" && next.Id != "[]?" {
		return false
	}
	f := next.Function
	return f != nil && f.Binding == ref &&
		len(f.Args) == 1 && types.Type(f.Args[0].Type) == types.String
}

// resolveDictPath walks segments through nested maps, shortest prefix first so
// that undotted documents resolve exactly as they always did.
//
// Backtracking is load-bearing: a managed plist holds "com.apple.MCX" beside
// "com.apple.MCX.FileVault2", so "com.apple.MCX.FileVault2.Enable" matches the
// shorter domain, finds no "FileVault2", and must come back for the longer one.
// The third return is how far the deepest prefix reached, for the diagnostic.
func resolveDictPath(container map[string]any, segments []string, probes *int) (any, bool, int) {
	deepest := 0

	for i := 1; i <= len(segments); i++ {
		if *probes <= 0 {
			return nil, false, deepest
		}
		*probes--

		v, present := container[strings.Join(segments[:i], ".")]
		if !present {
			continue
		}
		if i == len(segments) {
			return v, true, i
		}

		child, ok := v.(map[string]any)
		if !ok {
			// A leaf with segments left is a dead end for this split, not an
			// answer; a longer prefix may still carry the rest.
			if i > deepest {
				deepest = i
			}
			continue
		}
		cv, ok, d := resolveDictPath(child, segments[i:], probes)
		if ok {
			return cv, true, i + d
		}
		if i+d > deepest {
			deepest = i + d
		}
	}

	return nil, false, deepest
}

func mapGetIndex(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	args := chunk.Function.Args
	// TODO: all this needs to go into the compile phase
	if len(args) < 1 {
		return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	if len(args) > 1 {
		return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	// ^^ TODO

	childType := bind.Type.Child()
	if bind.Value == nil && bind.dictPath == nil {
		// Propagate null through map access chains instead of erroring.
		return &RawData{Type: childType}, 0, nil
	}

	var key string
	t := types.Type(args[0].Type)
	switch t {
	case types.Ref:
		// resolve ref
		argRaw, rref, err := e.resolveValue(args[0], ref)
		if err != nil || rref > 0 {
			return nil, rref, err
		}
		t = argRaw.Type
		if t != types.String {
			return nil, 0, errors.New("Called [] with wrong type " + t.Label())
		}
		key = argRaw.Value.(string)
	case types.String:
		key = string(args[0].Value)
	default:
		return nil, 0, errors.New("Called [] with wrong type " + t.Label())
	}

	// See dictGetIndex: a walk already under way reads through its own nulls.
	if bind.dictPath != nil {
		if res, err, handled := dictWalk(e, bind, chunk, ref, key, childType); handled {
			return res, 0, err
		}
	}

	m, ok := bind.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into map")
	}
	v, present := m[key]
	if !present {
		// `macos.userPreferences` is keyed by preference domain, so every one of
		// its keys is dotted; a chain over it has to be able to walk.
		if res, err, handled := dictWalk(e, bind, chunk, ref, key, childType); handled {
			return res, 0, err
		}
		return missingKey(chunk, key, childType)
	}
	return &RawData{
		Type:  childType,
		Value: v,
	}, 0, nil
}

func mapCmpNil(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}
	v, ok := bind.Value.(map[string]any)
	if !ok || v == nil {
		return BoolTrue, 0, nil
	}
	return BoolFalse, 0, nil
}

func mapNotNil(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	v, ok := bind.Value.(map[string]any)
	if !ok || v == nil {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func mapCmpEmpty(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}
	v, ok := bind.Value.(map[string]any)
	if !ok || v == nil {
		return BoolTrue, 0, nil
	}
	return BoolData(len(v) == 0), 0, nil
}

func mapNotEmpty(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	v, ok := bind.Value.(map[string]any)
	if !ok || v == nil {
		return BoolFalse, 0, nil
	}
	return BoolData(len(v) != 0), 0, nil
}

func mapLengthV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: types.Int}, 0, nil
	}

	arr, ok := bind.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into map")
	}
	return IntData(int64(len(arr))), 0, nil
}

func _mapWhereV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, invert bool) (*RawData, uint64, error) {
	// where(array, function)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: items.Type}, 0, nil
	}

	list := items.Value.(map[string]any)
	if len(list) == 0 {
		return items, 0, nil
	}

	arg1 := chunk.Function.Args[1]
	if types.Type(arg1.Type).Underlying() != types.FunctionLike {
		return nil, 0, errors.New("cannot call 'where' on a map without a filter function")
	}

	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'where' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	valueType := items.Type.Child()

	argsList := make([][]*RawData, len(list))
	i := 0
	for key, value := range list {
		argsList[i] = []*RawData{
			{
				Type:  types.String,
				Value: key,
			},
			{
				Type:  valueType,
				Value: value,
			},
		}
		i++
	}

	err = e.runFunctionBlocks(argsList, fref, func(results []arrayBlockCallResult, errs []error) {
		resMap := map[string]any{}
		for i, res := range results {
			if res.isTruthy() == !invert {
				key := argsList[i][0].Value.(string)
				resMap[key] = list[key]
			}
		}
		data := &RawData{
			Type:  bind.Type,
			Value: resMap,
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

func mapWhereV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _mapWhereV2(e, bind, chunk, ref, false)
}

func mapWhereNotV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _mapWhereV2(e, bind, chunk, ref, true)
}

func _mapSample(bmap map[string]any, cnt int64) map[string]any {
	keys := make([]string, len(bmap))
	i := 0
	for k := range bmap {
		keys[i] = k
		i++
	}

	res := make(map[string]any, cnt)
	// Note: we still go through the list, even if more items are requested than the list contains.
	// In that case we only return what we have, but in random order.
	for i := 0; i < int(cnt) && len(keys) > 0; i++ {
		candidate := rand.Intn(len(keys))
		key := keys[candidate]
		res[key] = bmap[key]
		keys = append(keys[0:candidate], keys[candidate+1:]...)
	}
	return res
}

func mapSample(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return NilData, 0, nil
	}

	bmap, ok := bind.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("can't run sample on data, it's not a map")
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

	res := _mapSample(bmap, cnt)
	return MapData(res, bind.Type.Child()), 0, nil
}

func mapAll(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// A null receiver propagates as a null bool so the check fails cleanly
		// instead of erroring the whole scan. Matches the array variants
		// (arrayAllV2 etc.) and the dict variants (dictAllV2 etc.). A genuine
		// upstream error is preserved.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.(map[string]any)

	if len(filteredList) != 0 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func mapNone(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// See mapAll: a null receiver propagates as a null bool so the check
		// fails cleanly instead of erroring the whole scan.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.(map[string]any)

	if len(filteredList) != 0 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func mapAny(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// See mapAll: a null receiver propagates as a null bool so the check
		// fails cleanly instead of erroring the whole scan.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.(map[string]any)

	if len(filteredList) == 0 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func mapOne(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// See mapAll: a null receiver propagates as a null bool so the check
		// fails cleanly instead of erroring the whole scan.
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	filteredList := bind.Value.(map[string]any)

	if len(filteredList) != 1 {
		return BoolFalse, 0, nil
	}
	return BoolTrue, 0, nil
}

func mapBlockCallV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return e.runBlock(bind, chunk.Function.Args[0], nil, ref)
}

func mapKeysV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{
			Type:  types.Array(types.Dict),
			Error: errors.New("failed to get keys of `null`"),
		}, 0, nil
	}

	m, ok := bind.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into map")
	}

	res := make([]any, len(m))
	var i int
	for key := range m {
		res[i] = key
		i++
	}

	return ArrayData(res, types.String), 0, nil
}

func mapValuesV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	typ := bind.Type.Child()

	if bind.Value == nil {
		return &RawData{
			Type:  types.Array(typ),
			Error: errors.New("failed to get values of `null`"),
		}, 0, nil
	}

	m, ok := bind.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("failed to typecast " + bind.Type.Label() + " into map")
	}

	res := make([]any, len(m))
	var i int
	for _, value := range m {
		res[i] = value
		i++
	}

	return ArrayData(res, typ), 0, nil
}

func dictGetIndex(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	args := chunk.Function.Args
	// TODO: all this needs to go into the compile phase
	if len(args) < 1 {
		return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}
	if len(args) > 1 {
		return nil, 0, errors.New("Called [] with " + strconv.Itoa(len(args)) + " arguments, only 1 supported.")
	}

	// A walk already under way is consulted before the type switch, because its
	// intermediate segments have no value to switch on - they are the nulls that
	// the missing "com" and "com.apple" produce on the way to
	// "com.apple.security.firewall". A chain that is not walking never gets
	// here, so the ordinary lookup below is untouched.
	if bind.dictPath != nil && types.Type(args[0].Type) == types.String {
		if res, err, handled := dictWalk(e, bind, chunk, ref, string(args[0].Value), bind.Type); handled {
			return res, 0, err
		}
	}

	if bind.Value == nil {
		// Propagate null through dict access chains instead of erroring.
		// This enables expressions like dict['a']['b'] to evaluate to null
		// when dict['a'] is nil, rather than failing with a runtime error.
		return &RawData{Type: bind.Type}, 0, nil
	}

	switch x := bind.Value.(type) {
	case []any:
		t := types.Type(args[0].Type)
		if t != types.Int {
			return nil, 0, errors.New("Called [] with wrong type " + t.Label())
		}

		key := int(bytes2int(args[0].Value))
		if key < 0 {
			if -key > len(x) {
				return nil, 0, errors.New("array index out of bound (trying to access element " + strconv.Itoa(key) + ", max: " + strconv.Itoa(len(x)-1) + ")")
			}
			key = len(x) + key
		}
		if key >= len(x) {
			return nil, 0, errors.New("array index out of bound (trying to access element " + strconv.Itoa(key) + ", max: " + strconv.Itoa(len(x)-1) + ")")
		}
		return &RawData{
			Value: x[key],
			Type:  bind.Type,
		}, 0, nil

	case map[string]any:
		t := types.Type(args[0].Type)
		if t != types.String {
			return nil, 0, errors.New("Called [] with wrong type " + t.Label())
		}
		// ^^ TODO

		key := string(args[0].Value)
		v, present := x[key]
		if !present {
			// Only now, once the key has genuinely missed, is it worth asking
			// whether a dotted key spells the path this chain is walking.
			if res, err, handled := dictWalk(e, bind, chunk, ref, key, bind.Type); handled {
				return res, 0, err
			}
			return missingKey(chunk, key, bind.Type)
		}
		return &RawData{
			Value: v,
			Type:  bind.Type,
		}, 0, nil

	default:
		return nil, 0, errors.New("dict value does not support accessor `[]`")
	}
}

func dictGetFirstIndexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	switch x := bind.Value.(type) {
	case []any:
		if len(x) == 0 {
			return &RawData{Type: bind.Type}, 0, nil
		}

		return &RawData{
			Value: x[0],
			Type:  bind.Type,
		}, 0, nil

	case map[string]any:
		if len(x) == 0 {
			return &RawData{Type: bind.Type}, 0, nil
		}

		var firstKey string
		for k := range x {
			firstKey = k
			break
		}
		for k := range x {
			if k < firstKey {
				firstKey = k
			}
		}

		return &RawData{
			Value: x[firstKey],
			Type:  bind.Type,
		}, 0, nil
	default:
		return &RawData{Type: bind.Type}, 0, nil
	}
}

func dictGetLastIndexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	switch x := bind.Value.(type) {
	case []any:
		if len(x) == 0 {
			return &RawData{Type: bind.Type}, 0, nil
		}

		return &RawData{
			Value: x[len(x)-1],
			Type:  bind.Type,
		}, 0, nil

	case map[string]any:
		if len(x) == 0 {
			return &RawData{Type: bind.Type}, 0, nil
		}

		var lastKey string
		for k := range x {
			lastKey = k
			break
		}
		for k := range x {
			if lastKey < k {
				lastKey = k
			}
		}

		return &RawData{
			Value: x[lastKey],
			Type:  bind.Type,
		}, 0, nil
	default:
		return &RawData{Type: bind.Type}, 0, nil
	}
}

func dictLengthV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{Type: bind.Type}, 0, nil
	}

	switch x := bind.Value.(type) {
	case string:
		return IntData(int64(len(x))), 0, nil
	case []any:
		return IntData(int64(len(x))), 0, nil
	case map[string]any:
		return IntData(int64(len(x))), 0, nil
	default:
		return nil, 0, errors.New("dict value does not support `length`")
	}
}

func dictInRange(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}

	switch v := bind.Value.(type) {
	case int64:
		return int64InRange(e, v, chunk, ref)
	case float64:
		return float64InRange(e, v, chunk, ref)
	case string:
		return stringInRange(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support `inRange`")
	}
}

func dictCmpEmpty(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}

	switch x := bind.Value.(type) {
	case string:
		return BoolData(len(x) == 0), 0, nil
	case []any:
		return BoolData(len(x) == 0), 0, nil
	case map[string]any:
		return BoolData(len(x) == 0), 0, nil
	default:
		return BoolFalse, 0, nil
	}
}

func dictNotEmpty(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}

	switch x := bind.Value.(type) {
	case string:
		return BoolData(len(x) != 0), 0, nil
	case []any:
		return BoolData(len(x) != 0), 0, nil
	case map[string]any:
		return BoolData(len(x) != 0), 0, nil
	default:
		return BoolTrue, 0, nil
	}
}

func dictBlockCallV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	switch bind.Value.(type) {
	case []any:
		return arrayBlockListV2(e, bind, chunk, ref)
	default:
		return e.runBlock(bind, chunk.Function.Args[0], chunk.Function.Args[1:], ref)
	}
}

func dictCamelcaseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `camelcase`")
	}

	return stringCamelcaseV2(e, bind, chunk, ref)
}

func dictDowncaseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `downcase`")
	}

	return stringDowncaseV2(e, bind, chunk, ref)
}

func dictUpcaseV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `upcase`")
	}

	return stringUpcaseV2(e, bind, chunk, ref)
}

func dictLinesV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `lines`")
	}

	return stringLinesV2(e, bind, chunk, ref)
}

func dictSplitV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `split`")
	}

	return stringSplitV2(e, bind, chunk, ref)
}

func dictTrimV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `trim`")
	}

	return stringTrimV2(e, bind, chunk, ref)
}

func dictJsonV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// Unlike the other string-ish dict builtins this returns null for a null
	// bind rather than erroring. The values it is aimed at are optional
	// resource attributes, and an absent one has to stay null so the
	// surrounding `== empty` guard can see it.
	if bind.Value == nil {
		return &RawData{Type: types.Dict}, 0, nil
	}

	_, ok := bind.Value.(string)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `json`")
	}

	return stringJsonV2(e, bind, chunk, ref)
}

func dictKeysV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{
			Type:  types.Array(types.Dict),
			Error: errors.New("failed to get keys of `null`"),
		}, 0, nil
	}

	m, ok := bind.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `keys`")
	}

	res := make([]any, len(m))
	var i int
	for key := range m {
		res[i] = key
		i++
	}

	return ArrayData(res, types.String), 0, nil
}

func dictValuesV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return &RawData{
			Type:  types.Array(types.Dict),
			Error: errors.New("failed to get values of `null`"),
		}, 0, nil
	}

	m, ok := bind.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("dict value does not support field `values`")
	}

	res := make([]any, len(m))
	var i int
	for _, value := range m {
		res[i] = value
		i++
	}

	return ArrayData(res, types.Dict), 0, nil
}

// Where blocks on strings try to see if the content is found inside the string.
// Due to the way the compiler behaves, if we check for static values, it is
// converted into a function:
//
//	"hello".contains("ll")  ==>  "hello".contains( _ == "ll" )
//
// ie: "hello".where("ll")     ==>  "hello".where(_ == "ll") = "ll"
//
// This means that we do not treat these operations the same we would for equality.
// This is why the operations need a bit of special handling, which is done
// inside this function.
func _stringWhere(e *blockExecutor, src string, chunk *Chunk, ref uint64, inverted bool) (*RawData, uint64, error) {
	arg1 := chunk.Function.Args[1]
	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'where' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	funBlock := e.ctx.code.Block(fref)
	if len(funBlock.Chunks) == 0 {
		return BoolFalse, 0, nil
	}

	var found *RawResult
	_ = e.runFunctionBlock([]*RawData{
		{Type: types.Nil, Value: nil},
		{Type: types.StringSlice, Value: src},
	}, fref, func(res *RawResult) {
		found = res
	})

	return found.Data, 0, nil
}

// requires at least 1 entry in the list!
func _dictArrayWhere(e *blockExecutor, list []any, chunk *Chunk, ref uint64, invert bool) (*RawData, uint64, error) {
	arg1 := chunk.Function.Args[1]
	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'where' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	argsList := make([][]*RawData, len(list))
	for i, value := range list {
		argsList[i] = []*RawData{
			{
				Type:  types.Dict,
				Value: i,
			},
			{
				Type:  types.Dict,
				Value: value,
			},
		}
	}

	err = e.runFunctionBlocks(argsList, fref, func(results []arrayBlockCallResult, errs []error) {
		resList := []any{}
		for i, res := range results {
			if res.isTruthy() == !invert {
				key := argsList[i][0].Value.(int)
				resList = append(resList, list[key])
			}
		}

		data := &RawData{
			Type:  types.Dict,
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

// Query a dict object, cycling over all child objects it contains with the given
// query function. This only works in cases where q query function makes sense,
// like:
// - [a, b, c].query( F )    = [a, b]
// - {a: b, c: d}.query( F ) = {a: b}
// Note: Results get stored in cache for this ref
func _dictWhere(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, invert bool) (*RawData, uint64, error) {
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: items.Type}, 0, nil
	}

	if s, ok := items.Value.(string); ok {
		return _stringWhere(e, s, chunk, ref, invert)
	}

	if list, ok := items.Value.([]any); ok {
		if len(list) == 0 {
			return items, 0, nil
		}
		return _dictArrayWhere(e, list, chunk, ref, invert)
	}

	list, ok := items.Value.(map[string]any)
	if !ok {
		return nil, 0, errors.New("failed to call dict.where on this value")
	}
	if len(list) == 0 {
		return items, 0, nil
	}

	arg1 := chunk.Function.Args[1]
	if types.Type(arg1.Type).Underlying() != types.FunctionLike {
		return nil, 0, errors.New("cannot call 'where' on a map without a filter function")
	}

	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference of 'where' call")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	valueType := items.Type.Child()

	argsList := make([][]*RawData, len(list))
	i := 0
	for key, value := range list {
		argsList[i] = []*RawData{
			{
				Type:  types.Dict,
				Value: key,
			},
			{
				Type:  valueType,
				Value: value,
			},
		}
		i++
	}

	err = e.runFunctionBlocks(argsList, fref, func(results []arrayBlockCallResult, errs []error) {
		resMap := map[string]any{}
		for i, res := range results {
			if res.isTruthy() == !invert {
				key := argsList[i][0].Value.(string)
				resMap[key] = list[key]
			}
		}
		data := &RawData{
			Type:  bind.Type,
			Value: resMap,
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

func dictWhere(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _dictWhere(e, bind, chunk, ref, false)
}

func dictWhereNot(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _dictWhere(e, bind, chunk, ref, true)
}

func dictSample(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return NilData, 0, nil
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

	var res any
	switch v := bind.Value.(type) {
	case []any:
		res = _arraySample(v, cnt)
	case map[string]any:
		res = _mapSample(v, cnt)
	default:
		return nil, 0, errors.New("failed to get sample, must be an array or map")
	}
	return DictData(res), 0, nil
}

func filterList(e *blockExecutor, list []any, chunk *Chunk, ref uint64, invert bool) ([]any, uint64, error) {
	arg1 := chunk.Function.Args[1]
	fref, ok := arg1.RefV2()
	if !ok {
		return nil, 0, errors.New("failed to retrieve function reference (in dict list query)")
	}

	dref, err := e.ensureArgsResolved(chunk.Function.Args[2:], ref)
	if dref != 0 || err != nil {
		return nil, dref, err
	}

	argsList := make([][]*RawData, len(list))
	for i, value := range list {
		argsList[i] = []*RawData{
			{
				Type:  types.Dict,
				Value: i,
			},
			{
				Type:  types.Dict,
				Value: value,
			},
		}
	}

	var res []any
	err = e.runFunctionBlocks(argsList, fref, func(results []arrayBlockCallResult, errs []error) {
		resList := []any{}
		for i, res := range results {
			if res.isTruthy() == !invert {
				key := argsList[i][0].Value.(int)
				resList = append(resList, list[key])
			}
		}
		res = resList
	})
	if err != nil {
		return nil, 0, err
	}

	return res, 0, nil
}

// The recurse function only works on lists and maps. It traverses child structures
// and finds any objects that match the given search function
func _dictRecurse(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64, invert bool) (*RawData, uint64, error) {
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: items.Type}, 0, nil
	}

	remaining := []any{items.Value}
	res := []any{}
	var candidate any
	for len(remaining) != 0 {
		candidate = remaining[0]
		remaining = remaining[1:]

		if candidate == nil {
			continue
		}

		var list []any
		if x, ok := candidate.([]any); ok {
			list = x
		} else if x, ok := candidate.(map[string]any); ok {
			list = make([]any, len(x))
			i := 0
			for _, v := range x {
				list[i] = v
				i++
			}
		}

		if len(list) == 0 {
			continue
		}

		partial, dref, err := filterList(e, list, chunk, ref, invert)
		if dref != 0 || err != nil {
			return nil, dref, err
		}
		res = append(res, partial...)

		// we only add items to the remaining, that actually match our type requirements
		// (this is trying to keep additional memory juggling to a minimum, instead
		// of doing this one level deeper)
		for i := range list {
			li := list[i]
			if x, ok := li.([]any); ok {
				remaining = append(remaining, x)
			} else if x, ok := li.(map[string]any); ok {
				remaining = append(remaining, x)
			}
		}
	}

	data := &RawData{
		Type:  types.Dict,
		Value: res,
	}
	e.cache.Store(ref, &stepCache{
		Result:   data,
		IsStatic: false,
	})

	return data, 0, nil
}

func dictRecurse(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return _dictRecurse(e, bind, chunk, ref, false)
}

func dictAllV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// Null receiver fails cleanly as a null bool; a genuine upstream error
		// is preserved (consistent with the array/map variants).
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	if filteredList, ok := bind.Value.([]any); ok {
		if len(filteredList) == 0 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	if filteredList, ok := bind.Value.(map[string]any); ok {
		if len(filteredList) == 0 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	return nil, 0, errors.New("failed to call dict assertion on a non-list/map value")
}

func dictNoneV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// Null receiver fails cleanly as a null bool; a genuine upstream error
		// is preserved (consistent with the array/map variants).
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	if filteredList, ok := bind.Value.([]any); ok {
		if len(filteredList) == 0 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	if filteredList, ok := bind.Value.(map[string]any); ok {
		if len(filteredList) == 0 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	return nil, 0, errors.New("failed to call dict assertion on a non-list/map value")
}

func dictAnyV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// Null receiver fails cleanly as a null bool; a genuine upstream error
		// is preserved (consistent with the array/map variants).
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	if filteredList, ok := bind.Value.([]any); ok {
		if len(filteredList) != 0 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	if filteredList, ok := bind.Value.(map[string]any); ok {
		if len(filteredList) != 0 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	return nil, 0, errors.New("failed to call dict assertion on a non-list/map value")
}

func dictOneV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		// Null receiver fails cleanly as a null bool; a genuine upstream error
		// is preserved (consistent with the array/map variants).
		return &RawData{Type: types.Bool, Error: bind.Error}, 0, nil
	}

	if filteredList, ok := bind.Value.([]any); ok {
		if len(filteredList) == 1 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	if filteredList, ok := bind.Value.(map[string]any); ok {
		if len(filteredList) == 1 {
			return BoolTrue, 0, nil
		}
		return BoolFalse, 0, nil
	}

	return nil, 0, errors.New("failed to call dict assertion on a non-list/map value")
}

func dictMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	// map(array, function)
	itemsRef := chunk.Function.Args[0]
	items, rref, err := e.resolveValue(itemsRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if items.Value == nil {
		return &RawData{Type: items.Type}, 0, nil
	}

	list, ok := items.Value.([]any)
	if !ok {
		return nil, 0, errors.New("failed to call dict.map on a non-list value")
	}

	if len(list) == 0 {
		return items, 0, nil
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
	mappedType := types.Unset
	resMap := map[int]any{}
	finishedResults := 0
	l := sync.Mutex{}
	for it := range list {
		i := it
		err := e.runFunctionBlock([]*RawData{{Type: ct, Value: list[i]}}, fref, func(res *RawResult) {
			resList := func() []any {
				l.Lock()
				defer l.Unlock()

				_, ok := resMap[i]
				if !ok {
					finishedResults++
					resMap[i] = res.Data.Value
					mappedType = res.Data.Type
				}

				if finishedResults == len(list) {
					resList := []any{}
					for j := 0; j < len(resMap); j++ {
						k := resMap[j]
						if k != nil {
							resList = append(resList, k)
						}
					}
					return resList
				}
				return nil
			}()

			if resList != nil {
				data := &RawData{
					Type:  types.Array(mappedType),
					Value: resList,
				}
				e.cache.Store(ref, &stepCache{
					Result:   data,
					IsStatic: false,
				})
				e.triggerChain(ref, data)
			}
		})
		if err != nil {
			return nil, 0, err
		}
	}

	return nil, 0, nil
}

func dictFlat(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
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

	return &RawData{Type: bind.Type.Child(), Value: res}, 0, nil
}

func dictDifferenceV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
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

	org, ok := bind.Value.([]any)
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("cannot compute difference of lists, argument is not a list")}, 0, nil
	}

	filters, ok := arg.Value.([]any)
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("tried to call function with a non-array, please make sure the argument is an array")}, 0, nil
	}

	res := make([]any, 0)
	var skip bool
	for i := range org {
		skip = false
		for j := range filters {
			if org[i] == filters[j] {
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

func dictContainsAll(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
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

	org, ok := bind.Value.([]any)
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("cannot compute difference of lists, argument is not a list")}, 0, nil
	}

	argFilters, ok := arg.Value.([]any)
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("tried to call function with a non-array, please make sure the argument is an array")}, 0, nil
		// filters = []any{arg.Value}
	}
	filters := make([]any, len(argFilters))
	copy(filters, argFilters)

	for i := range org {
		for j := range filters {
			if org[i] == filters[j] {
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

func dictContainsNone(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
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

	org, ok := bind.Value.([]any)
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("cannot compute difference of lists, argument is not a list")}, 0, nil
	}

	filters, ok := arg.Value.([]any)
	if !ok {
		return &RawData{Type: bind.Type, Error: errors.New("tried to call function with a non-array, please make sure the argument is an array")}, 0, nil
		// filters = []any{arg.Value}
	}

	res := make([]any, 0)
	var skip bool
	for i := range org {
		skip = true
		for j := range filters {
			if org[i] == filters[j] {
				skip = false
				break
			}
		}

		if !skip {
			res = append(res, org[i])
		}
	}

	return &RawData{Type: bind.Type, Value: res}, 0, nil
}

func anyContainsString(an any, s string) bool {
	if an == nil {
		return false
	}

	switch x := an.(type) {
	case string:
		return strings.Contains(x, s)
	case []any:
		for i := range x {
			if anyContainsString(x[i], s) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func anyContainsAny(an any, s any) (bool, error) {
	if an == nil {
		return false, nil
	}

	switch x := an.(type) {
	case string:
		return opStringContainsDict(x, s)
	case []any:
		for i := range x {
			ok, err := anyContainsAny(x[i], s)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, nil
	}
}

func anyContainsRegex(an any, re *regexp.Regexp) bool {
	if an == nil {
		return false
	}

	switch x := an.(type) {
	case string:
		return re.MatchString(x)
	case []any:
		for i := range x {
			if anyContainsRegex(x[i], re) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func dictContainsStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	ok := anyContainsString(bind.Value, arg.Value.(string))
	return BoolData(ok), 0, nil
}

func dictContainsDict(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	ok, err := anyContainsAny(bind.Value, arg.Value)
	if err != nil {
		return BoolData(false), 0, err
	}
	return BoolData(ok), 0, nil
}

func dictContainsIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	val := strconv.FormatInt(arg.Value.(int64), 10)

	ok := anyContainsString(bind.Value, val)
	return BoolData(ok), 0, nil
}

func dictContainsRegex(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}

	if arg.Value == nil {
		return BoolFalse, 0, nil
	}

	reContent := arg.Value.(string)
	re, err := regexp.Compile(reContent)
	if err != nil {
		return nil, 0, errors.New("Failed to compile regular expression: " + reContent)
	}

	ok := anyContainsRegex(bind.Value, re)
	return BoolData(ok), 0, nil
}

func dictContainsArrayStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	switch bind.Value.(type) {
	case string:
		return stringContainsArrayString(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `contains`")
	}
}

func dictContainsArrayDict(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	switch bind.Value.(type) {
	case string:
		return stringContainsArrayString(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `contains`")
	}
}

func dictContainsArrayIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	switch bind.Value.(type) {
	case string:
		return stringContainsArrayInt(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `contains`")
	}
}

func dictContainsArrayRegex(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	switch bind.Value.(type) {
	case string:
		return stringContainsArrayRegex(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `contains`")
	}
}

func dictIn(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	switch bind.Value.(type) {
	case []any:
		return anyArrayInStringArray(e, bind, chunk, ref)
	case string, int32, int64, float64, bool:
		return dictScalarInArray(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `in`")
	}
}

func dictNotIn(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolTrue, 0, nil
	}
	switch bind.Value.(type) {
	case []any:
		return anyArrayNotInStringArray(e, bind, chunk, ref)
	case string, int32, int64, float64, bool:
		return dictScalarNotInArray(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `in`")
	}
}

// loose cross-type equality: same semantics as the dict ==/!= operators
// (e.g. a DWORD-backed int64 matches both 2 and "2").
func dictScalarInArray(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	if bind.Value == nil {
		return BoolFalse, 0, nil
	}
	argRef := chunk.Function.Args[0]
	arg, rref, err := e.resolveValue(argRef, ref)
	if err != nil || rref > 0 {
		return nil, rref, err
	}
	if arg.Value == nil {
		return BoolFalse, 0, nil
	}
	arr := arg.Value.([]any)
	for i := range arr {
		if dictScalarEqual(bind.Value, arr[i]) {
			return BoolTrue, 0, nil
		}
	}
	return BoolFalse, 0, nil
}

func dictScalarNotInArray(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	res, rref, err := dictScalarInArray(e, bind, chunk, ref)
	if res == BoolTrue {
		return BoolFalse, rref, err
	}
	if res == BoolFalse {
		return BoolTrue, rref, err
	}
	return res, rref, err
}

func dictScalarEqual(bindVal, arrVal any) bool {
	if bindVal == nil || arrVal == nil {
		return bindVal == arrVal
	}
	switch arrVal.(type) {
	case string:
		return opDictCmpString(bindVal, arrVal)
	case int32, int64:
		if v, ok := arrVal.(int32); ok {
			arrVal = int64(v)
		}
		return opDictCmpInt(bindVal, arrVal)
	case float64:
		return opDictCmpFloat(bindVal, arrVal)
	case bool:
		return opDictCmpBool(bindVal, arrVal)
	default:
		return false
	}
}

func dictFindV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	switch bind.Value.(type) {
	case string:
		return stringFindV2(e, bind, chunk, ref)
	default:
		return nil, 0, errors.New("dict value does not support field `find`")
	}
}

// map &&/||

func opArrayAndMap(left any, right any) bool {
	return (len(left.([]any)) != 0) && (len(right.(map[string]any)) != 0)
}

func opArrayOrMap(left any, right any) bool {
	return (len(left.([]any)) != 0) || (len(right.(map[string]any)) != 0)
}

func opMapAndArray(left any, right any) bool {
	return (len(right.(map[string]any)) != 0) && (len(left.([]any)) != 0)
}

func opMapOrArray(left any, right any) bool {
	return (len(right.(map[string]any)) != 0) || (len(left.([]any)) != 0)
}

func arrayAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayAndMap)
}

func arrayOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opArrayOrMap)
}

func mapAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndArray)
}

func mapOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapOrArray)
}

func opMapAndMap(left any, right any) bool {
	return (len(left.(map[string]any)) != 0) && (len(right.(map[string]any)) != 0)
}

func opMapOrMap(left any, right any) bool {
	return (len(left.(map[string]any)) != 0) || (len(right.(map[string]any)) != 0)
}

func mapAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndMap)
}

func mapOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapOrMap)
}

// dict ==/!= nil

func opDictCmpNil(left any, right any) bool {
	return left == nil
}

func opNilCmpDict(left any, right any) bool { //nolint:unused
	return right == nil
}

func dictCmpNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpNil)
}

func dictNotNilV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpNil)
}

func nilCmpDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) { //nolint:unused
	return boolOpV2(e, bind, chunk, ref, opNilCmpDict)
}

func nilNotDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) { //nolint:unused
	return boolNotOpV2(e, bind, chunk, ref, opNilCmpDict)
}

// dict ==/!= bool

func opDictCmpBool(left any, right any) bool {
	switch x := left.(type) {
	case bool:
		return x == right.(bool)
	case string:
		return opStringCmpBool(x, right)
	default:
		return false
	}
}

func opBoolCmpDict(left any, right any) bool {
	switch x := right.(type) {
	case bool:
		return left.(bool) == x
	case string:
		return opBoolCmpString(left, x)
	default:
		return false
	}
}

func dictCmpBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpBool)
}

func dictNotBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpBool)
}

func boolCmpDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolCmpDict)
}

func boolNotDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opBoolCmpDict)
}

// dict ==/!= int   (embedded: string + float)

func opDictCmpInt(left any, right any) bool {
	if _, ok := left.(int32); ok {
		left = int64(left.(int32))
	}
	switch x := left.(type) {
	case int64:
		return x == right.(int64)
	case float64:
		return x == float64(right.(int64))
	case string:
		return opStringCmpInt(x, right)
	default:
		return false
	}
}

func opIntCmpDict(left any, right any) bool {
	if _, ok := right.(int32); ok {
		right = int64(right.(int32))
	}
	switch x := right.(type) {
	case int64:
		return left.(int64) == x
	case float64:
		return float64(left.(int64)) == x
	case string:
		return opIntCmpString(left, x)
	default:
		return false
	}
}

func dictCmpIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpInt)
}

func dictNotIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpInt)
}

func intCmpDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntCmpDict)
}

func intNotDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opIntCmpDict)
}

// dict ==/!= float

func opDictCmpFloat(left any, right any) bool {
	switch x := left.(type) {
	case int64:
		return float64(x) == right.(float64)
	case float64:
		return x == right.(float64)
	case string:
		return opStringCmpFloat(x, right)
	default:
		return false
	}
}

func opFloatCmpDict(left any, right any) bool {
	switch x := right.(type) {
	case int64:
		return left.(float64) == float64(x)
	case float64:
		return left.(float64) == x
	case string:
		return opFloatCmpString(left, x)
	default:
		return false
	}
}

func dictCmpFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpFloat)
}

func dictNotFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpFloat)
}

func floatCmpDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatCmpDict)
}

func floatNotDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opFloatCmpDict)
}

// dict ==/!= string

func opDictCmpString(left any, right any) bool {
	switch x := left.(type) {
	case string:
		return x == right.(string)
	case bool:
		return opBoolCmpString(x, right)
	case int64:
		return opIntCmpString(x, right)
	case float64:
		return opFloatCmpString(x, right)
	default:
		return false
	}
}

func opStringCmpDict(left any, right any) bool {
	switch x := right.(type) {
	case string:
		return left.(string) == x
	case bool:
		return opStringCmpBool(left, x)
	case int64:
		return opStringCmpInt(left, x)
	case float64:
		return opStringCmpFloat(left, x)
	default:
		return false
	}
}

func dictCmpStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpString)
}

func dictNotStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpString)
}

func stringCmpDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringCmpDict)
}

func stringNotDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opStringCmpDict)
}

// dict ==/!= regex

func opDictCmpRegex(left any, right any) bool {
	switch x := left.(type) {
	case string:
		return opStringCmpRegex(x, right)
	case int64:
		return opIntCmpRegex(x, right)
	case float64:
		return opFloatCmpRegex(x, right)
	default:
		return false
	}
}

func opRegexCmpDict(left any, right any) bool {
	switch x := right.(type) {
	case string:
		return opRegexCmpString(left, x)
	case int64:
		return opRegexCmpInt(left, x)
	case float64:
		return opRegexCmpFloat(left, x)
	default:
		return false
	}
}

func dictCmpRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpRegex)
}

func dictNotRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpRegex)
}

func regexCmpDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opRegexCmpDict)
}

func regexNotDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opRegexCmpDict)
}

// dict ==/!= arrays

func opDictCmpArray(left any, right any) bool {
	switch left.(type) {
	case string:
		return false
	default:
		return false
	}
}

func dictCmpArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpArray)
}

func dictNotArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpArray)
}

func opDictCmpStringarray(left *RawData, right *RawData) bool {
	switch left.Value.(type) {
	case string:
		return cmpArrayOne(right, left, opStringCmpString)
	case []any:
		return cmpArrays(left, right, opDictCmpString)
	default:
		return false
	}
}

func dictCmpStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, opDictCmpStringarray)
}

func dictNotStringarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, opDictCmpStringarray)
}

func opDictCmpRegexarray(left *RawData, right *RawData) bool {
	switch left.Value.(type) {
	case string:
		return cmpArrayOne(right, left, opStringCmpRegex)
	case []any:
		return cmpArrays(left, right, opDictCmpRegex)
	default:
		return false
	}
}

func dictCmpRegexarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, opDictCmpRegexarray)
}

func dictNotRegexarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, opDictCmpRegexarray)
}

func opDictCmpBoolarray(left *RawData, right *RawData) bool { //nolint:unused
	switch left.Value.(type) {
	case string:
		return cmpArrayOne(right, left, opBoolCmpString)
	default:
		return false
	}
}

func dictCmpBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, opDictCmpStringarray)
}

func dictNotBoolarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, opDictCmpStringarray)
}

func opDictCmpIntarray(left *RawData, right *RawData) bool {
	switch left.Value.(type) {
	case string:
		return cmpArrayOne(right, left, opIntCmpString)
	default:
		return false
	}
}

func dictCmpIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, opDictCmpIntarray)
}

func dictNotIntarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, opDictCmpIntarray)
}

func opDictCmpFloatarray(left *RawData, right *RawData) bool {
	switch left.Value.(type) {
	case string:
		return cmpArrayOne(right, left, opFloatCmpString)
	default:
		return false
	}
}

func dictCmpFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolOpV2(e, bind, chunk, ref, opDictCmpFloatarray)
}

func dictNotFloatarrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return rawboolNotOpV2(e, bind, chunk, ref, opDictCmpFloatarray)
}

// dict ==/!= dict

func opDictCmpDict(left any, right any) bool {
	switch x := left.(type) {
	case bool:
		return opBoolCmpDict(x, right)
	case int64:
		return opIntCmpDict(x, right)
	case float64:
		return opFloatCmpDict(x, right)
	case string:
		return opStringCmpDict(x, right)
	default:
		return false
	}
}

func dictCmpDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictCmpDict)
}

func dictNotDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolNotOpV2(e, bind, chunk, ref, opDictCmpDict)
}

// dict </>/<=/>= int

func opDictLTInt(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(x < right.(int64))
	case float64:
		return BoolData(x < float64(right.(int64)))
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f < right.(int64))
	default:
		return &RawData{Error: errors.New("type conflict for '<'"), Type: types.Bool}
	}
}

func opDictLTEInt(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(x <= right.(int64))
	case float64:
		return BoolData(x <= float64(right.(int64)))
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f <= right.(int64))
	default:
		return &RawData{Error: errors.New("type conflict for '<='"), Type: types.Bool}
	}
}

func opDictGTInt(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(x > right.(int64))
	case float64:
		return BoolData(x > float64(right.(int64)))
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f > right.(int64))
	default:
		return &RawData{Error: errors.New("type conflict for '>'"), Type: types.Bool}
	}
}

func opDictGTEInt(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(x >= right.(int64))
	case float64:
		return BoolData(x >= float64(right.(int64)))
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f >= right.(int64))
	default:
		return &RawData{Error: errors.New("type conflict for '>='"), Type: types.Bool}
	}
}

func dictLTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictLTInt)
}

func dictLTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictLTEInt)
}

func dictGTIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictGTInt)
}

func dictGTEIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictGTEInt)
}

func opIntLTDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		return BoolData(left.(int64) < x)
	case float64:
		return BoolData(float64(left.(int64)) < x)
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(int64) < f)
	default:
		return &RawData{Error: errors.New("type conflict for '<'"), Type: types.Bool}
	}
}

func opIntLTEDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		return BoolData(left.(int64) <= x)
	case float64:
		return BoolData(float64(left.(int64)) <= x)
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(int64) <= f)
	default:
		return &RawData{Error: errors.New("type conflict for '<='"), Type: types.Bool}
	}
}

func opIntGTDict(left any, right any) *RawData { //nolint:unused
	switch x := right.(type) {
	case int64:
		return BoolData(left.(int64) > x)
	case float64:
		return BoolData(float64(left.(int64)) > x)
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(int64) > f)
	default:
		return &RawData{Error: errors.New("type conflict for '>'"), Type: types.Bool}
	}
}

func opIntGTEDict(left any, right any) *RawData { //nolint:unused
	switch x := right.(type) {
	case int64:
		return BoolData(left.(int64) >= x)
	case float64:
		return BoolData(float64(left.(int64)) >= x)
	case string:
		f, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(int64) >= f)
	default:
		return &RawData{Error: errors.New("type conflict for '>='"), Type: types.Bool}
	}
}

func intLTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opIntLTDict)
}

func intLTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opIntLTEDict)
}

func intGTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opIntLTEDict)
}

func intGTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opIntLTDict)
}

// dict </>/<=/>= float

func opDictLTFloat(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(float64(x) < right.(float64))
	case float64:
		return BoolData(x < right.(float64))
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f < right.(float64))
	default:
		return &RawData{Error: errors.New("type conflict for '<'"), Type: types.Bool}
	}
}

func opDictLTEFloat(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(float64(x) <= right.(float64))
	case float64:
		return BoolData(x <= right.(float64))
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f <= right.(float64))
	default:
		return &RawData{Error: errors.New("type conflict for '<='"), Type: types.Bool}
	}
}

func opDictGTFloat(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(float64(x) > right.(float64))
	case float64:
		return BoolData(x > right.(float64))
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f > right.(float64))
	default:
		return &RawData{Error: errors.New("type conflict for '>'"), Type: types.Bool}
	}
}

func opDictGTEFloat(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		return BoolData(float64(x) >= right.(float64))
	case float64:
		return BoolData(x >= right.(float64))
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(f >= right.(float64))
	default:
		return &RawData{Error: errors.New("type conflict for '>='"), Type: types.Bool}
	}
}

func dictLTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictLTFloat)
}

func dictLTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictLTEFloat)
}

func dictGTFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictGTFloat)
}

func dictGTEFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictGTEFloat)
}

func opFloatLTDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		return BoolData(left.(float64) < float64(x))
	case float64:
		return BoolData(left.(float64) < x)
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(float64) < f)
	default:
		return &RawData{Error: errors.New("type conflict for '<'"), Type: types.Bool}
	}
}

func opFloatLTEDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		return BoolData(left.(float64) <= float64(x))
	case float64:
		return BoolData(left.(float64) <= x)
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(float64) <= f)
	default:
		return &RawData{Error: errors.New("type conflict for '<='"), Type: types.Bool}
	}
}

func opFloatGTDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		return BoolData(left.(float64) > float64(x))
	case float64:
		return BoolData(left.(float64) > x)
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(float64) > f)
	default:
		return &RawData{Error: errors.New("type conflict for '>'"), Type: types.Bool}
	}
}

func opFloatGTEDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		return BoolData(left.(float64) >= float64(x))
	case float64:
		return BoolData(left.(float64) >= x)
	case string:
		f, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + x + " as number"), Type: types.Bool}
		}
		return BoolData(left.(float64) >= f)
	default:
		return &RawData{Error: errors.New("type conflict for '>='"), Type: types.Bool}
	}
}

func floatLTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opFloatLTDict)
}

func floatLTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opFloatLTEDict)
}

func floatGTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opFloatGTDict)
}

func floatGTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opFloatGTEDict)
}

// dict </>/<=/>= string

func opDictLTString(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x < f)
	case float64:
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x < f)
	case string:
		return BoolData(x < right.(string))
	default:
		return &RawData{Error: errors.New("type conflict for '<'"), Type: types.Bool}
	}
}

func opDictLTEString(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x <= f)
	case float64:
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x <= f)
	case string:
		return BoolData(x <= right.(string))
	default:
		return &RawData{Error: errors.New("type conflict for '<='"), Type: types.Bool}
	}
}

func opDictGTString(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x > f)
	case float64:
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x > f)
	case string:
		return BoolData(x > right.(string))
	default:
		return &RawData{Error: errors.New("type conflict for '>'"), Type: types.Bool}
	}
}

func opDictGTEString(left any, right any) *RawData {
	switch x := left.(type) {
	case int64:
		f, err := strconv.ParseInt(right.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x >= f)
	case float64:
		f, err := strconv.ParseFloat(right.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + right.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(x >= f)
	case string:
		return BoolData(x >= right.(string))
	default:
		return &RawData{Error: errors.New("type conflict for '>='"), Type: types.Bool}
	}
}

func dictLTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictLTString)
}

func dictLTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictLTEString)
}

func dictGTStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictGTString)
}

func dictGTEStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opDictGTEString)
}

func opStringLTDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f < x)
	case float64:
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f < x)
	case string:
		return BoolData(left.(string) < x)
	default:
		return &RawData{Error: errors.New("type conflict for '<'"), Type: types.Bool}
	}
}

func opStringLTEDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f <= x)
	case float64:
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f <= x)
	case string:
		return BoolData(left.(string) <= x)
	default:
		return &RawData{Error: errors.New("type conflict for '<='"), Type: types.Bool}
	}
}

func opStringGTDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f > x)
	case float64:
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f > x)
	case string:
		return BoolData(left.(string) > x)
	default:
		return &RawData{Error: errors.New("type conflict for '>'"), Type: types.Bool}
	}
}

func opStringGTEDict(left any, right any) *RawData {
	switch x := right.(type) {
	case int64:
		f, err := strconv.ParseInt(left.(string), 10, 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f >= x)
	case float64:
		f, err := strconv.ParseFloat(left.(string), 64)
		if err != nil {
			return &RawData{Error: errors.New("cannot parse " + left.(string) + " as number"), Type: types.Bool}
		}
		return BoolData(f >= x)
	case string:
		return BoolData(left.(string) >= x)
	default:
		return &RawData{Error: errors.New("type conflict for '>='"), Type: types.Bool}
	}
}

func stringLTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opStringLTDict)
}

func stringLTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opStringLTEDict)
}

func stringGTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opStringGTDict)
}

func stringGTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, opStringGTEDict)
}

// dict </>/<=/>= dict

func dictLTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		switch x := right.(type) {
		case int64:
			return opDictLTInt(left, x)
		case float64:
			return opDictLTFloat(left, x)
		case string:
			return opDictLTString(left, x)
		default:
			return &RawData{Error: errors.New("type conflict for '<'"), Type: types.Bool}
		}
	})
}

func dictLTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		switch x := right.(type) {
		case int64:
			return opDictLTEInt(left, x)
		case float64:
			return opDictLTEFloat(left, x)
		case string:
			return opDictLTEString(left, x)
		default:
			return &RawData{Error: errors.New("type conflict for '<='"), Type: types.Bool}
		}
	})
}

func dictGTDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		switch x := right.(type) {
		case int64:
			return opDictLTEInt(left, x)
		case float64:
			return opDictLTEFloat(left, x)
		case string:
			return opDictLTString(left, x)
		default:
			return &RawData{Error: errors.New("type conflict for '>'"), Type: types.Bool}
		}
	})
}

func dictGTEDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return nonNilDataOpV2(e, bind, chunk, ref, types.Bool, func(left any, right any) *RawData {
		switch x := right.(type) {
		case int64:
			return opDictLTInt(left, x)
		case float64:
			return opDictLTFloat(left, x)
		case string:
			return opDictLTString(left, x)
		default:
			return &RawData{Error: errors.New("type conflict for '>='"), Type: types.Bool}
		}
	})
}

// dict && / || ...

func truthyDict(value any) bool {
	switch x := value.(type) {
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) != 0
	case map[string]any:
		return len(x) != 0
	default:
		return false
	}
}

// ... bool

func opBoolAndDict(left any, right any) bool {
	return left.(bool) && truthyDict(right)
}

func opBoolOrDict(left any, right any) bool {
	return left.(bool) || truthyDict(right)
}

func opDictAndBool(left any, right any) bool {
	return truthyDict(left) && right.(bool)
}

func opDictOrBool(left any, right any) bool {
	return truthyDict(left) || right.(bool)
}

func boolAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolAndDict)
}

func boolOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opBoolOrDict)
}

func dictAndBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndBool)
}

func dictOrBoolV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrBool)
}

// ... int

func opIntAndDict(left any, right any) bool {
	return left.(int64) != 0 && truthyDict(right)
}

func opIntOrDict(left any, right any) bool {
	return left.(int64) != 0 || truthyDict(right)
}

func opDictAndInt(left any, right any) bool {
	return truthyDict(left) && right.(int64) != 0
}

func opDictOrInt(left any, right any) bool {
	return truthyDict(left) || right.(int64) != 0
}

func intAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntAndDict)
}

func intOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opIntOrDict)
}

func dictAndIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndInt)
}

func dictOrIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrInt)
}

// ... float

func opFloatAndDict(left any, right any) bool {
	return left.(float64) != 0 && truthyDict(right)
}

func opFloatOrDict(left any, right any) bool {
	return left.(float64) != 0 || truthyDict(right)
}

func opDictAndFloat(left any, right any) bool {
	return truthyDict(left) && right.(float64) != 0
}

func opDictOrFloat(left any, right any) bool {
	return truthyDict(left) || right.(float64) != 0
}

func floatAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatAndDict)
}

func floatOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opFloatOrDict)
}

func dictAndFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndFloat)
}

func dictOrFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrFloat)
}

// ... string

func opStringAndDict(left any, right any) bool {
	return left.(string) != "" && truthyDict(right)
}

func opStringOrDict(left any, right any) bool {
	return left.(string) != "" || truthyDict(right)
}

func opDictAndString(left any, right any) bool {
	return truthyDict(left) && right.(string) != ""
}

func opDictOrString(left any, right any) bool {
	return truthyDict(left) || right.(string) != ""
}

func stringAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringAndDict)
}

func stringOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opStringOrDict)
}

func dictAndStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndString)
}

func dictOrStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrString)
}

// ... regex

func opRegexAndDict(left any, right any) bool {
	return left.(string) != "" && truthyDict(right)
}

func opRegexOrDict(left any, right any) bool {
	return left.(string) != "" || truthyDict(right)
}

func opDictAndRegex(left any, right any) bool {
	return truthyDict(left) && right.(string) != ""
}

func opDictOrRegex(left any, right any) bool {
	return truthyDict(left) || right.(string) != ""
}

func regexAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opRegexAndDict)
}

func regexOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opRegexOrDict)
}

func dictAndRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndRegex)
}

func dictOrRegexV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrRegex)
}

// ... time
// note: time cannot be falsy

func opTimeAndDict(left any, right any) bool {
	return truthyDict(right)
}

func opTimeOrDict(left any, right any) bool {
	return true
}

func opDictAndTime(left any, right any) bool {
	return truthyDict(left)
}

func opDictOrTime(left any, right any) bool {
	return true
}

func timeAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeAndDict)
}

func timeOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opTimeOrDict)
}

func dictAndTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndTime)
}

func dictOrTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrTime)
}

// ... dict

func opDictAndDict(left any, right any) bool {
	return truthyDict(left) && truthyDict(right)
}

func opDictOrDict(left any, right any) bool {
	return truthyDict(left) || truthyDict(right)
}

func dictAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndDict)
}

func dictOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrDict)
}

// ... array

func opDictAndArray(left any, right any) bool {
	return truthyDict(left) && (len(right.([]any)) != 0)
}

func opArrayAndDict(left any, right any) bool { //nolint:unused
	return truthyDict(right) && (len(left.([]any)) != 0)
}

func opDictOrArray(left any, right any) bool {
	return truthyDict(left) || (len(right.([]any)) != 0)
}

func opArrayOrDict(left any, right any) bool { //nolint:unused
	return truthyDict(right) || (len(left.([]any)) != 0)
}

func dictAndArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndArray)
}

func dictOrArrayV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrArray)
}

func arrayAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) { //nolint:unused
	return boolOpV2(e, bind, chunk, ref, opArrayAndDict)
}

func arrayOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) { //nolint:unused
	return boolOpV2(e, bind, chunk, ref, opArrayOrDict)
}

// ... map

func opDictAndMap(left any, right any) bool {
	return truthyDict(left) && (len(right.(map[string]any)) != 0)
}

func opMapAndDict(left any, right any) bool {
	return truthyDict(right) && (len(left.(map[string]any)) != 0)
}

func opDictOrMap(left any, right any) bool {
	return truthyDict(left) || (len(right.(map[string]any)) != 0)
}

func opMapOrDict(left any, right any) bool {
	return truthyDict(right) || (len(left.(map[string]any)) != 0)
}

func dictAndMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictAndMap)
}

func dictOrMapV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opDictOrMap)
}

func mapAndDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapAndDict)
}

func mapOrDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return boolOpV2(e, bind, chunk, ref, opMapOrDict)
}

// dict + - * /

func dictPlusStringV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(string)

		switch l := left.(type) {
		case string:
			return StringData(l + r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("dict value does not support `+` operation with string"),
			}
		}
	})
}

func stringPlusDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) { //nolint:unused
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(string)

		switch r := right.(type) {
		case string:
			return StringData(l + r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("dict value does not support `+` operation with string"),
			}
		}
	})
}

func intPlusDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(int64)

		switch r := right.(type) {
		case int64:
			return IntData(l + r)
		case float64:
			return FloatData(float64(l) + r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `+` operation is not number"),
			}
		}
	})
}

func dictPlusIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(int64)

		switch l := left.(type) {
		case int64:
			return IntData(l + r)
		case float64:
			return FloatData(l + float64(r))
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `+` operation is not number"),
			}
		}
	})
}

func floatPlusDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(float64)

		switch r := right.(type) {
		case int64:
			return FloatData(l + float64(r))
		case float64:
			return FloatData(l + r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `+` operation is not number"),
			}
		}
	})
}

func dictPlusFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(float64)

		switch l := left.(type) {
		case int64:
			return FloatData(float64(l) + r)
		case float64:
			return FloatData(l + r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `+` operation is not number"),
			}
		}
	})
}

func intMinusDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(int64)

		switch r := right.(type) {
		case int64:
			return IntData(l - r)
		case float64:
			return FloatData(float64(l) - r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `-` operation is not number"),
			}
		}
	})
}

func dictMinusIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(int64)

		switch l := left.(type) {
		case int64:
			return IntData(l - r)
		case float64:
			return FloatData(l - float64(r))
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `-` operation is not number"),
			}
		}
	})
}

func floatMinusDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(float64)

		switch r := right.(type) {
		case int64:
			return FloatData(l - float64(r))
		case float64:
			return FloatData(l - r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `-` operation is not number"),
			}
		}
	})
}

func dictMinusFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(float64)

		switch l := left.(type) {
		case int64:
			return FloatData(float64(l) - r)
		case float64:
			return FloatData(l - r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `-` operation is not number"),
			}
		}
	})
}

func intTimesDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(int64)

		switch r := right.(type) {
		case int64:
			return IntData(l * r)
		case float64:
			return FloatData(float64(l) * r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `*` operation is not number"),
			}
		}
	})
}

func dictTimesIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(int64)

		switch l := left.(type) {
		case int64:
			return IntData(l * r)
		case float64:
			return FloatData(l * float64(r))
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `*` operation is not number"),
			}
		}
	})
}

func floatTimesDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(float64)

		switch r := right.(type) {
		case int64:
			return FloatData(l * float64(r))
		case float64:
			return FloatData(l * r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `*` operation is not number"),
			}
		}
	})
}

func dictTimesFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(float64)

		switch l := left.(type) {
		case int64:
			return FloatData(float64(l) * r)
		case float64:
			return FloatData(l * r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `*` operation is not number"),
			}
		}
	})
}

func intDividedDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(int64)

		switch r := right.(type) {
		case int64:
			return IntData(l / r)
		case float64:
			return FloatData(float64(l) / r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `/` operation is not number"),
			}
		}
	})
}

func dictDividedIntV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(int64)

		switch l := left.(type) {
		case int64:
			return IntData(l / r)
		case float64:
			return FloatData(l / float64(r))
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `/` operation is not number"),
			}
		}
	})
}

func floatDividedDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		l := left.(float64)

		switch r := right.(type) {
		case int64:
			return FloatData(l / float64(r))
		case float64:
			return FloatData(l / r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("right side of `/` operation is not number"),
			}
		}
	})
}

func dictDividedFloatV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		r := right.(float64)

		switch l := left.(type) {
		case int64:
			return FloatData(float64(l) / r)
		case float64:
			return FloatData(l / r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `/` operation is not number"),
			}
		}
	})
}

func dictTimesTimeV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		switch l := left.(type) {
		case int64:
			return opTimeTimesInt(right, l)
		case float64:
			return opTimeTimesFloat(right, l)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `*` operation is not compatible with `time`"),
			}
		}
	})
}

func timeTimesDictV2(e *blockExecutor, bind *RawData, chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	return dataOpV2(e, bind, chunk, ref, types.Time, func(left any, right any) *RawData {
		switch r := right.(type) {
		case int64:
			return opTimeTimesInt(left, r)
		case float64:
			return opTimeTimesFloat(left, r)
		default:
			return &RawData{
				Type:  types.Nil,
				Value: nil,
				Error: errors.New("left side of `*` operation is not compatible with `time`"),
			}
		}
	})
}
