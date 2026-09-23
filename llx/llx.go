// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

//go:generate protoc --plugin=protoc-gen-go=../scripts/protoc/protoc-gen-go --plugin=protoc-gen-rangerrpc=../scripts/protoc/protoc-gen-rangerrpc --plugin=protoc-gen-go-vtproto=../scripts/protoc/protoc-gen-go-vtproto --proto_path=. --go_out=. --go_opt=paths=source_relative --rangerrpc_out=. --go-vtproto_out=. --go-vtproto_opt=paths=source_relative --go-vtproto_opt=features=marshal+unmarshal+size llx.proto

import (
	"errors"
	"sort"
	"strconv"
	"sync"
	"time"

	uuid "github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

// ResultCallback function type
type ResultCallback func(*RawResult)

var emptyFunction = Function{}

// RawResult wraps RawData to code and refs
type RawResult struct {
	Data   *RawData
	CodeID string
	Ref    uint64
}

type stepCache struct {
	Result   *RawData
	IsStatic bool
}

// Calls is a map connecting call-refs with each other
type Calls struct {
	locker sync.Mutex
	calls  map[uint64][]uint64
}

// Store a new call connection.
// Returns true if this connection already exists.
// Returns false if this is a new connection.
func (c *Calls) Store(k uint64, v uint64) bool {
	c.locker.Lock()
	defer c.locker.Unlock()

	calls, ok := c.calls[k]
	if !ok {
		calls = []uint64{}
	} else {
		for k := range calls {
			if calls[k] == v {
				return true
			}
		}
	}

	calls = append(calls, v)
	c.calls[k] = calls
	return false
}

// Load a call connection
func (c *Calls) Load(k uint64) ([]uint64, bool) {
	c.locker.Lock()
	v, ok := c.calls[k]
	c.locker.Unlock()
	return v, ok
}

// cache is a map containing stepCache values
type cache struct {
	data map[uint64]*stepCache
	lock sync.Mutex
}

func newCache() *cache {
	return &cache{
		data: map[uint64]*stepCache{},
		lock: sync.Mutex{},
	}
}

// Store a new call connection
func (c *cache) Store(k uint64, v *stepCache) {
	c.lock.Lock()
	c.data[k] = v
	c.lock.Unlock()
}

// Load a call connection
func (c *cache) Load(k uint64) (*stepCache, bool) {
	c.lock.Lock()
	res, ok := c.data[k]
	c.lock.Unlock()

	return res, ok
}

type blockExecutor struct {
	id             string
	blockRef       uint64
	entrypoints    map[uint64]struct{}
	callback       ResultCallback
	callbackPoints map[uint64]string
	cache          *cache
	stepTracker    *cache
	calls          *Calls
	block          *Block
	parent         *blockExecutor
	ctx            *MQLExecutorV2
	watcherIds     *types.StringSet
	// foreignWatchers maps a watcher id to the runtime it was placed on, for
	// the few that are not on the executor's own runtime. Cross-asset
	// resolution (ADR 031) reads a field from another asset's runtime, and
	// unregister has to take that watcher down where it was put.
	foreignWatchers sync.Map
	// blockCoverageGaps maps a ref to the coverage gaps its block calls
	// reported (ADR 046 §8): the gaps of a `{ … }` over a list are in the
	// results of each block run, not in the list itself.
	blockCoverageGaps sync.Map
}

// MQLExecutorV2 is the runtime of MQL codestructure
type MQLExecutorV2 struct {
	id      string
	runtime Runtime
	code    *CodeV2
	props   map[string]*Primitive
	// skew excuses fields this build was never going to have, because the
	// bundle declared it needs a newer provider than the one loaded. Nil when
	// the reader satisfies everything the bundle asked for, which is the normal
	// case. See SkewPolicy.
	skew *SkewPolicy

	lock           sync.Mutex
	blockExecutors []*blockExecutor
	unregistered   bool

	blockPointsLock sync.RWMutex
	blockPoints     map[uint64]*blockPoints
}

func (c *blockExecutor) watcherUID(ref uint64) string {
	return c.id + "\x00" + strconv.FormatInt(int64(ref), 10)
}

func errorResult(err error, codeID string) *RawResult {
	return &RawResult{
		Data:   &RawData{Error: err},
		CodeID: codeID,
	}
}

func errorResultMsg(msg string, codeID string) *RawResult {
	return &RawResult{
		Data:   &RawData{Error: errors.New(msg)},
		CodeID: codeID,
	}
}

// NewExecutor will create a code runner from code, running in a runtime, calling
// callback whenever we get a result
// NewExecutorV2 runs code with no tolerance for version skew: any field the
// reader's schema lacks fails the query. Use NewExecutorV2WithSkew when the
// bundle's provenance says the reader is behind.
func NewExecutorV2(code *CodeV2, runtime Runtime, props map[string]*Primitive, callback ResultCallback) (*MQLExecutorV2, error) {
	return NewExecutorV2WithSkew(code, runtime, props, callback, nil)
}

// NewExecutorV2WithSkew is NewExecutorV2 with a policy naming the providers the
// reader is behind on. Fields belonging to those providers that the reader does
// not have degrade to an unavailable value instead of failing the whole query.
func NewExecutorV2WithSkew(code *CodeV2, runtime Runtime, props map[string]*Primitive, callback ResultCallback, skew *SkewPolicy) (*MQLExecutorV2, error) {
	if runtime == nil {
		return nil, errors.New("cannot exec MQL without a runtime")
	}

	if code == nil {
		return nil, errors.New("cannot run executor without code")
	}

	res := &MQLExecutorV2{
		id:             uuid.Must(uuid.NewV4()).String(),
		runtime:        runtime,
		code:           code,
		props:          props,
		skew:           skew,
		blockExecutors: []*blockExecutor{},
		blockPoints:    map[uint64]*blockPoints{},
	}

	exec, err := res._newBlockExecutor(1<<32, callback, nil)
	if err != nil {
		return nil, err
	}

	res.blockExecutors = append(res.blockExecutors, exec)

	return res, nil
}

func (c *MQLExecutorV2) _newBlockExecutor(blockRef uint64, callback ResultCallback, parent *blockExecutor) (*blockExecutor, error) {
	block := c.code.Block(blockRef)

	if block == nil {
		return nil, errors.New("cannot find block " + strconv.FormatUint(blockRef, 10))
	}

	points, err := c.pointsForBlock(blockRef, block)
	if err != nil {
		return nil, err
	}

	res := &blockExecutor{
		id:             uuid.Must(uuid.NewV4()).String() + "/" + strconv.FormatUint(blockRef>>32, 10),
		blockRef:       blockRef,
		callback:       callback,
		callbackPoints: points.callbackPoints,
		cache:          newCache(),
		stepTracker:    newCache(),
		calls: &Calls{
			locker: sync.Mutex{},
			calls:  map[uint64][]uint64{},
		},
		block:       block,
		ctx:         c,
		parent:      parent,
		watcherIds:  &types.StringSet{},
		entrypoints: points.entrypoints,
	}

	return res, nil
}

// blockPoints holds the entrypoint and callback lookup tables of one block.
// Both derive from the block and from the code checksums, which never change
// while the executor runs. Both are read-only after this constructor returns.
type blockPoints struct {
	entrypoints    map[uint64]struct{}
	callbackPoints map[uint64]string
}

// pointsForBlock returns the lookup tables of a block. An array or map block
// runs one block executor per element, so a query over a large array asked for
// the same two tables thousands of times. The tables are equal for every
// executor of the same block, so they are built once and shared.
// The lock only covers the map lookup and the map write. The tables are built
// outside it. Two executors that reach a block at the same time may both build
// the tables, and the first result stored wins. The tables are equal either
// way, because they derive from the same immutable code.
func (c *MQLExecutorV2) pointsForBlock(blockRef uint64, block *Block) (*blockPoints, error) {
	c.blockPointsLock.RLock()
	points, ok := c.blockPoints[blockRef]
	c.blockPointsLock.RUnlock()
	if ok {
		return points, nil
	}

	points = &blockPoints{
		entrypoints:    make(map[uint64]struct{}, len(block.Entrypoints)),
		callbackPoints: make(map[uint64]string, len(block.Entrypoints)+len(block.Datapoints)),
	}

	for _, ref := range block.Entrypoints {
		id := c.code.Checksums[ref]
		if id == "" {
			return nil, errors.New("llx.executor> cannot execute with invalid ref ID in entrypoint")
		}
		if ref < 1 {
			return nil, errors.New("llx.executor> cannot execute with invalid ref number in entrypoint")
		}
		points.entrypoints[ref] = struct{}{}
		points.callbackPoints[ref] = id
	}

	for _, ref := range block.Datapoints {
		id := c.code.Checksums[ref]
		if id == "" {
			return nil, errors.New("llx.executor> cannot execute with invalid ref ID in datapoint")
		}
		if ref < 1 {
			return nil, errors.New("llx.executor> cannot execute with invalid ref number in datapoint")
		}
		points.callbackPoints[ref] = id
	}

	if len(points.callbackPoints) == 0 {
		panic("no callback points")
	}

	c.blockPointsLock.Lock()
	defer c.blockPointsLock.Unlock()

	if existing, ok := c.blockPoints[blockRef]; ok {
		return existing, nil
	}
	c.blockPoints[blockRef] = points
	return points, nil
}

// NoRun returns error for all callbacks and don't run code
func (c *MQLExecutorV2) NoRun(err error) {
	callback := c.blockExecutors[0].callback

	for ref := range c.blockExecutors[0].callbackPoints {
		if codeID, ok := c.blockExecutors[0].callbackPoints[ref]; ok {
			callback(errorResult(err, codeID))
		}
	}
}

func (c *MQLExecutorV2) addBlockExecutor(be *blockExecutor) bool {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.unregistered {
		return false
	}
	c.blockExecutors = append(c.blockExecutors, be)
	return true
}

func (c *MQLExecutorV2) Unregister() error {
	log.Trace().Str("id", c.id).Msg("exec> unregister")
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.unregistered {
		return nil
	}
	c.unregistered = true

	var errs []error
	for i := range c.blockExecutors {
		be := c.blockExecutors[i]
		errs = append(errs, be.unregister()...)
	}

	if len(errs) > 0 {
		return errors.New("multiple errors unregistering")
	}

	return nil
}

// Run a given set of code. Only returns an error if the couldn't be started.
func (c *MQLExecutorV2) Run() error {
	if len(c.blockExecutors) == 0 {
		return errors.New("cannot find initial block executor for running this code")
	}

	core := c.blockExecutors[0]
	core.run()
	return nil
}

func (b *blockExecutor) newBlockExecutor(blockRef uint64, callback ResultCallback) (*blockExecutor, error) {
	return b.ctx._newBlockExecutor(blockRef, callback, b)
}

func (e *blockExecutor) unregister() []error {
	var errs []error

	e.watcherIds.Range(func(key string) bool {
		runtime := e.ctx.runtime
		if foreign, ok := e.foreignWatchers.Load(key); ok {
			runtime = foreign.(Runtime)
		}
		if err := runtime.Unregister(key); err != nil {
			log.Error().Err(err).Msg("exec> unregister error")
			errs = append(errs, err)
		}
		return true
	})

	return errs
}

func (b *blockExecutor) isInMyBlock(ref uint64) bool {
	return (ref >> 32) == (b.blockRef >> 32)
}

func (b *blockExecutor) mustLookup(ref uint64) *RawData {
	d, _, err := b.parent.lookupValue(ref)
	if err != nil {
		panic("datapoint lookup failed: " + b.refContext(ref) + ": " + err.Error())
	}
	if d == nil {
		panic("did not lookup datapoint: " + b.refContext(ref))
	}
	return d
}

// run code with a runtime and return results
func (b *blockExecutor) run() {
	defer logger.FuncDur(time.Now(), "llx.blockExecutor.run")

	for ref, codeID := range b.callbackPoints {
		if !b.isInMyBlock(ref) {
			v := b.mustLookup(ref)
			b.callback(&RawResult{
				CodeID: codeID,
				Data:   b.resultWithCoverageGaps(ref, v),
			})
		}
	}
	// work down all entrypoints
	refs := make([]uint64, len(b.block.Entrypoints)+len(b.block.Datapoints))
	i := 0
	for _, ref := range b.block.Entrypoints {
		refs[i] = ref
		i++
	}
	for _, ref := range b.block.Datapoints {
		refs[i] = ref
		i++
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i] > refs[j] })

	for _, ref := range refs {
		// if this entrypoint is already connected, don't add it again
		if _, ok := b.stepTracker.Load(ref); ok {
			continue
		}

		log.Trace().Uint64("entrypoint", ref).Str("exec-ID", b.ctx.id).Msg("exec.Run>")
		b.runChain(ref)
	}
}

func (b *blockExecutor) ensureArgsResolved(args []*Primitive, ref uint64) (uint64, error) {
	for _, arg := range args {
		_, dref, err := b.resolveValue(arg, ref)
		if dref != 0 || err != nil {
			return dref, err
		}
	}
	return 0, nil
}

func reportSync(cb ResultCallback) ResultCallback {
	lock := sync.Mutex{}
	return func(rr *RawResult) {
		lock.Lock()
		defer lock.Unlock()
		cb(rr)
	}
}

type arrayBlockCallResults struct {
	lock                 sync.Mutex
	results              []arrayBlockCallResult
	errors               []error
	waiting              []int
	unfinishedBlockCalls int
	onComplete           func([]arrayBlockCallResult, []error)
	coverageGaps         []*Error
	entrypoints          map[string]struct{}
	datapoints           map[string]struct{}
}

type arrayBlockCallResult struct {
	entrypoints map[string]any
	datapoints  map[string]any
}

func (a arrayBlockCallResult) toRawData() *RawData {
	v := make(map[string]any, len(a.entrypoints)+len(a.datapoints))

	for checksum, res := range a.entrypoints {
		v[checksum] = res
	}

	for checksum, res := range a.datapoints {
		v[checksum] = res
	}

	v["__t"] = &RawData{
		Type:  types.Bool,
		Value: a.isTruthy(),
	}

	success, ok := a.isSuccess()
	if ok {
		v["__s"] = &RawData{
			Type:  types.Bool,
			Value: success,
		}
	} else {
		v["__s"] = &RawData{
			Type: types.Nil,
		}
	}

	return &RawData{
		Type:  types.Block,
		Value: v,
	}
}

func (a arrayBlockCallResult) isTruthy() bool {
	for _, res := range a.entrypoints {
		rd := &RawData{
			Type:  types.Any,
			Value: res,
		}
		isT, isValid := rd.IsTruthy()
		if isValid && !isT {
			return false
		}
	}
	return true
}

func (a arrayBlockCallResult) isSuccess() (bool, bool) {
	valid := false
	for _, res := range a.entrypoints {
		rd := &RawData{
			Type:  types.Any,
			Value: res,
		}
		isS, isValid := rd.IsSuccess()
		if isValid && !isS {
			return false, true
		}
		valid = valid || isValid
	}
	return true, valid
}

func (a *arrayBlockCallResults) update(i int, res *RawResult) {
	a.lock.Lock()
	defer a.lock.Unlock()

	_, isEntrypoint := a.entrypoints[res.CodeID]
	_, isDatapoint := a.datapoints[res.CodeID]

	if !isEntrypoint && !isDatapoint {
		return
	}

	_, hasEntrypointResult := a.results[i].entrypoints[res.CodeID]
	_, hasDatapointResult := a.results[i].datapoints[res.CodeID]

	if !hasEntrypointResult && !hasDatapointResult {
		a.waiting[i]--
		if a.waiting[i] == 0 {
			a.unfinishedBlockCalls--
		}
	}

	if isEntrypoint {
		a.results[i].entrypoints[res.CodeID] = res.Data
	}

	if isDatapoint {
		a.results[i].datapoints[res.CodeID] = res.Data
	}

	if res.Data.Error != nil {
		a.errors = append(a.errors, res.Data.Error)
	}
	a.coverageGaps = UnionCoverageGaps(a.coverageGaps, res.Data.CoverageGaps)

	if a.unfinishedBlockCalls == 0 {
		a.onComplete(a.results, a.errors)
	}
}

func newArrayBlockCallResultsV2(expectedBlockCalls int, code *CodeV2, blockRef uint64, onComplete func([]arrayBlockCallResult, []error)) (*arrayBlockCallResults, bool) {
	results := make([]arrayBlockCallResult, expectedBlockCalls)
	waiting := make([]int, expectedBlockCalls)

	codepoints := map[string]struct{}{}
	entrypoints := map[string]struct{}{}

	b := code.Block(blockRef)

	for _, ep := range b.Entrypoints {
		checksum := code.Checksums[ep]
		codepoints[checksum] = struct{}{}
		entrypoints[checksum] = struct{}{}
	}

	datapoints := map[string]struct{}{}
	for _, dp := range b.Datapoints {
		checksum := code.Checksums[dp]
		codepoints[checksum] = struct{}{}
		datapoints[checksum] = struct{}{}
	}

	expectedCodepoints := len(codepoints)
	if expectedCodepoints == 0 {
		results := make([]arrayBlockCallResult, expectedBlockCalls)
		onComplete(results, nil)
		return nil, false
	} else {
		for i := range waiting {
			waiting[i] = expectedCodepoints
		}
	}

	for i := range results {
		results[i] = arrayBlockCallResult{
			entrypoints: map[string]any{},
			datapoints:  map[string]any{},
		}
	}

	return &arrayBlockCallResults{
		lock:                 sync.Mutex{},
		results:              results,
		waiting:              waiting,
		unfinishedBlockCalls: expectedBlockCalls,
		onComplete:           onComplete,
		entrypoints:          entrypoints,
		datapoints:           datapoints,
	}, true
}

// runFunctionBlocks runs the block at blockRef once per entry in argList, on
// behalf of the chunk at ref, and calls onComplete when all runs finished.
func (c *blockExecutor) runFunctionBlocks(argList [][]*RawData, blockRef uint64, ref uint64,
	onComplete func([]arrayBlockCallResult, []error),
) error {
	var callResults *arrayBlockCallResults
	// Record what the block runs could not read before the result is stored
	// and delivered, so its delivery picks the gaps up.
	complete := func(results []arrayBlockCallResult, errs []error) {
		if callResults != nil && len(callResults.coverageGaps) != 0 {
			c.blockCoverageGaps.Store(ref, callResults.coverageGaps)
		}
		onComplete(results, errs)
	}
	callResults, shouldRun := newArrayBlockCallResultsV2(len(argList), c.ctx.code, blockRef, complete)
	if !shouldRun {
		return nil
	}
	for idx := range argList {
		i := idx
		args := argList[i]
		err := c.runFunctionBlock(args, blockRef, func(rr *RawResult) {
			callResults.update(i, rr)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (b *blockExecutor) runFunctionBlock(args []*RawData, blockRef uint64, cb ResultCallback) error {
	executor, err := b.newBlockExecutor(blockRef, reportSync(cb))
	if err != nil {
		return err
	}

	b.ctx.addBlockExecutor(executor)

	if len(args) < int(executor.block.Parameters) {
		panic("not enough arguments for block " + strconv.FormatUint(blockRef>>32, 10) +
			": got " + strconv.Itoa(len(args)) + ", want " + strconv.Itoa(int(executor.block.Parameters)))
	}

	for i := int32(0); i < executor.block.Parameters; i++ {
		executor.cache.Store(blockRef|uint64(i+1), &stepCache{
			Result:   args[i],
			IsStatic: true,
		})
	}

	executor.run()
	return nil
}

func (b *blockExecutor) runBlock(bind *RawData, functionRef *Primitive, args []*Primitive, ref uint64) (*RawData, uint64, error) {
	if bind != nil && bind.Value == nil && bind.Type != types.Nil {
		return &RawData{Type: bind.Type, Value: nil}, 0, nil
	}

	typ := types.Type(functionRef.Type)
	if !typ.IsFunction() {
		return nil, 0, errors.New("called block with wrong function type")
	}
	fref, ok := functionRef.RefV2()
	if !ok {
		return nil, 0, errors.New("cannot retrieve function reference on block call")
	}

	block := b.ctx.code.Block(fref)
	if block == nil {
		return nil, 0, errors.New("block function is nil")
	}

	fargs := []*RawData{}
	if bind != nil {
		fargs = append(fargs, bind)
	}
	for i := range args {
		a, b, c := b.resolveValue(args[i], ref)
		if c != nil || b != 0 {
			return a, b, c
		}
		fargs = append(fargs, a)
	}

	err := b.runFunctionBlocks([][]*RawData{fargs}, fref, ref, func(results []arrayBlockCallResult, errs []error) {
		var err multierr.Errors
		err.Add(errs...)

		if len(results) > 0 {
			fun := b.ctx.code.Block(fref)
			if fun.SingleValue {
				res := results[0].entrypoints[b.ctx.code.Checksums[fun.Entrypoints[0]]].(*RawData)
				b.cache.Store(ref, &stepCache{
					Result: res,
				})
				b.triggerChain(ref, res)
				return
			}
		}

		data := results[0].toRawData()
		data.Error = err.Deduplicate()
		blockResult := data.Value.(map[string]any)

		if bind != nil && bind.Type.IsResource() {
			rr, ok := bind.Value.(Resource)
			if !ok {
				log.Warn().Msg("cannot cast resource to resource type")
			} else {
				blockResult["_"] = &RawData{
					Type:  bind.Type,
					Value: rr,
				}
			}
		}

		b.cache.Store(ref, &stepCache{
			Result:   data,
			IsStatic: true,
		})
		b.triggerChain(ref, data)
	})

	return nil, 0, err
}

func pargs2argmap(b *blockExecutor, ref uint64, args []*Primitive) (map[string]*Primitive, uint64, error) {
	if len(args) == 0 {
		return nil, 0, nil
	}

	res := make(map[string]*Primitive, len(args))
	var x *RawData
	var rref uint64
	var err error
	for i := 0; i+1 < len(args); i += 2 {
		k := args[i]
		if types.Type(k.Type) != types.String {
			return nil, 0, errors.New("incorrect argument type (caller keys should always be strings)")
		}

		key := k.RawData().Value.(string)

		// TODO: this is a tedious and slow approach, speed it up...
		x, rref, err = b.resolveValue(args[i+1], ref)
		if rref != 0 || err != nil {
			return nil, rref, err
		}
		res[key] = x.Result().Data
	}

	return res, 0, nil
}

func (b *blockExecutor) createResource(name string, binding uint64, f *Function, ref uint64) (*RawData, uint64, error) {
	runtime := b.ctx.runtime

	// A resource created off a binding belongs to whatever that binding belongs
	// to. That matters once a chain has crossed into another asset (ADR 031):
	// `container.running.file("/etc/os-release")` builds a `file` resource, and
	// building it here would read the file on the host that owns the query
	// rather than on the asset the chain reached. The field-read path routes on
	// the same rule; this is the resource-construction half of it.
	var foreign Runtime
	if binding != 0 {
		res, dref, err := b.resolveRef(binding, ref)
		if dref != 0 || err != nil {
			return res, dref, err
		}
		if res != nil {
			if bound, ok := res.Value.(RuntimeBoundResource); ok {
				if boundRuntime := bound.MqlRuntime(); boundRuntime != nil {
					runtime, foreign = boundRuntime, boundRuntime
				}
			}
		}
	}

	args, rref, err := pargs2argmap(b, ref, f.Args)
	if err != nil || rref != 0 {
		return nil, rref, err
	}

	resource, err := runtime.CreateResource(name, args)
	if err != nil {
		// A resource this build has never heard of, in a bundle that already
		// told us it was compiled against a newer provider, degrades exactly
		// like a missing field does. Handling only the field case would make
		// the behaviour depend on how far into a chain the gap falls.
		if data, degraded := b.degradeUnavailableResource(name, err); degraded {
			b.cache.Store(ref, &stepCache{Result: data, IsStatic: true})
			return data, 0, nil
		}

		// in case it's not something that requires later loading, store the error
		// so that consecutive steps can retrieve it cached
		if _, ok := err.(resources.NotReadyError); !ok {
			res := stepCache{
				Result: &RawData{
					Type:  types.Resource(name),
					Value: nil,
					Error: err,
				},
				IsStatic: true,
			}
			b.cache.Store(ref, &res)
		}

		return nil, 0, err
	}

	res := stepCache{
		Result: &RawData{
			Type: types.Resource(name),
			// Whatever is chained off this resource has to keep asking the
			// runtime that built it.
			Value: BindResource(resource, foreign),
		},
		IsStatic: true,
	}
	b.cache.Store(ref, &res)
	return res.Result, 0, nil
}

func (b *blockExecutor) runGlobalFunction(chunk *Chunk, f *Function, ref uint64) (*RawData, uint64, error) {
	h, ok := handleGlobalV2(chunk.Id)
	if ok {
		if h == nil {
			return nil, 0, errors.New("found function " + chunk.Id + " but no handler. this should not happen and points to an implementation error")
		}

		res, dref, err := h(b, f, ref)
		log.Trace().Msgf("exec> global: %s %+v = %#v", chunk.Id, f.Args, res)
		if res != nil {
			b.cache.Store(ref, &stepCache{Result: res})
		}
		return res, dref, err
	}

	return b.createResource(chunk.Id, 0, f, ref)
}

// connect references, calling `dst` if `src` is updated
func (b *blockExecutor) connectRef(src uint64, dst uint64) (*RawData, uint64, error) {
	if !b.isInMyBlock(src) || !b.isInMyBlock(dst) {
		panic("cannot connect refs across block boundaries: src=(" + b.refContext(src) + ") dst=(" + b.refContext(dst) + ")")
	}
	// connect the ref. If it is already connected, someone else already made this
	// call, so we don't have to follow up anymore
	if exists := b.calls.Store(src, dst); exists {
		return nil, 0, nil
	}

	// if the ref was not yet connected, we must run the src ref after we connected it
	return nil, src, nil
}

func (e *blockExecutor) runFunction(chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	f := chunk.Function
	if f == nil {
		f = &emptyFunction
	}

	// global functions, for now only resources
	if f.Binding == 0 {
		return e.runGlobalFunction(chunk, f, ref)
	}

	// check if the bound value exists, otherwise connect it
	res, dref, err := e.resolveRef(f.Binding, ref)
	if res == nil {
		return res, dref, err
	}

	if res.Error != nil {
		// The data type that this chunk requests needs to be matched. If the
		// chunk was supposed to transform e.g. a []T into a T, then we need to
		// make sure that the result type - even if it's an error - is set to T.
		typ := f.Type
		if typ == "" {
			typ = string(res.Type)
		}

		e.cache.Store(ref, &stepCache{
			Result: &RawData{
				Type:  types.Type(typ),
				Value: res.Value,
				Error: res.Error,
			},
		})
		return nil, 0, res.Error
	}

	return e.runBoundFunction(res, chunk, ref)
}

func (e *blockExecutor) runChunk(chunk *Chunk, ref uint64) (*RawData, uint64, error) {
	switch chunk.Call {
	case Chunk_PRIMITIVE:
		res, dref, err := e.resolveValue(chunk.Primitive, ref)
		if res != nil {
			e.cache.Store(ref, &stepCache{Result: res})
		} else if err != nil {
			e.cache.Store(ref, &stepCache{Result: &RawData{
				Error: err,
			}})
		}

		return res, dref, err
	case Chunk_FUNCTION:
		return e.runFunction(chunk, ref)

	case Chunk_PROPERTY:
		property, ok := e.ctx.props[chunk.Id]
		if !ok {
			return nil, 0, errors.New("cannot find property '" + chunk.Id + "'")
		}

		res, dref, err := e.resolveValue(property, ref)
		if dref != 0 || err != nil {
			return res, dref, err
		}
		e.cache.Store(ref, &stepCache{Result: res})
		return res, dref, err

	default:
		return nil, 0, errors.New("Tried to run a chunk which has an unknown type: " + chunk.Call.String())
	}
}

func (e *blockExecutor) runRef(ref uint64) (*RawData, uint64, error) {
	chunk := e.ctx.code.Chunk(ref)
	if chunk == nil {
		return nil, 0, errors.New("Called a chunk that doesn't exist, ref = " + strconv.FormatInt(int64(ref), 10))
	}
	return e.runChunk(chunk, ref)
}

// runChain starting at a ref of the code, follow it down and report
// jever result it has at the end of its execution. this will register
// async callbacks against referenced chunks too
func (e *blockExecutor) runChain(start uint64) {
	var res *RawData
	var err error
	nextRef := start
	var curRef uint64
	var remaining []uint64

	for nextRef != 0 {
		curRef = nextRef
		e.stepTracker.Store(curRef, nil)
		// log.Trace().Uint64("ref", curRef).Msg("exec> run chain")

		// Try to load the result from cache if it already exists. This was added
		// so that blocks that are called on top of a binding, where the results
		// for the binding are pre-loaded, are actually read from cache. Typically
		// follow-up calls would try to load from cache and would get the correct
		// value, however if there are no follow-up calls we still want to return
		// the correct value.
		// This may be optimized in a way that we don't have to check loading it
		// on every call.
		cached, ok := e.cache.Load(curRef)
		if ok {
			res = cached.Result
			nextRef = 0
			err = nil
		} else {
			res, nextRef, err = e.runRef(curRef)
		}

		// stop this chain of execution, if it didn't return anything and
		// there is nothing else left to process
		// we need more data ie an event to provide info
		if res == nil && nextRef == 0 && err == nil && len(remaining) == 0 {
			log.Trace().Uint64("ref", curRef).Msg("exec> stop chain")
			return
		}

		// if this is a result for a callback (entry- or datapoint) send it
		if res != nil {
			if codeID, ok := e.callbackPoints[curRef]; ok {
				e.callback(&RawResult{Data: e.resultWithCoverageGaps(curRef, e.markTranslated(curRef, res)), CodeID: codeID})
			}
		} else if err != nil {
			if codeID, ok := e.callbackPoints[curRef]; ok {
				e.callback(errorResult(err, codeID))
			}
			if _, isNotReadyError := err.(resources.NotReadyError); !isNotReadyError {
				if sc, _ := e.cache.Load(curRef); sc == nil {
					e.cache.Store(curRef, &stepCache{
						Result: &RawData{
							Type:  types.Unset,
							Value: nil,
							Error: err,
						},
					})
				}
			}
		}

		// get the next reference, if we are not directed anywhere
		if nextRef == 0 {
			// note: if the call cannot be retrieved it will use the
			// zero value, which is 0 in this case; i.e. if !ok => ref = 0
			nextRefs, _ := e.calls.Load(curRef)
			cnt := len(nextRefs)
			if cnt != 0 {
				nextRef = nextRefs[0]
				remaining = append(remaining, nextRefs[1:]...)
				continue
			}

			cnt = len(remaining)
			if cnt == 0 {
				break
			}
			nextRef = remaining[0]
			remaining = remaining[1:]
		}
	}
}

// triggerChain when a reference has a new value set
// unlike runChain this will not execute the ref chunk, but rather
// try to move to the next called chunk - or if it's not available
// handle the result
func (e *blockExecutor) triggerChain(ref uint64, data *RawData) {
	// before we do anything else, we may have to provide the value from
	// this callback point
	if codeID, ok := e.callbackPoints[ref]; ok {
		e.callback(&RawResult{Data: e.resultWithCoverageGaps(ref, e.markTranslated(ref, data)), CodeID: codeID})
	}

	nxt, ok := e.calls.Load(ref)
	if ok {
		if len(nxt) == 0 {
			panic("internal state error: cannot trigger next call on chain because it points to a zero ref: " + e.refContext(ref))
		}
		for i := range nxt {
			e.runChain(nxt[i])
		}
		return
	}

	codeID := e.callbackPoints[ref]
	res, ok := e.cache.Load(ref)
	if !ok {
		e.callback(errorResultMsg("exec> cannot find results to chunk reference "+strconv.FormatInt(int64(ref), 10), codeID))
		return
	}

	log.Trace().Uint64("ref", ref).Msgf("exec> trigger callback")
	e.callback(&RawResult{Data: e.resultWithCoverageGaps(ref, e.markTranslated(ref, res.Result)), CodeID: codeID})
}

func (e *blockExecutor) triggerChainError(ref uint64, err error) {
	cur := ref
	var remaining []uint64
	for cur > 0 {
		if codeID, ok := e.callbackPoints[cur]; ok {
			e.callback(&RawResult{
				Data: &RawData{
					Error: err,
				},
				CodeID: codeID,
			})
		}

		nxt, ok := e.calls.Load(cur)
		if !ok {
			if len(remaining) == 0 {
				break
			}
			nxt = []uint64{remaining[0]}
			remaining = remaining[1:]
		}
		if len(nxt) == 0 {
			panic("internal state error: cannot trigger next call on chain because it points to a zero ref: " + e.refContext(cur))
		}
		cur = nxt[0]
		remaining = append(remaining, nxt[1:]...)
	}
}
