// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
	"golang.org/x/sync/singleflight"
)

type Runtime struct {
	Connection     Connection
	Resources      Resources[Resource]
	Callback       ProviderCallback
	HasRecording   bool
	CreateResource CreateNamedResource
	NewResource    NewResource
	GetData        GetData
	SetData        SetData
	Upstream       *upstream.UpstreamClient

	// initFlights collapses concurrent resolutions of the same resource into a
	// single run of its init function. See ResolveResource. Its zero value is
	// ready to use, so runtimes built as struct literals get it for free.
	initFlights singleflight.Group

	// sharedFlights points at the group of the runtime this one inherited its
	// resource cache from, so that a family of connections deduplicates against
	// each other exactly as far as it shares results. Nil means this runtime
	// owns its flights; see flights.
	sharedFlights *singleflight.Group
}

// flights returns the group this runtime resolves through. A child connection
// that inherited a parent's Resources must also inherit its flights: the two
// have to agree on scope, or sibling assets scanned in parallel would each run
// the same init and then race to publish into the one cache they share.
func (r *Runtime) flights() *singleflight.Group {
	if r.sharedFlights != nil {
		return r.sharedFlights
	}
	return &r.initFlights
}

// InheritResourceCacheFrom points this runtime at another runtime's resource
// cache, and at the flights that keep that cache consistent. Used when a child
// connection is opened under a parent that has already resolved resources the
// child would otherwise fetch again.
func (r *Runtime) InheritResourceCacheFrom(parent *Runtime) {
	r.Resources = parent.Resources
	r.sharedFlights = parent.flights()
}

func NewRuntime(
	conn Connection,
	callback ProviderCallback,
	hasRecording bool,
	createResource CreateNamedResource,
	newResource NewResource,
	getData GetData,
	setData SetData,
	upstream *upstream.UpstreamClient,
) *Runtime {
	return &Runtime{
		Connection:     conn,
		Resources:      &syncx.Map[Resource]{},
		Callback:       callback,
		HasRecording:   hasRecording,
		CreateResource: createResource,
		NewResource:    newResource,
		GetData:        getData,
		SetData:        setData,
		Upstream:       upstream,
	}
}

type (
	CreateNamedResource func(runtime *Runtime, name string, args map[string]*llx.RawData) (Resource, error)
	NewResource         func(runtime *Runtime, name string, args map[string]*llx.RawData) (Resource, error)
	GetData             func(resource Resource, field string, args map[string]*llx.RawData) *DataRes
	SetData             func(resource Resource, field string, val *llx.RawData) error
)

type Resource interface {
	MqlID() string
	MqlName() string
}

func (r *Runtime) ResourceFromRecording(name string, id string) (map[string]*llx.RawData, error) {
	data, err := r.Callback.GetRecording(&DataReq{
		Resource:   name,
		ResourceId: id,
	})
	if err != nil || data == nil {
		return nil, err
	}

	// We don't want resources at this stage, because they have to be requested and
	// initialized recursively. Instead callers can request these fields from the
	// recording and initialize them.
	// TODO: we could use the provided information for a later request.
	for k, v := range data.Fields {
		if types.Type(v.Data.Type).ContainsResource() {
			delete(data.Fields, k)
		}
	}

	return ProtoArgsToRawDataArgs(data.Fields)
}

// FieldResourceFromRecording loads a field which is a resource from a recording.
// These are not immediately initialized when the recording is loaded, to avoid
// having to recursively initialize too many things that won't be used. Once
// it's time, this function is called to initialize the resource.
func (r *Runtime) FieldResourceFromRecording(resource string, id string, field string) (*llx.RawData, error) {
	data, err := r.Callback.GetRecording(&DataReq{
		Resource:   resource,
		ResourceId: id,
		Field:      field,
	})
	if err != nil || data == nil {
		return nil, err
	}

	fieldObj, ok := data.Fields[field]
	if !ok {
		return nil, nil
	}

	raw := fieldObj.RawData()
	raw.Value, err = r.initResourcesFromRecording(raw.Value, raw.Type)
	return raw, err
}

func (r *Runtime) initResourcesFromRecording(val any, typ types.Type) (any, error) {
	switch {
	case typ.IsArray():
		arr := val.([]any)
		ct := typ.Child()
		var err error
		for i := range arr {
			arr[i], err = r.initResourcesFromRecording(arr[i], ct)
			if err != nil {
				return nil, err
			}
		}
		return arr, nil

	case typ.IsMap():
		m := val.(map[string]any)
		ct := typ.Child()
		var err error
		for k, v := range m {
			m[k], err = r.initResourcesFromRecording(v, ct)
			if err != nil {
				return nil, err
			}
		}
		return m, nil

	case typ.IsResource():
		// It has to be a mock resource if we loaded it from recording.
		// We also do this as a kind of safety check (instead of using the interface)
		resource := val.(*llx.MockResource)
		args, err := r.ResourceFromRecording(resource.Name, resource.ID)
		if err != nil {
			return nil, err
		}

		return r.CreateResource(r, resource.Name, args)

	default:
		return val, nil
	}
}

func (r *Runtime) CreateSharedResource(resource string, args map[string]*llx.RawData) (Resource, error) {
	pargs, err := RawDataArgsToPrimitiveArgs(args)
	if err != nil {
		return nil, err
	}

	res, err := r.Callback.GetData(&DataReq{
		Resource: resource,
		Args:     pargs,
	})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(res.Error)
	}
	raw := res.Data.RawData()
	if !raw.Type.IsResource() {
		return nil, errors.New("failed to create shared resource '" + resource + "' (non-resource return)")
	}
	return raw.Value.(Resource), nil
}

func (r *Runtime) GetSharedData(resource string, resourceID string, field string) (*llx.RawData, error) {
	res, err := r.Callback.GetData(&DataReq{
		Resource:   resource,
		ResourceId: resourceID,
		Field:      field,
	})
	if err != nil {
		return nil, err
	}

	if res.Error != "" {
		return nil, errors.New(res.Error)
	}
	return res.Data.RawData(), nil
}

type TValue[T any] struct {
	Data  T
	State State
	Error error
}

func (x *TValue[T]) ToDataRes(typ types.Type) *DataRes {
	if !x.IsSet() {
		return &DataRes{}
	}
	if x.IsNull() {
		if x.Error != nil {
			return &DataRes{
				Error: x.Error.Error(),
				Data:  &llx.Primitive{Type: string(typ)},
			}
		}

		return &DataRes{
			Data: &llx.Primitive{Type: string(types.Nil)},
		}
	}
	raw := llx.RawData{Type: typ, Value: x.Data, Error: x.Error}
	res := raw.Result()
	return &DataRes{Data: res.Data, Error: res.Error}
}

func PrimitiveToTValue[T any](p *llx.Primitive) TValue[T] {
	raw := p.RawData()
	if raw.Value == nil {
		return TValue[T]{State: StateIsNull}
	}
	return TValue[T]{Data: raw.Value.(T), State: StateIsSet}
}

// RawToTValue converts a raw (any) value into a typed value
// and returns true if the type was correct.
func RawToTValue[T any](value any, err error) (TValue[T], bool) {
	if value == nil {
		return TValue[T]{State: StateIsNull | StateIsSet, Error: err}, true
	}

	tv, ok := value.(T)
	if !ok {
		return TValue[T]{}, false
	}

	return TValue[T]{Data: tv, State: StateIsSet, Error: err}, true
}

type State byte

type notReady struct{}

func (n notReady) Error() string {
	return "NotReady"
}

var NotReady = notReady{}

func (x *TValue[T]) IsSet() bool {
	return x.State&StateIsSet != 0
}

func (x *TValue[T]) IsNull() bool {
	return x.State&StateIsNull != 0
}

const (
	StateIsSet State = 0x1 << iota
	StateIsNull
)

func GetOrCompute[T any](cached *TValue[T], compute func() (T, error)) *TValue[T] {
	if cached.IsSet() {
		return cached
	}

	x, err := compute()
	if err != nil {
		res := &TValue[T]{Data: x, Error: err}
		if err != NotReady {
			res.State = StateIsSet | StateIsNull
			(*cached) = *res
		}
		return res
	}

	// this only happens if the function set the field proactively, in which
	// case we grab the value from the cached entry for consistency
	if cached.IsSet() {
		return cached
	}

	(*cached) = TValue[T]{Data: x, State: StateIsSet, Error: err}
	return cached
}

func PrimitiveArgsToRawDataArgs(pargs map[string]*llx.Primitive, runtime *Runtime) map[string]*llx.RawData {
	res := make(map[string]*llx.RawData, len(pargs))
	for k, v := range pargs {
		// If it's an internal resource to this runtime, we need to look it up,
		// since we are only handed references to resources, never the native
		// resources themselves. Resources must exist before referencing them.
		if typ := types.Type(v.Type); typ.IsResource() {
			name := typ.ResourceName()
			id := string(v.Value)
			resource, _ := runtime.Resources.Get(name + "\x00" + id)
			if resource != nil {
				res[k] = llx.ResourceData(resource, name)
				continue
			}
			// If it's not an internal resource, we can only reference it vv
		}

		res[k] = v.RawData()
	}
	return res
}

func RawDataArgsToPrimitiveArgs(pargs map[string]*llx.RawData) (map[string]*llx.Primitive, error) {
	res := make(map[string]*llx.Primitive, len(pargs))
	for k, v := range pargs {
		vr := v.Result()
		if vr.Error != "" {
			return nil, errors.New("failed to serialize, error in raw data '" + k + "'")
		}

		res[k] = vr.Data
	}
	return res, nil
}

func ProtoArgsToRawDataArgs(pargs map[string]*llx.Result) (map[string]*llx.RawData, error) {
	res := make(map[string]*llx.RawData, len(pargs))
	var err error
	for k, v := range pargs {
		res[k] = v.RawData()
	}

	return res, err
}

func NonErrorArgs(pargs map[string]*llx.RawData) map[string]*llx.RawData {
	if len(pargs) == 0 {
		return map[string]*llx.RawData{}
	}

	res := map[string]*llx.RawData{}
	for k, v := range pargs {
		if v.Error != nil {
			continue
		}
		res[k] = v
	}
	return res
}
