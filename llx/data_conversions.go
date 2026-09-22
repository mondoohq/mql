// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/types"
	"google.golang.org/protobuf/proto"
)

type (
	dataConverter      func(any, types.Type) (*Primitive, error)
	primitiveConverter func(*Primitive) *RawData
)

var (
	dataConverters      map[types.Type]dataConverter
	primitiveConverters map[types.Type]primitiveConverter
)

func init() {
	dataConverters = map[types.Type]dataConverter{
		types.Unset:        unset2result,
		types.Nil:          nil2result,
		types.Bool:         bool2result,
		types.Int:          int2result,
		types.Float:        float2result,
		types.String:       string2result,
		types.Regex:        regex2result,
		types.Time:         time2result,
		types.Dict:         dict2result,
		types.Score:        score2result,
		types.Empty:        empty2result,
		types.Block:        block2result,
		types.Version:      version2result,
		types.IP:           ip2result,
		types.ArrayLike:    array2result,
		types.MapLike:      map2result,
		types.ResourceLike: resource2result,
		types.FunctionLike: function2result,
		types.Range:        range2result,
		types.AssetLike:    asset2result,
	}

	primitiveConverters = map[types.Type]primitiveConverter{
		types.Unset:        punset2raw,
		types.Nil:          pnil2raw,
		types.Bool:         pbool2raw,
		types.Int:          pint2raw,
		types.Float:        pfloat2raw,
		types.String:       pstring2raw,
		types.Regex:        pregex2raw,
		types.Time:         ptime2raw,
		types.Dict:         pdict2raw,
		types.Score:        pscore2raw,
		types.Empty:        pempty2raw,
		types.Block:        pblock2rawV2,
		types.Version:      pversion2raw,
		types.IP:           pip2raw,
		types.ArrayLike:    parray2raw,
		types.MapLike:      pmap2raw,
		types.ResourceLike: presource2raw,
		types.FunctionLike: pfunction2raw,
		types.Ref:          pref2raw,
		types.Range:        prange2raw,
		types.AssetLike:    passet2raw,
	}
}

func dict2primitive(value any) (*Primitive, error) {
	if value == nil {
		return NilPrimitive, nil
	}

	switch x := value.(type) {
	case bool:
		return BoolPrimitive(x), nil
	case int64:
		return IntPrimitive(x), nil
	case float64:
		return FloatPrimitive(x), nil
	case string:
		return StringPrimitive(x), nil
	case []any:
		res := make([]*Primitive, len(x))
		var err error
		for i := range x {
			res[i], err = dict2primitive(x[i])
			if err != nil {
				return nil, err
			}
		}
		return &Primitive{Type: string(types.Array(types.Dict)), Array: res}, nil

	case map[string]any:
		res := make(map[string]*Primitive, len(x))
		var err error
		for k, v := range x {
			res[k], err = dict2primitive(v)
			if err != nil {
				return nil, err
			}
		}
		return &Primitive{Type: string(types.Map(types.String, types.Dict)), Map: res}, nil

	default:
		return nil, errors.New("failed to convert dict to primitive, unsupported child type: " + reflect.TypeOf(x).String())
	}
}

func primitive2dictV2(p *Primitive) (any, error) {
	switch types.Type(p.Type).Underlying() {
	case types.Nil:
		return nil, nil
	case types.Bool:
		return bytes2bool(p.Value), nil
	case types.Int:
		return bytes2int(p.Value), nil
	case types.Float:
		return bytes2float(p.Value), nil
	case types.String:
		return string(p.Value), nil
	case types.ArrayLike:
		d, _, err := primitive2array(nil, 0, p.Array)
		return d, err
	case types.MapLike:
		m, err := primitive2mapV2(p.Map)
		return m, err
	default:
		hexType := make([]byte, hex.EncodedLen(len(p.Type)))
		hex.Encode(hexType, []byte(p.Type))
		return nil, errors.New("unknown type to convert dict primitive back to raw data (" + string(hexType) + ")")
	}
}

func unset2result(value any, typ types.Type) (*Primitive, error) {
	return UnsetPrimitive, nil
}

func nil2result(value any, typ types.Type) (*Primitive, error) {
	return NilPrimitive, nil
}

func errInvalidConversion(value any, expectedType types.Type) error {
	return fmt.Errorf("could not convert %T to %s", value, expectedType.Label())
}

func bool2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(bool)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	return BoolPrimitive(v), nil
}

func int2result(value any, typ types.Type) (*Primitive, error) {
	if v, ok := value.(int64); ok {
		return IntPrimitive(v), nil
	}
	// try to convert float64, which happens when we load this from JSON
	if v, ok := value.(float64); ok {
		return IntPrimitive(int64(v)), nil
	}
	return nil, errInvalidConversion(value, typ)
}

func float2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(float64)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	return FloatPrimitive(v), nil
}

func string2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(string)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	p := StringPrimitive(v)
	// special case for version
	p.Type = string(typ)
	return p, nil
}

func regex2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(string)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	return RegexPrimitive(v), nil
}

func time2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(*time.Time)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	return TimePrimitive(v), nil
}

func dict2result(value any, typ types.Type) (*Primitive, error) {
	prim, err := dict2primitive(value)
	if err != nil {
		return nil, err
	}

	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(prim)
	if err != nil {
		return nil, err
	}

	return &Primitive{Type: string(types.Dict), Value: raw}, nil
}

// The primitive keeps the full asset type, root and all: `asset<mcp>` is what
// lets the reader chain off the value, so dropping the parameter here would turn
// every asset that crosses the wire back into an unchainable bare reference.
func asset2result(value any, typ types.Type) (*Primitive, error) {
	if value == nil {
		return &Primitive{Type: string(typ)}, nil
	}
	v, ok := value.(*AssetValue)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	if v == nil {
		return &Primitive{Type: string(typ)}, nil
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(v)
	if err != nil {
		return nil, err
	}
	return &Primitive{Type: string(typ), Value: raw}, nil
}

func passet2raw(p *Primitive) *RawData {
	typ := types.Type(p.Type)
	if len(p.Value) == 0 {
		return &RawData{Type: typ, Value: (*AssetValue)(nil)}
	}
	v := AssetValue{}
	if err := proto.Unmarshal(p.Value, &v); err != nil {
		return &RawData{Error: err, Type: typ}
	}
	return &RawData{Type: typ, Value: &v}
}

func score2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.([]byte)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	return &Primitive{
		Type:  string(types.Score),
		Value: v,
	}, nil
}

func empty2result(value any, typ types.Type) (*Primitive, error) {
	return EmptyPrimitive, nil
}

func block2result(value any, typ types.Type) (*Primitive, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	res := make(map[string]*Primitive)

	for k, v := range m {
		raw, ok := v.(*RawData)
		if !ok {
			return nil, errInvalidConversion(value, typ)
		}
		res[k] = raw.Result().Data
	}
	return &Primitive{Type: string(typ), Map: res}, nil
}

func version2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(string)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	p := StringPrimitive(v)
	// special case for version
	p.Type = string(typ)
	return p, nil
}

func ip2result(value any, typ types.Type) (*Primitive, error) {
	m, ok := value.(RawIP)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}

	res, err := m.Marshal()
	return &Primitive{Type: string(typ), Value: res}, err
}

func array2result(value any, typ types.Type) (*Primitive, error) {
	arr, ok := value.([]any)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	res := make([]*Primitive, len(arr))
	ct := typ.Child()
	if ct.NotSet() {
		ct = types.Unset
	}
	var err error
	for i := range arr {
		res[i], err = raw2primitive(arr[i], ct)
		if err != nil {
			return nil, err
		}
	}
	return &Primitive{Type: string(typ), Array: res}, nil
}

func stringmap2result(value any, typ types.Type) (*Primitive, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	res := make(map[string]*Primitive)
	ct := typ.Child()
	var err error
	for k, v := range m {
		res[k], err = raw2primitive(v, ct)
		if err != nil {
			return nil, err
		}
	}
	return &Primitive{Type: string(typ), Map: res}, nil
}

func intmap2result(value any, typ types.Type) (*Primitive, error) {
	m, ok := value.(map[int64]any)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	res := make(map[string]*Primitive)
	ct := typ.Child()
	var err error
	for k, v := range m {
		res[strconv.FormatInt(k, 10)], err = raw2primitive(v, ct)
		if err != nil {
			return nil, err
		}
	}
	return &Primitive{Type: string(typ), Map: res}, nil
}

func map2result(value any, typ types.Type) (*Primitive, error) {
	if len(typ) < 2 {
		switch value.(type) {
		case map[string]any:
			return stringmap2result(value, types.Map(types.String, types.Unset))
		case map[int64]any:
			return intmap2result(value, types.Map(types.Int, types.Unset))
		default:
			return nil, errors.New("cannot serialize map with unknown key type: " + typ.Label())
		}
	}
	switch typ.Key() {
	case types.String:
		return stringmap2result(value, typ)
	case types.Int:
		return intmap2result(value, typ)
	default:
		return nil, errors.New("only supports turning string or int maps into primitives, not " + typ.Label())
	}
}

func resource2result(value any, typ types.Type) (*Primitive, error) {
	m, ok := value.(Resource)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	return &Primitive{Type: string(typ), Value: []byte(m.MqlID())}, nil
}

func function2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(uint64)
	if ok {
		return FunctionPrimitive(v), nil
	}
	return nil, errInvalidConversion(value, typ)
}

func range2result(value any, typ types.Type) (*Primitive, error) {
	v, ok := value.(Range)
	if !ok {
		return nil, errInvalidConversion(value, typ)
	}
	return RangePrimitive(v), nil
}

func raw2primitive(value any, typ types.Type) (*Primitive, error) {
	if value == nil {
		// there are only few types whose value is allowed to be nil
		switch typ {
		case types.Unset:
			return UnsetPrimitive, nil
		default:
			return NilPrimitive, nil
		}
	}

	if typ.NotSet() {
		return nil, errors.New("cannot serialize value of unknown type")
	}

	utyp := typ.Underlying()
	c, ok := dataConverters[utyp]
	if !ok {
		rdata, ok := value.(*RawData)
		if ok {
			return raw2primitive(rdata.Value, rdata.Type)
		}
		return nil, errors.New("cannot serialize data type " + typ.Label())
	}
	return c(value, typ)
}

// Result converts the raw data into a proto-compliant data structure that
// can be sent over the wire. It converts the any value of RawData
// into a []byte structure that is easily serializable
func (r *RawData) Result() *Result {
	errorMsg := ""
	// The kind rides beside the message rather than inside it, so that a
	// consumer reads a classification instead of parsing text (ADR 046). It is
	// nil for every unclassified error, which is most of them today.
	errorDetail := ErrorDetailOf(r.Error)

	// In case we encounter an error we need to still construct the result object
	// with the type information so it can be processed by the server
	if r.Error != nil {
		errorMsg = r.Error.Error()

		// if the value is nil, we don't want to loose the type information,
		// so we return it early before raw2primitive has a chance to change the
		// type to nil
		if r.Value == nil {
			return &Result{
				Data:        &Primitive{Type: string(r.Type)},
				Error:       errorMsg,
				ErrorDetail: errorDetail,
			}
		}
	}

	data, err := raw2primitive(r.Value, r.Type)
	if err != nil {
		// If we already have an error on record, we just return that instead.
		// This typically only happens when the above check for Value==nil cannot
		// be determined, because it is hidden behind an any. See:
		// https://stackoverflow.com/questions/43059653/golang-interfacenil-is-nil-or-not
		if errorMsg == "" {
			errorMsg = err.Error()
		}
		return &Result{
			Data:        &Primitive{Type: string(r.Type)},
			Error:       errorMsg,
			ErrorDetail: errorDetail,
		}
	}
	return &Result{
		Data:        data,
		Error:       errorMsg,
		ErrorDetail: errorDetail,
	}
}

func (r *RawData) CastResult(t types.Type) (*Result, error) {
	errorMsg := ""
	errorDetail := ErrorDetailOf(r.Error)

	// In case we encounter an error we need to still construct the result object
	// with the type information so it can be processed by the server
	if r.Error != nil {
		errorMsg = r.Error.Error()
	}

	// Allow any type to take on nil values
	if r.Value == nil {
		return &Result{
			Data:        &Primitive{Type: string(t)},
			Error:       errorMsg,
			ErrorDetail: errorDetail,
		}, nil
	}

	if t == types.Bool {
		truthy, castable := r.IsTruthy()
		if !castable {
			return nil, fmt.Errorf("cannot cast from %s to %s", r.Type.Label(), t.Label())
		}
		return &Result{
			Data:        BoolPrimitive(truthy),
			Error:       errorMsg,
			ErrorDetail: errorDetail,
		}, nil
	}

	data, err := raw2primitive(r.Value, t)
	if err != nil {
		return nil, err
	}
	return &Result{
		Data:        data,
		Error:       errorMsg,
		ErrorDetail: errorDetail,
	}, nil
}

func (r *RawResult) CastResult(t types.Type) *Result {
	res, err := r.Data.CastResult(t)
	if err != nil {
		return &Result{
			CodeId: r.CodeID,
			Data:   &Primitive{Type: string(t)},
			Error:  err.Error(),
		}
	}
	res.CodeId = r.CodeID
	return res
}

// Result converts the raw result into a proto-compliant data structure that
// can be sent over the wire. See RawData.Result()
func (r *RawResult) Result() *Result {
	res := r.Data.Result()
	res.CodeId = r.CodeID
	return res
}

func (r *Result) RawResultV2() *RawResult {
	if r == nil {
		return nil
	}

	res := &RawResult{
		Data: r.RawData(),
	}
	res.CodeID = r.CodeId
	return res
}

func (r *Result) RawData() *RawData {
	if r == nil {
		return nil
	}

	data := &RawData{}
	if r.Data != nil {
		// The type can be empty, when we do not have data
		if r.Data.IsNil() || types.Type(r.Data.Type).NotSet() {
			data.Type = types.Nil
		} else {
			data = r.Data.RawData()
		}
	}
	// Rebuild the classified error rather than an anonymous one, so a kind
	// survives a recording replay and a round trip through upstream storage
	// (ADR 046). An unclassified error comes back exactly as before.
	if err := ErrorFromDetail(r.Error, r.ErrorDetail); err != nil {
		data.Error = err
	}
	return data
}

func punset2raw(p *Primitive) *RawData {
	return UnsetData
}

func pnil2raw(p *Primitive) *RawData {
	return NilData
}

func pbool2raw(p *Primitive) *RawData {
	if len(p.Value) == 0 {
		return &RawData{
			Type:  types.Type(p.Type),
			Value: false,
		}
	}
	return BoolData(bytes2bool(p.Value))
}

func pint2raw(p *Primitive) *RawData {
	if len(p.Value) == 0 {
		return &RawData{
			Type:  types.Type(p.Type),
			Value: int64(0),
		}
	}
	return IntData(bytes2int(p.Value))
}

func pfloat2raw(p *Primitive) *RawData {
	if len(p.Value) == 0 {
		return &RawData{
			Type:  types.Type(p.Type),
			Value: float64(0),
		}
	}
	return FloatData(bytes2float(p.Value))
}

func pstring2raw(p *Primitive) *RawData {
	return StringData(string(p.Value))
}

func pregex2raw(p *Primitive) *RawData {
	return RegexData(string(p.Value))
}

func ptime2raw(p *Primitive) *RawData {
	if len(p.Value) == 0 {
		t := time.Unix(0, 0)
		return &RawData{
			Type:  types.Type(p.Type),
			Value: &t,
		}
	}
	return TimeData(bytes2time(p.Value))
}

func pdict2raw(p *Primitive) *RawData {
	if p.Value == nil {
		return &RawData{
			Type:  types.Dict,
			Value: nil,
		}
	}

	res := Primitive{} // unmarshal placeholder
	err := proto.Unmarshal(p.Value, &res)
	if err != nil {
		return &RawData{Error: err, Type: types.Dict}
	}

	raw, err := primitive2dictV2(&res)
	return &RawData{Error: err, Type: types.Dict, Value: raw}
}

func pscore2raw(p *Primitive) *RawData {
	if len(p.Value) == 0 {
		return &RawData{
			Value: int64(0),
			Type:  types.Score,
		}
	}
	return &RawData{Value: p.Value, Type: types.Score}
}

func pempty2raw(p *Primitive) *RawData {
	return &RawData{Type: types.Type(p.Type)}
}

func pblock2rawV2(p *Primitive) *RawData {
	d, err := primitive2rawdataMapV2(p.Map)
	return &RawData{Value: d, Error: err, Type: types.Type(p.Type)}
}

func pversion2raw(p *Primitive) *RawData {
	return VersionData(string(p.Value))
}

func pip2raw(p *Primitive) *RawData {
	ip, err := UnmarshalIP(p.Value)
	if err != nil || ip == nil {
		return &RawData{Error: err, Type: types.IP}
	}
	return IPData(*ip)
}

func parray2raw(p *Primitive) *RawData {
	// Note: We don't hand over the compiler here. Reason is that if you have
	// primitives that have refs in them, you should properly resolve them
	// during the execution of the code. This function is really only applicable
	// much later when you try to just get to the values of the returned data.
	d, _, err := primitive2array(nil, 0, p.Array)
	if d == nil {
		d = []any{}
	}
	return &RawData{Value: d, Error: err, Type: types.Type(p.Type)}
}

func pmap2raw(p *Primitive) *RawData {
	d, err := primitive2mapV2(p.Map)
	return &RawData{Value: d, Error: err, Type: types.Type(p.Type)}
}

func presource2raw(p *Primitive) *RawData {
	id := string(p.Value)
	typ := types.Type(p.Type)
	return &RawData{Value: &MockResource{
		Name: typ.ResourceName(),
		ID:   id,
	}, Type: typ}
}

func pfunction2raw(p *Primitive) *RawData {
	// note: function pointers can never have a value that is nil
	rv := bytes2int(p.Value)
	if rv>>32 != 0 {
		return &RawData{Value: uint64(bytes2int(p.Value)), Type: types.Type(p.Type)}
	} else {
		return &RawData{Value: int32(bytes2int(p.Value)), Type: types.Type(p.Type)}
	}
}

func pref2raw(p *Primitive) *RawData {
	// note: refs can never have a value that is nil
	rv := bytes2int(p.Value)
	if rv>>32 != 0 {
		return &RawData{Value: uint64(bytes2int(p.Value)), Type: types.Type(p.Type)}
	} else {
		return &RawData{Value: int32(bytes2int(p.Value)), Type: types.Type(p.Type)}
	}
}

func prange2raw(p *Primitive) *RawData {
	return RangeData(p.Value)
}

// Tries to resolve primitives; returns refs if they don't exist yet.
// Returns nil and a ref != 0 if a value needs resolving.
func primitive2array(b *blockExecutor, ref uint64, args []*Primitive) ([]any, uint64, error) {
	if args == nil {
		return []any{}, 0, nil
	}

	res := make([]any, len(args))
	for i := range args {
		var cur *RawData

		if b != nil && types.Type(args[i].Type) == types.Ref {
			var rref uint64
			var err error
			cur, rref, err = b.resolveValue(args[i], ref)
			if rref > 0 || err != nil {
				return nil, rref, err
			}
		} else {
			cur = args[i].RawData()
		}

		if cur != nil {
			if cur.Error != nil {
				// In execution mode (b != nil) a bad element is a real
				// computation error and must propagate. During late value
				// extraction (b == nil) it must not: discarding the whole
				// collection here is what let one malformed element empty an
				// entire array and surface as an empty assessment. Log it and
				// null out just that element instead.
				if b != nil {
					return nil, 0, cur.Error
				}
				log.Error().Err(cur.Error).Int("index", i).Msg("llx: dropping malformed array element during value conversion, coercing to null")
				res[i] = nil
				continue
			}
			res[i] = cur.Value
		}
	}
	return res, 0, nil
}

// Converts a map of primitives into a map of go data (no type info).
// Return map is never nil.
func primitive2mapV2(m map[string]*Primitive) (map[string]any, error) {
	if m == nil {
		return map[string]any{}, nil
	}

	res := make(map[string]any)
	for k, v := range m {
		if v == nil {
			res[k] = nil
			continue
		}
		cur := v.RawData()
		if cur.Error != nil {
			// Loud-and-narrow: a single malformed element must not discard the
			// whole map. Log it and null out just this key. (Previously this
			// propagated up and the surrounding collection was emptied.)
			log.Error().Err(cur.Error).Str("key", k).Msg("llx: dropping malformed map element during value conversion, coercing to null")
			res[k] = nil
			continue
		}
		res[k] = cur.Value
	}
	return res, nil
}

// Converts a map of primitives into a map of RawData (to preserve type-info).
// Return map is never nil.
func primitive2rawdataMapV2(m map[string]*Primitive) (map[string]any, error) {
	if m == nil {
		return map[string]any{}, nil
	}

	res := make(map[string]any)
	for k, v := range m {
		if v == nil {
			res[k] = nil
			continue
		}
		cur := v.RawData()
		if cur.Error != nil {
			// Loud-and-narrow: keep the erroring RawData under its key so the
			// error stays inspectable per-element, and log it — but never
			// discard the surrounding map because one element is malformed.
			log.Error().Err(cur.Error).Str("key", k).Msg("llx: malformed map element during value conversion, keeping per-key error")
		}
		res[k] = cur
	}
	return res, nil
}

// RawData converts the primitive into the internal go-representation of the
// data that can be used for computations
func (p *Primitive) RawData() *RawData {
	// A primitive with no type information is never produced deliberately (a
	// genuine null is `NilPrimitive`, with Type == types.Nil). It appears in
	// two situations, distinguished by whether it carries content:
	//
	//   - A nil or completely empty primitive is the husk of a value that was
	//     holding an error or was never set: an errored value frequently
	//     carries no type (e.g. a provider error is wrapped as a bare
	//     &RawData{Error: ...} at the plugin boundary), RawData.Result() stamps
	//     only the type on it, and block2result strips the per-field error when
	//     nesting, leaving {} behind (e.g. a `ports { process }` block where a
	//     port's process lookup failed). A provider that answers with neither
	//     data nor an error hands us a nil *Primitive outright (see
	//     providers.Runtime watchAndUpdate), which is why the checks below go
	//     through the nil-safe generated getters rather than the fields. The
	//     error, if any, already surfaced on the Result / query score, and a
	//     provider unset field is separately reported with full
	//     provider/resource/field attribution by providers.Runtime GetData, so
	//     re-reporting the husk on every read of the stored data would only
	//     duplicate it as unattributable noise. Coerce it to null quietly.
	//
	//   - A typeless primitive that still holds content is malformed: an
	//     upstream layer emitted a broken primitive, e.g. the compiler binding
	//     a predicate's value field to a resource that lacks it (see
	//     mqlc.addValueFieldChunks). Stay loud-and-narrow: log at error level
	//     (silently coercing is what made the original compiler bug nearly
	//     impossible to find), but coerce just this field to null instead of
	//     returning an error — an error would propagate through
	//     primitive2array / primitive2rawdataMapV2 and discard the entire
	//     surrounding collection (parray2raw rewrites the dropped slice to an
	//     empty `[]`), so one broken leaf would empty a whole failing-resource
	//     list and surface as an empty assessment.
	if p.GetType() == "" {
		if len(p.GetValue()) != 0 || len(p.GetArray()) != 0 || len(p.GetMap()) != 0 {
			log.Error().Msg("llx: encountered a primitive with no type information, coercing to null (an upstream layer — a provider or the compiler — produced a malformed primitive)")
		}
		return &RawData{Type: types.Nil}
	}

	typ := types.Type(p.Type)
	c, ok := primitiveConverters[typ.Underlying()]
	if !ok {
		return &RawData{Error: errors.New("cannot convert primitive to value for primitive type " + typ.Label())}
	}
	return c(p)
}

func (b *blockExecutor) lookupValue(ref uint64) (*RawData, uint64, error) {
	if b == nil {
		// Unreachable in practice: callers check parent != nil before
		// recursing and panic with full context there. Kept as a last-resort
		// guard so we never nil-deref silently if a new caller is added.
		panic("value not computed (ref=" + strconv.FormatUint(ref, 10) + ", no block executor)")
	}

	res, ok := b.cache.Load(ref)
	if ok {
		return res.Result, 0, res.Result.Error
	}

	if b.parent == nil {
		// We walked the whole parent chain without finding the value. This is
		// the "value not computed" case: a ref points to something that should
		// have been computed before this point but wasn't. Panic here, while we
		// still hold a valid executor, so the report can identify the ref.
		panic("value not computed: " + b.refContext(ref))
	}
	return b.parent.lookupValue(ref)
}

func (b *blockExecutor) resolveRef(srcRef uint64, ref uint64) (*RawData, uint64, error) {
	if !b.isInMyBlock(srcRef) {
		// the value is provided by a parent
		if b.parent == nil {
			panic("value not computed: " + b.refContext(srcRef))
		}
		return b.parent.lookupValue(srcRef)
	} else {
		// check if the reference exists; if not connect it
		res, ok := b.cache.Load(srcRef)
		if !ok {
			return b.connectRef(srcRef, ref)
		}
		return res.Result, 0, res.Result.Error
	}
}

// refContext builds a human-readable description of a ref for panic and error
// reporting. Reports like "value not computed" are otherwise opaque: this adds
// the block/chunk coordinates, the code checksum, and a compact, source-like
// reconstruction of the expression (e.g. "aws.ec2.instances.where.==") so the
// failing query can be identified from a crash report alone.
//
// It is deliberately defensive: a corrupt or out-of-range ref must never turn a
// useful panic into a second index/nil-deref panic, so all chunk lookups run
// under a recover. It intentionally never renders primitive values, only chunk
// IDs and types, to avoid leaking query literals into upstream crash reports.
func (b *blockExecutor) refContext(ref uint64) (desc string) {
	desc = fmt.Sprintf("ref=%d:%d", ref>>32, uint32(ref))

	defer func() {
		if r := recover(); r != nil {
			desc += fmt.Sprintf(" (further context unavailable: %v)", r)
		}
	}()

	if b.ctx != nil && b.ctx.code != nil {
		if b.ctx.code.Id != "" {
			desc += " codeID=" + b.ctx.code.Id
		}
		if cs := b.ctx.code.Checksums[ref]; cs != "" {
			desc += " checksum=" + cs
		}
		desc += " expr=" + b.describeRef(ref, 8)
	}
	desc += " executor=" + b.id
	return desc
}

// describeRef reconstructs a compact, source-like description of a ref by
// walking its function binding chain (most-bound first, e.g.
// "aws.ec2.instances.where.=="). Best-effort and bounded by maxDepth. Callers
// must run this under a recover (see refContext) since chunk lookups can index
// out of range for a malformed ref.
func (b *blockExecutor) describeRef(ref uint64, maxDepth int) string {
	if ref == 0 {
		return ""
	}
	if maxDepth <= 0 {
		return "…"
	}

	chunk := b.ctx.code.Chunk(ref)
	if chunk == nil {
		return "?"
	}

	name := chunk.Id
	if name == "" {
		// A primitive (or unnamed) chunk; never render its value.
		name = "<" + chunk.Type().Label() + ">"
	}

	if chunk.Function != nil && chunk.Function.Binding != 0 {
		if prefix := b.describeRef(chunk.Function.Binding, maxDepth-1); prefix != "" {
			return prefix + "." + name
		}
	}
	return name
}

// returns the resolved argument if it's a ref; otherwise just the argument
// returns the reference if something else needs executing before it can be computed
// returns an error otherwise
func (b *blockExecutor) resolveValue(arg *Primitive, ref uint64) (*RawData, uint64, error) {
	typ := types.Type(arg.Type)
	switch typ.Underlying() {
	case types.Ref:
		srcRef := uint64(bytes2int(arg.Value))
		return b.resolveRef(srcRef, ref)
	case types.ArrayLike:
		res := make([]any, len(arg.Array))
		for i := range arg.Array {
			c, ref, err := b.resolveValue(arg.Array[i], ref)
			if ref != 0 || err != nil {
				return nil, ref, err
			}
			res[i] = c.Value
		}

		// type is in arg.Value
		return &RawData{
			Type:  typ,
			Value: res,
		}, 0, nil
	case types.MapLike:
		res := make(map[string]any, len(arg.Map))
		for k, v := range arg.Map {
			c, ref, err := b.resolveValue(v, ref)
			if ref != 0 || err != nil {
				return nil, ref, err
			}
			res[k] = c.Value
		}

		// type is in arg.Value
		return &RawData{
			Type:  typ,
			Value: res,
		}, 0, nil
	default:
		v := arg.RawData()
		return v, 0, v.Error
	}
}

func TArr2Raw[T any](arr []T) []any {
	res := make([]any, len(arr))
	for i := range arr {
		res[i] = arr[i]
	}
	return res
}

func TMap2Raw[T any](m map[string]T) map[string]any {
	res := make(map[string]any, len(m))
	for k, v := range m {
		res[k] = v
	}
	return res
}

func TRaw2T[T any](v any) T {
	if res, ok := v.(T); ok {
		return res
	}
	var res T
	return res
}

func TRaw2TArr[T any](v any) []T {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}

	res := make([]T, len(arr))
	for i := range arr {
		res[i], _ = arr[i].(T)
	}
	return res
}

func TRaw2TMap[T any](v any) map[string]T {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}

	res := make(map[string]T, len(m))
	for k, v := range m {
		res[k], _ = v.(T)
	}
	return res
}
