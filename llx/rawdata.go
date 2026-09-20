// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

const UNKNOWN_VALUE = "?value?"

// RawData is an internal track of raw data that can be cast to the appropriate types
// It cannot be sent over the wire unless serialized (expensive) or
// converted to a proto data structure
type RawData struct {
	Type  types.Type `json:"type"`
	Value any        `json:"value"`
	Error error      `json:"-"`
	// ShortCircuited marks a null that an optional link (`?`) produced rather
	// than a null that was genuinely read. Under ADR 043 strict mode a required
	// link errors on a null binding, but passes a short-circuited one straight
	// through - that is what makes `a?.b.c` yield null when `a` is null while
	// still erroring when `a` is set and `b` is null, the same as optional
	// chaining in JavaScript.
	//
	// It is execution state, not data: it never crosses the plugin boundary and
	// is never recorded, because only the VM creates it and only within a single
	// chain evaluation.
	ShortCircuited bool `json:"-"`
	// Translated marks a value that a downgrade patch produced rather than the
	// call the bundle was compiled with (ADR 040 part 6). Patching deliberately
	// decouples what executes from what is reported - the result still carries
	// the checksum the producer shipped - so without this flag a wrong
	// translation is indistinguishable from a wrong provider.
	//
	// Like ShortCircuited it is execution state, not data: only the VM sets it,
	// and it never crosses the plugin boundary or reaches a recording.
	Translated bool `json:"-"`
	// dictPath carries an in-progress key-path walk across the links of a dict
	// or map chain, so a key containing dots stays reachable through dot
	// notation (see dictWalk). Execution state like the two above, and
	// unexported besides: it holds the caller's container, which has no business
	// being serialized.
	dictPath *dictPathState
}

// a helper structure exclusively used for json unmarshalling of errors
// TODO: find a better way of doing this, this workaround is annoying
type errData struct {
	Error string `json:"error"`
}

func (r *RawData) MarshalJSON() ([]byte, error) {
	if r.Error != nil {
		return json.Marshal(errData{Error: r.Error.Error()})
	}

	switch r.Type {
	case types.Time:
		tv := r.Value.(*time.Time)
		ut := tv.Unix()
		return json.Marshal(RawData{Type: r.Type, Value: ut})
	case types.IP:
		ip := r.Value.(RawIP)
		data, err := ip.Marshal()
		if err != nil {
			return nil, multierr.Wrap(err, "failed to marshal IP address "+ip.CIDR())
		}
		return json.Marshal(RawData{Type: r.Type, Value: data})
	}

	type rd2 RawData
	return json.Marshal((*rd2)(r))
}

func (r *RawData) UnmarshalJSON(data []byte) error {
	type tmp RawData
	if err := json.Unmarshal(data, (*tmp)(r)); err == nil && r.Type != "" {
		switch r.Type {
		case types.Int:
			r.Value = int64(r.Value.(float64))
		case types.Time:
			tv := r.Value.(float64)
			// JSON serialization of numbers is limited to 1**53 precision, see:
			// https://stackoverflow.com/questions/13502398/json-integers-limit-on-size#comment80159722_13502497
			if tv > (1 << 53) {
				r.Value = &NeverFutureTime
			} else if tv < (-(1 << 53)) {
				r.Value = &NeverPastTime
			} else {
				v := time.Unix(int64(tv), 0)
				r.Value = &v
			}
		case types.IP:
			raw, err := base64.StdEncoding.DecodeString(r.Value.(string))
			if err != nil {
				return multierr.Wrap(err, "failed to unmarshal IP bytes")
			}
			ip, err := UnmarshalIP(raw)
			if err != nil {
				return multierr.Wrap(err, "failed to unmarshal IP data")
			}
			r.Value = *ip
		}
		return nil
	}

	var e errData
	if err := json.Unmarshal(data, &e); err != nil {
		return err
	}

	r.Error = errors.New(e.Error)
	return nil
}

func dictRawDataString(value any) string {
	switch x := value.(type) {
	case bool:
		if x {
			return "true"
		} else {
			return "false"
		}
	case int64:
		return strconv.FormatInt(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case string:
		return "\"" + x + "\""
	case []any:
		var res strings.Builder
		res.WriteString("[")
		for i := range x {
			res.WriteString(dictRawDataString(x[i]))
			if i != len(x)-1 {
				res.WriteString(",")
			}
		}
		res.WriteString("]")
		return res.String()
	case map[string]any:
		var res strings.Builder
		var i int
		res.WriteString("{")
		for k, v := range x {
			res.WriteString("\"" + k + "\":")
			res.WriteString(dictRawDataString(v))
			if i != len(x)-1 {
				res.WriteString(",")
			}
			i++
		}
		res.WriteString("}")
		return res.String()
	default:
		return UNKNOWN_VALUE + " (type:dict)"
	}
}

func rawDataString(typ types.Type, value any) string {
	if value == nil {
		return "<null>"
	}

	switch typ.Underlying() {
	case types.Bool:
		b := value.(bool)
		if b {
			return "true"
		} else {
			return "false"
		}
	case types.Int:
		return strconv.FormatInt(value.(int64), 10)
	case types.Float:
		return strconv.FormatFloat(value.(float64), 'f', -1, 64)
	case types.String:
		return "\"" + value.(string) + "\""
	case types.Regex:
		return "/" + value.(string) + "/"
	case types.Time:
		return value.(*time.Time).String()
	case types.Dict:
		return dictRawDataString(value)
	case types.Score:
		return ScoreString(value.([]byte))
	case types.ArrayLike:
		var res strings.Builder
		arr := value.([]any)
		res.WriteString("[")
		for i := range arr {
			res.WriteString(rawDataString(typ.Child(), arr[i]))
			if i != len(arr)-1 {
				res.WriteString(",")
			}
		}
		res.WriteString("]")
		return res.String()
	case types.MapLike:
		switch typ.Key() {
		case types.String:
			var res strings.Builder
			m := value.(map[string]any)
			var i int
			res.WriteString("{")
			for k, v := range m {
				res.WriteString("\"" + k + "\":")
				res.WriteString(rawDataString(typ.Child(), v))
				if i != len(m)-1 {
					res.WriteString(",")
				}
				i++
			}
			res.WriteString("}")
			return res.String()
		default:
			return "map[?]?"
		}
	case types.Version:
		return value.(string)
	case types.IP:
		return value.(RawIP).CIDR()
	default:
		return UNKNOWN_VALUE + " (typ:" + typ.Label() + ")"
	}
}

func (r *RawData) String() string {
	return rawDataString(r.Type, r.Value)
}

// IsTruthy indicates how the query is scored.
// the first return value gives true/false based on if the data indicates success/failure
// the second value indicates if we were able to come to a decision based on the data
// examples:
//
//	truthy: true, 123, [true], "string"
//	falsey: false
//
// if the data includes an error, it is falsey
func (r *RawData) IsTruthy() (bool, bool) {
	if r.Error != nil {
		return false, false
	}
	return isTruthy(r.Value, r.Type)
}

// Score returns the score value if the value is of score type
func (r *RawData) Score() (int, bool) {
	if r.Error != nil {
		return 0, false
	}

	if r.Type != types.Score {
		return 0, false
	}

	v, err := scoreValue(r.Value.([]byte))
	if err != nil {
		return v, false
	}
	return v, true
}

func isTruthy(data any, typ types.Type) (bool, bool) {
	if data == nil &&
		(typ.NotSet() || !typ.IsResource()) {
		return false, true
	}

	switch typ.Underlying() {
	case types.Any:
		if b, ok := data.(bool); ok {
			return b, true
		}
		if d, ok := data.(*RawData); ok {
			return isTruthy(d.Value, d.Type)
		}
		return false, false

	case types.Nil:
		return false, true

	case types.Bool:
		b, ok := data.(bool)
		if !ok {
			return false, false
		}
		return b, true

	case types.Int:
		i, ok := data.(int64)
		if !ok {
			return false, false
		}
		return i != 0, true

	case types.Float:
		f, ok := data.(float64)
		if !ok {
			return false, false
		}
		return f != 0, true

	case types.String:
		s, ok := data.(string)
		if !ok {
			return false, false
		}
		return s != "", true

	case types.Regex:
		s, ok := data.(string)
		if !ok {
			return false, false
		}
		return s != "", true

	case types.Time:
		dt, ok := data.(*time.Time)
		if !ok {
			return false, false
		}

		// needs separate testing due to: https://go.dev/doc/faq#nil_error
		if dt == nil {
			return false, true
		}

		return !dt.IsZero(), true

	case types.Block:
		res := true

		m, ok := data.(map[string]any)
		if !ok {
			return false, false
		}
		if m != nil {
			if bif, ok := m["__t"]; ok {
				if rd, ok := bif.(*RawData); ok {
					return rd.IsTruthy()
				}
			}
			for _, v := range m {
				t1, f1 := isTruthy(v, types.Any)
				if f1 {
					res = res && t1
				}
			}
		}

		return res, true

	case types.Version:
		s, ok := data.(string)
		if !ok {
			return false, false
		}
		return s != "", true

	case types.IP:
		d, ok := data.(RawIP)
		if !ok {
			return false, false
		}
		return len(d.IP) != 0, true

	case types.ArrayLike:
		arr, ok := data.([]any)
		if !ok {
			return false, false
		}

		// Empty arrays count as false here, this is because users
		// frequently write statements like:
		//     list.where(a == 1) && list.where(b == 2)
		// which technically should be:
		//     list.contains(a == 1) && list.contains(b == 2)
		// However, it's so frequent with our users and we can't see
		// a reasonable upside to keeping empty array as truthy, since
		// null checks are far less likely.
		if len(arr) == 0 {
			return false, true
		}

		res := true
		for i := range arr {
			t1, f1 := isTruthy(arr[i], typ.Child())
			if f1 {
				res = res && t1
			}
		}

		return res, true

	case types.MapLike:
		res := true

		switch typ.Key() {
		case types.String:
			m, ok := data.(map[string]any)
			if !ok {
				return false, false
			}
			for _, v := range m {
				t1, f1 := isTruthy(v, typ.Child())
				if f1 {
					res = res && t1
				}
			}

		case types.Int:
			m, ok := data.(map[int64]any)
			if !ok {
				return false, false
			}
			for _, v := range m {
				t1, f1 := isTruthy(v, typ.Child())
				if f1 {
					res = res && t1
				}
			}

		default:
			return false, false
		}

		return res, true

	case types.ResourceLike:
		return true, true

	default:
		return false, false
	}
}

func (r *RawData) IsSuccess() (bool, bool) {
	if r.Error != nil {
		return false, false
	}
	return isSuccess(r.Value, r.Type)
}

func isSuccess(data any, typ types.Type) (bool, bool) {
	if data == nil &&
		(typ.NotSet() || !typ.IsResource()) {
		return false, false
	}

	switch typ.Underlying() {
	case types.Any:
		if b, ok := data.(bool); ok {
			return b, true
		}
		if d, ok := data.(*RawData); ok {
			return isSuccess(d.Value, d.Type)
		}
		return false, false
	case types.Bool:
		b, ok := data.(bool)
		if !ok {
			return false, false
		}
		return b, true
	case types.Block:
		m, ok := data.(map[string]any)
		if !ok {
			return false, false
		}
		if m != nil {
			if bif, ok := m["__s"]; ok {
				if rd, ok := bif.(*RawData); ok {
					return rd.IsSuccess()
				}
			}
			return false, false
		}

		return false, false

	case types.ArrayLike:
		arr, ok := data.([]any)
		if !ok {
			return false, false
		}
		res := true
		valid := false

		for i := range arr {
			t1, f1 := isSuccess(arr[i], typ.Child())
			if f1 {
				res = res && t1
				valid = true
			}
		}

		return res && valid, valid

	default:
		return false, false
	}
}

// UnsetData for the unset value
var UnsetData = &RawData{Type: types.Unset}

// AnyData returns any value embedded in a RawData
func AnyData(v any) *RawData {
	return &RawData{
		Type:  types.Any,
		Value: v,
	}
}

// NilData for the nil value
var NilData = &RawData{Type: types.Nil}

// BoolData creates a rawdata struct from a go boolean
func BoolData(v bool) *RawData {
	return &RawData{
		Type:  types.Bool,
		Value: v,
	}
}

// BoolDataPtr creates a rawdata struct from a go boolean
func BoolDataPtr(v *bool) *RawData {
	if v == nil {
		return NilData
	}
	return BoolData(*v)
}

// BoolFalse is a RawData boolean set to false
var BoolFalse = BoolData(false)

// BoolTrue is a RawData boolean set to true
var BoolTrue = BoolData(true)

// IntData creates a rawdata struct from a go int
func IntData[T int64 | int32 | int](v T) *RawData {
	return &RawData{
		Type:  types.Int,
		Value: int64(v),
	}
}

// IntDataPtr creates a rawdata struct from a go int pointer
func IntDataPtr[T int64 | int32 | int](v *T) *RawData {
	if v == nil {
		return NilData
	}
	return IntData(*v)
}

// IntDataDefault creates a rawdata struct from a go int pointer with a fallback default value
func IntDataDefault[T int64 | int32 | int](v *T, dflt int64) *RawData {
	if v == nil {
		return IntData(dflt)
	}
	return IntData(*v)
}

// FloatData creates a rawdata struct from a go float
func FloatData(v float64) *RawData {
	return &RawData{
		Type:  types.Float,
		Value: v,
	}
}

// FloatDataPtr creates a rawdata struct from a go float pointer, preserving the
// distinction between an absent value (null) and a reported zero.
func FloatDataPtr[T float64 | float32](v *T) *RawData {
	if v == nil {
		return NilData
	}
	return FloatData(float64(*v))
}

// StringData creates a rawdata struct from a go string
func StringData(s string) *RawData {
	return &RawData{
		Type:  types.String,
		Value: s,
	}
}

func StringDataPtr(s *string) *RawData {
	if s == nil {
		return NilData
	}
	return StringData(*s)
}

// RegexData creates a rawdata struct from a go string
func RegexData(r string) *RawData {
	return &RawData{
		Type:  types.Regex,
		Value: r,
	}
}

// TimeData creates a rawdata struct from a go time
func TimeData(t time.Time) *RawData {
	return TimeDataPtr(&t)
}

// TimeData creates a rawdata struct from a go time pointer
func TimeDataPtr(t *time.Time) *RawData {
	if t == nil {
		return NilData
	}
	return &RawData{
		Type:  types.Time,
		Value: t,
	}
}

// DictData creates a rawdata struct from raw dict data
func DictData(r any) *RawData {
	return &RawData{
		Type:  types.Dict,
		Value: r,
	}
}

// ScoreData creates a rawdata struct from raw score data
func ScoreData(r any) *RawData {
	return &RawData{
		Type:  types.Score,
		Value: r,
	}
}

// RefData creates a rawdata struct from a go ref
func RefDataV1(v int32) *RawData {
	return &RawData{
		Type:  types.Ref,
		Value: v,
	}
}

// RefData creates a rawdata struct from a go ref
func RefDataV2(v uint64) *RawData {
	return &RawData{
		Type:  types.Ref,
		Value: v,
	}
}

// ArrayData creates a rawdata struct from a go array + child data types
func ArrayData(v []any, typ types.Type) *RawData {
	return &RawData{
		Type:  types.Array(typ),
		Value: v,
	}
}

// MapData creates a rawdata struct from a go map + child data types
func MapData(v map[string]any, typ types.Type) *RawData {
	return &RawData{
		Type:  types.Map(types.String, typ),
		Value: v,
	}
}

// MapIntData creates a rawdata struct from a go int map + child data type
func MapIntData(v map[int32]any, typ types.Type) *RawData {
	return &RawData{
		Type:  types.Map(types.Int, typ),
		Value: v,
	}
}

// ResourceData creates a rawdata struct from a resource
func ResourceData(v Resource, name string) *RawData {
	return &RawData{
		Type:  types.Resource(name),
		Value: v,
	}
}

// AssetData creates a rawdata struct from a native asset reference value. The
// root is the resource type that roots the referenced asset's tree, i.e. what
// fields may be chained off this value; empty for a reference that declares
// none. See ADR 031.
func AssetData(v *AssetValue, root string) *RawData {
	return &RawData{
		Type:  types.Asset(root),
		Value: v,
	}
}

// FunctionData creates a rawdata struct from a function reference
func FunctionData(v int32, sig string) *RawData {
	return &RawData{
		Type:  types.Function(0, nil),
		Value: v,
	}
}

// RangeData creates a rawdata struct from a raw range
func RangeData(r Range) *RawData {
	return &RawData{
		Type:  types.Range,
		Value: r,
	}
}

// VersionData creates a rawdata struct from a raw ip address
func VersionData(version string) *RawData {
	return &RawData{
		Type:  types.Version,
		Value: version,
	}
}

// IPData creates a rawdata struct from a raw ip address
func IPData(ip RawIP) *RawData {
	if ip.IP == nil {
		return NilData
	}
	return &RawData{
		Type:  types.IP,
		Value: ip,
	}
}

// RawResultByRef is used to sort an array of raw results
type RawResultByRef []*RawResult

func (a RawResultByRef) Len() int           { return len(a) }
func (a RawResultByRef) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a RawResultByRef) Less(i, j int) bool { return a[i].CodeID < a[j].CodeID }
