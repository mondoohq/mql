// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"time"

	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/sortx"
)

func intKeys(m map[int]any) []int {
	keys := make([]int, len(m))
	var i int
	for k := range m {
		keys[i] = k
		i++
	}
	return keys
}

// MQL represents an unbounded int as math.MaxInt64 (Inf) or math.MinInt64
// (-Inf). JSON has no token for infinity, so these export as the strings
// "Inf" and "-Inf", the same way an infinite time exports as "Never".
func int2json(i int64) string {
	if i == math.MaxInt64 {
		return `"Inf"`
	}
	if i == math.MinInt64 {
		return `"-Inf"`
	}

	return strconv.FormatInt(i, 10)
}

// JSON has no token for infinity or NaN, so these export as the strings
// "Inf", "-Inf" and "NaN".
func float2json(f float64) string {
	if math.IsInf(f, 1) {
		return `"Inf"`
	}
	if math.IsInf(f, -1) {
		return `"-Inf"`
	}
	if math.IsNaN(f) {
		return `"NaN"`
	}

	return strconv.FormatFloat(f, 'g', -1, 64)
}

// Takes care of escaping the given string
func string2json(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func label(ref string, bundle *CodeBundle, isResource bool) string {
	if bundle == nil {
		return "<unknown>"
	}

	labels := bundle.Labels
	if labels == nil {
		return ref
	}

	label := labels.Labels[ref]
	if label == "" {
		return "<unknown>"
	}

	return label
}

func removeUnderscoreKeys(keys []string) []string {
	results := make([]string, 0, len(keys))
	for i := 0; i < len(keys); i++ {
		if keys[i] != "" && keys[i][0] != '_' {
			results = append(results, keys[i])
		}
	}
	return results
}

func refMapJSON(typ types.Type, data map[string]any, codeID string, bundle *CodeBundle, buf *bytes.Buffer) error {
	buf.WriteByte('{')

	keys := sortx.Keys(data)

	// What is the best explanation for why we do this?
	keys = removeUnderscoreKeys(keys)

	// Multiple entrypoints in a block can resolve to the same label (e.g.
	// `package("a").installed` and `package("b").installed` both label as
	// `package.installed`). Disambiguate so the resulting JSON has unique
	// keys — downstream consumers reject duplicates when unmarshaling into
	// proto map fields.
	seen := make(map[string]int, len(keys))
	last := len(keys) - 1
	for i, k := range keys {
		v := data[k]
		base := label(k, bundle, true)
		jsonKey := base
		if n := seen[base]; n > 0 {
			jsonKey = fmt.Sprintf("%s (%d)", base, n+1)
		}
		seen[base]++
		str, err := string2json(jsonKey)
		if err != nil {
			return err
		}
		buf.WriteString(str)
		buf.WriteString(":")

		val := v.(*RawData)
		if val.Error != nil {
			// PrettyPrintString un-escapes \n and \t back into real control
			// characters, which is what the terminal printer wants and what JSON
			// forbids inside a string (RFC 8259 section 7). Multi-line errors are
			// routine here - a multierror renders as "N errors occurred:\n\t* ..."
			// whenever more than one element of a collection fails - so using it
			// made the whole document unparseable. Encode the error the same way
			// every other string in this writer is encoded.
			str, err := string2json("Error: " + val.Error.Error())
			if err != nil {
				return err
			}
			buf.WriteString(str)
		} else {
			err = rawDataJSON(val.Type, val.Value, k, bundle, buf)
			if err != nil {
				return err
			}
		}

		if i != last {
			buf.WriteByte(',')
		}
	}

	buf.WriteByte('}')
	return nil
}

func rawDictJSON(typ types.Type, raw any, buf *bytes.Buffer) error {
	switch data := raw.(type) {
	case bool:
		if data {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil

	case int64:
		buf.WriteString(int2json(data))
		return nil

	case float64:
		buf.WriteString(float2json(data))
		return nil

	case string:
		str, err := string2json(data)
		if err != nil {
			return err
		}
		buf.WriteString(str)
		return nil

	case time.Time:
		b, err := data.MarshalJSON()
		buf.Write(b)
		return err

	case []any:
		buf.WriteByte('[')

		last := len(data) - 1
		for i := range data {
			err := rawDictJSON(typ, data[i], buf)
			if err != nil {
				return err
			}
			if i != last {
				buf.WriteByte(',')
			}
		}

		buf.WriteByte(']')
		return nil

	case map[string]any:
		buf.WriteByte('{')

		keys := sortx.Keys(data)

		last := len(keys) - 1
		for i, k := range keys {
			v := data[k]
			str, err := string2json(k)
			if err != nil {
				return err
			}
			buf.WriteString(str + ":")

			if v == nil {
				buf.WriteString("null")
			} else {
				err := rawDictJSON(typ, v, buf)
				if err != nil {
					return err
				}
			}

			if i != last {
				buf.WriteByte(',')
			}
		}

		buf.WriteByte('}')
		return nil

	default:
		b, err := json.Marshal(raw)
		buf.Write(b)
		return err
	}
}

func rawArrayJSON(typ types.Type, data []any, codeID string, bundle *CodeBundle, buf *bytes.Buffer) error {
	buf.WriteByte('[')

	last := len(data) - 1
	childType := typ.Child()
	var err error
	for i := range data {
		err = rawDataJSON(childType, data[i], codeID, bundle, buf)
		if err != nil {
			return err
		}

		if i != last {
			buf.WriteByte(',')
		}
	}

	buf.WriteByte(']')

	return nil
}

func rawStringMapJSON(typ types.Type, data map[string]any, codeID string, bundle *CodeBundle, buf *bytes.Buffer) error {
	buf.WriteByte('{')

	last := len(data) - 1
	childType := typ.Child()
	keys := sortx.Keys(data)

	for i, key := range keys {
		str, err := string2json(key)
		if err != nil {
			return err
		}
		buf.WriteString(str + ":")

		err = rawDataJSON(childType, data[key], codeID, bundle, buf)
		if err != nil {
			return err
		}

		if i != last {
			buf.WriteByte(',')
		}
	}

	buf.WriteByte('}')

	return nil
}

func rawIntMapJSON(typ types.Type, data map[int]any, codeID string, bundle *CodeBundle, buf *bytes.Buffer) error {
	buf.WriteByte('{')

	last := len(data) - 1
	childType := typ.Child()

	keys := intKeys(data)
	sort.Ints(keys)

	for i, key := range keys {
		str, err := string2json(strconv.Itoa(key))
		if err != nil {
			return err
		}
		buf.WriteString(str + ":")

		err = rawDataJSON(childType, data[key], codeID, bundle, buf)
		if err != nil {
			return err
		}

		if i != last {
			buf.WriteByte(',')
		}
	}

	buf.WriteByte('}')

	return nil
}

// The heart of the JSON marshaller. We try to avoid the default marshaller whenever
// possible for now, because our type system provides most of the information we need,
// allowing us to avoid more costly reflection calls.
func rawDataJSON(typ types.Type, data any, codeID string, bundle *CodeBundle, buf *bytes.Buffer) error {
	if typ.NotSet() {
		return errors.New("type information is missing")
	}

	if data == nil {
		buf.WriteString("null")
		return nil
	}

	switch typ.Underlying() {
	case types.Any:
		r, err := json.Marshal(data)
		buf.Write(r)
		return err

	case types.Ref:
		r := "\"ref:" + fmt.Sprintf("%d", data.(int32)) + "\""
		buf.WriteString(r)
		return nil

	case types.Nil:
		buf.WriteString("null")
		return nil

	case types.Bool:
		if data.(bool) {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
		return nil

	case types.Int:
		buf.WriteString(int2json(data.(int64)))
		return nil

	case types.Float:
		buf.WriteString(float2json(data.(float64)))
		return nil

	case types.String:
		str, err := string2json(data.(string))
		if err != nil {
			return err
		}
		buf.WriteString(str)
		return nil

	case types.Regex:
		raw, err := string2json(data.(string))
		if err != nil {
			return err
		}
		buf.WriteByte(raw[0])
		buf.WriteByte('/')
		buf.WriteString(raw[1 : len(raw)-1])
		buf.WriteByte('/')
		buf.WriteByte(raw[len(raw)-1])
		return nil

	case types.Time:
		time := data.(*time.Time)
		if time == nil {
			buf.WriteString("null")
			return nil
		}

		if time.Equal(NeverPastTime) || time.Equal(NeverFutureTime) {
			r := "\"" + "Never" + "\""

			buf.WriteString(r)
			return nil
		}

		if time.Unix() > 0 {
			b, err := time.MarshalJSON()
			if err != nil {
				return err
			}
			buf.Write(b)
		} else {
			buf.WriteByte('"')
			buf.WriteString(TimeToDurationString(*time))
			buf.WriteByte('"')
		}

		return nil

	case types.Dict:
		return rawDictJSON(typ, data, buf)

	case types.Score:
		buf.WriteString(ScoreString(data.([]byte)))
		return nil

	case types.Block:
		return refMapJSON(typ, data.(map[string]any), codeID, bundle, buf)

	case types.ArrayLike:
		return rawArrayJSON(typ, data.([]any), codeID, bundle, buf)

	case types.MapLike:
		if typ.Key() == types.String {
			return rawStringMapJSON(typ, data.(map[string]any), codeID, bundle, buf)
		}
		if typ.Key() == types.Int {
			return rawIntMapJSON(typ, data.(map[int]any), codeID, bundle, buf)
		}
		return errors.New("unable to marshal map, its type is not supported: " + typ.Label() + ", raw: " + fmt.Sprintf("%#v", data))

	case types.ResourceLike:
		r := data.(Resource)
		idline := r.MqlName()
		if id := r.MqlID(); id != "" {
			idline += " id = " + id
		}

		str, err := string2json(idline)
		if err != nil {
			return err
		}
		buf.WriteString(str)
		return nil

	case types.AssetLike:
		v, ok := data.(*AssetValue)
		if !ok || v == nil {
			buf.WriteString("null")
			return nil
		}
		rt, err := string2json(v.ResourceType)
		if err != nil {
			return err
		}
		rid, err := string2json(v.ResourceId)
		if err != nil {
			return err
		}
		buf.WriteString(`{"resourceType":`)
		buf.WriteString(rt)
		buf.WriteString(`,"resourceId":`)
		buf.WriteString(rid)
		buf.WriteString("}")
		return nil

	default:
		b, err := json.Marshal(data)
		buf.Write(b)
		return err
	}
}

func JSONerror(err error) []byte {
	str, err := string2json(err.Error())
	if err != nil {
		return []byte("{\"error\":\"" + err.Error() + "\"}")
	}
	return []byte("{\"error\":" + str + "}")
}

func (r *RawData) JSON(codeID string, bundle *CodeBundle) []byte {
	if r.Value == nil && r.Error != nil {
		return JSONerror(r.Error)
	}

	var res bytes.Buffer
	if err := rawDataJSON(r.Type, r.Value, codeID, bundle, &res); err != nil {
		return JSONerror(err)
	}
	return res.Bytes()
}

func (r *RawData) JSONfield(codeID string, bundle *CodeBundle) []byte {
	label := label(codeID, bundle, true)
	value := r.JSON(codeID, bundle)
	str, err := string2json(label)
	if err != nil {
		return JSONerror(err)
	}
	return []byte(str + ":" + string(value))
}
