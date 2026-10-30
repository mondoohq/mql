// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
)

// decode unmarshals a normalized query value into target. It is hand-rolled
// rather than routed through JSON because query values must keep their
// fidelity: int64 beyond 2^53, time values, and IPs all lose information in
// a JSON round-trip.
func decode(src any, target any) error {
	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return errors.New("decode target must be a non-nil pointer")
	}
	return decodeValue(src, rv.Elem(), "")
}

func decodeValue(src any, dst reflect.Value, path string) error {
	if src == nil {
		return nil
	}

	// Allocate and follow pointers so that *string, **T etc. work.
	for dst.Kind() == reflect.Pointer {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		dst = dst.Elem()
	}

	// An empty interface target takes the value as-is.
	if dst.Kind() == reflect.Interface && dst.NumMethod() == 0 {
		dst.Set(reflect.ValueOf(src))
		return nil
	}

	switch v := src.(type) {
	case bool:
		if dst.Kind() == reflect.Bool {
			dst.SetBool(v)
			return nil
		}

	case int64:
		return decodeInt(v, dst, path)

	case float64:
		return decodeFloat(v, dst, path)

	case string:
		if dst.Kind() == reflect.String {
			dst.SetString(v)
			return nil
		}

	case time.Time:
		return decodeTime(&v, dst, path)

	case *time.Time:
		return decodeTime(v, dst, path)

	case []byte:
		if dst.Type() == reflect.TypeFor[[]byte]() {
			dst.SetBytes(v)
			return nil
		}
		if dst.Kind() == reflect.String {
			dst.SetString(string(v))
			return nil
		}

	case llx.RawIP:
		if dst.Type() == reflect.TypeFor[llx.RawIP]() {
			dst.Set(reflect.ValueOf(v))
			return nil
		}
		if dst.Kind() == reflect.String {
			dst.SetString(v.String())
			return nil
		}

	case llx.Range:
		if dst.Type() == reflect.TypeFor[llx.Range]() {
			dst.Set(reflect.ValueOf(v))
			return nil
		}
		if dst.Kind() == reflect.String {
			dst.SetString(v.String())
			return nil
		}

	case llx.Resource:
		return decodeResource(v, dst, path)

	case []any:
		return decodeSlice(v, dst, path)

	case map[string]any:
		switch dst.Kind() {
		case reflect.Struct:
			return decodeStruct(v, dst, path)
		case reflect.Map:
			return decodeMap(v, dst, path)
		}
	}

	// Last resort: directly assignable values (e.g. custom leaf types).
	sv := reflect.ValueOf(src)
	if sv.Type().AssignableTo(dst.Type()) {
		dst.Set(sv)
		return nil
	}

	return decodeErr(path, src, dst)
}

func decodeInt(v int64, dst reflect.Value, path string) error {
	switch dst.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if dst.OverflowInt(v) {
			return fmt.Errorf("%s: value %d overflows %s", pathLabel(path), v, dst.Type())
		}
		dst.SetInt(v)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if v < 0 || dst.OverflowUint(uint64(v)) {
			return fmt.Errorf("%s: value %d overflows %s", pathLabel(path), v, dst.Type())
		}
		dst.SetUint(uint64(v))
		return nil
	case reflect.Float32, reflect.Float64:
		dst.SetFloat(float64(v))
		return nil
	}
	return decodeErr(path, v, dst)
}

func decodeFloat(v float64, dst reflect.Value, path string) error {
	switch dst.Kind() {
	case reflect.Float32, reflect.Float64:
		dst.SetFloat(v)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Only integral floats convert to ints; never truncate silently. Range
		// must be checked before int64(v): converting an out-of-range float is
		// implementation-defined per the Go spec. The || short-circuits so
		// OverflowInt only runs once int64(v) is well-defined.
		if v != math.Trunc(v) || v > float64(math.MaxInt64) || v < float64(math.MinInt64) || dst.OverflowInt(int64(v)) {
			return fmt.Errorf("%s: value %v does not fit %s", pathLabel(path), v, dst.Type())
		}
		dst.SetInt(int64(v))
		return nil
	}
	return decodeErr(path, v, dst)
}

func decodeTime(v *time.Time, dst reflect.Value, path string) error {
	if v == nil {
		return nil
	}
	if dst.Type() == reflect.TypeFor[time.Time]() {
		dst.Set(reflect.ValueOf(*v))
		return nil
	}
	return decodeErr(path, v, dst)
}

func decodeResource(v llx.Resource, dst reflect.Value, path string) error {
	// A bare resource only carries its identity. To decode its fields,
	// project them in the query instead: resource { field1 field2 }.
	if dst.Kind() == reflect.String {
		dst.SetString(v.MqlID())
		return nil
	}
	if dst.Kind() == reflect.Interface && reflect.TypeOf(v).AssignableTo(dst.Type()) {
		dst.Set(reflect.ValueOf(v))
		return nil
	}
	return fmt.Errorf("%s: cannot decode resource %s into %s; project its fields in the query instead, e.g. %s { ... }",
		pathLabel(path), v.MqlName(), dst.Type(), v.MqlName())
}

func decodeSlice(src []any, dst reflect.Value, path string) error {
	if dst.Kind() != reflect.Slice {
		return decodeErr(path, src, dst)
	}
	out := reflect.MakeSlice(dst.Type(), len(src), len(src))
	var errs []error
	for i := range src {
		if err := decodeValue(src[i], out.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
			errs = append(errs, err)
		}
	}
	dst.Set(out)
	return errors.Join(errs...)
}

func decodeMap(src map[string]any, dst reflect.Value, path string) error {
	if dst.Type().Key().Kind() != reflect.String {
		return decodeErr(path, src, dst)
	}
	out := reflect.MakeMapWithSize(dst.Type(), len(src))
	elemType := dst.Type().Elem()
	var errs []error
	for k, v := range src {
		elem := reflect.New(elemType).Elem()
		if err := decodeValue(v, elem, joinPath(path, k)); err != nil {
			errs = append(errs, err)
			continue
		}
		out.SetMapIndex(reflect.ValueOf(k).Convert(dst.Type().Key()), elem)
	}
	dst.Set(out)
	return errors.Join(errs...)
}

func decodeStruct(src map[string]any, dst reflect.Value, path string) error {
	exact, fold := structFields(dst.Type())
	var errs []error
	for key, val := range src {
		idx, ok := exact[key]
		if !ok {
			idx, ok = fold[strings.ToLower(key)]
		}
		if !ok {
			continue
		}
		if err := decodeValue(val, fieldByIndexAlloc(dst, idx), joinPath(path, key)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// structFields indexes the decodable fields of a struct type by their
// effective name: the `mql` tag if present, else the `json` tag, else the
// field name. A tag of "-" excludes the field. Fields of anonymous (embedded)
// structs are promoted, like encoding/json — an embedded field with an
// explicit tag is treated as a normal named field instead, and a shallower
// field wins a name collision with a more deeply embedded one.
func structFields(t reflect.Type) (exact map[string][]int, fold map[string][]int) {
	exact = map[string][]int{}
	fold = map[string][]int{}
	depthOf := map[string]int{}

	var visit func(t reflect.Type, prefix []int, depth int)
	visit = func(t reflect.Type, prefix []int, depth int) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			mtag := tagName(f.Tag.Get("mql"))
			jtag := tagName(f.Tag.Get("json"))
			hasTag := mtag != "" || jtag != ""

			index := append(append([]int{}, prefix...), i)

			// Promote fields of an untagged embedded struct (or *struct).
			if f.Anonymous && !hasTag {
				ft := f.Type
				if ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if ft.Kind() == reflect.Struct {
					visit(ft, index, depth+1)
					continue
				}
			}

			if !f.IsExported() {
				continue
			}
			name := f.Name
			if mtag != "" {
				name = mtag
			} else if jtag != "" {
				name = jtag
			}
			if name == "-" {
				continue
			}
			if d, seen := depthOf[name]; !seen || depth < d {
				exact[name] = index
				depthOf[name] = depth
			}
			if _, ok := fold[strings.ToLower(name)]; !ok {
				fold[strings.ToLower(name)] = index
			}
		}
	}
	visit(t, nil, 0)
	return exact, fold
}

// fieldByIndexAlloc walks an index path (as produced by structFields),
// dereferencing and allocating nil pointers to embedded structs along the way
// so the addressed field can be set.
func fieldByIndexAlloc(v reflect.Value, index []int) reflect.Value {
	for _, x := range index {
		for v.Kind() == reflect.Pointer {
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		v = v.Field(x)
	}
	return v
}

func tagName(tag string) string {
	if tag == "" {
		return ""
	}
	if i := strings.Index(tag, ","); i >= 0 {
		tag = tag[:i]
	}
	return tag
}

func pathLabel(path string) string {
	if path == "" {
		return "value"
	}
	return path
}

func decodeErr(path string, src any, dst reflect.Value) error {
	return fmt.Errorf("%s: cannot decode %T into %s", pathLabel(path), src, dst.Type())
}
