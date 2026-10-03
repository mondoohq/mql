// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"slices"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

var pluginStateType = reflect.TypeFor[plugin.State]()

// markUnsetFieldsNull marks every field of a resource that has not been
// computed yet as set and null, except the fields named in keep (by their Go
// name, such as "UserFiles").
//
// It is for a configuration resource whose files the scan was refused, while
// structured errors are off: v13 reported such a refusal as an absent
// product, and its accessors then filled in the product's defaults, which a
// check reads as configured values. Marking the fields here, before any
// accessor returns, makes each of them report null instead: GetOrCompute
// hands back a field that is already set rather than the value its accessor
// computed.
func markUnsetFieldsNull(resource any, keep ...string) {
	v := reflect.ValueOf(resource)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() || f.Anonymous || f.Type.Kind() != reflect.Struct || slices.Contains(keep, f.Name) {
			continue
		}
		state := v.Field(i).FieldByName("State")
		if !state.IsValid() || state.Type() != pluginStateType || !state.CanSet() {
			continue
		}
		if plugin.State(state.Uint())&plugin.StateIsSet != 0 {
			continue
		}
		state.SetUint(uint64(plugin.StateIsSet | plugin.StateIsNull))
	}
}
