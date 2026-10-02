// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	"github.com/microsoft/kiota-abstractions-go/store"
	kjson "github.com/microsoft/kiota-serialization-json-go"
)

// kiotaToDict serializes a Graph model with Kiota's JSON writer and decodes
// the result into a dict. Unlike convert.JsonToDict, which sees an empty
// struct because Kiota keeps values in an unexported backing store, this
// emits every property the concrete type (including a derived type) holds,
// under its Graph property name. Values are JSON-native: integers become
// int64, other numbers float64, enums and timestamps strings.
//
// ISO 8601 durations are taken out of the model while Kiota writes it and
// rendered by isoDurationPtr instead: Kiota's writer folds whole weeks (P14D
// reads P2W) and panics on a duration it cannot normalize (P7DT12H).
//
// A nil model returns a nil map.
func kiotaToDict(p serialization.Parsable) (map[string]any, error) {
	if p == nil {
		return nil, nil
	}
	// A non-nil interface can still hold a nil model pointer, which the
	// check above lets through and Serialize would dereference.
	if rv := reflect.ValueOf(p); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil, nil
	}

	durations := detachDurations(p)
	defer durations.restore()

	w := kjson.NewJsonSerializationWriter()
	defer w.Close()
	if err := w.WriteObjectValue("", p); err != nil {
		return nil, err
	}
	content, err := w.GetSerializedContent()
	if err != nil {
		return nil, err
	}

	dec := json.NewDecoder(bytes.NewReader(content))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	m, ok := normalizeJSONNumbers(raw).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("expected a JSON object, got %T", raw)
	}
	durations.apply(m)
	return m, nil
}

// detachedDurations holds the durations detachDurations took out of one
// model, and the models nested in it, by property name.
type detachedDurations struct {
	store     store.BackingStore
	durations map[string]*serialization.ISODuration
	objects   map[string]*detachedDurations
	lists     map[string][]*detachedDurations
}

// detachDurations takes every duration out of the backing store of v and of
// the models nested in it, so Kiota's writer omits them. It returns nil when
// v holds no duration.
func detachDurations(v any) *detachedDurations {
	bm, ok := v.(store.BackedModel)
	if !ok {
		return nil
	}
	if rv := reflect.ValueOf(v); rv.Kind() == reflect.Ptr && rv.IsNil() {
		return nil
	}
	bs := bm.GetBackingStore()
	if bs == nil {
		return nil
	}
	res := &detachedDurations{store: bs}
	found := false
	for key, val := range bs.Enumerate() {
		switch t := val.(type) {
		case nil:
		case *serialization.ISODuration:
			if t == nil {
				continue
			}
			if res.durations == nil {
				res.durations = map[string]*serialization.ISODuration{}
			}
			res.durations[key] = t
			found = true
		case serialization.Parsable:
			if child := detachDurations(t); child != nil {
				if res.objects == nil {
					res.objects = map[string]*detachedDurations{}
				}
				res.objects[key] = child
				found = true
			}
		default:
			rv := reflect.ValueOf(val)
			if rv.Kind() != reflect.Slice {
				continue
			}
			items := make([]*detachedDurations, rv.Len())
			hasDurations := false
			for i := range items {
				if items[i] = detachDurations(rv.Index(i).Interface()); items[i] != nil {
					hasDurations = true
				}
			}
			if hasDurations {
				if res.lists == nil {
					res.lists = map[string][]*detachedDurations{}
				}
				res.lists[key] = items
				found = true
			}
		}
	}
	if !found {
		return nil
	}
	for key := range res.durations {
		_ = bs.Set(key, nil)
	}
	return res
}

// restore puts the detached durations back into their models.
func (d *detachedDurations) restore() {
	if d == nil {
		return
	}
	for key, dur := range d.durations {
		_ = d.store.Set(key, dur)
	}
	for _, child := range d.objects {
		child.restore()
	}
	for _, items := range d.lists {
		for _, item := range items {
			item.restore()
		}
	}
}

// apply writes the detached durations into the dict Kiota's writer produced
// for their model, in the form isoDurationPtr renders.
func (d *detachedDurations) apply(dict map[string]any) {
	if d == nil || dict == nil {
		return
	}
	for key, dur := range d.durations {
		dict[key] = *isoDurationPtr(dur)
	}
	for key, child := range d.objects {
		if sub, ok := dict[key].(map[string]any); ok {
			child.apply(sub)
		}
	}
	for key, items := range d.lists {
		list, ok := dict[key].([]any)
		if !ok || len(list) != len(items) {
			continue
		}
		for i, item := range items {
			if sub, ok := list[i].(map[string]any); ok {
				item.apply(sub)
			}
		}
	}
}

// normalizeJSONNumbers replaces json.Number values with int64 when they are
// integral and in range, float64 otherwise.
func normalizeJSONNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = normalizeJSONNumbers(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = normalizeJSONNumbers(e)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, err := t.Float64()
		if err != nil || math.IsInf(f, 0) {
			return t.String()
		}
		return f
	default:
		return v
	}
}
