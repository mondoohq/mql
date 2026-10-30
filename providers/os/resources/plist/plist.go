// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plist

import (
	"bytes"
	"encoding/json"
	"io"

	"howett.net/plist"
)

func ToXml(r io.ReadSeeker) ([]byte, error) {
	// convert file format to xml
	var val any
	dec := plist.NewDecoder(r)
	err := dec.Decode(&val)
	if err != nil {
		return nil, err
	}

	out := &bytes.Buffer{}
	enc := plist.NewEncoderForFormat(out, plist.XMLFormat)
	err = enc.Encode(val)
	return out.Bytes(), err
}

type Data map[string]any

func Decode(r io.ReadSeeker) (Data, error) {
	var data map[string]any
	decoder := plist.NewDecoder(r)
	err := decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	// NOTE: we need to do the extra conversion here to make sure we use supported
	// values by our dict structure: string, float64, int64
	// plist also uses uint64 heavily which we do not support
	// TODO: we really do not want to use the poor-man's json conversion version
	jsondata, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	var dataJson Data
	err = json.Unmarshal(jsondata, &dataJson)
	if err != nil {
		return nil, err
	}

	return dataJson, nil
}

func (d Data) GetPlistData(path ...string) Data {
	val := d
	ok := false
	for i := range path {
		if val == nil {
			return nil
		}
		val, ok = val[path[i]].(map[string]any)
		if !ok {
			return nil
		}
	}
	return val
}

func (d Data) getEntry(path ...string) any {
	val := d
	ok := false
	for i := 0; i < len(path)-1; i++ {
		if val == nil {
			return nil
		}
		val, ok = val[path[i]].(map[string]any)
		if !ok {
			return nil
		}
	}
	key := path[len(path)-1]
	return val[key]
}

func (d Data) GetString(path ...string) (string, bool) {
	entry := d.getEntry(path...)
	str, converted := entry.(string)
	return str, converted
}

func (d Data) GetNumber(path ...string) (float64, bool) {
	entry := d.getEntry(path...)
	val, converted := entry.(float64)
	return val, converted
}

func (d Data) GetList(path ...string) ([]any, bool) {
	val := d
	for i := 0; i < len(path)-1; i++ {
		if val == nil {
			return nil, false
		}
		val = val[path[i]].(map[string]any)
	}
	key := path[len(path)-1]

	res, converted := val[key].([]any)
	return res, converted
}
