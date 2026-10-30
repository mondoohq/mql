// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/openstack/connection"
	"go.mondoo.com/mql/types"
)

func conn(runtime *plugin.Runtime) *connection.OpenstackConnection {
	return runtime.Connection.(*connection.OpenstackConnection)
}

// userOptionBool reads a Keystone user option key as a bool. Absent or
// non-bool values resolve to false, matching Keystone's default behaviour
// when an option is unset.
func userOptionBool(options map[string]any, key string) bool {
	if options == nil {
		return false
	}
	v, ok := options[key].(bool)
	return ok && v
}

func ctx() context.Context {
	return context.Background()
}

// translateOpenstackError maps 401/403/404 to "no data" so a missing
// capability (e.g. non-admin token calling Keystone list APIs) doesn't fail
// the whole query. Use this for list endpoints — for single-item Get calls,
// use translateGetError so a real "not found" surfaces. Mirrors the AWS
// Is400AccessDenied pattern.
func translateOpenstackError(err error) error {
	if err == nil {
		return nil
	}
	if resp, ok := errors.AsType[gophercloud.ErrUnexpectedResponseCode](err); ok {
		switch resp.Actual {
		case 401, 403, 404:
			log.Warn().Err(err).Int("status", resp.Actual).Msg("openstack> permission denied or not found; returning empty result")
			return nil
		}
	}
	return err
}

// translateGetError is the single-item-Get equivalent of
// translateOpenstackError: 401/403 (no permission) become nil so a non-admin
// token doesn't fail the query, but 404 (resource genuinely missing)
// propagates so callers can surface it.
func translateGetError(err error) error {
	if err == nil {
		return nil
	}
	if resp, ok := errors.AsType[gophercloud.ErrUnexpectedResponseCode](err); ok {
		switch resp.Actual {
		case 401, 403:
			log.Warn().Err(err).Int("status", resp.Actual).Msg("openstack> permission denied; returning empty result")
			return nil
		}
	}
	return err
}

// serviceMissing reports whether err indicates the service or endpoint is
// absent from the Keystone catalog — the OpenStack way of saying "this
// deployment doesn't run that service". Callers should treat this as "no
// data" rather than a failure so a Cinder-less cloud can still query Nova.
func serviceMissing(err error) bool {
	if err == nil {
		return false
	}
	if _, ok := errors.AsType[gophercloud.ErrServiceNotFound](err); ok {
		return true
	}
	var ep gophercloud.ErrEndpointNotFound
	return errors.As(err, &ep)
}

func stringSlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func stringSliceData(in []string) *llx.RawData {
	return llx.ArrayData(stringSlice(in), types.String)
}

func stringMap(in map[string]string) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func stringMapData(in map[string]string) *llx.RawData {
	return llx.MapData(stringMap(in), types.String)
}

// dictSliceData wraps a slice of map[string]any (or nil) as a []dict field.
func dictSliceData(in []any) *llx.RawData {
	if in == nil {
		in = []any{}
	}
	return llx.ArrayData(in, types.Dict)
}

// timePtr returns a pointer to t, or nil if t is the zero value. OpenStack
// returns the zero time for unset timestamps (e.g. terminated_at while running).
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// stringArg returns a string argument from an init args map. Returns
// (zero-value, false) when the arg is missing or the wrong type.
func stringArg(args map[string]*llx.RawData, key string) (string, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return "", false
	}
	s, ok := v.Value.(string)
	if !ok {
		return "", false
	}
	return s, true
}

// initSyntheticID synthesizes an `__id` of `<resource>/<idValue>` from
// args[idField] when an init function is invoked without a pre-set `__id`
// (e.g., from a cross-resource accessor that only knows the natural key).
// Without this, NewResource produces a resource with no cache key, which
// breaks runtime serialization with "cannot convert primitive with NO type
// information".
func initSyntheticID(resourceName, idField string, args map[string]*llx.RawData) {
	if v, ok := args["__id"]; ok && v != nil && v.Value != nil {
		return
	}
	id, ok := stringArg(args, idField)
	if !ok || id == "" {
		return
	}
	args["__id"] = llx.StringData(resourceName + "/" + id)
}
