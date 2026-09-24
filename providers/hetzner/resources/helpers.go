// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hetzner/connection"
	"go.mondoo.com/mql/types"
)

// translateHcloudError decides which hcloud failures are a real answer and
// which are an error.
//
// Only a missing collection is an answer. A denial is not: a token that was
// refused the read has established nothing about what exists, so reporting an
// empty list would assert the project has no firewalls, no volumes, no
// servers, which is a different and unverified claim. Every list in this
// provider runs through paginate and therefore through here, so the choice
// applies to all of them at once.
func translateHcloudError(err error) error {
	if err == nil {
		return nil
	}
	var hErr hcloud.Error
	if errors.As(err, &hErr) {
		switch hErr.Code {
		case hcloud.ErrorCodeNotFound:
			// A collection endpoint answering 404 means the product is not
			// provisioned for this project at all, which genuinely is none.
			// Storage Boxes answer this way on a plain cloud project.
			return nil
		}
	}
	return err
}

// isRemovedAPIEndpoint reports the answer Hetzner gives once an endpoint has
// been withdrawn: HTTP 410 with the deprecated_api_endpoint code.
//
// This is deliberately not folded into translateHcloudError, which answers a
// different question. A collection that 404s is genuinely empty, because the
// product is not provisioned for the project. A withdrawn endpoint establishes
// nothing at all: there may well be resources, there is simply no longer any
// way to ask. Reporting those as an empty list would be the same false claim
// as reporting a denial that way.
func isRemovedAPIEndpoint(err error) bool {
	if err == nil {
		return false
	}
	var hErr hcloud.Error
	if errors.As(err, &hErr) {
		return hErr.Code == hcloud.ErrorDeprecatedAPIEndpoint
	}
	return false
}

func conn(runtime *plugin.Runtime) *connection.HetznerConnection {
	return runtime.Connection.(*connection.HetznerConnection)
}

func ctx() context.Context {
	return context.Background()
}

// paginate accumulates all pages of an hcloud list endpoint. It retries from
// page 1 with PerPage=50 (hcloud's max). The list closure receives the per-page
// ListOpts (Page/PerPage/LabelSelector) — the closure is responsible for wrapping
// it in the resource-specific ListOpts type.
func paginate[T any](
	list func(opts hcloud.ListOpts) ([]T, *hcloud.Response, error),
) ([]T, error) {
	var out []T
	opts := hcloud.ListOpts{Page: 1, PerPage: 50}
	read := false
	for {
		page, resp, err := list(opts)
		if err != nil {
			// A collection that is absent from the start is genuinely empty:
			// the product is not provisioned for this project. One that
			// disappears part way through is not. Returning the pages read so
			// far would present a truncated list as the whole of it, which is
			// the same silent-undercount this helper exists to prevent.
			if translateHcloudError(err) == nil && !read {
				return out, nil
			}
			return nil, err
		}
		read = true
		out = append(out, page...)
		if resp == nil || resp.Meta.Pagination == nil || resp.Meta.Pagination.NextPage == 0 {
			break
		}
		opts.Page = resp.Meta.Pagination.NextPage
	}
	return out, nil
}

// labelMap turns a Hetzner Cloud label map into the any-typed map MQL uses for
// `map[string]string` resource fields.
func labelMap(in map[string]string) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// labelData wraps a Hetzner label map for direct assignment to a labels field.
func labelData(in map[string]string) *llx.RawData {
	return llx.MapData(labelMap(in), types.String)
}

// stringMapAny converts a string→string map into the any-valued form that
// dicts accept (the dict-to-primitive converter rejects nested typed maps).
func stringMapAny(in map[string]string) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// dictArrayData wraps a slice of dicts for assignment to a `[]dict` field.
func dictArrayData(in []any) *llx.RawData {
	return llx.ArrayData(in, types.Dict)
}

// stringArrayData wraps a string slice for assignment to a `[]string` field.
func stringArrayData(in []string) *llx.RawData {
	return llx.ArrayData(stringSlice(in), types.String)
}

func stringSlice(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func ipNetString(n *net.IPNet) string {
	if n == nil {
		return ""
	}
	return n.String()
}

// timePtr returns a pointer for non-zero times, nil otherwise. Hetzner uses
// the zero time to mean "not set".
func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// timePtrUnix0 treats both zero and Unix(0,0) as "not set" — hcloud's
// DeprecatableResource.UnavailableAfter() returns Unix(0,0) for non-deprecated.
func timePtrUnix0(t time.Time) *time.Time {
	if t.IsZero() || t.Equal(time.Unix(0, 0)) {
		return nil
	}
	return &t
}

// deprecationDict renders an hcloud DeprecationInfo as a dict with RFC3339
// timestamp strings. Times are formatted to strings because the dict-to-
// primitive converter only accepts bool/int64/float64/string/[]any/map values;
// a raw time.Time would fail serialization when the field is queried. Returns an
// empty dict when the resource is not deprecated.
func deprecationDict(d *hcloud.DeprecationInfo) map[string]any {
	out := map[string]any{}
	if d == nil {
		return out
	}
	if !d.Announced.IsZero() {
		out["announced"] = d.Announced.Format(time.RFC3339)
	}
	if !d.UnavailableAfter.IsZero() {
		out["unavailableAfter"] = d.UnavailableAfter.Format(time.RFC3339)
	}
	return out
}

func dnsPtrSliceFromMap(m map[string]string) []any {
	if len(m) == 0 {
		return []any{}
	}
	out := make([]any, 0, len(m))
	for ip, ptr := range m {
		out = append(out, map[string]any{
			"ip":     ip,
			"dnsPtr": ptr,
		})
	}
	return out
}

func protectionDict(delete bool) map[string]any {
	return map[string]any{"delete": delete}
}

func protectionDictRebuild(delete, rebuild bool) map[string]any {
	return map[string]any{"delete": delete, "rebuild": rebuild}
}

// resolveTypedResource is a generic helper used by lazy typed-ref methods.
// It marks the field as nullable+set when src is nil and returns nil; otherwise
// it calls the build callback (which constructs the typed resource from src).
func resolveTypedResource[T any, R any](
	field *plugin.TValue[*R],
	src *T,
	build func(*T) (*R, error),
) (*R, error) {
	if src == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return build(src)
}

// idArg pulls the int64 "id" out of an init args map. Returns (0, false) if
// the arg is missing or not an int.
func idArg(args map[string]*llx.RawData, key string) (int64, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return 0, false
	}
	n, ok := v.Value.(int64)
	if !ok {
		return 0, false
	}
	return n, true
}

// errResourceNotFound marks an init that was given an id Hetzner does not
// know. It lets a caller holding a reference that may outlive its target tell
// "that resource is gone" apart from a failed lookup.
var errResourceNotFound = errors.New("not found")

func notFoundErr(resource string, id int64) error {
	return fmt.Errorf("hetzner %s %w: %d", resource, errResourceNotFound, id)
}
