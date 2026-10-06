// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/exoscale/connection"
	"go.mondoo.com/mql/types"
)

func conn(runtime *plugin.Runtime) *connection.ExoscaleConnection {
	return runtime.Connection.(*connection.ExoscaleConnection)
}

func ctx() context.Context {
	return context.Background()
}

// classifyError turns an Exoscale API failure into an llx error kind (ADR
// 046). operation is the IAM operation the call needed, for example
// list-instances, recorded on a refusal. Anything that is not an API answer
// (a transport failure, a timeout) is returned unclassified.
func classifyError(err error, operation string) error {
	if err == nil {
		return nil
	}
	var apiErr *v3.APIError
	if !errors.As(err, &apiErr) {
		return err
	}
	var opts []llx.ErrorOption
	if operation != "" {
		opts = append(opts, llx.WithPermissions(operation))
	}
	switch {
	case apiErr.StatusCode == 401 || isBadSignature(apiErr):
		// Every later call with these credentials fails the same way.
		return llx.Unauthenticated(err, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))
	case apiErr.StatusCode == 403 && isNotEnabled(apiErr):
		return llx.NotApplicable(err)
	case apiErr.StatusCode == 403:
		return llx.Forbidden(err, opts...)
	case apiErr.StatusCode == 404:
		return llx.NotFound(err)
	case apiErr.StatusCode == 410:
		return llx.Gone(err)
	case apiErr.StatusCode == 429:
		if rl, ok := apiErr.Response.(*v3.RateLimited); ok && rl.RetryAfter > 0 {
			return llx.TooManyRequests(err, llx.WithRetryAfter(time.Duration(rl.RetryAfter*float64(time.Second))))
		}
		return llx.TooManyRequests(err)
	case apiErr.StatusCode >= 500:
		return llx.Unavailable(err)
	}
	return err
}

// isNotEnabled reports the 403 Exoscale answers for an operation that is not
// enabled for the organization at all ("Operation 'list-vpcs' not enabled"),
// as opposed to an IAM policy denying it.
func isNotEnabled(apiErr *v3.APIError) bool {
	return strings.Contains(strings.ToLower(apiErr.Message), "not enabled")
}

// isBadSignature reports the answer Exoscale gives a wrong API secret: a 403
// "Invalid request signature" rather than a 401. It is a credential failure,
// not a permission one.
func isBadSignature(apiErr *v3.APIError) bool {
	return apiErr.StatusCode == 403 && strings.Contains(strings.ToLower(apiErr.Message), "invalid request signature")
}

// isRefusal reports a failure that refuses one partition (one zone) rather
// than the whole query: a permission denial or a feature not enabled there.
func isRefusal(err error) bool {
	switch llx.KindOf(err) {
	case llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE:
		return true
	}
	return false
}

// zoned pairs an item with the zone it was listed in.
type zoned[T any] struct {
	zone string
	item T
}

// listAllZones calls list against every zone of the connection concurrently
// and returns the items in zone order. A zone that refuses the call (ADR 046
// §8) is logged and skipped so the other zones' data survives; any other
// failure fails the whole list rather than presenting a partial one as
// complete.
func listAllZones[T any](runtime *plugin.Runtime, operation string, list func(c *v3.Client) ([]T, error)) ([]zoned[T], error) {
	c := conn(runtime)
	zones, err := c.Zones()
	if err != nil {
		return nil, classifyError(err, "list-zones")
	}

	results := make([][]T, len(zones))
	errs := make([]error, len(zones))
	var wg sync.WaitGroup
	for i := range zones {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			items, err := list(c.ZoneClient(zones[i]))
			results[i] = items
			errs[i] = classifyError(err, operation)
		}(i)
	}
	wg.Wait()

	names := make([]string, len(zones))
	for i := range zones {
		names[i] = string(zones[i].Name)
	}
	return mergeZoneResults(names, results, errs, operation)
}

// mergeZoneResults joins the per-zone answers in zone order. A refused zone
// is skipped so the others' data survives, but when no zone answered at all
// the refusal is returned: an empty list would claim the organization has
// none of the resource, which nothing established.
func mergeZoneResults[T any](zones []string, results [][]T, errs []error, operation string) ([]zoned[T], error) {
	var out []zoned[T]
	var refusal error
	answered := false
	for i, z := range zones {
		if errs[i] != nil {
			if isRefusal(errs[i]) {
				log.Debug().Err(errs[i]).Str("zone", z).Str("operation", operation).Msg("exoscale> skipping zone")
				if refusal == nil {
					refusal = errs[i]
				}
				continue
			}
			return nil, errs[i]
		}
		answered = true
		for _, item := range results[i] {
			out = append(out, zoned[T]{zone: z, item: item})
		}
	}
	if !answered && refusal != nil {
		return nil, refusal
	}
	// Every zone that answered returned nothing: the resource genuinely does
	// not exist in the queried zones, so the empty list is the answer.
	return out, nil
}

// zoneByName returns the connection's zone with the given name.
func zoneByName(runtime *plugin.Runtime, name string) (v3.Zone, bool, error) {
	zones, err := conn(runtime).Zones()
	if err != nil {
		return v3.Zone{}, false, classifyError(err, "list-zones")
	}
	for _, z := range zones {
		if string(z.Name) == name {
			return z, true, nil
		}
	}
	return v3.Zone{}, false, nil
}

// root returns the singleton exoscale resource whose list fields are the
// shared, once-fetched caches every cross-reference resolves through.
func root(runtime *plugin.Runtime) (*mqlExoscale, error) {
	res, err := NewResource(runtime, "exoscale", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlExoscale), nil
}

// pickByID returns the entries of list whose id (as read by idOf) is in ids,
// in the order of ids. Ids that are not in the list are logged and skipped:
// the list is complete for the zones the connection covers, so a miss is a
// resource outside them.
func pickByID[R any](list []any, ids []string, idOf func(R) string) []any {
	if len(ids) == 0 {
		return []any{}
	}
	byID := make(map[string]any, len(list))
	for _, e := range list {
		if r, ok := e.(R); ok {
			byID[idOf(r)] = e
		}
	}
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		if e, ok := byID[id]; ok {
			out = append(out, e)
			continue
		}
		log.Debug().Str("id", id).Msg("exoscale> referenced resource not found in the listed zones")
	}
	return out
}

// pickOneByID is pickByID for a single reference. It reports false when the
// id is empty or not listed.
func pickOneByID[R any](list []any, id string, idOf func(R) string) (R, bool) {
	var zero R
	if id == "" {
		return zero, false
	}
	for _, e := range list {
		if r, ok := e.(R); ok && idOf(r) == id {
			return r, true
		}
	}
	return zero, false
}

// nullResource marks a singular resource field as resolved to null.
func nullResource[T any](field *plugin.TValue[T]) {
	field.State = plugin.StateIsSet | plugin.StateIsNull
}

func labelData[M ~map[string]string](in M) *llx.RawData {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return llx.MapData(out, types.String)
}

func stringArrayData[S ~string](in []S) *llx.RawData {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return llx.ArrayData(out, types.String)
}

func ipArrayData(in []net.IP) *llx.RawData {
	out := make([]any, 0, len(in))
	for _, ip := range in {
		if ip != nil {
			out = append(out, ip.String())
		}
	}
	return llx.ArrayData(out, types.String)
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// timeData maps the SDK's zero time (an absent timestamp) to null.
func timeData(t time.Time) *llx.RawData {
	if t.IsZero() {
		return llx.NilData
	}
	return llx.TimeData(t)
}

// boolData maps an absent optional flag to null.
func boolData(b *bool) *llx.RawData {
	return llx.BoolDataPtr(b)
}

func uuidStrings[T any](in []T, id func(T) v3.UUID) []string {
	out := make([]string, 0, len(in))
	for _, e := range in {
		if s := string(id(e)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func stringArg(args map[string]*llx.RawData, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.Value.(string)
	return s
}

// setBool fills a field from an optional SDK flag; an absent flag is null.
func setBool(field *plugin.TValue[bool], b *bool) {
	if b == nil {
		field.Data = false
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return
	}
	field.Data = *b
	field.State = plugin.StateIsSet
}

func setInt(field *plugin.TValue[int64], v int64) {
	field.Data = v
	field.State = plugin.StateIsSet
}
