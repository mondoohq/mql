// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/go-openapi/strfmt"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ibm/connection"
	"go.mondoo.com/mql/types"
)

func conn(runtime *plugin.Runtime) *connection.IbmConnection {
	return runtime.Connection.(*connection.IbmConnection)
}

// classifyError turns an IBM Cloud API failure into an llx error kind (ADR
// 046). permission is the IAM action the call needed, recorded on a refusal.
// A failure that is not an API answer (a transport error, a timeout) is
// returned unclassified.
func classifyError(err error, permission string) error {
	if err == nil {
		return nil
	}
	var opts []llx.ErrorOption
	if permission != "" {
		opts = append(opts, llx.WithPermissions(permission))
	}
	switch code := connection.StatusCode(err); {
	case code == http.StatusUnauthorized:
		// The token was refused: every later call fails the same way.
		return llx.Unauthenticated(err, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))
	case code == http.StatusForbidden:
		return llx.Forbidden(err, opts...)
	case code == http.StatusNotFound:
		return llx.NotFound(err)
	case code == http.StatusGone:
		return llx.Gone(err)
	case code == http.StatusTooManyRequests:
		return llx.TooManyRequests(err)
	case code >= 500:
		return llx.Unavailable(err)
	}
	return err
}

// isRefusal reports a failure that refuses one partition (one region) rather
// than the whole query.
func isRefusal(err error) bool {
	return llx.KindOf(err) == llx.ErrorKind_ERROR_KIND_FORBIDDEN
}

// regional pairs an item with the VPC region it was listed in.
type regional[T any] struct {
	region string
	item   T
}

// listAllRegions calls list for every VPC region of the connection
// concurrently and returns the items in region order. A region that refuses
// the call is logged and skipped so the other regions' data survives (ADR 046
// §8); when no region answered, the refusal is returned rather than an empty
// list. Any other failure fails the whole list.
func listAllRegions[T any](runtime *plugin.Runtime, permission string, list func(c *vpcv1.VpcV1) ([]T, error)) ([]regional[T], error) {
	c := conn(runtime)
	regions, err := c.VpcRegions()
	if err != nil {
		return nil, classifyError(err, "is.region.region.read")
	}
	results := make([][]T, len(regions))
	errs := make([]error, len(regions))
	names := make([]string, len(regions))
	var wg sync.WaitGroup
	for i := range regions {
		names[i] = derefStr(regions[i].Name)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			client, err := c.VpcClient(regions[i])
			if err != nil {
				errs[i] = err
				return
			}
			items, err := list(client)
			results[i] = items
			errs[i] = classifyError(err, permission)
		}(i)
	}
	wg.Wait()
	return mergeRegionResults(names, results, errs, permission)
}

func mergeRegionResults[T any](regions []string, results [][]T, errs []error, permission string) ([]regional[T], error) {
	var out []regional[T]
	var refusal error
	answered := false
	for i, r := range regions {
		if errs[i] != nil {
			if isRefusal(errs[i]) {
				log.Debug().Err(errs[i]).Str("region", r).Str("permission", permission).Msg("ibm> skipping region")
				if refusal == nil {
					refusal = errs[i]
				}
				continue
			}
			return nil, errs[i]
		}
		answered = true
		for _, item := range results[i] {
			out = append(out, regional[T]{region: r, item: item})
		}
	}
	if !answered && refusal != nil {
		return nil, refusal
	}
	// Every region that answered returned nothing: the resource genuinely does
	// not exist in the queried regions.
	return out, nil
}

// root returns the singleton ibm resource whose list fields are the shared,
// once-fetched caches every cross-reference resolves through.
func root(runtime *plugin.Runtime) (*mqlIbm, error) {
	res, err := NewResource(runtime, "ibm", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlIbm), nil
}

// pickByID returns the entries of list whose id is in ids, in the order of
// ids. Ids not in the list are logged and skipped: the list covers the
// regions the connection queries, so a miss is a resource outside them.
func pickByID[R any](list []any, ids []string, idOf func(R) string) []any {
	out := make([]any, 0, len(ids))
	if len(ids) == 0 {
		return out
	}
	byID := make(map[string]any, len(list))
	for _, e := range list {
		if r, ok := e.(R); ok {
			byID[idOf(r)] = e
		}
	}
	for _, id := range ids {
		if e, ok := byID[id]; ok {
			out = append(out, e)
			continue
		}
		log.Debug().Str("id", id).Msg("ibm> referenced resource not found in the listed regions")
	}
	return out
}

// pickOneByID is pickByID for a single reference.
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

// resolveOne resolves a typed reference through a cached list, null when the
// id is empty or the target is not listed.
func resolveOne[R any](field *plugin.TValue[R], list *plugin.TValue[[]any], id string, idOf func(R) string) (R, error) {
	var zero R
	if id == "" {
		nullResource(field)
		return zero, nil
	}
	if list.Error != nil {
		return zero, list.Error
	}
	return resolveIn(field, list.Data, id, idOf)
}

// resolveIn resolves a typed reference through an already-read list, null
// when the target is not listed.
func resolveIn[R any](field *plugin.TValue[R], list []any, id string, idOf func(R) string) (R, error) {
	if r, ok := pickOneByID(list, id, idOf); ok {
		return r, nil
	}
	nullResource(field)
	var zero R
	return zero, nil
}

// filterByTags narrows a list to the resources --filters keeps. The tag index
// is only read when a filter is set.
func filterByTags[R any](runtime *plugin.Runtime, list []any, crnOf func(R) string) ([]any, error) {
	if !conn(runtime).Filters.HasFilters() {
		return list, nil
	}
	out := make([]any, 0, len(list))
	for _, e := range list {
		r, ok := e.(R)
		if !ok {
			continue
		}
		skip, err := filteredOut(runtime, crnOf(r))
		if err != nil {
			return nil, err
		}
		if !skip {
			out = append(out, e)
		}
	}
	return out, nil
}

// stringArg reads a string init argument; an absent or non-string one is "".
func stringArg(args map[string]*llx.RawData, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	s, _ := v.Value.(string)
	return s
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func strData(s *string) *llx.RawData {
	return llx.StringData(derefStr(s))
}

func intPtrData(v *int64) *llx.RawData {
	return llx.IntDataPtr(v)
}

// dateTimeData maps an absent or zero SDK timestamp to null.
func dateTimeData(t *strfmt.DateTime) *llx.RawData {
	if t == nil || time.Time(*t).IsZero() {
		return llx.NilData
	}
	return llx.TimeData(time.Time(*t))
}

// rfc3339Data parses a timestamp the API returns as a string; an empty or
// unparseable one is null.
func rfc3339Data(s *string) *llx.RawData {
	if s == nil || *s == "" {
		return llx.NilData
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return llx.NilData
	}
	return llx.TimeData(t)
}

func stringsData(in []string) *llx.RawData {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return llx.ArrayData(out, types.String)
}

func stringMapData(in map[string]string) *llx.RawData {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return llx.MapData(out, types.String)
}

// notSet maps IBM Cloud's NOT_SET placeholder, and an absent value, to null.
func notSet(s *string) *llx.RawData {
	if s == nil || *s == "" || *s == "NOT_SET" {
		return llx.NilData
	}
	return llx.StringData(*s)
}

// notSetInt parses a numeric account setting IBM Cloud returns as a string;
// NOT_SET, absent, or unparseable is null.
func notSetInt(s *string) *llx.RawData {
	if s == nil || *s == "" || *s == "NOT_SET" {
		return llx.NilData
	}
	n, err := strconv.ParseInt(*s, 10, 64)
	if err != nil {
		return llx.NilData
	}
	return llx.IntData(n)
}

// splitList splits a comma-separated list, dropping blanks.
func splitList(s *string) []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, p := range strings.Split(*s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// crnService returns the service name segment of a CRN:
// crn:v1:bluemix:public:<service>:<location>:...
func crnService(crn string) string {
	parts := strings.Split(crn, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}

// asJSON re-reads one of the SDK's polymorphic values (a rule variant, a
// target reference) through its JSON form into a flat struct, so every variant
// is read the same way instead of through a type switch per variant.
func asJSON(in any, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// getJSON reads an API path the SDK models lossily, or not at all, into out
// through the service's own client, so it shares its authentication, retries,
// and timeout.
func getJSON(svc *core.BaseService, path string, headers map[string]string, out any) error {
	b := core.NewRequestBuilder(core.GET)
	if _, err := b.ResolveRequestURL(svc.Options.URL, path, nil); err != nil {
		return err
	}
	b.AddHeader("Accept", "application/json")
	for k, v := range headers {
		b.AddHeader(k, v)
	}
	req, err := b.Build()
	if err != nil {
		return err
	}
	var raw json.RawMessage
	if _, err := svc.Request(req, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// crnSegment returns a segment of a CRN:
// crn:v1:bluemix:public:<service 4>:<location 5>:a/<account 6>:<instance 7>:<type 8>:<resource 9>
func crnSegment(crn string, i int) string {
	parts := strings.Split(crn, ":")
	if i < len(parts) {
		return parts[i]
	}
	return ""
}

// pageToken extracts the paging token from the next-page URL the IAM APIs
// return.
func pageToken(next *string, param string) *string {
	if next == nil || *next == "" {
		return nil
	}
	tok, err := core.GetQueryParam(next, param)
	if err != nil || tok == nil || *tok == "" {
		return nil
	}
	return tok
}

// advances reports whether a next-page cursor moves past the current one. An
// absent cursor ends the walk, and so does one the API hands back unchanged,
// which would otherwise loop forever.
func advances(current, next *string) bool {
	if next == nil {
		return false
	}
	return current == nil || *current != *next
}

func resourceGroupID(ref *vpcv1.ResourceGroupReference) string {
	if ref == nil {
		return ""
	}
	return derefStr(ref.ID)
}

func zoneName(ref *vpcv1.ZoneReference) string {
	if ref == nil {
		return ""
	}
	return derefStr(ref.Name)
}

func vpcID(ref *vpcv1.VPCReference) string {
	if ref == nil {
		return ""
	}
	return derefStr(ref.ID)
}
