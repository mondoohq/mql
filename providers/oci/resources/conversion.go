// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func stringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func boolValue(s *bool) bool {
	if s == nil {
		return false
	}
	return *s
}

func int64Value(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

func intValue(i *int) int64 {
	if i == nil {
		return 0
	}
	return int64(*i)
}

// intPtrToInt64 widens an optional SDK int so llx.IntDataPtr can tell an absent
// value from a zero one. Dropping the pointer here would report "no lead time
// configured" and "a lead time of zero weeks" as the same answer.
func intPtrToInt64(i *int) *int64 {
	if i == nil {
		return nil
	}
	v := int64(*i)
	return &v
}

// isOcid returns true if the string looks like a valid OCI resource identifier.
// OCI uses placeholder values like "ORACLE_MANAGED_KEY" for system-managed
// resources; those should not be resolved via init lookups.
func isOcid(s string) bool {
	return strings.HasPrefix(s, "ocid1.")
}

// ociRegionFromOCID extracts the region from an OCI resource OCID. OCIDs have
// the shape ocid1.<resourceType>.<realm>.<region>.<uniqueID>, so the region is
// the fourth dot-separated segment (e.g. "us-sanjose-1"). It is empty for
// global resources (ocid1.user.oc1..aaaa). Returns "" when the OCID is
// malformed or carries no region; callers should fall back to a known region.
func ociRegionFromOCID(ocid string) string {
	parts := strings.Split(ocid, ".")
	if len(parts) < 5 {
		return ""
	}
	return parts[3]
}

// ociResourceTypeFromOCID extracts the resource-type segment from an OCI OCID.
// OCIDs have the shape ocid1.<resourceType>.<realm>.<region>.<uniqueID>, so the
// type is the second dot-separated segment (e.g. "internetgateway", "drg",
// "natgateway"). Returns "" when the OCID is malformed.
func ociResourceTypeFromOCID(ocid string) string {
	parts := strings.Split(ocid, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// ociRouteTargetType maps a route rule's target OCID to the kind of network
// entity it forwards traffic to. Returns the uppercased raw OCID resource type
// for entity kinds without a dedicated route accessor, or "" for a malformed
// OCID.
func ociRouteTargetType(ocid string) string {
	switch ociResourceTypeFromOCID(ocid) {
	case "":
		return ""
	case "internetgateway":
		return "INTERNET_GATEWAY"
	case "natgateway":
		return "NAT_GATEWAY"
	case "servicegateway":
		return "SERVICE_GATEWAY"
	case "drg":
		return "DRG"
	case "localpeeringgateway":
		return "LOCAL_PEERING_GATEWAY"
	case "privateip":
		return "PRIVATE_IP"
	default:
		return strings.ToUpper(ociResourceTypeFromOCID(ocid))
	}
}

func jobErr(err error) []*jobpool.Job {
	return []*jobpool.Job{{Err: err}}
}

// sdkTimeData wraps an OCI SDKTime as RawData, returning NilData for nil.
func sdkTimeData(t *common.SDKTime) *llx.RawData {
	if t == nil {
		return llx.NilData
	}
	return llx.TimeData(t.Time)
}

// stringsToAny converts an OCI-typed []string to []any for llx.ArrayData.
func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// stringsOrNull converts an optional []string to a string array, keeping a
// list the API omitted null rather than reporting it as an empty list.
func stringsOrNull(in []string) *llx.RawData {
	if in == nil {
		return llx.NilData
	}
	return llx.ArrayData(stringsToAny(in), types.String)
}

// dictSlice converts a slice of SDK structs to []dict, keeping an absent one
// empty rather than nil.
//
// convert.JsonToDictSlice marshals a nil slice to "null" and unmarshals that
// back into a nil slice, because encoding/json sets a slice to nil for a JSON
// null rather than leaving the empty one it was given. So a resource whose
// list the API omitted ends up with a nil where every other list field in this
// provider has an empty slice.
//
// Today that renders the same, but only because rawDataString reaches the
// value through a bare `value.([]any)` that a typed nil happens to satisfy.
// That is not a property worth depending on, and the inconsistency is the kind
// that surfaces later as "why is this one field null".
func dictSlice(in any) ([]any, error) {
	out, err := convert.JsonToDictSlice(in)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return []any{}, nil
	}
	return out, nil
}

// strMapToAny converts an OCI freeform-tags-style map[string]string to
// map[string]any so it can be passed to llx.MapData.
func strMapToAny(in map[string]string) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// definedTagsToAny converts the OCI defined-tags shape (namespace -> key -> value)
// to map[string]any (namespace -> map[string]any), preserving string values and
// passing through anything non-string unchanged.
func definedTagsToAny(in map[string]map[string]interface{}) map[string]any {
	out := make(map[string]any, len(in))
	for ns, kv := range in {
		nsOut := make(map[string]any, len(kv))
		for k, v := range kv {
			if s, ok := v.(string); ok {
				nsOut[k] = s
				continue
			}
			nsOut[k] = v
		}
		out[ns] = nsOut
	}
	return out
}

// ociRegionServiceUnavailable reports whether the error means the service has
// no endpoint in that region, either because it is not deployed there or the
// tenancy is not entitled to it. Such a region is an expected absence and is
// skipped so a tenancy-wide query still returns what does exist.
//
// It deliberately does not treat an authorization or throttling failure as an
// absence: those are real problems, and reporting a short list as authoritative
// is worse than reporting the error. See ociRunRegionPool, which is the main
// consumer.
func ociRegionServiceUnavailable(err error) bool {
	if svcErr, ok := common.IsServiceError(err); ok {
		// Only a 404 can mean "this service has no endpoint in this region".
		// 401 is a credential problem and 403 (NotAuthorizedOrNotFound) is the
		// standard IAM-policy gap, which OCI returns in *every* region -
		// swallowing either turns an under-scoped token into an authoritative
		// "this tenancy has no resources", which is worse than an error.
		if svcErr.GetHTTPStatusCode() == 404 {
			return true
		}
		// A service error carries a real API response, so the transport-level
		// signatures below cannot apply to it.
		return false
	}
	// Regions where the service is not deployed have no regional endpoint, so
	// the DNS lookup for the host fails with "no such host".
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	// Some regions publish a wildcard DNS record for a service that is not
	// actually deployed there, so the host resolves but the TCP connection
	// times out. Treat connection timeouts (and the deadline they surface as)
	// the same as an absent endpoint.
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	// The OCI SDK wraps transport errors in a type that does not implement
	// Unwrap, so errors.As/Is above can miss a timeout. Fall back to matching
	// the message for the unreachable-endpoint signatures.
	msg := strings.ToLower(err.Error())
	for _, s := range []string{
		"timeout", "timed out", "deadline exceeded",
		"no such host", "connection refused", "no route to host",
	} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// ociRunRegionPool joins a set of jobs the caller built itself, under the same
// error policy ociCollect applies to the tenancy-root scope.
//
// It is the escape hatch for the handful of collections that are not a
// (region, compartment) fan-out and so cannot go through ociCollect:
//
//   - OCI IAM is global within a realm. Every regional identity endpoint serves
//     the same tenancy-wide set, so users, groups and policies run as a single
//     job. Fanning them out over regions returned each one once per subscribed
//     region, and because CreateResource hands back the cached instance for a
//     repeated __id, the result held N copies of one pointer and every count was
//     inflated N-fold.
//   - The AI services wrap their per-region fetch in their own helper so an
//     undeployed region is skipped per-region rather than per-job.
//
// Anything that is a plain (region, compartment) fan-out should use ociCollect,
// which names its scope. This exists so those two cases do not have to pretend
// to be one.
func ociRunRegionPool(jobs []*jobpool.Job) ([]any, error) {
	return ociJoinRegionJobs(jobs, ociScopeTenancyRoot.concurrency())
}

// ociAvailabilityDomainCache memoizes a region's availability domains.
//
// Some OCI APIs are scoped to an availability domain rather than a region, so a
// lister has to ask which domains exist before it can ask its real question.
// That answer is the same for every compartment and does not change during a
// scan, while the listers needing it run inside a compartment fan-out - so
// without this, one collection costs an Identity call per compartment. Keyed by
// connection and region because a tenancy's domains differ between regions.
// The mutex guards the map only. The fetch itself is serialized by the
// per-region ociRetryLazy, so a cold cache blocks the callers asking about that
// one region rather than every caller in the scan - and other regions keep
// resolving in parallel.
var (
	ociAvailabilityDomainCache   = map[string]*ociRetryLazy[[]string]{}
	ociAvailabilityDomainCacheMu sync.Mutex
)

// ociAvailabilityDomainEntry returns the fetch guard for one cache key,
// creating it on first use.
//
// Separated from the fetch so the lock covers the map access and nothing else.
// Holding it across the API call would serialize every region in the scan
// behind whichever one happened to ask first.
func ociAvailabilityDomainEntry(key string) *ociRetryLazy[[]string] {
	ociAvailabilityDomainCacheMu.Lock()
	defer ociAvailabilityDomainCacheMu.Unlock()

	entry, ok := ociAvailabilityDomainCache[key]
	if !ok {
		entry = &ociRetryLazy[[]string]{}
		ociAvailabilityDomainCache[key] = entry
	}
	return entry
}

// ociAvailabilityDomains returns the names of the availability domains in a
// region.
//
// compartmentID is passed through to the Identity call, which accepts any
// compartment in the tenancy and answers the same either way; it is not part of
// the cache key for that reason. A failure is not cached - that is
// ociRetryLazy's policy - so a throttled call is retried by the next caller
// rather than emptying the region for the rest of the scan.
func ociAvailabilityDomains(ctx context.Context, conn *connection.OciConnection, region, compartmentID string) ([]string, error) {
	entry := ociAvailabilityDomainEntry(fmt.Sprintf("%d/%s", conn.ID(), region))

	return entry.get(func() ([]string, error) {
		client, err := conn.IdentityClientWithRegion(region)
		if err != nil {
			return nil, err
		}
		resp, err := client.ListAvailabilityDomains(ctx, identity.ListAvailabilityDomainsRequest{
			CompartmentId: common.String(compartmentID),
		})
		if err != nil {
			return nil, err
		}

		names := make([]string, 0, len(resp.Items))
		for i := range resp.Items {
			if name := stringValue(resp.Items[i].Name); name != "" {
				names = append(names, name)
			}
		}
		return names, nil
	})
}
