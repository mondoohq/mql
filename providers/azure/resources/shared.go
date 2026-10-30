// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

// parseAzureTimestamp parses an RFC 3339 timestamp string into a *time.Time,
// returning nil when the input is nil, empty, or not valid RFC 3339. Some Azure
// SDK models expose creation timestamps as strings rather than typed time
// values (e.g. the Cognitive Services account DateCreated field).
func parseAzureTimestamp(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &t
}

// isAzureNotConfigured reports whether an error means the optional feature is
// simply not configured on this resource, rather than a real failure.
//
// Azure answers 404 for sub-resources that were never created (a SQL server
// with no vulnerability-assessment storage account, a policy that does not
// apply to a database's SKU, a Defender plan that was never enabled) and 403
// when the caller holds the parent's read permission but not the narrower
// data action on the sub-resource. Neither should fail the surrounding query:
// the honest answer is a null field, not an error on every row.
//
// Some resource providers answer 400 instead, for the same "there is nothing
// here" reason. Those are matched by code, never by status alone, because 400
// also carries the two things that must NOT be swallowed: a request the caller
// got wrong, and a resource whose provisioning state has not settled yet. See
// azureNotApplicableCodes.
//
// It deliberately does NOT match 429 or 5xx. A throttled or failing call
// proves nothing about configuration, and swallowing it would report an
// authoritative "not configured" for a resource that may well be configured.
func isAzureNotConfigured(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	if respErr.StatusCode == http.StatusNotFound || respErr.StatusCode == http.StatusForbidden {
		return true
	}
	return azureFeatureNotApplicable(respErr.StatusCode, azureErrorCode(respErr), azureErrorSubcode(respErr))
}

// isAzureAccessDenied reports whether ARM refused the read.
//
// It is deliberately narrower than isAzureNotConfigured, which folds 403 in
// with the absences. On a collection that is itself the security finding -- who
// holds a grant, which rules exist -- a refused read must not be reported as an
// empty collection, because "nothing is configured" and "not allowed to look"
// would then be the same answer. A transport failure is not a refusal and does
// not match: only an ARM response carrying 403 does.
func isAzureAccessDenied(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	return respErr.StatusCode == http.StatusForbidden
}

// isAzureFeatureUnavailable reports whether ARM answered that the thing being
// read is not there to read: the resource provider is not registered, the
// resource type is not supported, or the capability is not available on this
// resource. These are absences, not failures, so a lister may report an empty
// collection for them.
//
// A refused read (403) is excluded on purpose; use isAzureAccessDenied for
// that. A transport failure carries no ARM response and does not match.
func isAzureFeatureUnavailable(err error) bool {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return false
	}
	if respErr.StatusCode == http.StatusNotFound {
		return true
	}
	return azureFeatureNotApplicable(respErr.StatusCode, azureErrorCode(respErr), azureErrorSubcode(respErr))
}

// azureErrorCode reads the error code, falling back to the body when azcore did
// not populate it.
//
// azcore fills ResponseError.ErrorCode from the wrapped {"error":{"code":...}}
// envelope. ARM also sends errors bare - {"code":"ResourceTypeNotSupported",
// "message":...} - and for those ErrorCode is empty, so an allowlist keyed on
// it can never match however many codes are added. azureErrorSubcode already
// reads both shapes; this is the same treatment for the code.
func azureErrorCode(respErr *azcore.ResponseError) string {
	if respErr == nil {
		return ""
	}
	if respErr.ErrorCode != "" {
		return respErr.ErrorCode
	}
	if respErr.RawResponse == nil {
		return ""
	}
	body, err := runtime.Payload(respErr.RawResponse)
	if err != nil || len(body) == 0 {
		return ""
	}
	var envelope struct {
		Code  string `json:"code"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	if envelope.Code != "" {
		return envelope.Code
	}
	return envelope.Error.Code
}

// azureNotApplicableCodes maps an ARM error code to the subcode that has to
// accompany it, or "" when the code alone is specific enough. Keys and values
// are lower-cased; matching is case-insensitive.
//
// This is an allowlist rather than a status check because a 400 from ARM means
// three different things, and only one of them is an absence:
//
//   - the feature this sub-resource describes does not exist on the parent, and
//     never will unless it is reconfigured. That is the honest empty answer, and
//     what is listed below.
//   - the parent's provisioning state has not settled ("Cannot fetch databases
//     while resource is in state 'Creating'", "API Management service is
//     activating"). Retrying succeeds, so reporting empty would report an
//     authoritative "no databases" for a cluster that has them.
//   - the request itself is wrong: a malformed filter, an API version the
//     provider does not accept. That is our bug, and swallowing it hides it.
//
// Only the first belongs here, so every entry names the resource and quotes the
// message ARM returns with it.
var azureNotApplicableCodes = map[string]string{
	// AKS private endpoint connections: "Cluster <name> is not a private link
	// service based private cluster." Answered by every cluster that is not a
	// private-link private cluster, which is the default shape. The code itself
	// is the generic BadRequest, so the subcode is what tells this apart from a
	// request the caller got wrong.
	"badrequest": "clusterisnotaprivatelinkcluster",

	// Azure SQL long-term retention: "Long Term Retention is not supported :
	// Not supported for master." Every server has a master database, so every
	// server produces this.
	"longtermretentionpolicynotsupported": "",

	// Defender for Cloud regulatory compliance: "Regulatory compliance is not
	// supported for subscription '...' as it has no standard pricing bundle."
	// ARM puts the whole sentence in the code field for this one.
	"subscription with no standard pricing bundle": "",

	// Diagnostic settings on a resource type that has none: "The resource type
	// 'microsoft.network/networkwatchers' does not support diagnostic
	// settings." Reading them across a subscription reaches many such types,
	// and no amount of reconfiguration makes the type support them.
	"resourcetypenotsupported": "",
}

// azureFeatureNotApplicable reports whether an ARM 400's code and subcode name
// a feature that is absent from the parent rather than a fault.
func azureFeatureNotApplicable(statusCode int, code, subcode string) bool {
	if statusCode != http.StatusBadRequest {
		return false
	}
	wantSubcode, ok := azureNotApplicableCodes[strings.ToLower(strings.TrimSpace(code))]
	if !ok {
		return false
	}
	return wantSubcode == "" || wantSubcode == strings.ToLower(strings.TrimSpace(subcode))
}

// azureErrorSubcode reads the subcode out of an ARM error body.
//
// azcore surfaces only the code (ResponseError.ErrorCode), and some providers
// leave that generic and put the useful discriminator in a sibling subcode
// field. Reading the body back is safe and cheap: azcore already downloaded it
// to build the error, and runtime.Payload serves the cached copy rather than
// re-reading the stream.
func azureErrorSubcode(respErr *azcore.ResponseError) string {
	if respErr == nil || respErr.RawResponse == nil {
		return ""
	}
	body, err := runtime.Payload(respErr.RawResponse)
	if err != nil || len(body) == 0 {
		return ""
	}
	// ARM sends the error bare or wrapped in an "error" envelope, depending on
	// the resource provider.
	var envelope struct {
		Subcode string `json:"subcode"`
		Error   struct {
			Subcode string `json:"subcode"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return ""
	}
	if envelope.Subcode != "" {
		return envelope.Subcode
	}
	return envelope.Error.Subcode
}

// missingResourceID reports that a resource was asked for without an id, and
// the scanned asset could not supply one either.
//
// An init in that position used to fall through with `return args, nil, nil`,
// which is not the harmless no-op it reads as: the runtime takes it as
// permission to build the resource from the args it has, so it creates one with
// no id and no fields set. Every field then crosses the plugin boundary as an
// empty DataRes and surfaces client-side as
//
//	provider returned no data and no error for a field ... field=tags id=
//	llx: encountered a primitive with no type information, coercing to null
//
// once per field, per asset, with an empty id to identify it by. An error says
// what actually happened and says it once.
//
// This is reachable whenever one of these resources is queried bare against an
// asset that is not itself that resource -- a subscription asset, for instance,
// whose platform ids carry only the //platformid.api.mondoo.app form and never
// the /subscriptions/... ARM id getAssetIdentifier looks for.
func missingResourceID(resourceName string) error {
	return fmt.Errorf(
		"%s requires an id: reach it from the list it belongs to, or scan the %s itself",
		resourceName, resourceName)
}

// orZero returns p when it is set, and a pointer to the zero value of T
// otherwise, so a caller can read fields off it without a nil check.
//
// ARM models almost every nested block as an optional pointer, including the
// `properties` of a list row. Reading entry.Properties.Field directly panics on
// a row that omits it -- and a panic in a provider accessor is unrecoverable:
// the executor runs blocks in goroutines, so it takes down the whole scan
// rather than the one query. Going through this helper keeps the row in the
// result with its fields reading null, which is the honest answer, instead of
// dropping it or crashing.
func orZero[T any](p *T) *T {
	if p != nil {
		return p
	}
	return new(T)
}

// subResourceCacheID builds the cache key for a sub-resource that ARM normally
// identifies by its own resource id.
//
// A resource created with neither an explicit "__id" argument nor an id()
// method gets the empty cache key. CreateResource returns the cached occupant
// of a key it has already seen, so every such instance in the scan aliases to
// the first one created and the collection reports one row's data N times. The
// failure is silent: the list has the right length, every entry has the wrong
// contents.
//
// armID is preferred because it is already parent-qualified. When the service
// omits it, parentID+collection+name reproduces the same shape from values the
// caller always has, so an absent id degrades to a longer key rather than to a
// shared one.
func subResourceCacheID(armID *string, parentID, collection, name string) string {
	if armID != nil && *armID != "" {
		return *armID
	}
	return parentID + "/" + collection + "/" + name
}

type assetIdentifier struct {
	name string
	id   string
}

func getAssetIdentifier(runtime *plugin.Runtime) *assetIdentifier {
	a := runtime.Connection.(*connection.AzureConnection).Asset()
	if a == nil {
		return nil
	}
	azureId := ""
	for _, id := range a.PlatformIds {
		if strings.HasPrefix(id, "/subscriptions/") {
			azureId = id
		}
	}
	return &assetIdentifier{name: a.Name, id: azureId}
}
