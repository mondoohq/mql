// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

// Nearly every list accessor in this provider walks an ARM pager and turns each
// row into an MQL resource. Written out per call site, that loop is about
// fifteen lines of scaffolding around two lines of service-specific logic -- and
// four of the things it does are decisions rather than mechanism: how long a
// call may take, what a denied read reports, what a truncated walk reports, and
// whether a nil row is dropped or dereferenced. Made independently a few hundred
// times, those decisions drift, and the drift is invisible because nothing
// fails: the list still has a length, the rows are just wrong or absent.
//
// listPaged makes them once. What is left at each call site is the pager and a
// mapping function, which is the part that actually differs between services --
// and, being pure, the part that can be tested without a subscription.

// listPagerTimeout bounds a single page fetch.
//
// The plugin API gives an accessor no context to inherit, so there is nothing to
// propagate a cancelled scan from; the best available is to make sure no single
// call can hang forever. The bound is per page rather than per walk so that a
// large collection is not cut off partway through merely for being large.
//
// Matches armHTTPTimeout in arm_paging.go, which bounds the hand-rolled requests
// for the same reason.
const listPagerTimeout = 60 * time.Second

// pager is the part of *azruntime.Pager[P] that listPaged uses. Depending on the
// interface rather than the concrete SDK type is what lets the walk be tested
// against a fake that returns pages and errors on demand, with no HTTP and no
// credential.
type pager[P any] interface {
	More() bool
	NextPage(context.Context) (P, error)
}

// azureFaultKind classifies an ARM error by what the caller should report,
// rather than by what went wrong.
type azureFaultKind int

const (
	// faultFatal is anything that proves nothing about the resource: a
	// throttle, a 5xx, a transport failure, an expired credential. It must
	// surface as an error. Reporting it as "nothing here" would state as fact
	// something the call never established.
	faultFatal azureFaultKind = iota

	// faultDenied is a 403: the collection exists, and this identity may not
	// see it. The honest answer is null -- unknown -- not an empty list.
	//
	// This distinction is the whole reason the type exists. An empty list is a
	// claim that there is nothing there, and a policy written as
	// `things.none(insecure)` passes on it. Reported for a read that was
	// refused, that is a silent pass on an unexamined subscription.
	faultDenied

	// faultAbsent is a 404: the resource provider is not registered in this
	// subscription, or the service is not available here. Unlike a denial this
	// is an answer -- there are genuinely zero resources of this kind -- so an
	// empty list is correct and a null would understate what is known.
	faultAbsent
)

// azureFault classifies err.
//
// It deliberately does not treat 429 or 5xx as anything but fatal: a throttled
// or failing call says nothing about whether the collection is empty, and
// degrading it would report an authoritative answer derived from no data.
//
// note: the provider still carries about ten hand-written variants of this
// predicate (isAzureForbidden, isCosmosForbiddenError, isFunctionAppForbiddenError
// and so on) plus a further ~99 inline status checks. Folding those onto this
// function is follow-up work; this is the classifier the shared lister uses.
func azureFault(err error) azureFaultKind {
	var respErr *azcore.ResponseError
	if !errors.As(err, &respErr) {
		return faultFatal
	}
	switch respErr.StatusCode {
	case http.StatusForbidden:
		return faultDenied
	case http.StatusNotFound:
		return faultAbsent
	default:
		return faultFatal
	}
}

// listPaged walks every page of an ARM pager and builds one MQL resource per
// row.
//
// field is the resource field being computed. listPaged writes null into it
// directly when the read was denied; returning (nil, nil) would not do it,
// because GetOrCompute renders an unset nil slice as an empty list -- which is
// exactly the silent pass faultDenied exists to prevent. GetOrCompute checks
// whether the field was set proactively and keeps that value, so setting it here
// is the supported way to report null from an accessor.
//
// what names the collection for log messages, e.g. "event hub namespaces".
func listPaged[P, I any](
	runtime *plugin.Runtime,
	field *plugin.TValue[[]any],
	what string,
	p pager[P],
	pageItems func(P) []*I,
	create func(*plugin.Runtime, *I) (plugin.Resource, error),
) ([]any, error) {
	var res []any

	for p.More() {
		ctx, cancel := context.WithTimeout(context.Background(), listPagerTimeout)
		page, err := p.NextPage(ctx)
		cancel()

		if err != nil {
			// A fault partway through a walk is not the same as a fault on the
			// first page. Returning what was collected so far would present a
			// truncated collection as a complete one, and a policy cannot tell
			// the difference -- so once any row has been read, only a complete
			// walk may be reported.
			if len(res) > 0 {
				return nil, errors.New("could not read all " + what + ": " + err.Error())
			}

			switch azureFault(err) {
			case faultDenied:
				log.Warn().Err(err).Str("collection", what).
					Msg("azure> not permitted to list, reporting null")
				field.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			case faultAbsent:
				log.Debug().Err(err).Str("collection", what).
					Msg("azure> not available in this subscription, reporting an empty list")
				return []any{}, nil
			default:
				return nil, err
			}
		}

		for _, item := range pageItems(page) {
			// ARM omits rows on occasion; dereferencing one would panic, and a
			// panic in an accessor takes down the whole scan rather than the
			// one query, because the executor runs blocks in goroutines.
			if item == nil {
				continue
			}
			resource, err := create(runtime, item)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}

	return res, nil
}

// azureConn returns the Azure connection behind a runtime.
//
// The unchecked form of this assertion appears at ~394 sites in this package.
// Each is a panic waiting on a connection of the wrong type, and a panic in an
// accessor is unrecoverable -- the executor runs blocks in goroutines, so it
// ends the scan rather than the query.
func azureConn(runtime *plugin.Runtime) (*connection.AzureConnection, error) {
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return conn, nil
}
