// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"runtime"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/serialization"
	msgraphgocore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/rs/zerolog/log"
)

// iterate walks every page of a Microsoft Graph collection response and returns
// the flattened list of items. See iterateEach for the error handling.
func iterate[T any](ctx context.Context, res any, adapter abstractions.RequestAdapter, constructorFunc serialization.ParsableFactory) ([]T, error) {
	resp := []T{}
	err := iterateEach(ctx, res, adapter, constructorFunc, func(item T) error {
		resp = append(resp, item)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// iterateEach walks every page of a Microsoft Graph collection response and
// passes each item to each as its page arrives. An error from each stops the
// walk and is returned. Nothing is kept between pages,
// so a caller that reduces each item to what it needs holds only that. Use it
// over iterate for collections that grow with the tenant, such as reports with
// a row per user.
//
// It recovers from the failed type assertion raised inside the SDK's page
// iterator. The SDK's convertToPage (msgraph-sdk-go-core page_iterator.go)
// type-asserts every element of a page's `value` collection to T without a nil
// check. When Graph returns a null entry in the collection, the SDK's own
// deserializer stores it as a nil interface (see e.g.
// ServicePrincipalCollectionResponse: nil elements are left as the zero value),
// and the subsequent assertion panics with "interface conversion: interface {}
// is nil" (a *runtime.TypeAssertionError). A single malformed page must not
// crash the whole scan, so we recover from that specific panic and keep
// whatever was handed over before it, following the provider's "continue with
// accessible resources" error-handling convention. Any other panic is
// re-raised unchanged so genuine bugs are not silently swallowed.
func iterateEach[T any](ctx context.Context, res any, adapter abstractions.RequestAdapter, constructorFunc serialization.ParsableFactory, each func(T) error) (err error) {
	collected := 0
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(*runtime.TypeAssertionError); !ok {
				panic(r) // not the known SDK nil-element panic; preserve normal panic semantics
			}
			log.Warn().
				Interface("recover", r).
				Int("collected", collected).
				Msg("ms365> recovered from nil-element panic while paging Graph results; returning partial results")
			err = nil
		}
	}()

	iterator, err := msgraphgocore.NewPageIterator[T](res, adapter, constructorFunc)
	if err != nil {
		return transformError(err)
	}
	var eachErr error
	err = iterator.Iterate(ctx, func(item T) bool {
		if eachErr = each(item); eachErr != nil {
			return false
		}
		collected++
		return true
	})
	if eachErr != nil {
		return eachErr
	}
	if err != nil {
		return transformError(err)
	}
	return nil
}
