// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

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
// walk and is returned. No item is kept between pages,
// so a caller that reduces each item to what it needs holds only that. Use it
// over iterate for collections that grow with the tenant, such as reports with
// a row per user.
//
// It follows @odata.nextLink itself instead of using the SDK's PageIterator.
// Graph can return a null entry in a page's `value` collection, which the
// SDK's deserializer keeps as a nil element, and the SDK's convertToPage
// (msgraph-sdk-go-core page_iterator.go) then panics asserting it to T. The
// page is fetched and parsed by then: only the null entry is unreadable. So a
// null entry is skipped, the rest of its page is handed over and the walk goes
// on to the next page. One warning per walk says how many entries were skipped
// and in which collection.
func iterateEach[T any](ctx context.Context, res any, adapter abstractions.RequestAdapter, constructorFunc serialization.ParsableFactory, each func(T) error) error {
	if adapter == nil {
		return errors.New("reqAdapter can't be nil")
	}
	collection := collectionName(res)
	skipped := 0
	defer func() {
		if skipped > 0 {
			log.Warn().
				Str("collection", collection).
				Int("skipped", skipped).
				Msg("ms365> skipped null entries while paging Graph results")
		}
	}()

	errorMappings, _ := msgraphgocore.GetErrorFactoryFromRegistry(msgraphgocore.PageIteratorErrorRegistryKey)
	fetched := map[string]struct{}{} // the next links followed so far
	for {
		items, nulls, nextLink, err := graphPage[T](res)
		skipped += nulls
		if err != nil {
			return transformError(err)
		}
		for _, item := range items {
			if err := each(item); err != nil {
				return err
			}
		}
		if nextLink == "" {
			return nil
		}
		if _, ok := fetched[nextLink]; ok {
			return fmt.Errorf("paging %s: a page names an already fetched page as the next page", collection)
		}
		fetched[nextLink] = struct{}{}

		link, err := url.Parse(nextLink)
		if err != nil {
			return fmt.Errorf("paging %s: parsing nextLink: %w", collection, err)
		}
		requestInfo := abstractions.NewRequestInformation()
		requestInfo.Method = abstractions.GET
		requestInfo.SetUri(*link)
		next, err := adapter.Send(ctx, requestInfo, constructorFunc, errorMappings)
		if err != nil {
			return transformError(err)
		}
		res = next
	}
}

// graphPage reads one page of a Graph collection response: its non-null
// entries, the number of null entries left out, and its @odata.nextLink (empty
// on the last page).
func graphPage[T any](res any) (items []T, nulls int, nextLink string, err error) {
	rv := reflect.ValueOf(res)
	if isNilValue(rv) {
		return nil, 0, "", errors.New("response cannot be nil")
	}
	getValue := rv.MethodByName("GetValue")
	if !getValue.IsValid() || getValue.Type().NumIn() != 0 || getValue.Type().NumOut() != 1 {
		return nil, 0, "", errors.New("value property missing in response object")
	}
	value := getValue.Call(nil)[0]
	if value.Kind() != reflect.Slice {
		return nil, 0, "", errors.New("value property of the response object is not a list")
	}
	page, ok := res.(msgraphgocore.PageWithOdataNextLink)
	if !ok {
		return nil, 0, "", errors.New("response does not have next link accessor")
	}

	items = make([]T, 0, value.Len())
	for i := 0; i < value.Len(); i++ {
		entry := value.Index(i)
		if isNilValue(entry) {
			nulls++
			continue
		}
		item, ok := entry.Interface().(T)
		if !ok {
			return nil, nulls, "", fmt.Errorf("%s holds entries of type %T, not %s", collectionName(res), entry.Interface(), reflect.TypeFor[T]())
		}
		items = append(items, item)
	}
	if link := page.GetOdataNextLink(); link != nil {
		nextLink = *link
	}
	return items, nulls, nextLink, nil
}

// isNilValue reports whether v holds no value: an invalid value, a nil
// interface, or a nil pointer, also when an interface wraps that pointer.
func isNilValue(v reflect.Value) bool {
	if v.Kind() == reflect.Interface {
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Invalid:
		return true
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// collectionName names the Graph collection a response holds, for log lines:
// the response's type without its package, such as UserCollectionResponse.
func collectionName(res any) string {
	name := fmt.Sprintf("%T", res)
	return name[strings.LastIndex(name, ".")+1:]
}
