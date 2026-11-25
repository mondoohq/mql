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
//
// An entry of a type derived from T is handed over as the T it is built on,
// see baseEntry. The SDK's iterator panics on those as well.
//
// A panic during the walk, in each or in the SDK while fetching or decoding a
// page, ends the walk with an error for this one list. Callers page from
// worker goroutines too (pim_groups.go), where the plugin SDK's recovery does
// not reach.
func iterateEach[T any](ctx context.Context, res any, adapter abstractions.RequestAdapter, constructorFunc serialization.ParsableFactory, each func(T) error) (err error) {
	collection := collectionName(res)
	defer recoverAsError("paging "+collection, &err)
	if adapter == nil {
		return errors.New("reqAdapter can't be nil")
	}
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
	// The page is read through reflection, as the SDK reads it. A response
	// this cannot read is an error for the one list, never a panic that takes
	// the provider down with it.
	defer func() {
		if r := recover(); r != nil {
			items, nextLink = nil, ""
			err = fmt.Errorf("reading a page of %s: %v", collectionName(res), r)
		}
	}()
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
			item, ok = baseEntry[T](entry)
		}
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

// baseEntry returns the T that a page entry of a derived Graph type is built
// on. Graph answers a collection with the entries' most specific types: a
// service principal listing can hold an agentIdentityBlueprintPrincipal, which
// the SDK models as a struct embedding ServicePrincipal. Such an entry is not
// a *models.ServicePrincipal, but the one it embeds is, and holds every
// property of the base type. A caller that asks for the concrete base type
// gets that one.
func baseEntry[T any](entry reflect.Value) (T, bool) {
	var none T
	if entry.Kind() == reflect.Interface {
		entry = entry.Elem()
	}
	if entry.Kind() != reflect.Pointer || entry.Elem().Kind() != reflect.Struct {
		return none, false
	}
	derived := entry.Elem()
	for i := 0; i < derived.NumField(); i++ {
		field := derived.Type().Field(i)
		if !field.Anonymous || !field.IsExported() || field.Type.Kind() != reflect.Struct {
			continue
		}
		base := derived.Field(i).Addr()
		if item, ok := base.Interface().(T); ok {
			return item, true
		}
		if item, ok := baseEntry[T](base); ok {
			return item, true
		}
	}
	return none, false
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
