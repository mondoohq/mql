// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

// --- event hooks ---

func (o *mqlOkta) eventHooks() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.EventHookAPI.ListEventHooks(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.EventHook) error {
		for i := range datalist {
			r, err := newMqlOktaEventHook(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.EventHook
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaEventHook(runtime *plugin.Runtime, entry *okta.EventHook) (any, error) {
	authScheme, err := convert.JsonToDict(entry.Channel.Config.AuthScheme)
	if err != nil {
		return nil, err
	}
	headers, err := convert.JsonToDictSlice(entry.Channel.Config.Headers)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.eventHook", map[string]*llx.RawData{
		"id":                 llx.StringData(oktaStr(entry.Id)),
		"name":               llx.StringData(entry.Name),
		"description":        llx.StringData(oktaStr(entry.Description.Get())),
		"status":             llx.StringData(oktaStr(entry.Status)),
		"verificationStatus": llx.StringData(oktaStr(entry.VerificationStatus)),
		"events":             llx.ArrayData(convert.SliceAnyToInterface(entry.Events.Items), types.String),
		"channelType":        llx.StringData(entry.Channel.Type),
		"channelUri":         llx.StringData(entry.Channel.Config.Uri),
		"channelAuthScheme":  llx.DictData(authScheme),
		"headers":            llx.ArrayData(headers, types.Dict),
		"created":            llx.TimeDataPtr(entry.Created),
		"lastUpdated":        llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaEventHook) id() (string, error) {
	return "okta.eventHook/" + o.Id.Data, o.Id.Error
}

// --- inline hooks ---

// oktaInlineHookChannelRaw flattens the inline hook's channel, whose config
// (uri, authScheme) the SDK carries in the generic channel's untyped
// AdditionalProperties rather than a typed field. Marshaling the channel to
// JSON gives one stable path to the fields regardless of the concrete channel
// variant. This mirrors the shape of the marshaled channel object itself
// (`{"type":...,"config":{...}}`), not a wrapper around it.
type oktaInlineHookChannelRaw struct {
	Type   string `json:"type"`
	Config struct {
		Uri        string         `json:"uri"`
		AuthScheme map[string]any `json:"authScheme"`
	} `json:"config"`
}

// parseInlineHookChannel extracts the channel type, endpoint URI, and auth
// scheme from a marshaled inline hook channel object of the shape
// `{"type":...,"config":{"uri":...,"authScheme":{...}}}`.
func parseInlineHookChannel(channelJSON []byte) (channelType, channelURI string, authScheme map[string]any, err error) {
	var parsed oktaInlineHookChannelRaw
	if err := json.Unmarshal(channelJSON, &parsed); err != nil {
		return "", "", nil, err
	}
	return parsed.Type, parsed.Config.Uri, parsed.Config.AuthScheme, nil
}

func (o *mqlOkta) inlineHooks() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.InlineHookAPI.ListInlineHooks(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.InlineHook) error {
		for i := range datalist {
			r, err := newMqlOktaInlineHook(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.InlineHook
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaInlineHook(runtime *plugin.Runtime, entry *okta.InlineHook) (any, error) {
	var channelType, channelUri string
	var authScheme any
	if entry.Channel != nil {
		raw, err := json.Marshal(entry.Channel)
		if err != nil {
			return nil, err
		}
		channelType, channelUri, authScheme, err = parseInlineHookChannel(raw)
		if err != nil {
			return nil, err
		}
	}
	authSchemeDict, err := convert.JsonToDict(authScheme)
	if err != nil {
		return nil, err
	}

	metadata := oktaStringMapFrom(entry.AdditionalProperties["metadata"])

	return CreateResource(runtime, "okta.inlineHook", map[string]*llx.RawData{
		"id":                llx.StringData(oktaStr(entry.Id)),
		"name":              llx.StringData(oktaStr(entry.Name)),
		"type":              llx.StringData(oktaStr(entry.Type)),
		"status":            llx.StringData(oktaStr(entry.Status)),
		"version":           llx.StringData(oktaStr(entry.Version)),
		"channelType":       llx.StringData(channelType),
		"channelUri":        llx.StringData(channelUri),
		"channelAuthScheme": llx.DictData(authSchemeDict),
		"metadata":          llx.MapData(metadata, types.String),
		"created":           llx.TimeDataPtr(entry.Created),
		"lastUpdated":       llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaInlineHook) id() (string, error) {
	return "okta.inlineHook/" + o.Id.Data, o.Id.Error
}

// --- hook keys ---

func (o *mqlOkta) hookKeys() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.HookKeyAPI.ListHookKeys(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.HookKey) error {
		for i := range datalist {
			r, err := newMqlOktaHookKey(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.HookKey
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaHookKey(runtime *plugin.Runtime, entry *okta.HookKey) (any, error) {
	embedded, err := convert.JsonToDict(entry.AdditionalProperties["_embedded"])
	if err != nil {
		return nil, err
	}
	publicKey := oktaHookKeyPublicKey(embedded)

	var isUsed bool
	if entry.IsUsed != nil {
		isUsed = *entry.IsUsed
	}

	return CreateResource(runtime, "okta.hookKey", map[string]*llx.RawData{
		"id":          llx.StringData(oktaStr(entry.Id)),
		"name":        llx.StringData(oktaStr(entry.Name)),
		"keyId":       llx.StringData(oktaStr(entry.KeyId)),
		"isUsed":      llx.BoolData(isUsed),
		"publicKey":   llx.DictData(publicKey),
		"created":     llx.TimeDataPtr(entry.Created.Get()),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated.Get()),
	})
}

func (o *mqlOktaHookKey) id() (string, error) {
	return "okta.hookKey/" + o.Id.Data, o.Id.Error
}

// oktaHookKeyPublicKey narrows a hook key's `_embedded` payload to the public
// JWK. Okta nests the key under `_embedded.publicKey`, but the SDK types
// `_embedded` as a bare JsonWebKey, so the wrapper lands in the JWK's
// AdditionalProperties and survives the dict conversion. Unwrap the publicKey
// sub-object when present so the dict is the JWK itself; otherwise return the
// payload unchanged (correct if the envelope is ever flattened upstream).
func oktaHookKeyPublicKey(embedded any) any {
	m, ok := embedded.(map[string]any)
	if !ok {
		return embedded
	}
	if pk, ok := m["publicKey"]; ok {
		return pk
	}
	return m
}
