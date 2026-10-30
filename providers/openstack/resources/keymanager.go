// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/acls"
	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/containers"
	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/orders"
	"github.com/gophercloud/gophercloud/v2/openstack/keymanager/v1/secrets"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// barbicanRefID returns the trailing path segment of a Barbican ref URL
// (secret_ref, container_ref, order_ref). Returns "" for empty input.
func barbicanRefID(ref string) string {
	if ref == "" {
		return ""
	}
	if _, after, ok := strings.CutLast(ref, "/"); ok {
		return after
	}
	return ref
}

// ---- openstack.keymanager.secret ----

type mqlOpenstackKeymanagerSecretInternal struct {
	cacheCreatorID string
}

func (r *mqlOpenstackKeymanagerSecret) id() (string, error) {
	return "openstack.keymanager.secret/" + r.Id.Data, nil
}

func initOpenstackKeymanagerSecret(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetSecrets()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackKeymanagerSecret)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.keymanager.secret", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) secrets() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.KeyManagerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := secrets.List(client, secrets.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := secrets.ExtractSecrets(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		s := &items[i]
		if barbicanRefID(s.SecretRef) == "" {
			log.Warn().Str("secretRef", s.SecretRef).Msg("openstack: skipping Barbican secret with unresolvable ref")
			continue
		}
		res, err := newMqlOpenstackKeymanagerSecret(o.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlOpenstackKeymanagerSecret(runtime *plugin.Runtime, s *secrets.Secret) (*mqlOpenstackKeymanagerSecret, error) {
	id := barbicanRefID(s.SecretRef)
	res, err := CreateResource(runtime, "openstack.keymanager.secret", map[string]*llx.RawData{
		"__id":         llx.StringData("openstack.keymanager.secret/" + id),
		"id":           llx.StringData(id),
		"name":         llx.StringData(s.Name),
		"secretType":   llx.StringData(s.SecretType),
		"algorithm":    llx.StringData(s.Algorithm),
		"bitLength":    llx.IntData(int64(s.BitLength)),
		"mode":         llx.StringData(s.Mode),
		"status":       llx.StringData(s.Status),
		"contentTypes": stringMapData(s.ContentTypes),
		"secretRef":    llx.StringData(s.SecretRef),
		"expiresAt":    llx.TimeDataPtr(timePtr(s.Expiration)),
		"createdAt":    llx.TimeDataPtr(timePtr(s.Created)),
		"updatedAt":    llx.TimeDataPtr(timePtr(s.Updated)),
	})
	if err != nil {
		return nil, err
	}
	mqlSecret := res.(*mqlOpenstackKeymanagerSecret)
	mqlSecret.cacheCreatorID = s.CreatorID
	return mqlSecret, nil
}

func (r *mqlOpenstackKeymanagerSecret) creator() (*mqlOpenstackUser, error) {
	if r.cacheCreatorID == "" {
		r.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.user", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheCreatorID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackUser), nil
}

// ---- openstack.keymanager.container ----

type mqlOpenstackKeymanagerContainerInternal struct {
	cacheCreatorID      string
	cacheSecretRefs     []containers.SecretRef
	cacheCertificateID  string
	cachePrivateKeyID   string
	cacheIntermediateID string
}

func (r *mqlOpenstackKeymanagerContainer) id() (string, error) {
	return "openstack.keymanager.container/" + r.Id.Data, nil
}

func initOpenstackKeymanagerContainer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetSecretContainers()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		c := raw.(*mqlOpenstackKeymanagerContainer)
		if c.Id.Data == id {
			return args, c, nil
		}
	}
	initSyntheticID("openstack.keymanager.container", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) secretContainers() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.KeyManagerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := containers.List(client, containers.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := containers.ExtractContainers(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		ct := &items[i]
		id := barbicanRefID(ct.ContainerRef)
		if id == "" {
			log.Warn().Str("containerRef", ct.ContainerRef).Msg("openstack: skipping Barbican container with unresolvable ref")
			continue
		}
		res, err := CreateResource(o.MqlRuntime, "openstack.keymanager.container", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.keymanager.container/" + id),
			"id":           llx.StringData(id),
			"name":         llx.StringData(ct.Name),
			"type":         llx.StringData(ct.Type),
			"status":       llx.StringData(ct.Status),
			"containerRef": llx.StringData(ct.ContainerRef),
			"secretRefs":   dictSliceData(secretRefsToDict(ct.SecretRefs)),
			"consumers":    dictSliceData(consumersToDict(ct.Consumers)),
			"createdAt":    llx.TimeDataPtr(timePtr(ct.Created)),
			"updatedAt":    llx.TimeDataPtr(timePtr(ct.Updated)),
		})
		if err != nil {
			return nil, err
		}
		mqlCt := res.(*mqlOpenstackKeymanagerContainer)
		mqlCt.cacheCreatorID = ct.CreatorID
		mqlCt.cacheSecretRefs = ct.SecretRefs
		mqlCt.cacheCertificateID = barbicanRefID(namedSecretRef(ct.SecretRefs, "certificate"))
		mqlCt.cachePrivateKeyID = barbicanRefID(namedSecretRef(ct.SecretRefs, "private_key"))
		mqlCt.cacheIntermediateID = barbicanRefID(namedSecretRef(ct.SecretRefs, "intermediates"))
		out = append(out, mqlCt)
	}
	return out, nil
}

func (r *mqlOpenstackKeymanagerContainer) creator() (*mqlOpenstackUser, error) {
	if r.cacheCreatorID == "" {
		r.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.user", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheCreatorID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackUser), nil
}

func (r *mqlOpenstackKeymanagerContainer) secrets() ([]any, error) {
	if len(r.cacheSecretRefs) == 0 {
		return []any{}, nil
	}
	out := make([]any, 0, len(r.cacheSecretRefs))
	for _, ref := range r.cacheSecretRefs {
		id := barbicanRefID(ref.SecretRef)
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.keymanager.secret", map[string]*llx.RawData{
			"id":        llx.StringData(id),
			"secretRef": llx.StringData(ref.SecretRef),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackKeymanagerContainer) certificate() (*mqlOpenstackKeymanagerSecret, error) {
	return r.namedSecret(r.cacheCertificateID, &r.Certificate)
}

func (r *mqlOpenstackKeymanagerContainer) privateKey() (*mqlOpenstackKeymanagerSecret, error) {
	return r.namedSecret(r.cachePrivateKeyID, &r.PrivateKey)
}

func (r *mqlOpenstackKeymanagerContainer) intermediates() (*mqlOpenstackKeymanagerSecret, error) {
	return r.namedSecret(r.cacheIntermediateID, &r.Intermediates)
}

func (r *mqlOpenstackKeymanagerContainer) namedSecret(id string, field *plugin.TValue[*mqlOpenstackKeymanagerSecret]) (*mqlOpenstackKeymanagerSecret, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.keymanager.secret", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackKeymanagerSecret), nil
}

func secretRefsToDict(in []containers.SecretRef) []any {
	out := make([]any, 0, len(in))
	for _, ref := range in {
		out = append(out, map[string]any{
			"name":       ref.Name,
			"secret_ref": ref.SecretRef,
		})
	}
	return out
}

func consumersToDict(in []containers.ConsumerRef) []any {
	out := make([]any, 0, len(in))
	for _, c := range in {
		out = append(out, map[string]any{
			"name": c.Name,
			"url":  c.URL,
		})
	}
	return out
}

func namedSecretRef(refs []containers.SecretRef, name string) string {
	for _, ref := range refs {
		if ref.Name == name {
			return ref.SecretRef
		}
	}
	return ""
}

// ---- openstack.keymanager.order ----

type mqlOpenstackKeymanagerOrderInternal struct {
	cacheCreatorID   string
	cacheSecretID    string
	cacheContainerID string
}

func (r *mqlOpenstackKeymanagerOrder) id() (string, error) {
	return "openstack.keymanager.order/" + r.Id.Data, nil
}

func initOpenstackKeymanagerOrder(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetSecretOrders()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		o := raw.(*mqlOpenstackKeymanagerOrder)
		if o.Id.Data == id {
			return args, o, nil
		}
	}
	initSyntheticID("openstack.keymanager.order", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) secretOrders() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.KeyManagerClient()
	if err != nil {
		if serviceMissing(err) {
			return []any{}, nil
		}
		return nil, err
	}
	pages, err := orders.List(client, orders.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := orders.ExtractOrders(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		ord := &items[i]
		id := barbicanRefID(ord.OrderRef)
		if id == "" {
			log.Warn().Str("orderRef", ord.OrderRef).Msg("openstack: skipping Barbican order with unresolvable ref")
			continue
		}
		res, err := CreateResource(o.MqlRuntime, "openstack.keymanager.order", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.keymanager.order/" + id),
			"id":               llx.StringData(id),
			"type":             llx.StringData(ord.Type),
			"status":           llx.StringData(ord.Status),
			"subStatus":        llx.StringData(ord.SubStatus),
			"subStatusMessage": llx.StringData(ord.SubStatusMessage),
			"errorReason":      llx.StringData(ord.ErrorReason),
			"errorStatusCode":  llx.StringData(ord.ErrorStatusCode),
			"orderRef":         llx.StringData(ord.OrderRef),
			"meta":             llx.DictData(orderMetaToDict(ord.Meta)),
			"createdAt":        llx.TimeDataPtr(timePtr(ord.Created)),
			"updatedAt":        llx.TimeDataPtr(timePtr(ord.Updated)),
		})
		if err != nil {
			return nil, err
		}
		mqlOrd := res.(*mqlOpenstackKeymanagerOrder)
		mqlOrd.cacheCreatorID = ord.CreatorID
		mqlOrd.cacheSecretID = barbicanRefID(ord.SecretRef)
		mqlOrd.cacheContainerID = barbicanRefID(ord.ContainerRef)
		out = append(out, mqlOrd)
	}
	return out, nil
}

func (r *mqlOpenstackKeymanagerOrder) creator() (*mqlOpenstackUser, error) {
	if r.cacheCreatorID == "" {
		r.Creator.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.user", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheCreatorID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackUser), nil
}

func (r *mqlOpenstackKeymanagerOrder) secret() (*mqlOpenstackKeymanagerSecret, error) {
	if r.cacheSecretID == "" {
		r.Secret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.keymanager.secret", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheSecretID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackKeymanagerSecret), nil
}

func (r *mqlOpenstackKeymanagerOrder) container() (*mqlOpenstackKeymanagerContainer, error) {
	if r.cacheContainerID == "" {
		r.Container.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.keymanager.container", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheContainerID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackKeymanagerContainer), nil
}

func orderMetaToDict(m orders.Meta) map[string]any {
	out := map[string]any{
		"algorithm":            m.Algorithm,
		"bit_length":           m.BitLength,
		"mode":                 m.Mode,
		"name":                 m.Name,
		"payload_content_type": m.PayloadContentType,
	}
	if !m.Expiration.IsZero() {
		out["expiration"] = m.Expiration
	}
	return out
}

// ---- openstack.keymanager.acl ----

func (r *mqlOpenstackKeymanagerSecret) acl() (*mqlOpenstackKeymanagerAcl, error) {
	return loadKeymanagerACL(r.MqlRuntime, "secret", r.Id.Data, &r.Acl)
}

func (r *mqlOpenstackKeymanagerContainer) acl() (*mqlOpenstackKeymanagerAcl, error) {
	return loadKeymanagerACL(r.MqlRuntime, "container", r.Id.Data, &r.Acl)
}

type mqlOpenstackKeymanagerAclInternal struct {
	synthId string
}

func (r *mqlOpenstackKeymanagerAcl) id() (string, error) {
	return r.synthId, nil
}

func loadKeymanagerACL(runtime *plugin.Runtime, kind, id string, field *plugin.TValue[*mqlOpenstackKeymanagerAcl]) (*mqlOpenstackKeymanagerAcl, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	c := conn(runtime)
	client, err := c.KeyManagerClient()
	if err != nil {
		return nil, err
	}
	var raw *acls.ACL
	switch kind {
	case "secret":
		raw, err = acls.GetSecretACL(ctx(), client, id).Extract()
	case "container":
		raw, err = acls.GetContainerACL(ctx(), client, id).Extract()
	}
	if err != nil {
		if translateGetError(err) == nil {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if raw == nil || len(*raw) == 0 {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	entries := map[string]any{}
	for op, details := range *raw {
		users := make([]any, len(details.Users))
		for i, u := range details.Users {
			users[i] = u
		}
		entry := map[string]any{
			"users":          users,
			"project_access": details.ProjectAccess,
		}
		if !details.Created.IsZero() {
			entry["created"] = details.Created
		}
		if !details.Updated.IsZero() {
			entry["updated"] = details.Updated
		}
		entries[op] = entry
	}
	synth := "openstack.keymanager.acl/" + kind + "/" + id
	res, err := CreateResource(runtime, "openstack.keymanager.acl", map[string]*llx.RawData{
		"__id":    llx.StringData(synth),
		"entries": llx.DictData(entries),
	})
	if err != nil {
		return nil, err
	}
	mqlAcl := res.(*mqlOpenstackKeymanagerAcl)
	mqlAcl.synthId = synth
	return mqlAcl, nil
}
