// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/federation"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The client models only federation mappings, so identity providers, their
// protocols, and service providers are read straight off the OS-FEDERATION
// endpoints. All three return the whole collection in one response; Keystone
// does not paginate them.

type federationIdentityProviderEntry struct {
	ID               string   `json:"id"`
	Description      string   `json:"description"`
	Enabled          bool     `json:"enabled"`
	RemoteIDs        []string `json:"remote_ids"`
	DomainID         string   `json:"domain_id"`
	AuthorizationTTL *int     `json:"authorization_ttl"`
}

type federationProtocolEntry struct {
	ID        string `json:"id"`
	MappingID string `json:"mapping_id"`
}

type federationServiceProviderEntry struct {
	ID               string `json:"id"`
	Description      string `json:"description"`
	Enabled          bool   `json:"enabled"`
	SpURL            string `json:"sp_url"`
	AuthURL          string `json:"auth_url"`
	RelayStatePrefix string `json:"relay_state_prefix"`
}

// ---- openstack.identity.federation.identityProvider ----

type mqlOpenstackIdentityFederationIdentityProviderInternal struct {
	cacheDomainID string
}

func (r *mqlOpenstackIdentityFederationIdentityProvider) id() (string, error) {
	return "openstack.identity.federation.identityProvider/" + r.Id.Data, nil
}

func (o *mqlOpenstack) federationIdentityProviders() ([]any, error) {
	client, err := conn(o.MqlRuntime).IdentityClient()
	if err != nil {
		return nil, err
	}
	var body struct {
		IdentityProviders []federationIdentityProviderEntry `json:"identity_providers"`
	}
	url := client.ServiceURL("OS-FEDERATION", "identity_providers")
	if _, err := client.Get(ctx(), url, &body, &gophercloud.RequestOpts{OkCodes: []int{200}}); err != nil {
		// A deployment without federation enabled has no identity providers
		// rather than a failing query.
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}

	out := make([]any, 0, len(body.IdentityProviders))
	for _, idp := range body.IdentityProviders {
		ttl := int64(0)
		if idp.AuthorizationTTL != nil {
			ttl = int64(*idp.AuthorizationTTL)
		}
		res, err := CreateResource(o.MqlRuntime, "openstack.identity.federation.identityProvider", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.identity.federation.identityProvider/" + idp.ID),
			"id":               llx.StringData(idp.ID),
			"enabled":          llx.BoolData(idp.Enabled),
			"description":      llx.StringData(idp.Description),
			"remoteIds":        stringSliceData(idp.RemoteIDs),
			"authorizationTtl": llx.IntData(ttl),
		})
		if err != nil {
			return nil, err
		}
		mqlIdp := res.(*mqlOpenstackIdentityFederationIdentityProvider)
		mqlIdp.cacheDomainID = idp.DomainID
		out = append(out, mqlIdp)
	}
	return out, nil
}

func (r *mqlOpenstackIdentityFederationIdentityProvider) domain() (*mqlOpenstackDomain, error) {
	if r.cacheDomainID == "" {
		r.Domain.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.domain", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheDomainID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackDomain), nil
}

// protocols reads the protocols enabled on this provider. They are only
// addressable under their provider, so this is one call per provider and it
// stays lazy until the field is asked for.
func (r *mqlOpenstackIdentityFederationIdentityProvider) protocols() ([]any, error) {
	client, err := conn(r.MqlRuntime).IdentityClient()
	if err != nil {
		return nil, err
	}
	var body struct {
		Protocols []federationProtocolEntry `json:"protocols"`
	}
	url := client.ServiceURL("OS-FEDERATION", "identity_providers", r.Id.Data, "protocols")
	if _, err := client.Get(ctx(), url, &body, &gophercloud.RequestOpts{OkCodes: []int{200}}); err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}

	out := make([]any, 0, len(body.Protocols))
	for _, p := range body.Protocols {
		res, err := CreateResource(r.MqlRuntime, "openstack.identity.federation.protocol", map[string]*llx.RawData{
			"__id": llx.StringData("openstack.identity.federation.protocol/" + r.Id.Data + "/" + p.ID),
			"id":   llx.StringData(p.ID),
		})
		if err != nil {
			return nil, err
		}
		mqlProto := res.(*mqlOpenstackIdentityFederationProtocol)
		mqlProto.cacheIdentityProvider = r
		mqlProto.cacheMappingID = p.MappingID
		out = append(out, mqlProto)
	}
	return out, nil
}

// ---- openstack.identity.federation.protocol ----

type mqlOpenstackIdentityFederationProtocolInternal struct {
	cacheIdentityProvider *mqlOpenstackIdentityFederationIdentityProvider
	cacheMappingID        string
}

func (r *mqlOpenstackIdentityFederationProtocol) identityProvider() (*mqlOpenstackIdentityFederationIdentityProvider, error) {
	if r.cacheIdentityProvider == nil {
		r.IdentityProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.cacheIdentityProvider, nil
}

func (r *mqlOpenstackIdentityFederationProtocol) mapping() (*mqlOpenstackIdentityFederationMapping, error) {
	if r.cacheMappingID == "" {
		r.Mapping.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	root, err := CreateResource(r.MqlRuntime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetFederationMappings()
	if list.Error != nil {
		return nil, list.Error
	}
	for _, raw := range list.Data {
		m, ok := raw.(*mqlOpenstackIdentityFederationMapping)
		if ok && m.Id.Data == r.cacheMappingID {
			return m, nil
		}
	}
	// The protocol names a mapping the caller cannot read, so the rules it
	// applies are unknown rather than absent.
	r.Mapping.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ---- openstack.identity.federation.mapping ----

func (r *mqlOpenstackIdentityFederationMapping) id() (string, error) {
	return "openstack.identity.federation.mapping/" + r.Id.Data, nil
}

func (o *mqlOpenstack) federationMappings() ([]any, error) {
	client, err := conn(o.MqlRuntime).IdentityClient()
	if err != nil {
		return nil, err
	}
	pages, err := federation.ListMappings(client).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := federation.ExtractMappings(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, m := range items {
		rules, err := mappingRulesToDict(m.Rules)
		if err != nil {
			return nil, err
		}
		res, err := CreateResource(o.MqlRuntime, "openstack.identity.federation.mapping", map[string]*llx.RawData{
			"__id":  llx.StringData("openstack.identity.federation.mapping/" + m.ID),
			"id":    llx.StringData(m.ID),
			"rules": dictSliceData(rules),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mappingRulesToDict renders the rule structs back to their JSON shape. Dict
// values have to be JSON-native, so the structs cannot be handed over directly.
func mappingRulesToDict(rules []federation.MappingRule) ([]any, error) {
	if len(rules) == 0 {
		return []any{}, nil
	}
	raw, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}
	var out []any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- openstack.identity.federation.serviceProvider ----

func (r *mqlOpenstackIdentityFederationServiceProvider) id() (string, error) {
	return "openstack.identity.federation.serviceProvider/" + r.Id.Data, nil
}

func (o *mqlOpenstack) federationServiceProviders() ([]any, error) {
	client, err := conn(o.MqlRuntime).IdentityClient()
	if err != nil {
		return nil, err
	}
	var body struct {
		ServiceProviders []federationServiceProviderEntry `json:"service_providers"`
	}
	url := client.ServiceURL("OS-FEDERATION", "service_providers")
	if _, err := client.Get(ctx(), url, &body, &gophercloud.RequestOpts{OkCodes: []int{200}}); err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}

	out := make([]any, 0, len(body.ServiceProviders))
	for _, sp := range body.ServiceProviders {
		res, err := CreateResource(o.MqlRuntime, "openstack.identity.federation.serviceProvider", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.identity.federation.serviceProvider/" + sp.ID),
			"id":               llx.StringData(sp.ID),
			"enabled":          llx.BoolData(sp.Enabled),
			"description":      llx.StringData(sp.Description),
			"spUrl":            llx.StringData(sp.SpURL),
			"authUrl":          llx.StringData(sp.AuthURL),
			"relayStatePrefix": llx.StringData(sp.RelayStatePrefix),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
