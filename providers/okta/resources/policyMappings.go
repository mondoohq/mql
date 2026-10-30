// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// oktaPolicyMappingResourceTypeApp is the resource type Okta reports for a
// mapping that binds a policy to an application. It is the only type an
// application reference can be resolved from.
const oktaPolicyMappingResourceTypeApp = "APP"

type mqlOktaPolicyMappingInternal struct {
	cacheApplicationID string
}

func (o *mqlOktaPolicy) mappings() ([]any, error) {
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	if o.Id.Data == "" {
		return []any{}, nil
	}

	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()

	mappings, resp, err := client.PolicyAPI.ListPolicyMappings(ctx, o.Id.Data).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.Mappings)
		}
		return nil, err
	}

	list := []any{}
	appendEntries := func(entries []okta.PolicyMapping) error {
		for i := range entries {
			r, err := newMqlOktaPolicyMapping(o.MqlRuntime, o.Id.Data, &entries[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntries(mappings); err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var page []okta.PolicyMapping
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntries(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

// oktaPolicyMappingFields reads the mapping's own fields. The generated model
// declares only the id and the HAL links, so the resource ids Okta actually
// sends land in AdditionalProperties and are read from there. The application
// id falls back to the HAL link when the resource fields are absent, since the
// link is present on every application binding.
func oktaPolicyMappingFields(entry *okta.PolicyMapping) (resourceType, resourceID, status, applicationID string) {
	resourceType = oktaStrFrom(entry.AdditionalProperties["resourceType"])
	resourceID = oktaStrFrom(entry.AdditionalProperties["resourceId"])
	status = oktaStrFrom(entry.AdditionalProperties["status"])

	if links := entry.Links; links != nil && links.Application != nil {
		applicationID = lastPathSegment(links.Application.Href)
	}
	if resourceType == oktaPolicyMappingResourceTypeApp && resourceID != "" {
		applicationID = resourceID
	}
	// A binding of some other kind must not resolve to an application, however
	// its link happens to be shaped.
	if resourceType != "" && resourceType != oktaPolicyMappingResourceTypeApp {
		applicationID = ""
	}
	return resourceType, resourceID, status, applicationID
}

func newMqlOktaPolicyMapping(runtime *plugin.Runtime, policyID string, entry *okta.PolicyMapping) (*mqlOktaPolicyMapping, error) {
	if entry == nil {
		return nil, errors.New("okta returned an empty policy mapping")
	}

	id := oktaStr(entry.Id)
	resourceType, resourceID, status, applicationID := oktaPolicyMappingFields(entry)

	// A mapping repeats per policy as well as per mapping id, so the cache key
	// carries both. Two policies bound to the same application would otherwise
	// collide and the second would report the first one's binding.
	r, err := CreateResource(runtime, "okta.policy.mapping", map[string]*llx.RawData{
		"__id":         llx.StringData("okta.policy.mapping/" + policyID + "/" + id),
		"id":           llx.StringData(id),
		"resourceType": llx.StringData(resourceType),
		"resourceId":   llx.StringData(resourceID),
		"status":       llx.StringData(status),
	})
	if err != nil {
		return nil, err
	}

	mapping := r.(*mqlOktaPolicyMapping)
	mapping.cacheApplicationID = applicationID
	return mapping, nil
}

func (o *mqlOktaPolicyMapping) application() (*mqlOktaApplication, error) {
	return resolveOktaApplicationRef(o.MqlRuntime, o.cacheApplicationID, &o.Application)
}
