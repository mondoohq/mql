// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

func (r *mqlAzuredevopsRepository) webhooks() ([]any, error) {
	client := connectionOf(r.MqlRuntime).Client()
	// Without View subscriptions the list below comes back empty with a 200, so
	// a policy would pass on hooks it cannot see. Ask first and refuse instead.
	ok, err := client.CanViewSubscriptions(apiContext(), r.ProjectId.Data)
	if err != nil {
		return nil, classifyForbidden(err)
	}
	if !ok {
		// The portal has no page for this permission, so name the CLI call.
		return nil, llx.Forbidden(fmt.Errorf("azure devops: the credential may not view the service hooks of project %q; "+
			"grant it View subscriptions with: az devops security permission update --namespace-id %s "+
			"--token PublisherSecurity/%s --allow-bit 1 --subject <its descriptor>",
			r.ProjectName.Data, connection.ServiceHooksNamespace, r.ProjectId.Data))
	}

	subs, err := client.Subscriptions(apiContext())
	if err != nil {
		return nil, classifyForbidden(err)
	}

	out := []any{}
	for _, s := range subs {
		if !s.AppliesToRepository(r.ProjectId.Data, r.Id.Data) {
			continue
		}
		u := s.URL()
		if u == nil {
			continue
		}
		scheme := strings.ToLower(u.Scheme)
		res, err := CreateResource(r.MqlRuntime, "azuredevops.webhook", map[string]*llx.RawData{
			"__id":       llx.StringData("azuredevops.webhook/" + s.ID),
			"id":         llx.StringData(s.ID),
			"eventType":  llx.StringData(s.EventType),
			"consumerId": llx.StringData(s.ConsumerID),
			"status":     llx.StringData(s.Status),
			"active":     llx.BoolData(s.Active()),
			"scheme":     llx.StringData(scheme),
			"host":       llx.StringData(u.Host),
			"isHttps":    llx.BoolData(scheme == "https"),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
