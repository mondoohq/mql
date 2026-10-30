// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

func (o *mqlOkta) deviceAssurancePolicies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.DeviceAssuranceAPI.ListDeviceAssurancePolicies(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.ListDeviceAssurancePolicies200ResponseInner) error {
		for i := range datalist {
			r, err := newMqlOktaDeviceAssurancePolicy(o.MqlRuntime, &datalist[i])
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
		var page []okta.ListDeviceAssurancePolicies200ResponseInner
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

// deviceAssuranceMetadataKeys are the policy-level fields lifted out of the
// flattened response; every remaining key is a platform-specific constraint
// and belongs in the settings dict.
var deviceAssuranceMetadataKeys = []string{
	"id", "name", "platform", "createdBy", "createdDate",
	"lastUpdate", "lastUpdatedBy", "_links",
}

// deviceAssuranceConstraints returns a copy of the flattened policy map with
// the policy-level metadata keys removed, leaving only the platform-specific
// device-trust constraints. The input map is not mutated.
func deviceAssuranceConstraints(policy map[string]any) map[string]any {
	metadata := make(map[string]struct{}, len(deviceAssuranceMetadataKeys))
	for _, k := range deviceAssuranceMetadataKeys {
		metadata[k] = struct{}{}
	}
	constraints := map[string]any{}
	for k, v := range policy {
		if _, isMeta := metadata[k]; !isMeta {
			constraints[k] = v
		}
	}
	return constraints
}

func newMqlOktaDeviceAssurancePolicy(runtime *plugin.Runtime, entry *okta.ListDeviceAssurancePolicies200ResponseInner) (any, error) {
	raw, err := json.Marshal(entry.GetActualInstance())
	if err != nil {
		return nil, err
	}

	var meta struct {
		Id          string `json:"id"`
		Name        string `json:"name"`
		Platform    string `json:"platform"`
		CreatedDate string `json:"createdDate"`
		LastUpdate  string `json:"lastUpdate"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, err
	}

	// Everything that is not policy metadata is a platform-specific constraint.
	settingsMap := map[string]any{}
	if err := json.Unmarshal(raw, &settingsMap); err != nil {
		return nil, err
	}
	settings, err := convert.JsonToDict(deviceAssuranceConstraints(settingsMap))
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.deviceAssurancePolicy", map[string]*llx.RawData{
		"id":          llx.StringData(meta.Id),
		"name":        llx.StringData(meta.Name),
		"platform":    llx.StringData(meta.Platform),
		"settings":    llx.DictData(settings),
		"created":     llx.TimeDataPtr(parseOktaRFC3339(meta.CreatedDate)),
		"lastUpdated": llx.TimeDataPtr(parseOktaRFC3339(meta.LastUpdate)),
	})
}

func (o *mqlOktaDeviceAssurancePolicy) id() (string, error) {
	return "okta.deviceAssurancePolicy/" + o.Id.Data, o.Id.Error
}

// parseOktaRFC3339 parses an RFC3339 timestamp string, returning nil when the
// value is empty or not parseable so the field renders as null rather than a
// zero time.
func parseOktaRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}
