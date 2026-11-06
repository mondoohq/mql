// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// nspConfigurationRecord is the ARM wire shape of a network security perimeter
// configuration. Every resource provider that supports perimeters returns this
// same document, but each Azure SDK module generates its own Go type for it,
// so the SDK value is re-read through its JSON form instead of per-SDK code.
type nspConfigurationRecord struct {
	ID         *string        `json:"id"`
	Name       *string        `json:"name"`
	Type       *string        `json:"type"`
	SystemData map[string]any `json:"systemData"`
	Properties *struct {
		ProvisioningState        *string `json:"provisioningState"`
		NetworkSecurityPerimeter *struct {
			ID            *string `json:"id"`
			Location      *string `json:"location"`
			PerimeterGUID *string `json:"perimeterGuid"`
		} `json:"networkSecurityPerimeter"`
		Profile *struct {
			Name                      *string          `json:"name"`
			AccessRulesVersion        *int64           `json:"accessRulesVersion"`
			DiagnosticSettingsVersion *int64           `json:"diagnosticSettingsVersion"`
			EnabledLogCategories      []string         `json:"enabledLogCategories"`
			AccessRules               []map[string]any `json:"accessRules"`
		} `json:"profile"`
		ResourceAssociation *struct {
			Name       *string `json:"name"`
			AccessMode *string `json:"accessMode"`
		} `json:"resourceAssociation"`
		ProvisioningIssues []map[string]any `json:"provisioningIssues"`
	} `json:"properties"`
}

// decodeNspConfiguration reads any SDK network security perimeter
// configuration value into the shared wire record.
func decodeNspConfiguration(sdkValue any) (*nspConfigurationRecord, error) {
	raw, err := json.Marshal(sdkValue)
	if err != nil {
		return nil, err
	}
	var rec nspConfigurationRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// nspConfigurationArgs builds the resource arguments for a decoded record.
// Values the service did not send stay null rather than reading as an empty
// string or zero version.
func nspConfigurationArgs(rec *nspConfigurationRecord) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(rec.ID),
		"name":                      llx.StringDataPtr(rec.Name),
		"type":                      llx.StringDataPtr(rec.Type),
		"provisioningState":         llx.NilData,
		"perimeterId":               llx.NilData,
		"perimeterLocation":         llx.NilData,
		"perimeterGuid":             llx.NilData,
		"profileName":               llx.NilData,
		"accessRulesVersion":        llx.NilData,
		"diagnosticSettingsVersion": llx.NilData,
		"enabledLogCategories":      llx.ArrayData([]any{}, types.String),
		"accessRules":               llx.ArrayData([]any{}, types.Dict),
		"associationName":           llx.NilData,
		"associationAccessMode":     llx.NilData,
		"provisioningIssues":        llx.ArrayData([]any{}, types.Dict),
	}
	props := rec.Properties
	if props == nil {
		return args
	}
	args["provisioningState"] = llx.StringDataPtr(props.ProvisioningState)
	if p := props.NetworkSecurityPerimeter; p != nil {
		args["perimeterId"] = llx.StringDataPtr(p.ID)
		args["perimeterLocation"] = llx.StringDataPtr(p.Location)
		args["perimeterGuid"] = llx.StringDataPtr(p.PerimeterGUID)
	}
	if p := props.Profile; p != nil {
		args["profileName"] = llx.StringDataPtr(p.Name)
		args["accessRulesVersion"] = llx.IntDataPtr(p.AccessRulesVersion)
		args["diagnosticSettingsVersion"] = llx.IntDataPtr(p.DiagnosticSettingsVersion)
		cats := make([]any, 0, len(p.EnabledLogCategories))
		for _, c := range p.EnabledLogCategories {
			cats = append(cats, c)
		}
		args["enabledLogCategories"] = llx.ArrayData(cats, types.String)
		rules := make([]any, 0, len(p.AccessRules))
		for _, r := range p.AccessRules {
			if r != nil {
				rules = append(rules, flattenNspProperties(r))
			}
		}
		args["accessRules"] = llx.ArrayData(rules, types.Dict)
	}
	if ra := props.ResourceAssociation; ra != nil {
		args["associationName"] = llx.StringDataPtr(ra.Name)
		args["associationAccessMode"] = llx.StringDataPtr(ra.AccessMode)
	}
	issues := make([]any, 0, len(props.ProvisioningIssues))
	for _, iss := range props.ProvisioningIssues {
		if iss != nil {
			issues = append(issues, flattenNspProperties(iss))
		}
	}
	args["provisioningIssues"] = llx.ArrayData(issues, types.Dict)
	return args
}

// nspConfigurationsToMql builds the shared configuration resources from a page
// of SDK values. Entries without an id are skipped: the id is the cache key.
func nspConfigurationsToMql[T any](runtime *plugin.Runtime, values []*T) ([]any, error) {
	res := make([]any, 0, len(values))
	for _, v := range values {
		if v == nil {
			continue
		}
		rec, err := decodeNspConfiguration(v)
		if err != nil {
			return nil, err
		}
		if rec.ID == nil || *rec.ID == "" {
			continue
		}
		r, err := CreateResource(runtime, ResourceAzureSubscriptionNetworkSecurityPerimeterConfiguration, nspConfigurationArgs(rec))
		if err != nil {
			return nil, err
		}
		r.(*mqlAzureSubscriptionNetworkSecurityPerimeterConfiguration).cacheSystemData = rec.SystemData
		res = append(res, r)
	}
	return res, nil
}

// nspConfigurationsFailure decides what a failed configuration list reports.
// A resource kind or region without perimeter support is an absence: an empty
// list in v13 behavior, NotApplicable with structured errors. A refusal is
// never an absence and stays an error, Forbidden with structured errors.
func nspConfigurationsFailure(err error, what string, permission string) ([]any, error) {
	if isAzureFeatureUnavailable(err) {
		if !plugin.StructuredErrors() {
			log.Debug().Err(err).Str("resource", what).
				Msg("azure> network security perimeter configurations not available, reporting an empty list")
			return []any{}, nil
		}
		return nil, llx.NotApplicable(err)
	}
	return nil, classifyAzureRefusal(err, permission)
}

type mqlAzureSubscriptionNetworkSecurityPerimeterConfigurationInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionNetworkSecurityPerimeterConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkSecurityPerimeterConfiguration) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
