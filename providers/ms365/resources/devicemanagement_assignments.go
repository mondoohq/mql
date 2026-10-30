// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// additionalDataString reads a string out of a kiota AdditionalData bag.
//
// Kiota stores unmatched JSON scalars as pointers, so a value that arrived as a
// JSON string is a *string in the bag, not a string. A direct assertion to
// string therefore never succeeds and silently yields the zero value. Accept
// both shapes so the read works regardless of how the property was stored.
func additionalDataString(add map[string]any, key string) string {
	switch v := add[key].(type) {
	case string:
		return v
	case *string:
		if v != nil {
			return *v
		}
	}
	return ""
}

// assignmentTargetInfo extracts the discriminator, group id, exclusion flag,
// and optional assignment-filter metadata from a Graph assignment target.
// The filter id and type live in AdditionalData because the v1 SDK does not
// expose typed getters for them on the base target interface.
func assignmentTargetInfo(target models.DeviceAndAppManagementAssignmentTargetable) (targetType, groupId string, excluded bool, filterType, filterId string) {
	if target == nil {
		return "", "", false, "", ""
	}
	if t := target.GetOdataType(); t != nil {
		targetType = trimOdataType(*t)
	}
	switch concrete := target.(type) {
	case *models.GroupAssignmentTarget:
		if g := concrete.GetGroupId(); g != nil {
			groupId = *g
		}
	case *models.ExclusionGroupAssignmentTarget:
		excluded = true
		if g := concrete.GetGroupId(); g != nil {
			groupId = *g
		}
	}
	add := target.GetAdditionalData()
	filterType = additionalDataString(add, "deviceAndAppManagementAssignmentFilterType")
	filterId = additionalDataString(add, "deviceAndAppManagementAssignmentFilterId")
	return targetType, groupId, excluded, filterType, filterId
}

// trimOdataType strips the leading "#microsoft.graph." namespace from an
// @odata.type value so the result reads as a plain discriminator name.
func trimOdataType(s string) string {
	const prefix = "#microsoft.graph."
	if len(s) > len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

// newPolicyAssignmentResource builds a microsoft.devicemanagement.policyAssignment
// from an assignment id and target. The id is used as the resource cache key.
func newPolicyAssignmentResource(runtime *plugin.Runtime, id string, target models.DeviceAndAppManagementAssignmentTargetable) (any, error) {
	targetType, groupId, excluded, filterType, filterId := assignmentTargetInfo(target)
	return createPolicyAssignmentResource(runtime, id, targetType, groupId, excluded, filterType, filterId)
}

// betaAssignmentTargetInfo mirrors assignmentTargetInfo for the beta SDK's
// parallel target type. Endpoint security intents, app detections per device,
// and Windows Autopilot live on the beta endpoint.
//
// Unlike v1, the beta target declares the assignment-filter properties as real
// field deserializers, so they are consumed into the backing store and never
// reach AdditionalData. Read the typed getters here; the AdditionalData lookup
// is kept only as a fallback in case a future SDK drops the typed accessors.
func betaAssignmentTargetInfo(target betamodels.DeviceAndAppManagementAssignmentTargetable) (targetType, groupId string, excluded bool, filterType, filterId string) {
	if target == nil {
		return "", "", false, "", ""
	}
	if t := target.GetOdataType(); t != nil {
		targetType = trimOdataType(*t)
	}
	switch concrete := target.(type) {
	case *betamodels.GroupAssignmentTarget:
		if g := concrete.GetGroupId(); g != nil {
			groupId = *g
		}
	case *betamodels.ExclusionGroupAssignmentTarget:
		excluded = true
		if g := concrete.GetGroupId(); g != nil {
			groupId = *g
		}
	}
	if v := target.GetDeviceAndAppManagementAssignmentFilterType(); v != nil {
		filterType = v.String()
	}
	if v := target.GetDeviceAndAppManagementAssignmentFilterId(); v != nil {
		filterId = *v
	}
	add := target.GetAdditionalData()
	if filterType == "" {
		filterType = additionalDataString(add, "deviceAndAppManagementAssignmentFilterType")
	}
	if filterId == "" {
		filterId = additionalDataString(add, "deviceAndAppManagementAssignmentFilterId")
	}
	return targetType, groupId, excluded, filterType, filterId
}

// newBetaPolicyAssignmentResource mirrors newPolicyAssignmentResource for the
// beta SDK. The resulting MQL schema is identical to the v1 path.
func newBetaPolicyAssignmentResource(runtime *plugin.Runtime, id string, target betamodels.DeviceAndAppManagementAssignmentTargetable) (any, error) {
	targetType, groupId, excluded, filterType, filterId := betaAssignmentTargetInfo(target)
	return createPolicyAssignmentResource(runtime, id, targetType, groupId, excluded, filterType, filterId)
}

// createPolicyAssignmentResource is the shared builder behind the v1 and beta
// paths. The group and filter IDs are kept on the resource rather than in the
// schema, because only the group and filter accessors consume them.
func createPolicyAssignmentResource(runtime *plugin.Runtime, id, targetType, groupId string, excluded bool, filterType, filterId string) (any, error) {
	resource, err := CreateResource(runtime, "microsoft.devicemanagement.policyAssignment",
		map[string]*llx.RawData{
			"__id":       llx.StringData(id),
			"id":         llx.StringData(id),
			"targetType": llx.StringData(targetType),
			"excluded":   llx.BoolData(excluded),
			"filterType": llx.StringData(filterType),
		})
	if err != nil {
		return nil, err
	}
	mqlAssignment := resource.(*mqlMicrosoftDevicemanagementPolicyAssignment)
	mqlAssignment.cacheGroupID = groupId
	mqlAssignment.cacheFilterID = filterId
	return mqlAssignment, nil
}
