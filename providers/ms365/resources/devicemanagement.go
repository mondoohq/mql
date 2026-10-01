// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/devicemanagement"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

type mqlMicrosoftDevicemanagementInternal struct {
	// per-device properties the managedDevices list never returns, fetched
	// for every listed device in one batched call on first access
	managedDeviceDetails batchFieldCache
}

// managedDeviceDetailFields are the managedDevice properties Graph only
// returns from a single-device GET that selects them; the list call leaves
// them empty.
var managedDeviceDetailFields = []string{"udid", "iccid", "notes", "ethernetMacAddress"}

// managedDeviceDetail holds the detail properties of one managed device. A
// nil pointer means Graph returned no value.
type managedDeviceDetail struct {
	udid               *string
	iccid              *string
	notes              *string
	ethernetMacAddress *string
}

func newManagedDeviceDetail(d models.ManagedDeviceable) managedDeviceDetail {
	if d == nil {
		return managedDeviceDetail{}
	}
	return managedDeviceDetail{
		udid:               d.GetUdid(),
		iccid:              d.GetIccid(),
		notes:              d.GetNotes(),
		ethernetMacAddress: d.GetEthernetMacAddress(),
	}
}

func (m *mqlMicrosoftDevicemanagementDeviceconfiguration) id() (string, error) {
	return m.Id.Data, nil
}

func (m *mqlMicrosoftDevicemanagementDevicecompliancepolicy) id() (string, error) {
	return m.Id.Data, nil
}

// requires DeviceManagementManagedDevices.Read.All permission
// see https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0
func (a *mqlMicrosoftDevicemanagement) managedDevices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().ManagedDevices().Get(ctx, &devicemanagement.ManagedDevicesRequestBuilderGetRequestConfiguration{
		QueryParameters: &devicemanagement.ManagedDevicesRequestBuilderGetQueryParameters{
			Expand: []string{"windowsProtectionState"},
		},
	})
	if err != nil {
		return nil, transformError(err)
	}
	allDevices, err := iterate[models.ManagedDeviceable](ctx, resp, graphClient.GetAdapter(), models.CreateManagedDeviceCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, device := range allDevices {
		device, err := newMqlMicrosoftManagedDevice(a.MqlRuntime, device)
		if err != nil {
			return nil, err
		}
		res = append(res, device)
	}
	return res, nil
}

func newMqlMicrosoftManagedDevice(runtime *plugin.Runtime, u models.ManagedDeviceable) (*mqlMicrosoftDevicemanagementManageddevice, error) {
	protectionState, err := convert.JsonToDict(newWindowsProtectionState(u.GetWindowsProtectionState()))
	if err != nil {
		return nil, err
	}

	var complianceState *string
	if u.GetComplianceState() != nil {
		s := u.GetComplianceState().String()
		complianceState = &s
	}
	var deviceRegistrationState *string
	if u.GetDeviceRegistrationState() != nil {
		s := u.GetDeviceRegistrationState().String()
		deviceRegistrationState = &s
	}
	var managementAgent *string
	if u.GetManagementAgent() != nil {
		s := u.GetManagementAgent().String()
		managementAgent = &s
	}
	var deviceEnrollmentType *string
	if u.GetDeviceEnrollmentType() != nil {
		s := u.GetDeviceEnrollmentType().String()
		deviceEnrollmentType = &s
	}
	var partnerReportedThreatState *string
	if u.GetPartnerReportedThreatState() != nil {
		s := u.GetPartnerReportedThreatState().String()
		partnerReportedThreatState = &s
	}

	graphDevice, err := CreateResource(runtime, "microsoft.devicemanagement.manageddevice",
		map[string]*llx.RawData{
			"__id":                         llx.StringDataPtr(u.GetId()),
			"id":                           llx.StringDataPtr(u.GetId()),
			"name":                         llx.StringDataPtr(u.GetDeviceName()),
			"operatingSystem":              llx.StringDataPtr(u.GetOperatingSystem()),
			"jailBroken":                   llx.StringDataPtr(u.GetJailBroken()),
			"osVersion":                    llx.StringDataPtr(u.GetOsVersion()),
			"easActivated":                 llx.BoolDataPtr(u.GetEasActivated()),
			"easDeviceId":                  llx.StringDataPtr(u.GetEasDeviceId()),
			"azureADRegistered":            llx.BoolDataPtr(u.GetAzureADRegistered()),
			"azureActiveDirectoryDeviceId": llx.StringDataPtr(u.GetAzureADDeviceId()),
			"emailAddress":                 llx.StringDataPtr(u.GetEmailAddress()),
			"deviceCategoryDisplayName":    llx.StringDataPtr(u.GetDeviceCategoryDisplayName()),
			"isSupervised":                 llx.BoolDataPtr(u.GetIsSupervised()),
			"isEncrypted":                  llx.BoolDataPtr(u.GetIsEncrypted()),
			"userPrincipalName":            llx.StringDataPtr(u.GetUserPrincipalName()),
			"model":                        llx.StringDataPtr(u.GetModel()),
			"manufacturer":                 llx.StringDataPtr(u.GetManufacturer()),
			"imei":                         llx.StringDataPtr(u.GetImei()),
			"serialNumber":                 llx.StringDataPtr(u.GetSerialNumber()),
			"androidSecurityPatchLevel":    llx.StringDataPtr(u.GetAndroidSecurityPatchLevel()),
			"userDisplayName":              llx.StringDataPtr(u.GetUserDisplayName()),
			"wiFiMacAddress":               llx.StringDataPtr(u.GetWiFiMacAddress()),
			"meid":                         llx.StringDataPtr(u.GetMeid()),
			"enrollmentProfileName":        llx.StringDataPtr(u.GetEnrollmentProfileName()),
			"windowsProtectionState":       llx.DictData(protectionState),
			"complianceState":              llx.StringDataPtr(complianceState),
			"deviceRegistrationState":      llx.StringDataPtr(deviceRegistrationState),
			"managementAgent":              llx.StringDataPtr(managementAgent),
			"lastSyncDateTime":             llx.TimeDataPtr(u.GetLastSyncDateTime()),
			"freeStorageSpaceInBytes":      llx.IntDataPtr(u.GetFreeStorageSpaceInBytes()),
			"totalStorageSpaceInBytes":     llx.IntDataPtr(u.GetTotalStorageSpaceInBytes()),
			"enrolledDateTime":             llx.TimeDataPtr(u.GetEnrolledDateTime()),
			"deviceEnrollmentType":         llx.StringDataPtr(deviceEnrollmentType),
			"partnerReportedThreatState":   llx.StringDataPtr(partnerReportedThreatState),
			"phoneNumber":                  llx.StringDataPtr(u.GetPhoneNumber()),
			"subscriberCarrier":            llx.StringDataPtr(u.GetSubscriberCarrier()),
			"complianceGracePeriodExpirationDateTime": llx.TimeDataPtr(u.GetComplianceGracePeriodExpirationDateTime()),
			"managementCertificateExpirationDate":     llx.TimeDataPtr(u.GetManagementCertificateExpirationDate()),
		})
	if err != nil {
		return nil, err
	}
	mqlDevice := graphDevice.(*mqlMicrosoftDevicemanagementManageddevice)
	if userID := u.GetUserId(); userID != nil {
		mqlDevice.cacheUserID = *userID
	}
	return mqlDevice, nil
}

func (a *mqlMicrosoftDevicemanagement) deviceConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().DeviceConfigurations().Get(ctx, &devicemanagement.DeviceConfigurationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &devicemanagement.DeviceConfigurationsRequestBuilderGetQueryParameters{
			Expand: []string{"assignments"},
		},
	})
	if err != nil {
		return nil, transformError(err)
	}

	configurations, err := iterate[models.DeviceConfigurationable](ctx, resp, graphClient.GetAdapter(), models.CreateDeviceConfigurationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, configuration := range configurations {
		policyAssignments := []any{}
		for _, assignment := range configuration.GetAssignments() {
			id := ""
			if v := assignment.GetId(); v != nil {
				id = *v
			}
			assignmentResource, err := newPolicyAssignmentResource(a.MqlRuntime, id, assignment.GetTarget())
			if err != nil {
				return nil, err
			}
			policyAssignments = append(policyAssignments, assignmentResource)
		}
		mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.deviceconfiguration",
			map[string]*llx.RawData{
				"id":                   llx.StringDataPtr(configuration.GetId()),
				"lastModifiedDateTime": llx.TimeDataPtr(configuration.GetLastModifiedDateTime()),
				"createdDateTime":      llx.TimeDataPtr(configuration.GetCreatedDateTime()),
				"description":          llx.StringDataPtr(configuration.GetDescription()),
				"displayName":          llx.StringDataPtr(configuration.GetDisplayName()),
				"version":              llx.IntDataDefault(configuration.GetVersion(), 0),
				"policyAssignments":    llx.ArrayData(policyAssignments, types.Resource("microsoft.devicemanagement.policyAssignment")),
				"platformType":         llx.StringData(deviceConfigurationPlatform(configuration)),
				"settings":             llx.DictData(deviceConfigurationSettings(configuration)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}
	return res, nil
}

func (a *mqlMicrosoftDevicemanagement) deviceEnrollmentConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.DeviceManagement().DeviceEnrollmentConfigurations().Get(ctx, &devicemanagement.DeviceEnrollmentConfigurationsRequestBuilderGetRequestConfiguration{
		QueryParameters: &devicemanagement.DeviceEnrollmentConfigurationsRequestBuilderGetQueryParameters{
			Expand: []string{"assignments"},
		},
	})
	if err != nil {
		return nil, transformError(err)
	}
	configs, err := iterate[models.DeviceEnrollmentConfigurationable](ctx, resp, graphClient.GetAdapter(), models.CreateDeviceEnrollmentConfigurationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, config := range configs {
		policyAssignments := []any{}
		for _, assignment := range config.GetAssignments() {
			id := ""
			if v := assignment.GetId(); v != nil {
				id = *v
			}
			assignmentResource, err := newPolicyAssignmentResource(a.MqlRuntime, id, assignment.GetTarget())
			if err != nil {
				return nil, err
			}
			policyAssignments = append(policyAssignments, assignmentResource)
		}
		mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.deviceEnrollmentConfiguration",
			map[string]*llx.RawData{
				"__id":                 llx.StringDataPtr(config.GetId()),
				"id":                   llx.StringDataPtr(config.GetId()),
				"displayName":          llx.StringDataPtr(config.GetDisplayName()),
				"description":          llx.StringDataPtr(config.GetDescription()),
				"createdDateTime":      llx.TimeDataPtr(config.GetCreatedDateTime()),
				"lastModifiedDateTime": llx.TimeDataPtr(config.GetLastModifiedDateTime()),
				"priority":             llx.IntDataDefault(config.GetPriority(), 0),
				"version":              llx.IntDataDefault(config.GetVersion(), 0),
				"configurationType":    llx.StringData(enrollmentConfigurationKind(config)),
				"settings":             llx.DictData(enrollmentConfigurationSettings(config)),
				"policyAssignments":    llx.ArrayData(policyAssignments, types.Resource("microsoft.devicemanagement.policyAssignment")),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}

	return res, nil
}

func (a *mqlMicrosoftDevicemanagement) deviceCompliancePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	requestConfig := &devicemanagement.DeviceCompliancePoliciesRequestBuilderGetRequestConfiguration{
		QueryParameters: &devicemanagement.DeviceCompliancePoliciesRequestBuilderGetQueryParameters{
			Expand: []string{"assignments", "scheduledActionsForRule($expand=scheduledActionConfigurations)"},
		},
	}
	resp, err := graphClient.DeviceManagement().DeviceCompliancePolicies().Get(ctx, requestConfig)
	if err != nil {
		return nil, transformError(err)
	}
	compliancePolicies, err := iterate[models.DeviceCompliancePolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateDeviceCompliancePolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, compliancePolicy := range compliancePolicies {
		assignments, err := convert.JsonToDictSlice(newDeviceCompliancePolicyAssignments(compliancePolicy.GetAssignments()))
		if err != nil {
			return nil, err
		}
		policyAssignments := []any{}
		for _, assignment := range compliancePolicy.GetAssignments() {
			id := ""
			if v := assignment.GetId(); v != nil {
				id = *v
			}
			assignmentResource, err := newPolicyAssignmentResource(a.MqlRuntime, id, assignment.GetTarget())
			if err != nil {
				return nil, err
			}
			policyAssignments = append(policyAssignments, assignmentResource)
		}
		mqlResource, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement.devicecompliancepolicy",
			map[string]*llx.RawData{
				"id":                      llx.StringDataPtr(compliancePolicy.GetId()),
				"createdDateTime":         llx.TimeDataPtr(compliancePolicy.GetCreatedDateTime()),
				"description":             llx.StringDataPtr(compliancePolicy.GetDescription()),
				"displayName":             llx.StringDataPtr(compliancePolicy.GetDisplayName()),
				"lastModifiedDateTime":    llx.TimeDataPtr(compliancePolicy.GetLastModifiedDateTime()),
				"version":                 llx.IntDataDefault(compliancePolicy.GetVersion(), 0),
				"assignments":             llx.ArrayData(assignments, types.Any),
				"policyAssignments":       llx.ArrayData(policyAssignments, types.Resource("microsoft.devicemanagement.policyAssignment")),
				"platformType":            llx.StringData(compliancePolicyPlatform(compliancePolicy)),
				"settings":                llx.DictData(complianceSettings(compliancePolicy)),
				"scheduledActionsForRule": llx.ArrayData(scheduledActionsForRule(compliancePolicy), types.Any),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlResource)
	}
	return res, nil
}

// detail returns the per-device detail properties, fetching them for every
// listed managed device in one batched Graph call on first access.
func (a *mqlMicrosoftDevicemanagementManageddevice) detail() (managedDeviceDetail, error) {
	res, err := CreateResource(a.MqlRuntime, "microsoft.devicemanagement", nil)
	if err != nil {
		return managedDeviceDetail{}, err
	}
	dm := res.(*mqlMicrosoftDevicemanagement)
	var ids []string
	if list := dm.GetManagedDevices(); list.Error == nil {
		ids = make([]string, 0, len(list.Data))
		for _, item := range list.Data {
			ids = append(ids, item.(*mqlMicrosoftDevicemanagementManageddevice).Id.Data)
		}
	}
	v, err := dm.managedDeviceDetails.resolve(a.Id.Data, ids, dm.loadManagedDeviceDetails)
	if err != nil {
		return managedDeviceDetail{}, err
	}
	if v == nil {
		return managedDeviceDetail{}, nil
	}
	return v.(managedDeviceDetail), nil
}

// loadManagedDeviceDetails issues one GET per managed device, selecting only
// the detail properties, through the Graph $batch endpoint.
func (a *mqlMicrosoftDevicemanagement) loadManagedDeviceDetails(ids []string) (map[string]any, map[string]error, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, nil, err
	}
	return fetchManagedDeviceDetails(context.Background(), graphClient, ids)
}

// fetchManagedDeviceDetails reads the detail properties of each managed
// device, keyed by device id. A per-device failure lands in the error map
// without failing the others.
func fetchManagedDeviceDetails(ctx context.Context, graphClient *msgraphsdkgo.GraphServiceClient, ids []string) (map[string]any, map[string]error, error) {
	reqs := make([]batchItemRequest, 0, len(ids))
	for _, id := range ids {
		info, err := graphClient.DeviceManagement().ManagedDevices().ByManagedDeviceId(id).ToGetRequestInformation(ctx,
			&devicemanagement.ManagedDevicesManagedDeviceItemRequestBuilderGetRequestConfiguration{
				QueryParameters: &devicemanagement.ManagedDevicesManagedDeviceItemRequestBuilderGetQueryParameters{
					Select: managedDeviceDetailFields,
				},
			})
		if err != nil {
			return nil, nil, transformError(err)
		}
		reqs = append(reqs, batchItemRequest{key: id, reqInfo: info})
	}
	batch, err := batchGet[models.ManagedDeviceable](ctx, graphClient.GetAdapter(), reqs, models.CreateManagedDeviceFromDiscriminatorValue)
	if err != nil {
		return nil, nil, err
	}
	data := make(map[string]any, len(ids))
	for id, d := range batch.results {
		data[id] = newManagedDeviceDetail(d)
	}
	return data, batch.errs, nil
}

func (a *mqlMicrosoftDevicemanagementManageddevice) udid() (string, error) {
	d, err := a.detail()
	if err != nil {
		return "", err
	}
	return detailString(&a.Udid, d.udid), nil
}

func (a *mqlMicrosoftDevicemanagementManageddevice) iccid() (string, error) {
	d, err := a.detail()
	if err != nil {
		return "", err
	}
	return detailString(&a.Iccid, d.iccid), nil
}

func (a *mqlMicrosoftDevicemanagementManageddevice) notes() (string, error) {
	d, err := a.detail()
	if err != nil {
		return "", err
	}
	return detailString(&a.Notes, d.notes), nil
}

func (a *mqlMicrosoftDevicemanagementManageddevice) ethernetMacAddress() (string, error) {
	d, err := a.detail()
	if err != nil {
		return "", err
	}
	return detailString(&a.EthernetMacAddress, d.ethernetMacAddress), nil
}

// detailString returns the value of an optional detail property, marking the
// field null when Graph returned none so it reads as null rather than "".
func detailString(field *plugin.TValue[string], v *string) string {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return ""
	}
	return *v
}
