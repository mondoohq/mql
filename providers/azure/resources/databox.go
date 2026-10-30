// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databox/armdatabox/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionDataBoxServiceJobInternal struct {
	cacheSystemData              any
	cacheUserAssignedIdentityIds []string

	detailsOnce sync.Once
	details     *armdatabox.CommonJobDetails
	detailsErr  error
}

func (a *mqlAzureSubscriptionDataBoxService) id() (string, error) {
	return "azure.subscription.dataBoxService/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionDataBoxService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())

	return args, nil, nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionDataBoxServiceJob(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionDataBoxService,
		func(s *mqlAzureSubscriptionDataBoxService) *plugin.TValue[[]any] { return s.GetJobs() },
		ResourceAzureSubscriptionDataBoxServiceJob)
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionDataBoxService) jobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := armdatabox.NewJobsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, job := range page.Value {
			if job == nil {
				continue
			}
			mqlJob, err := createDataBoxJobResource(a.MqlRuntime, job)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlJob)
		}
	}
	return res, nil
}

func createDataBoxJobResource(runtime *plugin.Runtime, job *armdatabox.JobResource) (*mqlAzureSubscriptionDataBoxServiceJob, error) {
	props := job.Properties
	if props == nil {
		props = &armdatabox.JobProperties{}
	}

	identity, err := convert.JsonToDict(job.Identity)
	if err != nil {
		return nil, err
	}

	jobIdentity := orZero(job.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(jobIdentity.UserAssignedIdentities)

	var skuName, skuDisplayName, skuFamily, skuModel string
	if job.SKU != nil {
		skuName = enumString(job.SKU.Name)
		skuDisplayName = convert.ToValue(job.SKU.DisplayName)
		skuFamily = convert.ToValue(job.SKU.Family)
		skuModel = enumString(job.SKU.Model)
	}

	resourceIdentity, err := resourceIdentityData(runtime, convert.ToValue(job.ID), userAssignedIdentityIds,
		identityType(jobIdentity.Type), identityPrincipalId(jobIdentity.PrincipalID), identityTenantId(jobIdentity.TenantID))
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, ResourceAzureSubscriptionDataBoxServiceJob,
		map[string]*llx.RawData{
			"id":                 llx.StringDataPtr(job.ID),
			"name":               llx.StringDataPtr(job.Name),
			"location":           llx.StringDataPtr(job.Location),
			"type":               llx.StringDataPtr(job.Type),
			"tags":               llx.MapData(convert.PtrMapStrToInterface(job.Tags), types.String),
			"status":             llx.StringData(enumString(props.Status)),
			"transferType":       llx.StringData(enumString(props.TransferType)),
			"deliveryType":       llx.StringData(enumString(props.DeliveryType)),
			"startTime":          llx.TimeDataPtr(props.StartTime),
			"isCancellable":      llx.BoolDataPtr(props.IsCancellable),
			"isDeletable":        llx.BoolDataPtr(props.IsDeletable),
			"allDevicesLost":     llx.BoolDataPtr(props.AllDevicesLost),
			"cancellationReason": llx.StringDataPtr(props.CancellationReason),
			"skuName":            llx.StringData(skuName),
			"skuDisplayName":     llx.StringData(skuDisplayName),
			"skuFamily":          llx.StringData(skuFamily),
			"skuModel":           llx.StringData(skuModel),
			"identity":           llx.DictData(identity),
			"resourceIdentity":   resourceIdentity,
		})
	if err != nil {
		return nil, err
	}

	mqlJob := resource.(*mqlAzureSubscriptionDataBoxServiceJob)

	sysData, err := convert.JsonToDict(job.SystemData)
	if err != nil {
		return nil, err
	}
	mqlJob.cacheSystemData = sysData

	return mqlJob, nil
}

// fetchDetails reads the job's detail block, which carries the encryption
// preferences and the passkey protection.
//
// The list endpoint does not return it: only the per-job read does, and only
// when asked with $expand=details. Every field that comes out of the block
// shares this one call, so a query naming several of them still costs one
// request per job, and a query naming none costs nothing.
func (a *mqlAzureSubscriptionDataBoxServiceJob) fetchDetails() (*armdatabox.CommonJobDetails, error) {
	a.detailsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
		ctx := context.Background()

		parsed, err := ParseResourceID(a.Id.Data)
		if err != nil {
			a.detailsErr = err
			return
		}
		jobName, err := parsed.Component("jobs")
		if err != nil {
			a.detailsErr = err
			return
		}

		client, err := armdatabox.NewJobsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
			ClientOptions: conn.ClientOptions(),
		})
		if err != nil {
			a.detailsErr = err
			return
		}

		expand := "details"
		resp, err := client.Get(ctx, parsed.ResourceGroup, jobName, &armdatabox.JobsClientGetOptions{
			Expand: &expand,
		})
		if err != nil {
			a.detailsErr = err
			return
		}
		if resp.Properties == nil || resp.Properties.Details == nil {
			return
		}
		a.details = resp.Properties.Details.GetCommonJobDetails()
	})
	return a.details, a.detailsErr
}

// dataBoxEncryptionPreferences reads the two encryption states out of a job's
// detail block. Both levels are optional, and a job that states no preference
// gets Azure's default rather than nothing, so the absence reports as empty
// rather than as "Disabled" — the caller can tell "not requested" from
// "requested off".
func dataBoxEncryptionPreferences(details *armdatabox.CommonJobDetails) (doubleEncryption string, hardwareEncryption string) {
	if details == nil || details.Preferences == nil || details.Preferences.EncryptionPreferences == nil {
		return "", ""
	}
	prefs := details.Preferences.EncryptionPreferences
	return enumString(prefs.DoubleEncryption), enumString(prefs.HardwareEncryption)
}

// dataBoxKeyEncryptionKey reads the protection on the device passkey: whether
// the key is Microsoft-managed or customer-managed, the key URL, and the vault
// holding it. A Microsoft-managed job carries no URL or vault, which is the
// answer rather than a missing reading.
func dataBoxKeyEncryptionKey(details *armdatabox.CommonJobDetails) (kekType string, kekURL string, kekVaultID string) {
	if details == nil || details.KeyEncryptionKey == nil {
		return "", "", ""
	}
	kek := details.KeyEncryptionKey
	return enumString(kek.KekType), convert.ToValue(kek.KekURL), convert.ToValue(kek.KekVaultResourceID)
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) jobDetailsType() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil {
		a.JobDetailsType.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return enumString(details.JobDetailsType), nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) expectedDataSizeInTeraBytes() (int64, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return 0, err
	}
	if details == nil {
		a.ExpectedDataSizeInTeraBytes.State = plugin.StateIsNull | plugin.StateIsSet
		return 0, nil
	}
	return int64(convert.ToValue(details.ExpectedDataSizeInTeraBytes)), nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) doubleEncryption() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil {
		a.DoubleEncryption.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	doubleEncryption, _ := dataBoxEncryptionPreferences(details)
	return doubleEncryption, nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) hardwareEncryption() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil {
		a.HardwareEncryption.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	_, hardwareEncryption := dataBoxEncryptionPreferences(details)
	return hardwareEncryption, nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) kekType() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil {
		a.KekType.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	kekType, _, _ := dataBoxKeyEncryptionKey(details)
	return kekType, nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) kekUrl() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil {
		a.KekUrl.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	_, kekURL, _ := dataBoxKeyEncryptionKey(details)
	return kekURL, nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) kek() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	_, kekURL, _ := dataBoxKeyEncryptionKey(details)
	if kekURL == "" {
		a.Kek.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, kekURL)
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) kekVault() (*mqlAzureSubscriptionKeyVaultServiceVault, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return nil, err
	}
	_, _, kekVaultID := dataBoxKeyEncryptionKey(details)
	if kekVaultID == "" {
		a.KekVault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionKeyVaultServiceVault,
		map[string]*llx.RawData{"id": llx.StringData(kekVaultID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionKeyVaultServiceVault), nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) dataCenterCode() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil {
		a.DataCenterCode.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return enumString(details.DataCenterCode), nil
}

func (a *mqlAzureSubscriptionDataBoxServiceJob) deviceErasureStatus() (string, error) {
	details, err := a.fetchDetails()
	if err != nil {
		return "", err
	}
	if details == nil || details.DeviceErasureDetails == nil {
		a.DeviceErasureStatus.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return enumString(details.DeviceErasureDetails.DeviceErasureStatus), nil
}
