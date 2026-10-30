// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	cloudssoclient "github.com/alibabacloud-go/cloudsso-20210515/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// cloudssoStatusEnabled reports whether a CloudSSO Enabled/Disabled status
// string means the feature is on. An absent status reads as off, because a
// setting nobody could read must not report a control that may not be in place.
func cloudssoStatusEnabled(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "Enabled")
}

// cloudssoTaskSucceeded reports whether a provisioning task completed. Only
// Success counts: InProgress has not finished, and a failed revocation leaves
// the access it was withdrawing still granted.
func cloudssoTaskSucceeded(status *string) bool {
	return strings.EqualFold(strings.TrimSpace(tea.StringValue(status)), "Success")
}

// cloudssoSamlState memoizes the directory's federated identity provider, which
// both samlIdentityProvider and ssoEnabled read.
type cloudssoSamlState struct {
	samlOnce sync.Once
	saml     *cloudssoclient.GetExternalSAMLIdentityProviderResponseBodySAMLIdentityProviderConfiguration
}

// samlConfiguration reads the directory's external SAML identity provider once.
// A directory with no provider configured answers with an empty configuration
// or an error; both resolve to nil, which the callers report as "no federated
// sign-in" rather than as a failure.
func (r *mqlAlicloudCloudssoDirectory) samlConfiguration() *cloudssoclient.GetExternalSAMLIdentityProviderResponseBodySAMLIdentityProviderConfiguration {
	r.samlOnce.Do(func() {
		client, directoryID, err := r.cloudssoClient()
		if err != nil {
			log.Debug().Err(err).Msg("alicloud> could not reach CloudSSO to read the SAML provider")
			return
		}
		resp, err := client.GetExternalSAMLIdentityProvider(&cloudssoclient.GetExternalSAMLIdentityProviderRequest{
			DirectoryId: new(directoryID),
		})
		if err != nil {
			log.Debug().Err(err).Str("directory", directoryID).
				Msg("alicloud> could not read the CloudSSO SAML identity provider")
			return
		}
		if resp == nil || resp.Body == nil || resp.Body.SAMLIdentityProviderConfiguration == nil {
			return
		}
		cfg := resp.Body.SAMLIdentityProviderConfiguration
		// a directory with no provider answers with a populated envelope whose
		// entity is blank, which is "not configured" rather than a provider
		if tea.StringValue(cfg.EntityId) == "" && tea.StringValue(cfg.SSOStatus) == "" {
			return
		}
		r.saml = cfg
	})
	return r.saml
}

func (r *mqlAlicloudCloudssoDirectory) samlIdentityProvider() (*mqlAlicloudCloudssoSamlIdentityProvider, error) {
	cfg := r.samlConfiguration()
	if cfg == nil {
		r.SamlIdentityProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	directoryID := r.DirectoryId.Data
	resource, err := CreateResource(r.MqlRuntime, "alicloud.cloudsso.samlIdentityProvider", map[string]*llx.RawData{
		"__id":              llx.StringData(directoryID + "/samlIdentityProvider"),
		"directoryId":       llx.StringData(directoryID),
		"entityId":          llx.StringDataPtr(cfg.EntityId),
		"loginUrl":          llx.StringDataPtr(cfg.LoginUrl),
		"bindingType":       llx.StringDataPtr(cfg.BindingType),
		"ssoStatus":         llx.StringDataPtr(cfg.SSOStatus),
		"enabled":           llx.BoolData(cloudssoStatusEnabled(cfg.SSOStatus)),
		"wantRequestSigned": llx.BoolData(tea.BoolValue(cfg.WantRequestSigned)),
		"certificateIds":    llx.ArrayData(strPtrsToAny(cfg.CertificateIds), types.String),
		"createTime":        llx.TimeDataPtr(cloudssoParseTime(cfg.CreateTime)),
		"updateTime":        llx.TimeDataPtr(cloudssoParseTime(cfg.UpdateTime)),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAlicloudCloudssoSamlIdentityProvider), nil
}

// ssoEnabled reports whether federated sign-in is switched on. False both when
// no provider is configured and when one is configured but disabled, which are
// the two ways sign-in falls back to the local user store.
func (r *mqlAlicloudCloudssoDirectory) ssoEnabled() (bool, error) {
	cfg := r.samlConfiguration()
	if cfg == nil {
		return false, nil
	}
	return cloudssoStatusEnabled(cfg.SSOStatus), nil
}

func (r *mqlAlicloudCloudssoSamlIdentityProvider) id() (string, error) {
	return r.DirectoryId.Data + "/samlIdentityProvider", nil
}

// mqlAlicloudCloudssoTaskInternal carries the directory the task was listed
// from, so the access-configuration reference resolves against that directory's
// already-fetched configuration list rather than through a per-task lookup.
type mqlAlicloudCloudssoTaskInternal struct {
	parentDirectory *mqlAlicloudCloudssoDirectory
}

func (r *mqlAlicloudCloudssoTask) id() (string, error) {
	return r.TaskId.Data, nil
}

// tasks lists the directory's access-provisioning history.
func (r *mqlAlicloudCloudssoDirectory) tasks() ([]any, error) {
	client, directoryID, err := r.cloudssoClient()
	if err != nil {
		return nil, err
	}

	res := []any{}
	req := &cloudssoclient.ListTasksRequest{
		DirectoryId: new(directoryID),
		MaxResults:  new(cloudssoPageSize),
	}
	for {
		resp, err := client.ListTasks(req)
		if err != nil {
			return nil, err
		}
		if resp == nil || resp.Body == nil {
			break
		}
		for _, task := range resp.Body.Tasks {
			if task == nil || task.TaskId == nil {
				continue
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.cloudsso.task", map[string]*llx.RawData{
				"__id":                    llx.StringDataPtr(task.TaskId),
				"taskId":                  llx.StringDataPtr(task.TaskId),
				"taskType":                llx.StringDataPtr(task.TaskType),
				"status":                  llx.StringDataPtr(task.Status),
				"succeeded":               llx.BoolData(cloudssoTaskSucceeded(task.Status)),
				"failureReason":           llx.StringDataPtr(task.FailureReason),
				"principalId":             llx.StringDataPtr(task.PrincipalId),
				"principalName":           llx.StringDataPtr(task.PrincipalName),
				"principalType":           llx.StringDataPtr(task.PrincipalType),
				"accessConfigurationId":   llx.StringDataPtr(task.AccessConfigurationId),
				"accessConfigurationName": llx.StringDataPtr(task.AccessConfigurationName),
				"targetId":                llx.StringDataPtr(task.TargetId),
				"targetName":              llx.StringDataPtr(task.TargetName),
				"targetPath":              llx.StringDataPtr(task.TargetPath),
				"targetPathName":          llx.StringDataPtr(task.TargetPathName),
				"targetType":              llx.StringDataPtr(task.TargetType),
				"startTime":               llx.TimeDataPtr(cloudssoParseTime(task.StartTime)),
				"endTime":                 llx.TimeDataPtr(cloudssoParseTime(task.EndTime)),
			})
			if err != nil {
				return nil, err
			}
			mqlTask := resource.(*mqlAlicloudCloudssoTask)
			mqlTask.parentDirectory = r
			res = append(res, mqlTask)
		}
		if !tea.BoolValue(resp.Body.IsTruncated) || tea.StringValue(resp.Body.NextToken) == "" {
			break
		}
		req.NextToken = resp.Body.NextToken
	}
	return res, nil
}

// accessConfiguration resolves the configuration the task acted on by scanning
// the directory's configuration list, which is fetched once and shared by every
// task rather than being looked up per task.
func (r *mqlAlicloudCloudssoTask) accessConfiguration() (*mqlAlicloudCloudssoAccessConfiguration, error) {
	wanted := r.AccessConfigurationId.Data
	if r.parentDirectory == nil || wanted == "" {
		r.AccessConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	configurations := r.parentDirectory.GetAccessConfigurations()
	if configurations.Error != nil {
		log.Debug().Err(configurations.Error).Str("task", r.TaskId.Data).
			Msg("alicloud> could not list CloudSSO access configurations for a task")
		r.AccessConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	for _, entry := range configurations.Data {
		cfg, ok := entry.(*mqlAlicloudCloudssoAccessConfiguration)
		if !ok {
			continue
		}
		if cfg.AccessConfigurationId.Data == wanted {
			return cfg, nil
		}
	}
	// the configuration has been deleted since the task ran; the task keeps its
	// raw id and name as the record of what was granted
	r.AccessConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
