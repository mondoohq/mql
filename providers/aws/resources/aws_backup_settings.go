// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// fetchDetail describes the vault once, for the fields the list call does not
// return. A nil result with a nil error means the account may not describe
// the vault and structured errors are off.
func (a *mqlAwsBackupVault) fetchDetail() (*backup.DescribeBackupVaultOutput, error) {
	a.detailLock.Lock()
	defer a.detailLock.Unlock()
	if a.detailFetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Backup(a.Region.Data)
	name := a.Name.Data
	out, err := svc.DescribeBackupVault(context.Background(), &backup.DescribeBackupVaultInput{
		BackupVaultName: &name,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.detailFetched = true
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("backup:DescribeBackupVault"))
		}
		return nil, err
	}
	a.detail = out
	a.detailFetched = true
	return a.detail, nil
}

func (a *mqlAwsBackupVault) sourceBackupVault() (*mqlAwsBackupVault, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.SourceBackupVaultArn == nil || *detail.SourceBackupVaultArn == "" {
		a.SourceBackupVault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsBackupVault, map[string]*llx.RawData{
		"arn": llx.StringDataPtr(detail.SourceBackupVaultArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupVault), nil
}

func (a *mqlAwsBackupVault) mpaApprovalTeamArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.MpaApprovalTeamArn == nil {
		a.MpaApprovalTeamArn.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.MpaApprovalTeamArn, nil
}

func (a *mqlAwsBackupVault) mpaSessionArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.MpaSessionArn == nil {
		a.MpaSessionArn.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *detail.MpaSessionArn, nil
}

// backupGlobalSettingBool reads a boolean global setting. AWS Backup reports
// every setting as a string; a setting that is absent or not a boolean is
// reported as null rather than guessed.
func backupGlobalSettingBool(settings map[string]string, key string) *bool {
	raw, ok := settings[key]
	if !ok {
		return nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil
	}
	return &v
}

func (a *mqlAwsBackup) globalSettings() (*mqlAwsBackupGlobalSettings, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Backup("")
	out, err := svc.DescribeGlobalSettings(context.Background(), &backup.DescribeGlobalSettingsInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.GlobalSettings.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("backup:DescribeGlobalSettings"))
		}
		return nil, err
	}
	settings := map[string]any{}
	for k, v := range out.GlobalSettings {
		settings[k] = v
	}
	res, err := CreateResource(a.MqlRuntime, ResourceAwsBackupGlobalSettings, map[string]*llx.RawData{
		"__id":                          llx.StringData("aws.backup.globalSettings/" + conn.AccountId()),
		"settings":                      llx.MapData(settings, types.String),
		"crossAccountBackupEnabled":     llx.BoolDataPtr(backupGlobalSettingBool(out.GlobalSettings, "isCrossAccountBackupEnabled")),
		"multiPartyApprovalEnabled":     llx.BoolDataPtr(backupGlobalSettingBool(out.GlobalSettings, "isMpaEnabled")),
		"delegatedAdministratorEnabled": llx.BoolDataPtr(backupGlobalSettingBool(out.GlobalSettings, "isDelegatedAdministratorEnabled")),
		"updatedAt":                     llx.TimeDataPtr(out.LastUpdateTime),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupGlobalSettings), nil
}

func (a *mqlAwsBackupGlobalSettings) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsBackup) legalHolds() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "backup", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Backup(region)
		res := []any{}
		paginator := backup.NewListLegalHoldsPaginator(svc, &backup.ListLegalHoldsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, hold := range page.LegalHolds {
				mqlHold, err := CreateResource(a.MqlRuntime, ResourceAwsBackupLegalHold, map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(hold.LegalHoldArn),
					"arn":         llx.StringDataPtr(hold.LegalHoldArn),
					"id":          llx.StringDataPtr(hold.LegalHoldId),
					"title":       llx.StringDataPtr(hold.Title),
					"description": llx.StringDataPtr(hold.Description),
					"status":      llx.StringDataPtr(nonEmptyEnum(hold.Status)),
					"region":      llx.StringData(region),
					"createdAt":   llx.TimeDataPtr(hold.CreationDate),
					"cancelledAt": llx.TimeDataPtr(hold.CancellationDate),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlHold)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsBackupLegalHold) id() (string, error) {
	return a.__id, nil
}

type mqlAwsBackupLegalHoldInternal struct {
	lazyTags
}

func (a *mqlAwsBackupLegalHold) tags() (map[string]any, error) {
	return backupResolveTags(a.MqlRuntime, &a.lazyTags, &a.Tags, a.Region.Data, a.Arn.Data)
}
