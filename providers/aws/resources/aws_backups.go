// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsBackup) id() (string, error) {
	return "aws.backup", nil
}

type mqlAwsBackupVaultInternal struct {
	lazyTags
	cacheEncryptionKeyArn string
}

func (a *mqlAwsBackupVault) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBackupVault) tags() (map[string]any, error) {
	return backupResolveTags(a.MqlRuntime, &a.lazyTags, &a.Tags, a.Region.Data, a.Arn.Data)
}

type mqlAwsBackupVaultRecoveryPointInternal struct {
	lazyTags
	cacheEncryptionKeyArn string
	cacheIamRoleArn       string
}

func (a *mqlAwsBackupVaultRecoveryPoint) id() (string, error) {
	return a.Arn.Data, nil
}

// tags passes no region: a recovery point has no region field, so the region
// comes from its ARN, which is only parsed when Backup manages the resource.
func (a *mqlAwsBackupVaultRecoveryPoint) tags() (map[string]any, error) {
	return backupResolveTags(a.MqlRuntime, &a.lazyTags, &a.Tags, "", a.Arn.Data)
}

// backupManagedArn reports whether Backup can read tags for resourceArn, and
// the region to read them from.
//
// ListTags only accepts resources Backup fully manages, whose ARNs begin with
// arn:aws:backup. A recovery point of a resource Backup does not fully manage
// keeps the source service's ARN (arn:aws:dynamodb, arn:aws:ec2, and so on),
// and ListTags rejects those. Callers must report unreadable rather than empty
// tags for them, or an audit filtering on a tag would silently treat every such
// recovery point as untagged.
func backupManagedArn(resourceArn string) (region string, ok bool) {
	parsed, err := arn.Parse(resourceArn)
	if err != nil || parsed.Service != "backup" {
		return "", false
	}
	return parsed.Region, true
}

// backupResolveTags resolves and caches a Backup resource's tags, marking the
// field null when Backup cannot read them.
func backupResolveTags(runtime *plugin.Runtime, cache *lazyTags, field *plugin.TValue[map[string]any], region, resourceArn string) (map[string]any, error) {
	return cache.resolveTags(field, func() (map[string]any, error) {
		return backupTagsForArn(runtime, region, resourceArn)
	})
}

// backupTagsForArn reads the tags of a Backup-managed resource, reporting
// errTagsUnreadable for a resource Backup does not manage (see
// backupManagedArn).
func backupTagsForArn(runtime *plugin.Runtime, region, resourceArn string) (map[string]any, error) {
	arnRegion, ok := backupManagedArn(resourceArn)
	if !ok {
		return nil, errTagsUnreadable
	}
	if region == "" {
		region = arnRegion
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Backup(region)
	ctx := context.Background()

	tags := map[string]any{}
	var nextToken *string
	for {
		resp, err := svc.ListTags(ctx, &backup.ListTagsInput{
			ResourceArn: &resourceArn,
			NextToken:   nextToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "backup:ListTags")
		}
		for k, v := range resp.Tags {
			tags[k] = v
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return tags, nil
}

func (a *mqlAwsBackup) vaults() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVaults(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsBackup) getVaults(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Backup(region)
			ctx := context.Background()
			res := []any{}

			paginator := backup.NewListBackupVaultsPaginator(svc, &backup.ListBackupVaultsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, v := range page.BackupVaultList {
					mqlGroup, err := CreateResource(a.MqlRuntime, "aws.backup.vault",
						map[string]*llx.RawData{
							"arn":              llx.StringDataPtr(v.BackupVaultArn),
							"createdAt":        llx.TimeDataPtr(v.CreationDate),
							"locked":           llx.BoolDataPtr(v.Locked),
							"lockedAt":         llx.TimeDataPtr(v.LockDate),
							"maxRetentionDays": llx.IntDataPtr(v.MaxRetentionDays),
							"minRetentionDays": llx.IntDataPtr(v.MinRetentionDays),
							"name":             llx.StringDataPtr(v.BackupVaultName),
							"region":           llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					mqlGroup.(*mqlAwsBackupVault).cacheEncryptionKeyArn = convert.ToValue(v.EncryptionKeyArn)
					res = append(res, mqlGroup)
				}
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// backupVaultNameFromArn extracts the vault name from a backup vault ARN of the
// form arn:aws:backup:<region>:<account>:backup-vault:<name>.
func backupVaultNameFromArn(vaultArn string) (name, region string, err error) {
	parsed, err := arn.Parse(vaultArn)
	if err != nil {
		return "", "", err
	}
	return strings.TrimPrefix(parsed.Resource, "backup-vault:"), parsed.Region, nil
}

// initAwsBackupVault resolves a vault from its ARN, or from a name and region.
// Without it, the typed vault accessors on scan jobs, copy actions, and access
// points would hand back a resource whose fields are all unset.
func initAwsBackupVault(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	var name, region string
	if args["arn"] != nil {
		var err error
		name, region, err = backupVaultNameFromArn(args["arn"].Value.(string))
		if err != nil {
			return nil, nil, err
		}
	} else if args["name"] != nil && args["region"] != nil {
		name = args["name"].Value.(string)
		region = args["region"].Value.(string)
	} else {
		return nil, nil, errors.New("arn, or name and region, required to fetch aws backup vault")
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Backup(region)
	vault, err := svc.DescribeBackupVault(context.Background(), &backup.DescribeBackupVaultInput{
		BackupVaultName: &name,
	})
	if err != nil {
		return nil, nil, err
	}

	res, err := CreateResource(runtime, "aws.backup.vault", backupVaultArgs(vault, region))
	if err != nil {
		return nil, nil, err
	}
	// The encryption key is not an argument: the schema exposes it as the typed
	// encryptionKey accessor, which reads the ARN back off the internal cache.
	// Seeding it here is what makes that accessor resolve on this path as well
	// as on the listing path.
	res.(*mqlAwsBackupVault).cacheEncryptionKeyArn = convert.ToValue(vault.EncryptionKeyArn)
	return nil, res, nil
}

// backupVaultArgs maps a described vault onto the fields aws.backup.vault
// declares. Every key here has to be a settable field: SetAllData fails the
// whole resource on an unknown one, so a field that the schema exposes through
// a typed accessor - encryptionKey - must be seeded on the internal cache
// instead of passed as an argument.
func backupVaultArgs(vault *backup.DescribeBackupVaultOutput, region string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"arn":              llx.StringDataPtr(vault.BackupVaultArn),
		"name":             llx.StringDataPtr(vault.BackupVaultName),
		"region":           llx.StringData(region),
		"createdAt":        llx.TimeDataPtr(vault.CreationDate),
		"locked":           llx.BoolDataPtr(vault.Locked),
		"lockedAt":         llx.TimeDataPtr(vault.LockDate),
		"maxRetentionDays": llx.IntDataPtr(vault.MaxRetentionDays),
		"minRetentionDays": llx.IntDataPtr(vault.MinRetentionDays),
	}
}

// newMqlBackupRecoveryPoint builds a recovery point resource. Both the vault
// listing and the per-recovery-point describe call feed through here so the two
// paths populate an identical resource.
func newMqlBackupRecoveryPoint(runtime *plugin.Runtime, rp backuptypes.RecoveryPointByBackupVault) (plugin.Resource, error) {
	createdBy, err := convert.JsonToDict(rp.CreatedBy)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, "aws.backup.vaultRecoveryPoint",
		backupRecoveryPointArgs(rp, createdBy))
	if err != nil {
		return nil, err
	}
	// The KMS key and the IAM role are not arguments: the schema exposes both
	// as typed accessors, which read the ARNs back off the internal cache.
	mqlRP := res.(*mqlAwsBackupVaultRecoveryPoint)
	mqlRP.cacheEncryptionKeyArn = convert.ToValue(rp.EncryptionKeyArn)
	mqlRP.cacheIamRoleArn = convert.ToValue(rp.IamRoleArn)
	return mqlRP, nil
}

// backupRecoveryPointArgs maps a recovery point onto the fields
// aws.backup.vaultRecoveryPoint declares. Every key has to be a settable
// field: SetAllData fails the whole resource on an unknown one, so the two
// ARNs the schema exposes through typed accessors - encryptionKey and iamRole
// - are seeded on the internal cache instead of passed here.
func backupRecoveryPointArgs(rp backuptypes.RecoveryPointByBackupVault, createdBy map[string]any) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"arn":                  llx.StringDataPtr(rp.RecoveryPointArn),
		"completionDate":       llx.TimeDataPtr(rp.CompletionDate),
		"createdAt":            llx.TimeDataPtr(rp.CreationDate),
		"createdBy":            llx.MapData(createdBy, types.String),
		"isEncrypted":          llx.BoolData(rp.IsEncrypted),
		"resourceType":         llx.StringDataPtr(rp.ResourceType),
		"status":               llx.StringData(string(rp.Status)),
		"sourceResourceArn":    llx.StringDataPtr(rp.ResourceArn),
		"sourceBackupVaultArn": llx.StringDataPtr(rp.SourceBackupVaultArn),
	}
}

func (a *mqlAwsBackupVault) recoveryPoints() ([]any, error) {
	name, region, err := backupVaultNameFromArn(a.Arn.Data)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Backup(region)
	ctx := context.Background()
	res := []any{}

	params := &backup.ListRecoveryPointsByBackupVaultInput{BackupVaultName: &name}
	paginator := backup.NewListRecoveryPointsByBackupVaultPaginator(svc, params)
	for paginator.HasMorePages() {
		recovPoints, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rp := range recovPoints.RecoveryPoints {
			mqlRP, err := newMqlBackupRecoveryPoint(a.MqlRuntime, rp)
			if err != nil {
				return nil, err
			}
			mqlRP.(*mqlAwsBackupVaultRecoveryPoint).cacheEncryptionKeyArn = convert.ToValue(rp.EncryptionKeyArn)
			mqlRP.(*mqlAwsBackupVaultRecoveryPoint).cacheIamRoleArn = convert.ToValue(rp.IamRoleArn)
			res = append(res, mqlRP)
		}
	}
	return res, nil
}

func (a *mqlAwsBackupVault) accessPolicy() (string, error) {
	vArn := a.Arn.Data
	parsedArn, err := arn.Parse(vArn)
	if err != nil {
		return "", err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Backup(parsedArn.Region)
	ctx := context.Background()

	name := strings.TrimPrefix(parsedArn.Resource, "backup-vault:")
	resp, err := svc.GetBackupVaultAccessPolicy(ctx, &backup.GetBackupVaultAccessPolicyInput{
		BackupVaultName: &name,
	})
	if err != nil {
		// vaults without an access policy return ResourceNotFoundException
		var rnf *backuptypes.ResourceNotFoundException
		if errors.As(err, &rnf) {
			return "", nil
		}
		return "", err
	}
	if resp.Policy == nil {
		return "", nil
	}
	return *resp.Policy, nil
}

func (a *mqlAwsBackupVault) policyStatements() ([]any, error) {
	return policyStatementsFromString(a.MqlRuntime, a.Arn.Data, a.GetAccessPolicy())
}

// ========================
// aws.backup.plan
// ========================

type mqlAwsBackupPlanInternal struct {
	lazyTags
}

func (a *mqlAwsBackupPlan) tags() (map[string]any, error) {
	return backupResolveTags(a.MqlRuntime, &a.lazyTags, &a.Tags, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsBackupPlan) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBackup) plans() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPlans(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsBackup) getPlans(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Backup(region)
			ctx := context.Background()
			res := []any{}

			paginator := backup.NewListBackupPlansPaginator(svc, &backup.ListBackupPlansInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, plan := range page.BackupPlansList {
					advSettings, err := newMqlBackupAdvancedSettings(a.MqlRuntime, convert.ToValue(plan.BackupPlanArn), plan.AdvancedBackupSettings)
					if err != nil {
						return nil, err
					}

					mqlPlan, err := CreateResource(a.MqlRuntime, ResourceAwsBackupPlan,
						map[string]*llx.RawData{
							"__id":                   llx.StringDataPtr(plan.BackupPlanArn),
							"arn":                    llx.StringDataPtr(plan.BackupPlanArn),
							"id":                     llx.StringDataPtr(plan.BackupPlanId),
							"name":                   llx.StringDataPtr(plan.BackupPlanName),
							"versionId":              llx.StringDataPtr(plan.VersionId),
							"region":                 llx.StringData(region),
							"createdAt":              llx.TimeDataPtr(plan.CreationDate),
							"lastExecutionDate":      llx.TimeDataPtr(plan.LastExecutionDate),
							"deletionDate":           llx.TimeDataPtr(plan.DeletionDate),
							"advancedBackupSettings": llx.ArrayData(advSettings, types.Resource(ResourceAwsBackupPlanAdvancedBackupSetting)),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPlan)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsBackupPlan) rules() ([]any, error) {
	planId := a.Id.Data
	planArn := a.Arn.Data

	region, err := GetRegionFromArn(planArn)
	if err != nil {
		return nil, err
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Backup(region)
	ctx := context.Background()

	resp, err := svc.GetBackupPlan(ctx, &backup.GetBackupPlanInput{
		BackupPlanId: &planId,
	})
	if err != nil {
		return nil, classifyAwsError(err, "backup:GetBackupPlan")
	}

	if resp.BackupPlan == nil {
		return nil, nil
	}

	res := []any{}
	for _, rule := range resp.BackupPlan.Rules {
		mqlRule, err := newMqlBackupPlanRule(a.MqlRuntime, planArn, rule)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

type mqlAwsBackupPlanSelectionInternal struct {
	cacheIamRoleArn string
}

func (a *mqlAwsBackupPlan) resourceSelections() ([]any, error) {
	planId := a.Id.Data
	planArn := a.Arn.Data

	region, err := GetRegionFromArn(planArn)
	if err != nil {
		return nil, err
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Backup(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.ListBackupSelections(ctx, &backup.ListBackupSelectionsInput{
			BackupPlanId: &planId,
			NextToken:    nextToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "backup:ListBackupSelections")
		}
		for _, sel := range resp.BackupSelectionsList {
			detail, err := svc.GetBackupSelection(ctx, &backup.GetBackupSelectionInput{
				BackupPlanId: &planId,
				SelectionId:  sel.SelectionId,
			})
			if err != nil {
				if Is400AccessDeniedError(err) {
					continue
				}
				return nil, err
			}
			if detail.BackupSelection == nil {
				continue
			}
			mqlSel, err := newMqlBackupPlanSelection(a.MqlRuntime, planArn, convert.ToValue(detail.SelectionId), detail.CreationDate, *detail.BackupSelection)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSel)
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

func newMqlBackupPlanSelection(runtime *plugin.Runtime, planArn, selectionId string, creationDate *time.Time, sel backuptypes.BackupSelection) (*mqlAwsBackupPlanSelection, error) {
	uniqueId := planArn + "\x00" + selectionId

	resources := make([]any, 0, len(sel.Resources))
	for _, r := range sel.Resources {
		resources = append(resources, r)
	}
	notResources := make([]any, 0, len(sel.NotResources))
	for _, r := range sel.NotResources {
		notResources = append(notResources, r)
	}

	listOfTags := make([]any, 0, len(sel.ListOfTags))
	for _, c := range sel.ListOfTags {
		listOfTags = append(listOfTags, map[string]any{
			"conditionType":  string(c.ConditionType),
			"conditionKey":   convert.ToValue(c.ConditionKey),
			"conditionValue": convert.ToValue(c.ConditionValue),
		})
	}

	var conditions any
	if sel.Conditions != nil {
		conditions = map[string]any{
			"stringEquals":    conditionParametersToList(sel.Conditions.StringEquals),
			"stringNotEquals": conditionParametersToList(sel.Conditions.StringNotEquals),
			"stringLike":      conditionParametersToList(sel.Conditions.StringLike),
			"stringNotLike":   conditionParametersToList(sel.Conditions.StringNotLike),
		}
	}

	resource, err := CreateResource(runtime, ResourceAwsBackupPlanSelection,
		map[string]*llx.RawData{
			"__id":         llx.StringData(uniqueId),
			"id":           llx.StringData(selectionId),
			"name":         llx.StringDataPtr(sel.SelectionName),
			"createdAt":    llx.TimeDataPtr(creationDate),
			"resources":    llx.ArrayData(resources, types.String),
			"notResources": llx.ArrayData(notResources, types.String),
			"listOfTags":   llx.ArrayData(listOfTags, types.Dict),
			"conditions":   llx.DictData(conditions),
		})
	if err != nil {
		return nil, err
	}

	mqlSel := resource.(*mqlAwsBackupPlanSelection)
	mqlSel.cacheIamRoleArn = convert.ToValue(sel.IamRoleArn)
	return mqlSel, nil
}

func conditionParametersToList(params []backuptypes.ConditionParameter) []any {
	res := make([]any, 0, len(params))
	for _, p := range params {
		res = append(res, map[string]any{
			"conditionKey":   convert.ToValue(p.ConditionKey),
			"conditionValue": convert.ToValue(p.ConditionValue),
		})
	}
	return res
}

func (a *mqlAwsBackupPlanSelection) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheIamRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheIamRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// ========================
// aws.backup.scanJob
// ========================

func (a *mqlAwsBackup) scanJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getScanJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsBackup) getScanJobs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Backup(region)
			ctx := context.Background()
			res := []any{}

			paginator := backup.NewListScanJobsPaginator(svc, &backup.ListScanJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, sj := range page.ScanJobs {
					mqlScanJob, err := newMqlBackupScanJob(a.MqlRuntime, region, sj)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlScanJob)
				}
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlBackupScanJob(runtime *plugin.Runtime, region string, sj backuptypes.ScanJob) (*mqlAwsBackupScanJob, error) {
	args := map[string]*llx.RawData{
		"__id":                    llx.StringDataPtr(sj.ScanJobId),
		"id":                      llx.StringDataPtr(sj.ScanJobId),
		"accountId":               llx.StringDataPtr(sj.AccountId),
		"region":                  llx.StringData(region),
		"resourceArn":             llx.StringDataPtr(sj.ResourceArn),
		"resourceName":            llx.StringDataPtr(sj.ResourceName),
		"resourceType":            llx.StringData(string(sj.ResourceType)),
		"malwareScanner":          llx.StringData(string(sj.MalwareScanner)),
		"scanMode":                llx.StringData(string(sj.ScanMode)),
		"scanId":                  llx.StringDataPtr(sj.ScanId),
		"state":                   llx.StringData(string(sj.State)),
		"statusMessage":           llx.StringDataPtr(sj.StatusMessage),
		"createdAt":               llx.TimeDataPtr(sj.CreationDate),
		"completionDate":          llx.TimeDataPtr(sj.CompletionDate),
		"continuousScanStartTime": llx.TimeDataPtr(sj.ContinuousScanStartTime),
		"continuousScanEndTime":   llx.TimeDataPtr(sj.ContinuousScanEndTime),
	}

	if sj.ScanResult != nil {
		args["scanResultStatus"] = llx.StringData(string(sj.ScanResult.ScanResultStatus))
	} else {
		args["scanResultStatus"] = llx.StringData("")
	}

	var backupPlanVersion, backupRuleId string
	if sj.CreatedBy != nil {
		backupPlanVersion = convert.ToValue(sj.CreatedBy.BackupPlanVersion)
		backupRuleId = convert.ToValue(sj.CreatedBy.BackupRuleId)
	}
	args["backupPlanVersion"] = llx.StringData(backupPlanVersion)
	args["backupRuleId"] = llx.StringData(backupRuleId)

	resource, err := CreateResource(runtime, ResourceAwsBackupScanJob, args)
	if err != nil {
		return nil, err
	}

	mqlScanJob := resource.(*mqlAwsBackupScanJob)
	mqlScanJob.cacheVaultArn = convert.ToValue(sj.BackupVaultArn)
	mqlScanJob.cacheRecoveryPointArn = convert.ToValue(sj.RecoveryPointArn)
	mqlScanJob.cacheBaseRecoveryPointArn = convert.ToValue(sj.ScanBaseRecoveryPointArn)
	mqlScanJob.cacheIamRoleArn = convert.ToValue(sj.IamRoleArn)
	mqlScanJob.cacheScannerRoleArn = convert.ToValue(sj.ScannerRoleArn)
	if sj.CreatedBy != nil {
		mqlScanJob.cacheBackupPlanArn = convert.ToValue(sj.CreatedBy.BackupPlanArn)
	}
	return mqlScanJob, nil
}

func newMqlBackupPlanRule(runtime *plugin.Runtime, planArn string, rule backuptypes.BackupRule) (*mqlAwsBackupPlanRule, error) {
	ruleId := convert.ToValue(rule.RuleId)
	uniqueId := planArn + "\x00" + ruleId

	// Build lifecycle resource
	var lifecycle *mqlAwsBackupLifecycle
	if rule.Lifecycle != nil {
		lc, err := newMqlBackupLifecycle(runtime, uniqueId+"/lifecycle", rule.Lifecycle)
		if err != nil {
			return nil, err
		}
		lifecycle = lc
	}

	// Build copy actions
	copyActions := []any{}
	for _, ca := range rule.CopyActions {
		mqlCA, err := newMqlBackupCopyAction(runtime, uniqueId, ca)
		if err != nil {
			return nil, err
		}
		copyActions = append(copyActions, mqlCA)
	}

	// Convert recovery point tags
	var rpTags map[string]any
	if rule.RecoveryPointTags != nil {
		rpTags = toInterfaceMap(rule.RecoveryPointTags)
	}

	// Build malware scan actions
	scanActions := make([]any, 0, len(rule.ScanActions))
	for _, sa := range rule.ScanActions {
		scanActions = append(scanActions, map[string]any{
			"malwareScanner": string(sa.MalwareScanner),
			"scanMode":       string(sa.ScanMode),
		})
	}

	resource, err := CreateResource(runtime, ResourceAwsBackupPlanRule,
		map[string]*llx.RawData{
			"__id":                       llx.StringData(uniqueId),
			"id":                         llx.StringData(ruleId),
			"ruleName":                   llx.StringDataPtr(rule.RuleName),
			"targetBackupVaultName":      llx.StringDataPtr(rule.TargetBackupVaultName),
			"scheduleExpression":         llx.StringDataPtr(rule.ScheduleExpression),
			"scheduleExpressionTimezone": llx.StringDataPtr(rule.ScheduleExpressionTimezone),
			"startWindowMinutes":         llx.IntDataDefault(rule.StartWindowMinutes, 0),
			"completionWindowMinutes":    llx.IntDataDefault(rule.CompletionWindowMinutes, 0),
			"enableContinuousBackup":     llx.BoolDataPtr(rule.EnableContinuousBackup),
			"copyActions":                llx.ArrayData(copyActions, types.Resource(ResourceAwsBackupPlanRuleCopyAction)),
			"recoveryPointTags":          llx.MapData(rpTags, types.String),
			"scanActions":                llx.ArrayData(scanActions, types.Dict),
		})
	if err != nil {
		return nil, err
	}

	mqlRule := resource.(*mqlAwsBackupPlanRule)
	if lifecycle != nil {
		mqlRule.Lifecycle = plugin.TValue[*mqlAwsBackupLifecycle]{Data: lifecycle, State: plugin.StateIsSet}
	} else {
		mqlRule.Lifecycle = plugin.TValue[*mqlAwsBackupLifecycle]{State: plugin.StateIsNull | plugin.StateIsSet}
	}

	return mqlRule, nil
}

func newMqlBackupLifecycle(runtime *plugin.Runtime, id string, lc *backuptypes.Lifecycle) (*mqlAwsBackupLifecycle, error) {
	resource, err := CreateResource(runtime, ResourceAwsBackupLifecycle,
		map[string]*llx.RawData{
			"__id":                                llx.StringData(id),
			"id":                                  llx.StringData(id),
			"deleteAfterDays":                     llx.IntDataDefault(lc.DeleteAfterDays, 0),
			"moveToColdStorageAfterDays":          llx.IntDataDefault(lc.MoveToColdStorageAfterDays, 0),
			"optInToArchiveForSupportedResources": llx.BoolDataPtr(lc.OptInToArchiveForSupportedResources),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsBackupLifecycle), nil
}

func newMqlBackupCopyAction(runtime *plugin.Runtime, ruleId string, ca backuptypes.CopyAction) (*mqlAwsBackupPlanRuleCopyAction, error) {
	destArn := convert.ToValue(ca.DestinationBackupVaultArn)
	uniqueId := ruleId + "\x00copyAction\x00" + destArn

	var deleteAfterDays, moveToColdStorageDays int64
	var optInToArchive bool
	if ca.Lifecycle != nil {
		deleteAfterDays = convert.ToValue(ca.Lifecycle.DeleteAfterDays)
		moveToColdStorageDays = convert.ToValue(ca.Lifecycle.MoveToColdStorageAfterDays)
		if ca.Lifecycle.OptInToArchiveForSupportedResources != nil {
			optInToArchive = *ca.Lifecycle.OptInToArchiveForSupportedResources
		}
	}

	resource, err := CreateResource(runtime, ResourceAwsBackupPlanRuleCopyAction,
		map[string]*llx.RawData{
			"__id":                                llx.StringData(uniqueId),
			"id":                                  llx.StringData(uniqueId),
			"deleteAfterDays":                     llx.IntData(deleteAfterDays),
			"moveToColdStorageAfterDays":          llx.IntData(moveToColdStorageDays),
			"optInToArchiveForSupportedResources": llx.BoolData(optInToArchive),
		})
	if err != nil {
		return nil, err
	}
	resource.(*mqlAwsBackupPlanRuleCopyAction).cacheDestinationBackupVaultArn = destArn
	return resource.(*mqlAwsBackupPlanRuleCopyAction), nil
}

func newMqlBackupAdvancedSettings(runtime *plugin.Runtime, planArn string, settings []backuptypes.AdvancedBackupSetting) ([]any, error) {
	res := []any{}
	for _, s := range settings {
		resourceType := convert.ToValue(s.ResourceType)
		uniqueId := planArn + "\x00advSetting\x00" + resourceType

		mqlSetting, err := CreateResource(runtime, ResourceAwsBackupPlanAdvancedBackupSetting,
			map[string]*llx.RawData{
				"__id":          llx.StringData(uniqueId),
				"id":            llx.StringData(uniqueId),
				"resourceType":  llx.StringData(resourceType),
				"backupOptions": llx.MapData(toInterfaceMap(s.BackupOptions), types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSetting)
	}
	return res, nil
}

func (a *mqlAwsBackupLifecycle) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsBackupPlanAdvancedBackupSetting) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsBackupPlanRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsBackupPlanRuleCopyAction) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsBackupVault) encryptionKey() (*mqlAwsKmsKey, error) {
	arnVal := a.cacheEncryptionKeyArn
	if arnVal == "" {
		a.EncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsBackupVaultRecoveryPoint) iamRole() (*mqlAwsIamRole, error) {
	arnVal := a.cacheIamRoleArn
	if arnVal == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBackupVaultRecoveryPoint) encryptionKey() (*mqlAwsKmsKey, error) {
	arnVal := a.cacheEncryptionKeyArn
	if arnVal == "" {
		a.EncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsBackupPlanRuleCopyAction) destinationVault() (*mqlAwsBackupVault, error) {
	arnVal := a.cacheDestinationBackupVaultArn
	if arnVal == "" {
		a.DestinationVault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.backup.vault",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupVault), nil
}

type mqlAwsBackupScanJobInternal struct {
	cacheVaultArn             string
	cacheRecoveryPointArn     string
	cacheBaseRecoveryPointArn string
	cacheIamRoleArn           string
	cacheScannerRoleArn       string
	cacheBackupPlanArn        string
}

func (a *mqlAwsBackupScanJob) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsBackupScanJob) vault() (*mqlAwsBackupVault, error) {
	if a.cacheVaultArn == "" {
		a.Vault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.backup.vault",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheVaultArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupVault), nil
}

func (a *mqlAwsBackupScanJob) recoveryPoint() (*mqlAwsBackupVaultRecoveryPoint, error) {
	if a.cacheRecoveryPointArn == "" {
		a.RecoveryPoint.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.backup.vaultRecoveryPoint",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheRecoveryPointArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupVaultRecoveryPoint), nil
}

func (a *mqlAwsBackupScanJob) baseRecoveryPoint() (*mqlAwsBackupVaultRecoveryPoint, error) {
	if a.cacheBaseRecoveryPointArn == "" {
		a.BaseRecoveryPoint.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.backup.vaultRecoveryPoint",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheBaseRecoveryPointArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupVaultRecoveryPoint), nil
}

func (a *mqlAwsBackupScanJob) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheIamRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheIamRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBackupScanJob) scannerRole() (*mqlAwsIamRole, error) {
	if a.cacheScannerRoleArn == "" {
		a.ScannerRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheScannerRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// ========================
// aws.backup.accessPoint
// ========================

type mqlAwsBackupAccessPointInternal struct {
	lazyTags
	cacheVaultArn         string
	cacheVaultName        string
	cacheRecoveryPointArn string
	cacheRegion           string
}

func (a *mqlAwsBackupAccessPoint) tags() (map[string]any, error) {
	return backupResolveTags(a.MqlRuntime, &a.lazyTags, &a.Tags, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsBackupAccessPoint) id() (string, error) {
	return a.Arn.Data, nil
}

func newMqlBackupAccessPoint(runtime *plugin.Runtime, region string, ap backuptypes.ListAccessPointsMember) (*mqlAwsBackupAccessPoint, error) {
	resource, err := CreateResource(runtime, ResourceAwsBackupAccessPoint,
		map[string]*llx.RawData{
			"__id":              llx.StringDataPtr(ap.AccessPointArn),
			"arn":               llx.StringDataPtr(ap.AccessPointArn),
			"name":              llx.StringDataPtr(ap.Name),
			"region":            llx.StringData(region),
			"status":            llx.StringData(string(ap.Status)),
			"statusMessage":     llx.StringDataPtr(ap.StatusMessage),
			"resourceType":      llx.StringDataPtr(ap.ResourceType),
			"sourceResourceArn": llx.StringDataPtr(ap.ResourceArn),
			"backupVaultName":   llx.StringDataPtr(ap.BackupVaultName),
			"metadata":          llx.MapData(toInterfaceMap(ap.AccessPointMetadata), types.String),
			"createdAt":         llx.TimeDataPtr(ap.CreationTime),
		})
	if err != nil {
		return nil, err
	}

	mqlAp := resource.(*mqlAwsBackupAccessPoint)
	mqlAp.cacheVaultArn = convert.ToValue(ap.BackupVaultArn)
	mqlAp.cacheVaultName = convert.ToValue(ap.BackupVaultName)
	mqlAp.cacheRecoveryPointArn = convert.ToValue(ap.RecoveryPointArn)
	mqlAp.cacheRegion = region
	return mqlAp, nil
}

func (a *mqlAwsBackup) accessPoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAccessPoints(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsBackup) getAccessPoints(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Backup(region)
			ctx := context.Background()
			res := []any{}

			paginator := backup.NewListBackupAccessPointsPaginator(svc, &backup.ListBackupAccessPointsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("aws backup access points are not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, ap := range page.BackupAccessPoints {
					mqlAp, err := newMqlBackupAccessPoint(a.MqlRuntime, region, ap)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAp)
				}
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsBackupVaultRecoveryPoint) accessPoints() ([]any, error) {
	rpArn := a.Arn.Data
	region, err := GetRegionFromArn(rpArn)
	if err != nil {
		return nil, err
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Backup(region)
	ctx := context.Background()

	res := []any{}
	paginator := backup.NewListBackupAccessPointsByRecoveryPointPaginator(svc, &backup.ListBackupAccessPointsByRecoveryPointInput{
		RecoveryPointArn: &rpArn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "backup:ListBackupAccessPointsByRecoveryPoint")
		}
		for _, ap := range page.BackupAccessPoints {
			mqlAp, err := newMqlBackupAccessPoint(a.MqlRuntime, region, ap)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAp)
		}
	}
	return res, nil
}

func (a *mqlAwsBackupAccessPoint) vault() (*mqlAwsBackupVault, error) {
	args := map[string]*llx.RawData{}
	switch {
	case a.cacheVaultArn != "":
		args["arn"] = llx.StringData(a.cacheVaultArn)
	case a.cacheVaultName != "" && a.cacheRegion != "":
		args["name"] = llx.StringData(a.cacheVaultName)
		args["region"] = llx.StringData(a.cacheRegion)
	default:
		a.Vault.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.backup.vault", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupVault), nil
}

// recoveryPoint describes the recovery point the access point reads. A recovery
// point ARN does not carry its vault name, so there is no ARN-only lookup to
// defer to; the access point already knows both and resolves it here.
func (a *mqlAwsBackupAccessPoint) recoveryPoint() (*mqlAwsBackupVaultRecoveryPoint, error) {
	if a.cacheRecoveryPointArn == "" || a.cacheVaultName == "" {
		a.RecoveryPoint.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Backup(a.cacheRegion)
	rp, err := svc.DescribeRecoveryPoint(context.Background(), &backup.DescribeRecoveryPointInput{
		BackupVaultName:  &a.cacheVaultName,
		RecoveryPointArn: &a.cacheRecoveryPointArn,
	})
	if err != nil {
		return nil, err
	}

	res, err := newMqlBackupRecoveryPoint(a.MqlRuntime, backuptypes.RecoveryPointByBackupVault{
		RecoveryPointArn:     rp.RecoveryPointArn,
		CompletionDate:       rp.CompletionDate,
		CreationDate:         rp.CreationDate,
		CreatedBy:            rp.CreatedBy,
		EncryptionKeyArn:     rp.EncryptionKeyArn,
		IamRoleArn:           rp.IamRoleArn,
		IsEncrypted:          rp.IsEncrypted,
		ResourceType:         rp.ResourceType,
		Status:               rp.Status,
		ResourceArn:          rp.ResourceArn,
		SourceBackupVaultArn: rp.SourceBackupVaultArn,
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupVaultRecoveryPoint), nil
}

func (a *mqlAwsBackupScanJob) backupPlan() (*mqlAwsBackupPlan, error) {
	if a.cacheBackupPlanArn == "" {
		a.BackupPlan.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.backup.plan",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheBackupPlanArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBackupPlan), nil
}

type mqlAwsBackupPlanRuleCopyActionInternal struct {
	cacheDestinationBackupVaultArn string
}
