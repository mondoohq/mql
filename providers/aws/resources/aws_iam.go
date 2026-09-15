// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/providers/aws/resources/awsiam"
	"go.mondoo.com/mql/v13/providers/aws/resources/awspolicy"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsIam) id() (string, error) {
	return ResourceAwsIam, nil
}

func (a *mqlAwsIam) accountAlias() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	resp, err := svc.ListAccountAliases(ctx, &iam.ListAccountAliasesInput{})
	if err != nil {
		return "", err
	}
	if len(resp.AccountAliases) > 0 {
		return resp.AccountAliases[0], nil
	}
	return "", nil
}

func (a *mqlAwsIam) serverCertificates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()
	res := []any{}
	params := &iam.ListServerCertificatesInput{}
	paginator := iam.NewListServerCertificatesPaginator(svc, params)
	for paginator.HasMorePages() {
		certsResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		if len(certsResp.ServerCertificateMetadataList) > 0 {
			certs, err := convert.JsonToDictSlice(certsResp.ServerCertificateMetadataList)
			if err != nil {
				return nil, err
			}
			res = append(res, certs...)
		}
	}
	return res, nil
}

func (a *mqlAwsIam) credentialReport() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	var data []byte
	// try to fetch the credential report
	// https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetCredentialReport.html
	// 410 - ReportExpired
	// 404 - ReportInProgress
	// 410 - ReportNotPresent
	// 500 - ServiceFailure
	_, err := svc.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		var awsFailErr *iamtypes.ServiceFailureException
		if errors.As(err, &awsFailErr) {
			return nil, errors.Wrap(err, "could not gather aws iam credential report")
		}
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() == "LimitExceeded" {
				return nil, errors.Wrap(err, "could not gather aws iam credential report, rate limit exceeded")
			}
		}

		// if we have an error and it is not 500 we generate a report.
		// ReportExpired (410) needs the same treatment as ReportNotPresent:
		// AWS expires cached credential reports and the only way forward is to
		// regenerate. Without this branch the whole credentialReport field --
		// and every root-MFA / key-rotation check built on it -- hard-errors.
		if errors.As(err, &ae) {
			if code := ae.ErrorCode(); code == "ReportNotPresent" || code == "ReportExpired" {
				// generate a new report
				_, err := svc.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
				if err != nil {
					return nil, err
				}
			}
		}
	}

	// loop as long as the response is 404 since this means the report is still in progress
	rresp, err := svc.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	var ae smithy.APIError
	if errors.As(err, &ae) {
		maxRetries := 0
		for ae.ErrorCode() == "NoSuchEntity" || ae.ErrorCode() == "ReportInProgress" {
			rresp, err = svc.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
			if err == nil {
				break
			}
			if maxRetries == 5 {
				return nil, errors.Wrap(err, "timed out trying to gather aws iam credential report")
			}
			// re-extract the API error so the loop condition reflects the latest
			// response; without this it keeps testing the original error code.
			if !errors.As(err, &ae) {
				return nil, errors.Wrap(err, "could not gather aws iam credential report")
			}
			time.Sleep(200 * time.Millisecond)
			maxRetries++
		}
		if ae.ErrorCode() != "NoSuchEntity" && ae.ErrorCode() != "ReportInProgress" {
			return nil, errors.Wrap(err, "could not gather aws iam credential report")
		}
	}
	if rresp == nil {
		return nil, errors.Wrap(err, "could not gather aws iam credential report")
	}

	data = rresp.Content

	// parse csv output
	entries, err := awsiam.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, errors.Wrap(err, "could not parse aws iam credential report")
	}

	res := []any{}
	for i := range entries {
		userEntry, err := CreateResource(a.MqlRuntime, ResourceAwsIamUsercredentialreportentry,
			map[string]*llx.RawData{"properties": llx.MapData(entries[i], types.String)},
		)
		if err != nil {
			return nil, err
		}
		res = append(res, userEntry)
	}
	return res, nil
}

func (a *mqlAwsIam) accountPasswordPolicy() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	resp, err := svc.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	var notFoundErr *iamtypes.NoSuchEntityException
	if err != nil {
		if errors.As(err, &notFoundErr) {
			return nil, nil
		}
		return nil, errors.Wrap(err, "could not gather aws iam account-password-policy")
	}

	res := ParsePasswordPolicy(resp.PasswordPolicy)

	return res, nil
}

func ParsePasswordPolicy(passwordPolicy *iamtypes.PasswordPolicy) map[string]any {
	res := map[string]any{}

	if passwordPolicy != nil {
		prp := int64(0)
		if passwordPolicy.PasswordReusePrevention != nil {
			prp = int64(*passwordPolicy.PasswordReusePrevention)
		}
		mpa := int64(0)
		if passwordPolicy.MaxPasswordAge != nil {
			mpa = int64(*passwordPolicy.MaxPasswordAge)
		}
		mpl := int64(0)
		if passwordPolicy.MinimumPasswordLength != nil {
			mpl = int64(*passwordPolicy.MinimumPasswordLength)
		}

		res["AllowUsersToChangePassword"] = passwordPolicy.AllowUsersToChangePassword
		res["RequireUppercaseCharacters"] = passwordPolicy.RequireUppercaseCharacters
		res["RequireSymbols"] = passwordPolicy.RequireSymbols
		res["ExpirePasswords"] = passwordPolicy.ExpirePasswords
		res["PasswordReusePrevention"] = strconv.FormatInt(prp, 10)
		res["RequireLowercaseCharacters"] = passwordPolicy.RequireLowercaseCharacters
		res["MaxPasswordAge"] = strconv.FormatInt(mpa, 10)
		res["HardExpiry"] = convert.ToValue(passwordPolicy.HardExpiry)
		res["RequireNumbers"] = passwordPolicy.RequireNumbers
		res["MinimumPasswordLength"] = strconv.FormatInt(mpl, 10)
	}
	return res
}

// initAwsIamPasswordPolicy lets the resource be queried by its dotted path
// (aws.iam.passwordPolicy) rather than only through the aws.iam accessor. A bare
// instantiation has no __id, so it delegates to the parent accessor to populate
// the policy data.
func initAwsIamPasswordPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["__id"]; ok {
		return args, nil, nil
	}
	iam, err := NewResource(runtime, "aws.iam", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	pp := iam.(*mqlAwsIam).GetPasswordPolicy()
	if pp.Error != nil {
		return nil, nil, pp.Error
	}
	return args, pp.Data, nil
}

// iamUserFromList resolves an IAM user out of the aws.iam users list, which a
// scan fetches once for the whole account, instead of spending a GetUser per
// referrer.
//
// The init runs before NewResource consults the resource cache, and the cache is
// keyed on the resource's ARN while this lookup arrives with a name, so the
// ARN-keyed check cannot fire and every reference re-fetched the same user: one
// measured scan spent 59 GetUser calls on 4 distinct users.
//
// Resolving from the list costs nothing extra because ListUsers is already made
// once per scan, and it loses no data: everything ListUsers omits is resolved
// lazily anyway -- tags() through ListUserTags, and permissionsBoundary()
// through its own GetUser fallback when the boundary was never set.
//
// Returns nil when the list cannot be read or holds no match, so callers keep
// their existing fetch as the fallback rather than turning a readable user into
// an error.
func iamUserFromList(runtime *plugin.Runtime, name, arn string) *mqlAwsIamUser {
	obj, err := NewResource(runtime, "aws.iam", map[string]*llx.RawData{})
	if err != nil {
		return nil
	}
	users := obj.(*mqlAwsIam).GetUsers()
	if users.Error != nil {
		return nil
	}
	for i := range users.Data {
		usr, ok := users.Data[i].(*mqlAwsIamUser)
		if !ok {
			continue
		}
		// An ARN identifies exactly one user, so when the caller has one it
		// decides on its own. Testing both per element would let an ARN match on
		// one entry beat a name match on another purely by list order.
		if arn != "" {
			if usr.Arn.Data == arn {
				return usr
			}
			continue
		}
		if name != "" && usr.Name.Data == name {
			return usr
		}
	}
	return nil
}

// iamGroupFromList is the group counterpart of iamUserFromList. GetGroup made no
// calls in the account measured, so this is a latent case rather than a measured
// one -- but the group init has no cache check at all, so it is the weaker of
// the two.
func iamGroupFromList(runtime *plugin.Runtime, name, arn string) *mqlAwsIamGroup {
	obj, err := NewResource(runtime, "aws.iam", map[string]*llx.RawData{})
	if err != nil {
		return nil
	}
	groups := obj.(*mqlAwsIam).GetGroups()
	if groups.Error != nil {
		return nil
	}
	for i := range groups.Data {
		grp, ok := groups.Data[i].(*mqlAwsIamGroup)
		if !ok {
			continue
		}
		// An ARN identifies exactly one group, so when the caller has one it
		// decides on its own. Testing both per element would let an ARN match on
		// one entry beat a name match on another purely by list order.
		if arn != "" {
			if grp.Arn.Data == arn {
				return grp
			}
			continue
		}
		if name != "" && grp.Name.Data == name {
			return grp
		}
	}
	return nil
}

func (a *mqlAwsIam) passwordPolicy() (*mqlAwsIamPasswordPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	var pp *iamtypes.PasswordPolicy
	resp, err := svc.GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{})
	if err != nil {
		var notFoundErr *iamtypes.NoSuchEntityException
		if !errors.As(err, &notFoundErr) {
			return nil, errors.Wrap(err, "could not gather aws iam account-password-policy")
		}
		// no password policy is configured for the account; pp stays nil
	} else {
		pp = resp.PasswordPolicy
	}

	res, err := CreateResource(a.MqlRuntime, "aws.iam.passwordPolicy", passwordPolicyData(conn.AccountId(), pp))
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamPasswordPolicy), nil
}

// passwordPolicyData builds the resource arguments for aws.iam.passwordPolicy.
// When pp is nil no policy is configured, so exists is false and every other
// field is null. Optional settings the policy leaves unset (reuse prevention,
// max password age, hard expiry) are null rather than zero.
func passwordPolicyData(accountID string, pp *iamtypes.PasswordPolicy) map[string]*llx.RawData {
	id := "aws.iam.passwordPolicy/" + accountID
	if pp == nil {
		return map[string]*llx.RawData{
			"__id":                       llx.StringData(id),
			"exists":                     llx.BoolData(false),
			"minimumPasswordLength":      llx.NilData,
			"requireUppercaseCharacters": llx.NilData,
			"requireLowercaseCharacters": llx.NilData,
			"requireSymbols":             llx.NilData,
			"requireNumbers":             llx.NilData,
			"passwordReusePrevention":    llx.NilData,
			"maxPasswordAge":             llx.NilData,
			"expirePasswords":            llx.NilData,
			"hardExpiry":                 llx.NilData,
			"allowUsersToChangePassword": llx.NilData,
		}
	}
	return map[string]*llx.RawData{
		"__id":                       llx.StringData(id),
		"exists":                     llx.BoolData(true),
		"minimumPasswordLength":      llx.IntDataPtr(pp.MinimumPasswordLength),
		"requireUppercaseCharacters": llx.BoolData(pp.RequireUppercaseCharacters),
		"requireLowercaseCharacters": llx.BoolData(pp.RequireLowercaseCharacters),
		"requireSymbols":             llx.BoolData(pp.RequireSymbols),
		"requireNumbers":             llx.BoolData(pp.RequireNumbers),
		"passwordReusePrevention":    llx.IntDataPtr(pp.PasswordReusePrevention),
		"maxPasswordAge":             llx.IntDataPtr(pp.MaxPasswordAge),
		"expirePasswords":            llx.BoolData(pp.ExpirePasswords),
		"hardExpiry":                 llx.BoolDataPtr(pp.HardExpiry),
		"allowUsersToChangePassword": llx.BoolData(pp.AllowUsersToChangePassword),
	}
}

func (a *mqlAwsIam) accountSummary() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	resp, err := svc.GetAccountSummary(ctx, &iam.GetAccountSummaryInput{})
	if err != nil {
		return nil, errors.Wrap(err, "could not gather aws iam account-summary")
	}

	// convert result to MQL
	res := map[string]any{}
	for k := range resp.SummaryMap {
		res[k] = int64(resp.SummaryMap[k])
	}

	return res, nil
}

func (a *mqlAwsIam) users() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	params := &iam.ListUsersInput{}
	paginator := iam.NewListUsersPaginator(svc, params)
	for paginator.HasMorePages() {
		usersResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws iam users")
		}
		for _, user := range usersResp.Users {
			mqlAwsIamUser, err := a.createIamUser(&user)
			if err != nil {
				return nil, err
			}

			res = append(res, mqlAwsIamUser)
		}
	}
	return res, nil
}

// tags for IAM users/roles/instance profiles must be fetched separately: the
// ListUsers / ListRoles / ListInstanceProfiles responses explicitly omit Tags
// (the SDK documents this on each operation), so the collection path used to
// report {} for every principal while the single-object path returned the real
// tags. Fetching lazily keeps queries that don't select tags free of the call.
// The init paths (GetUser/GetRole/GetInstanceProfile) already populate the
// field eagerly, so GetOrCompute short-circuits and these never fire there.

func (a *mqlAwsIamUser) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	userName := a.Name.Data
	res := []iamtypes.Tag{}
	paginator := iam.NewListUserTagsPaginator(svc, &iam.ListUserTagsInput{UserName: &userName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return markTagsUnreadable(&a.Tags)
			}
			return nil, err
		}
		res = append(res, page.Tags...)
	}
	return iamTagsToMap(res), nil
}

func (a *mqlAwsIamRole) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	roleName := a.Name.Data
	res := []iamtypes.Tag{}
	paginator := iam.NewListRoleTagsPaginator(svc, &iam.ListRoleTagsInput{RoleName: &roleName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return markTagsUnreadable(&a.Tags)
			}
			return nil, err
		}
		res = append(res, page.Tags...)
	}
	return iamTagsToMap(res), nil
}

func (a *mqlAwsIamInstanceProfile) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	name := a.InstanceProfileName.Data
	res := []iamtypes.Tag{}
	paginator := iam.NewListInstanceProfileTagsPaginator(svc, &iam.ListInstanceProfileTagsInput{InstanceProfileName: &name})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return markTagsUnreadable(&a.Tags)
			}
			return nil, err
		}
		res = append(res, page.Tags...)
	}
	return iamTagsToMap(res), nil
}

func iamTagsToMap(tags []iamtypes.Tag) map[string]any {
	return tagsToMap(tags, func(t iamtypes.Tag) *string { return t.Key }, func(t iamtypes.Tag) *string { return t.Value })
}

func (a *mqlAwsIam) instanceProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	params := &iam.ListInstanceProfilesInput{}
	paginator := iam.NewListInstanceProfilesPaginator(svc, params)
	for paginator.HasMorePages() {
		instanceProfilesResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws iam instance profiles")
		}
		for _, itp := range instanceProfilesResp.InstanceProfiles {
			mqlAwsIamUser, err := a.createInstanceProfile(&itp)
			if err != nil {
				return nil, err
			}

			res = append(res, mqlAwsIamUser)
		}
	}
	return res, nil
}

func (a *mqlAwsIam) createInstanceProfile(instanceProfile *iamtypes.InstanceProfile) (plugin.Resource, error) {
	if instanceProfile == nil {
		return nil, errors.New("no instance profile provided")
	}
	res, err := CreateResource(a.MqlRuntime, ResourceAwsIamInstanceProfile,
		map[string]*llx.RawData{
			"arn":                 llx.StringDataPtr(instanceProfile.Arn),
			"createdAt":           llx.TimeDataPtr(instanceProfile.CreateDate),
			"instanceProfileId":   llx.StringDataPtr(instanceProfile.InstanceProfileId),
			"instanceProfileName": llx.StringDataPtr(instanceProfile.InstanceProfileName),
			// "roles":               llx.MapDataPtr(instanceProfile.Roles),
		},
	)
	if err != nil {
		return nil, err
	}
	res.(*mqlAwsIamInstanceProfile).rolesCache = instanceProfile.Roles
	return res, nil
}

func (a *mqlAwsIamInstanceProfile) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsIamInstanceProfileInternal struct {
	rolesCache []iamtypes.Role
}

func (a *mqlAwsIamInstanceProfile) iamRoles() ([]any, error) {
	res := []any{}
	for _, role := range a.rolesCache {
		roleRes, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{
			"arn": llx.StringDataPtr(role.Arn),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, roleRes)
	}

	return res, nil
}

func (a *mqlAwsIam) createIamUser(usr *iamtypes.User) (plugin.Resource, error) {
	if usr == nil {
		return nil, errors.New("no iam user provided")
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAwsIamUser,
		map[string]*llx.RawData{
			"arn":              llx.StringDataPtr(usr.Arn),
			"id":               llx.StringDataPtr(usr.UserId),
			"name":             llx.StringDataPtr(usr.UserName),
			"createdAt":        llx.TimeDataPtr(usr.CreateDate),
			"passwordLastUsed": llx.TimeDataPtr(usr.PasswordLastUsed),
			"path":             llx.StringDataPtr(usr.Path),
		},
	)
	if err != nil {
		return nil, err
	}
	mqlUser := res.(*mqlAwsIamUser)
	if usr.PermissionsBoundary != nil {
		mqlUser.permissionsBoundaryArn = convert.ToValue(usr.PermissionsBoundary.PermissionsBoundaryArn)
		mqlUser.permissionsBoundaryArnSet = true
	}
	return res, nil
}

// permissionsBoundary resolves the managed policy that sets the user's
// permissions boundary. ListUsers populates the boundary directly; resources
// built via NewResource without it fall back to a targeted GetUser.
func (a *mqlAwsIamUser) permissionsBoundary() (*mqlAwsIamPolicy, error) {
	if !a.permissionsBoundaryArnSet {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Iam("")
		userName := a.Name.Data
		resp, err := svc.GetUser(context.Background(), &iam.GetUserInput{UserName: &userName})
		if err != nil {
			return nil, err
		}
		if resp.User != nil && resp.User.PermissionsBoundary != nil {
			a.permissionsBoundaryArn = convert.ToValue(resp.User.PermissionsBoundary.PermissionsBoundaryArn)
		}
		a.permissionsBoundaryArnSet = true
	}

	if a.permissionsBoundaryArn == "" {
		a.PermissionsBoundary.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	mqlPolicy, err := NewResource(a.MqlRuntime, "aws.iam.policy",
		map[string]*llx.RawData{"arn": llx.StringData(a.permissionsBoundaryArn)})
	if err != nil {
		return nil, err
	}
	return mqlPolicy.(*mqlAwsIamPolicy), nil
}

func (a *mqlAwsIamUser) mfaDevices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	userName := a.Name.Data
	res := []any{}
	params := &iam.ListMFADevicesInput{UserName: &userName}
	paginator := iam.NewListMFADevicesPaginator(svc, params)
	for paginator.HasMorePages() {
		devices, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		dicts, err := convert.JsonToDictSlice(devices.MFADevices)
		if err != nil {
			return nil, err
		}
		res = append(res, dicts...)
	}
	return res, nil
}

func (a *mqlAwsIam) virtualMfaDevices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	devicesResp, err := svc.ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{})
	if err != nil {
		log.Error().Err(err).Msg("cannot gather virtual mfa devices info")
		a.VirtualMfaDevices = plugin.TValue[[]any]{Error: err, State: plugin.StateIsSet}
		return nil, nil
	}

	// note: adding pagination to this call results in Throttling: Rate exceeded error
	res := []any{}
	for i := range devicesResp.VirtualMFADevices {
		device := devicesResp.VirtualMFADevices[i]

		args := map[string]*llx.RawData{
			"serialNumber": llx.StringDataPtr(device.SerialNumber),
			"enableDate":   llx.TimeDataPtr(device.EnableDate),
		}

		mqlAwsIamMfaDevice, err := CreateResource(a.MqlRuntime, ResourceAwsIamVirtualmfadevice, args)
		if err != nil {
			return nil, err
		}

		res = append(res, mqlAwsIamMfaDevice)
		if device.User != nil {
			mqlAwsIamMfaDevice.(*mqlAwsIamVirtualmfadevice).cacheUserArn = device.User.Arn
			mqlAwsIamMfaDevice.(*mqlAwsIamVirtualmfadevice).cacheUserName = device.User.UserName
		}
	}

	return res, nil
}

func (a *mqlAwsIamVirtualmfadevice) user() (*mqlAwsIamUser, error) {
	if a.cacheUserArn != nil && a.cacheUserName != nil {
		awsIamUser, err := NewResource(a.MqlRuntime, ResourceAwsIamUser, map[string]*llx.RawData{
			"arn":  llx.StringDataPtr(a.cacheUserArn),
			"name": llx.StringDataPtr(a.cacheUserName),
		})
		if err != nil {
			return nil, err
		}
		return awsIamUser.(*mqlAwsIamUser), nil
	}
	a.User.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

type mqlAwsIamVirtualmfadeviceInternal struct {
	cacheUserName *string
	cacheUserArn  *string
}

func (a *mqlAwsIam) mqlPolicies(policies []iamtypes.Policy) ([]any, error) {
	res := []any{}
	for i := range policies {
		policy := policies[i]
		// NOTE: here we have all the information about the policy already
		// therefore we pass the information in, so that MQL does not have to resolve it again
		mqlAwsIamPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsIamPolicy,
			map[string]*llx.RawData{
				"arn":             llx.StringDataPtr(policy.Arn),
				"policyId":        llx.StringDataPtr(policy.PolicyId),
				"name":            llx.StringDataPtr(policy.PolicyName),
				"isAttachable":    llx.BoolData(policy.IsAttachable),
				"attachmentCount": llx.IntDataDefault(policy.AttachmentCount, 0),
				"createdAt":       llx.TimeDataPtr(policy.CreateDate),
				"updatedAt":       llx.TimeDataPtr(policy.UpdateDate),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAwsIamPolicy)
	}
	return res, nil
}

func (a *mqlAwsIam) attachedPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	params := &iam.ListPoliciesInput{
		// setting only attached ensures we only fetch policies attached to a user, group, or role
		OnlyAttached: true,
	}
	paginator := iam.NewListPoliciesPaginator(svc, params)
	for paginator.HasMorePages() {
		policiesResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws iam policies")
		}

		policies, err := a.mqlPolicies(policiesResp.Policies)
		if err != nil {
			return nil, err
		}
		res = append(res, policies...)
	}

	return res, nil
}

func (a *mqlAwsIam) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	params := &iam.ListPoliciesInput{}
	paginator := iam.NewListPoliciesPaginator(svc, params)
	for paginator.HasMorePages() {
		policiesResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws iam policies")
		}

		policies, err := a.mqlPolicies(policiesResp.Policies)
		if err != nil {
			return nil, err
		}
		res = append(res, policies...)
	}

	return res, nil
}

func (a *mqlAwsIam) roles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	params := &iam.ListRolesInput{}
	paginator := iam.NewListRolesPaginator(svc, params)
	for paginator.HasMorePages() {
		rolesResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, role := range rolesResp.Roles {
			policyDocumentMap := decodeIamPolicyDocument(role.AssumeRolePolicyDocument)

			var permBoundaryArn string
			if role.PermissionsBoundary != nil {
				permBoundaryArn = convert.ToValue(role.PermissionsBoundary.PermissionsBoundaryArn)
			}

			mqlAwsIamRole, err := CreateResource(a.MqlRuntime, ResourceAwsIamRole,
				map[string]*llx.RawData{
					"arn":                      llx.StringDataPtr(role.Arn),
					"id":                       llx.StringDataPtr(role.RoleId),
					"name":                     llx.StringDataPtr(role.RoleName),
					"description":              llx.StringDataPtr(role.Description),
					"createdAt":                llx.TimeDataPtr(role.CreateDate),
					"assumeRolePolicyDocument": llx.MapData(policyDocumentMap, types.Any),
					"maxSessionDuration":       llx.IntDataDefault(role.MaxSessionDuration, 3600),
					"permissionsBoundaryArn":   llx.StringData(permBoundaryArn),
					"path":                     llx.StringDataPtr(role.Path),
					"isServiceLinked":          llx.BoolData(isServiceLinkedRolePath(convert.ToValue(role.Path))),
				})
			if err != nil {
				return nil, err
			}

			res = append(res, mqlAwsIamRole)
		}
	}

	return res, nil
}

func (a *mqlAwsIam) groups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	params := &iam.ListGroupsInput{}
	paginator := iam.NewListGroupsPaginator(svc, params)
	for paginator.HasMorePages() {
		groupsResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for i := range groupsResp.Groups {
			mqlAwsIamGroup, err := a.createIamGroup(&groupsResp.Groups[i])
			if err != nil {
				return nil, err
			}

			res = append(res, mqlAwsIamGroup)
		}
	}

	return res, nil
}

func (p *mqlAwsIamUsercredentialreportentry) id() (string, error) {
	props := p.Properties.Data

	// The credential report is a hand-parsed CSV; a ragged row yields a map
	// without "arn". A bare assertion here panics inside an executor goroutine
	// and takes the whole scan with it.
	userid, ok := props["arn"].(string)
	if !ok {
		return "", errors.New("aws iam credential report entry has no arn")
	}

	return "aws/iam/credentialreport/" + userid, nil
}

func (p *mqlAwsIamUsercredentialreportentry) arn() (string, error) {
	props := p.Properties.Data

	if props == nil {
		return "", errors.New("could not read the credentials report")
	}

	val, ok := props["arn"].(string)
	if !ok {
		return "", errors.New("arn is not a string value")
	}

	return val, nil
}

func (p *mqlAwsIamUsercredentialreportentry) getBoolValue(key string) (bool, error) {
	props := p.Properties.Data

	if props == nil {
		return false, errors.New("could not read the credentials report")
	}

	val, ok := props[key].(string)
	if !ok {
		return false, errors.New(key + " is not a string value")
	}

	// handle "N/A" and "not_supported" value
	// some accounts do not support specific values eg. root_account does not support password_enabled
	if val == "not_supported" {
		return false, nil
	}

	return strconv.ParseBool(val)
}

func (p *mqlAwsIamUsercredentialreportentry) getStringValue(key string) (string, error) {
	props := p.Properties.Data

	if props == nil {
		return "", errors.New("could not read the credentials report")
	}

	val, ok := props[key].(string)
	if !ok {
		return "", errors.New(key + " is not a string value")
	}

	return val, nil
}

func (p *mqlAwsIamUsercredentialreportentry) getTimeValue(key string) (*time.Time, error) {
	props := p.Properties.Data

	if props == nil {
		log.Info().Msgf("could not retrieve key")
		return nil, errors.New("could not read the credentials report")
	}

	val, ok := props[key].(string)
	if !ok {
		log.Info().Msgf("key is not a string")
		return nil, errors.New(key + " is not a valid string value")
	}

	// handle "N/A" and "not_supported" value
	// some accounts do not support specific values eg. root_account does not support password_last_changed or password_next_rotation
	if val == "N/A" || val == "not_supported" || val == "no_information" {
		return &llx.NeverFutureTime, nil
	}

	// parse iso 8601  "2020-07-15T14:52:00+00:00"
	format := time.RFC3339
	parsed, err := time.Parse(format, val)
	if err != nil {
		log.Error().Err(err).Msg("could not parse the time")
		return nil, errors.New("failed to parse time: " + err.Error())
	}

	return &parsed, nil
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey1Active() (bool, error) {
	return p.getBoolValue("access_key_1_active")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey1LastRotated() (*time.Time, error) {
	return p.getTimeValue("access_key_1_last_rotated")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey1LastUsedDate() (*time.Time, error) {
	return p.getTimeValue("access_key_1_last_used_date")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey1LastUsedRegion() (string, error) {
	return p.getStringValue("access_key_1_last_used_region")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey1LastUsedService() (string, error) {
	return p.getStringValue("access_key_1_last_used_service")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey2Active() (bool, error) {
	return p.getBoolValue("access_key_2_active")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey2LastRotated() (*time.Time, error) {
	return p.getTimeValue("access_key_2_last_rotated")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey2LastUsedDate() (*time.Time, error) {
	return p.getTimeValue("access_key_2_last_used_date")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey2LastUsedRegion() (string, error) {
	return p.getStringValue("access_key_2_last_used_region")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey2LastUsedService() (string, error) {
	return p.getStringValue("access_key_2_last_used_service")
}

// TODO: update keys

func (p *mqlAwsIamUsercredentialreportentry) cert1Active() (bool, error) {
	return p.getBoolValue("cert_1_active")
}

func (p *mqlAwsIamUsercredentialreportentry) cert1LastRotated() (*time.Time, error) {
	return p.getTimeValue("cert_1_last_rotated")
}

func (p *mqlAwsIamUsercredentialreportentry) cert2Active() (bool, error) {
	return p.getBoolValue("cert_2_active")
}

func (p *mqlAwsIamUsercredentialreportentry) cert2LastRotated() (*time.Time, error) {
	return p.getTimeValue("cert_2_last_rotated")
}

func (p *mqlAwsIamUsercredentialreportentry) mfaActive() (bool, error) {
	return p.getBoolValue("mfa_active")
}

func (p *mqlAwsIamUsercredentialreportentry) passwordEnabled() (bool, error) {
	return p.getBoolValue("password_enabled")
}

func (p *mqlAwsIamUsercredentialreportentry) passwordLastChanged() (*time.Time, error) {
	return p.getTimeValue("password_last_changed")
}

func (p *mqlAwsIamUsercredentialreportentry) passwordLastUsed() (*time.Time, error) {
	return p.getTimeValue("password_last_used")
}

func (p *mqlAwsIamUsercredentialreportentry) passwordNextRotation() (*time.Time, error) {
	return p.getTimeValue("password_next_rotation")
}

func (a *mqlAwsIamUsercredentialreportentry) user() (*mqlAwsIamUser, error) {
	props := a.Properties.Data

	if props == nil {
		log.Info().Msgf("could not retrieve key")
		return nil, errors.New("could not read the credentials report")
	}
	// handle special case for the root account since that user does not exist
	if props["user"] == "<root_account>" {
		return nil, errors.New("root user does not exist")
	}

	userName, ok := props["user"].(string)
	if !ok {
		return nil, errors.New("aws iam credential report entry has no user")
	}
	mqlUser, err := NewResource(a.MqlRuntime, ResourceAwsIamUser,
		map[string]*llx.RawData{
			"name": llx.StringData(userName),
		},
	)
	if err != nil {
		return nil, err
	}

	return mqlUser.(*mqlAwsIamUser), nil
}

func (a *mqlAwsIamUsercredentialreportentry) createdAt() (*time.Time, error) {
	return a.getTimeValue("user_creation_time")
}

func (p *mqlAwsIamUsercredentialreportentry) isRoot() (bool, error) {
	props := p.Properties.Data
	if props == nil {
		return false, errors.New("could not read the credentials report")
	}
	return props["user"] == "<root_account>", nil
}

// isCredentialReportPlaceholder reports whether a credential-report value is a
// placeholder for data the account never produced rather than a real value.
func isCredentialReportPlaceholder(val string) bool {
	switch val {
	case "", "N/A", "no_information", "not_supported":
		return true
	}
	return false
}

// lastActivityTime returns the timestamp to measure inactivity from: the most
// recent use recorded under usedKey, or, when the credential has never been
// used, the creation or rotation time under fallbackKey. It returns nil when
// neither key holds a real timestamp.
func (p *mqlAwsIamUsercredentialreportentry) lastActivityTime(usedKey, fallbackKey string) (*time.Time, error) {
	props := p.Properties.Data
	if props == nil {
		return nil, errors.New("could not read the credentials report")
	}
	for _, key := range []string{usedKey, fallbackKey} {
		val, ok := props[key].(string)
		if !ok || isCredentialReportPlaceholder(val) {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, val)
		if err != nil {
			return nil, errors.New("failed to parse time: " + err.Error())
		}
		return &parsed, nil
	}
	return nil, nil
}

func daysSince(ref time.Time) int64 {
	days := int64(time.Since(ref).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
}

func (p *mqlAwsIamUsercredentialreportentry) passwordInactiveDays() (int64, error) {
	enabled, err := p.passwordEnabled()
	if err != nil {
		return 0, err
	}
	if !enabled {
		p.PasswordInactiveDays = plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
		return 0, nil
	}
	ref, err := p.lastActivityTime("password_last_used", "user_creation_time")
	if err != nil {
		return 0, err
	}
	if ref == nil {
		p.PasswordInactiveDays = plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
		return 0, nil
	}
	return daysSince(*ref), nil
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey1InactiveDays() (int64, error) {
	return p.accessKeyInactiveDays(&p.AccessKey1InactiveDays, "access_key_1_active", "access_key_1_last_used_date", "access_key_1_last_rotated")
}

func (p *mqlAwsIamUsercredentialreportentry) accessKey2InactiveDays() (int64, error) {
	return p.accessKeyInactiveDays(&p.AccessKey2InactiveDays, "access_key_2_active", "access_key_2_last_used_date", "access_key_2_last_rotated")
}

// accessKeyInactiveDays returns whole days since the access key was last used,
// or since it was last rotated when it has never been used. It is null when the
// key is inactive.
func (p *mqlAwsIamUsercredentialreportentry) accessKeyInactiveDays(field *plugin.TValue[int64], activeKey, usedKey, rotatedKey string) (int64, error) {
	active, err := p.getBoolValue(activeKey)
	if err != nil {
		return 0, err
	}
	if !active {
		*field = plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
		return 0, nil
	}
	ref, err := p.lastActivityTime(usedKey, rotatedKey)
	if err != nil {
		return 0, err
	}
	if ref == nil {
		*field = plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
		return 0, nil
	}
	return daysSince(*ref), nil
}

func (a *mqlAwsIamVirtualmfadevice) id() (string, error) {
	return a.SerialNumber.Data, nil
}

func initAwsIamUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// A reference already materialized by an earlier referrer or by the
	// list that built it. NewResource consults the cache only after this
	// init returns, so without this the same target is fetched once per
	// referring resource and the result discarded.
	if cached := cachedArgByArn(runtime, ResourceAwsIamUser, args); cached != nil {
		return args, cached, nil
	}
	// The lookup is name-driven (GetUser); discovery sets the asset name to
	// the IAM user name.
	if len(args) == 0 {
		if name := getAssetName(runtime, connection.PlatformIamUser); name != "" {
			args["name"] = llx.StringData(name)
		}
	}

	if args["name"] == nil {
		return nil, nil, errors.New("name required to fetch aws iam user")
	}

	// Resolve from the account's user list before falling back to a GetUser the
	// ARN-keyed cache check above cannot serve, because this lookup is by name.
	if name, ok := args["name"].Value.(string); ok && name != "" {
		if usr := iamUserFromList(runtime, name, ""); usr != nil {
			return args, usr, nil
		}
	}

	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	usr, ok := args["name"].Value.(string)
	if !ok {
		return nil, nil, errors.New("invalid name argument for aws iam user")
	}
	resp, err := svc.GetUser(ctx, &iam.GetUserInput{
		UserName: &usr,
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.User == nil {
		return nil, nil, fmt.Errorf("aws.iam.user %q not found", usr)
	}

	user := resp.User
	args["arn"] = llx.StringDataPtr(user.Arn)
	args["id"] = llx.StringDataPtr(user.UserId)
	args["name"] = llx.StringDataPtr(user.UserName)
	args["createdAt"] = llx.TimeDataPtr(user.CreateDate)
	args["passwordLastUsed"] = llx.TimeDataPtr(user.PasswordLastUsed)
	args["tags"] = llx.MapData(iamTagsToMap(user.Tags), types.String)
	args["path"] = llx.StringDataPtr(user.Path)

	return args, nil, nil
}

type mqlAwsIamUserInternal struct {
	accessKeyMetaFetched atomic.Bool
	accessKeyMetaCache   []iamtypes.AccessKeyMetadata
	accessKeyMetaLock    sync.Mutex

	policiesFetched atomic.Bool
	policiesCache   []any
	policiesLock    sync.Mutex

	attachedPoliciesFetched atomic.Bool
	attachedPoliciesCache   []any
	attachedPoliciesLock    sync.Mutex

	groupsFetched atomic.Bool
	groupsCache   []any
	groupsLock    sync.Mutex

	loginProfileFetched atomic.Bool
	loginProfileCache   *mqlAwsIamLoginProfile
	loginProfileLock    sync.Mutex

	permissionsBoundaryArn    string
	permissionsBoundaryArnSet bool
}

func (a *mqlAwsIamUser) id() (string, error) {
	if a.Arn.Error != nil {
		return "", a.Arn.Error
	}
	return a.Arn.Data, nil
}

// listAccessKeyMetadata fetches the user's access-key metadata once and caches
// it, so accessKeys and accessKeyDetails share a single ListAccessKeys call
// instead of each making their own.
func (a *mqlAwsIamUser) listAccessKeyMetadata() ([]iamtypes.AccessKeyMetadata, error) {
	if a.accessKeyMetaFetched.Load() {
		return a.accessKeyMetaCache, nil
	}
	a.accessKeyMetaLock.Lock()
	defer a.accessKeyMetaLock.Unlock()
	if a.accessKeyMetaFetched.Load() {
		return a.accessKeyMetaCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()
	username := a.Name.Data

	res := []iamtypes.AccessKeyMetadata{}
	paginator := iam.NewListAccessKeysPaginator(svc, &iam.ListAccessKeysInput{
		UserName: &username,
	})
	for paginator.HasMorePages() {
		keysResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, keysResp.AccessKeyMetadata...)
	}

	a.accessKeyMetaCache = res
	a.accessKeyMetaFetched.Store(true)
	return res, nil
}

func (a *mqlAwsIamUser) accessKeys() ([]any, error) {
	metadata, err := a.listAccessKeyMetadata()
	if err != nil {
		return nil, err
	}
	// JsonToDictSlice already returns a []any of per-key dicts; return it
	// directly. (The pre-refactor code wrapped it in another slice, yielding
	// [[dict, …]] instead of [dict, …] — a latent bug, now fixed.)
	dicts, err := convert.JsonToDictSlice(metadata)
	if err != nil {
		return nil, err
	}
	return dicts, nil
}

func (a *mqlAwsIamUser) accessKeyDetails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	keys, err := a.listAccessKeyMetadata()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range keys {
		key := keys[i]

		// One GetAccessKeyLastUsed call per key. IAM caps users at 2 access
		// keys, so this loop makes at most 2 calls and is not an N+1 risk.
		// AWS returns "N/A" for region and service and a nil date when the
		// key has never been used.
		lastUsedRegion := ""
		lastUsedService := ""
		var lastUsedDate *time.Time
		if key.AccessKeyId != nil {
			lastUsed, err := svc.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{
				AccessKeyId: key.AccessKeyId,
			})
			if err != nil {
				return nil, err
			}
			if lastUsed.AccessKeyLastUsed != nil {
				lastUsedDate = lastUsed.AccessKeyLastUsed.LastUsedDate
				lastUsedRegion = convert.ToValue(lastUsed.AccessKeyLastUsed.Region)
				lastUsedService = convert.ToValue(lastUsed.AccessKeyLastUsed.ServiceName)
			}
		}

		mqlKey, err := CreateResource(a.MqlRuntime, "aws.iam.user.accessKey",
			map[string]*llx.RawData{
				"__id":            llx.StringDataPtr(key.AccessKeyId),
				"accessKeyId":     llx.StringDataPtr(key.AccessKeyId),
				"username":        llx.StringDataPtr(key.UserName),
				"status":          llx.StringData(string(key.Status)),
				"createdAt":       llx.TimeDataPtr(key.CreateDate),
				"lastUsedDate":    llx.TimeDataPtr(lastUsedDate),
				"lastUsedRegion":  llx.StringData(lastUsedRegion),
				"lastUsedService": llx.StringData(lastUsedService),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

func (a *mqlAwsIamUser) policies() ([]any, error) {
	if a.policiesFetched.Load() {
		return a.policiesCache, nil
	}
	a.policiesLock.Lock()
	defer a.policiesLock.Unlock()
	if a.policiesFetched.Load() {
		return a.policiesCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	policyNames, err := listUserInlinePolicyNames(context.Background(), conn.Iam(""), a.Name.Data)
	if err != nil {
		return nil, err
	}
	res := convert.SliceAnyToInterface(policyNames)

	a.policiesCache = res
	a.policiesFetched.Store(true)
	return res, nil
}

func (a *mqlAwsIamUser) attachedPolicies() ([]any, error) {
	if a.attachedPoliciesFetched.Load() {
		return a.attachedPoliciesCache, nil
	}
	a.attachedPoliciesLock.Lock()
	defer a.attachedPoliciesLock.Unlock()
	if a.attachedPoliciesFetched.Load() {
		return a.attachedPoliciesCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	username := a.Name.Data

	res := []any{}
	params := &iam.ListAttachedUserPoliciesInput{
		UserName: &username,
	}
	paginator := iam.NewListAttachedUserPoliciesPaginator(svc, params)
	for paginator.HasMorePages() {
		userAttachedPolicies, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, attachedPolicy := range userAttachedPolicies.AttachedPolicies {
			mqlAwsIamPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsIamPolicy,
				map[string]*llx.RawData{"arn": llx.StringDataPtr(attachedPolicy.PolicyArn)})
			if err != nil {
				return nil, err
			}

			res = append(res, mqlAwsIamPolicy)
		}
	}

	a.attachedPoliciesCache = res
	a.attachedPoliciesFetched.Store(true)
	return res, nil
}

type mqlAwsIamPolicyInternal struct {
	cachePolicy     *iamtypes.Policy
	policyFetched   atomic.Bool
	policyLock      sync.Mutex
	cachedVersions  []iamtypes.PolicyVersion
	versionsFetched atomic.Bool
	versionsLock    sync.Mutex
}

// id keys the resource on the policy ARN. Without it every aws.iam.policy
// shares the empty cache key, so CreateResource returns the first-created
// policy for every subsequent one.
func (a *mqlAwsIamPolicy) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsIamPolicy) loadPolicy(arn string) (*iamtypes.Policy, error) {
	if a.policyFetched.Load() {
		return a.cachePolicy, nil
	}
	a.policyLock.Lock()
	defer a.policyLock.Unlock()
	if a.policyFetched.Load() {
		return a.cachePolicy, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	policy, err := svc.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &arn})
	if err != nil {
		return nil, err
	}

	a.cachePolicy = policy.Policy
	a.policyFetched.Store(true)
	return policy.Policy, nil
}

func (a *mqlAwsIamPolicy) name() (string, error) {
	arn := a.Arn.Data

	policy, err := a.loadPolicy(arn)
	if err != nil {
		return "", err
	}
	return convert.ToValue(policy.PolicyName), nil
}

func (a *mqlAwsIamPolicy) description() (string, error) {
	arn := a.Arn.Data

	policy, err := a.loadPolicy(arn)
	if err != nil {
		return "", err
	}
	return convert.ToValue(policy.Description), nil
}

func (a *mqlAwsIamPolicy) policyId() (string, error) {
	arn := a.Arn.Data

	policy, err := a.loadPolicy(arn)
	if err != nil {
		return "", err
	}
	return convert.ToValue(policy.PolicyId), nil
}

// tags reads the policy tags off the cached GetPolicy response. ListPolicies,
// which is what aws.iam.policies pages through, leaves Tags empty on every
// Policy it returns even though the field exists, so the tags have to come from
// the per-policy call that name and description already share.
func (a *mqlAwsIamPolicy) tags() (map[string]any, error) {
	policy, err := a.loadPolicy(a.Arn.Data)
	if err != nil {
		return nil, err
	}
	return iamTagsToMap(policy.Tags), nil
}

func (a *mqlAwsIamPolicy) isAttachable() (bool, error) {
	arn := a.Arn.Data

	policy, err := a.loadPolicy(arn)
	if err != nil {
		return false, err
	}
	return policy.IsAttachable, nil
}

func (a *mqlAwsIamPolicy) attachmentCount() (int64, error) {
	arn := a.Arn.Data

	policy, err := a.loadPolicy(arn)
	if err != nil || policy.AttachmentCount == nil {
		return int64(0), err
	}
	return int64(*policy.AttachmentCount), nil
}

func (a *mqlAwsIamPolicy) createdAt() (*time.Time, error) {
	arn := a.Arn.Data

	policy, err := a.loadPolicy(arn)
	if err != nil {
		return nil, err
	}
	return policy.CreateDate, nil
}

func (a *mqlAwsIamPolicy) updatedAt() (*time.Time, error) {
	arn := a.Arn.Data

	policy, err := a.loadPolicy(arn)
	if err != nil {
		return nil, err
	}
	return policy.UpdateDate, nil
}

func (a *mqlAwsIamPolicy) scope() (string, error) {
	arnVal := a.Arn.Data

	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return "", err
	}

	if parsed.AccountID == "aws" {
		return "aws", nil
	}

	return "local", nil
}

type attachedEntities struct {
	PolicyGroups []iamtypes.PolicyGroup
	PolicyRoles  []iamtypes.PolicyRole
	PolicyUsers  []iamtypes.PolicyUser
}

func (a *mqlAwsIamPolicy) listAttachedEntities(arn string) (attachedEntities, error) {
	// c, ok := a.Cache.Load("_attachedentities")
	// if ok {
	// 	log.Debug().Msg("use attached entities from cache")
	// 	return c.Data.(attachedEntities), nil
	// }
	var res attachedEntities

	// if its not in the cache, fetch it
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	params := &iam.ListEntitiesForPolicyInput{
		PolicyArn: &arn,
	}
	paginator := iam.NewListEntitiesForPolicyPaginator(svc, params)
	for paginator.HasMorePages() {
		entities, err := paginator.NextPage(ctx)
		if err != nil {
			return res, err
		}

		if len(entities.PolicyGroups) > 0 {
			res.PolicyGroups = append(res.PolicyGroups, entities.PolicyGroups...)
		}

		if len(entities.PolicyRoles) > 0 {
			res.PolicyRoles = append(res.PolicyRoles, entities.PolicyRoles...)
		}

		if len(entities.PolicyUsers) > 0 {
			res.PolicyUsers = append(res.PolicyUsers, entities.PolicyUsers...)
		}
	}

	// cache the data
	// a.Cache.Store("_attachedentities", &resources.CacheEntry{Data: res})
	return res, nil
}

func (a *mqlAwsIamPolicy) attachedUsers() ([]any, error) {
	arn := a.Arn.Data

	entities, err := a.listAttachedEntities(arn)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, usr := range entities.PolicyUsers {
		mqlUser, err := NewResource(a.MqlRuntime, ResourceAwsIamUser,
			map[string]*llx.RawData{
				"name": llx.StringDataPtr(usr.UserName),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, mqlUser)
	}
	return res, nil
}

func (a *mqlAwsIamPolicy) attachedRoles() ([]any, error) {
	arn := a.Arn.Data
	entities, err := a.listAttachedEntities(arn)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, role := range entities.PolicyRoles {
		mqlUser, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
			map[string]*llx.RawData{"name": llx.StringDataPtr(role.RoleName)},
		)
		if err != nil {
			return nil, err
		}

		res = append(res, mqlUser)
	}
	return res, nil
}

func (a *mqlAwsIamPolicy) attachedGroups() ([]any, error) {
	arn := a.Arn.Data

	entities, err := a.listAttachedEntities(arn)
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range entities.PolicyGroups {
		group := entities.PolicyGroups[i]

		mqlUser, err := NewResource(a.MqlRuntime, ResourceAwsIamGroup,
			map[string]*llx.RawData{
				"name": llx.StringDataPtr(group.GroupName),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, mqlUser)
	}
	return res, nil
}

// fetchPolicyVersions fetches and caches ListPolicyVersions with double-check locking.
// Shared between defaultVersion() and versions().
func (a *mqlAwsIamPolicy) fetchPolicyVersions() ([]iamtypes.PolicyVersion, error) {
	if a.versionsFetched.Load() {
		return a.cachedVersions, nil
	}
	a.versionsLock.Lock()
	defer a.versionsLock.Unlock()
	if a.versionsFetched.Load() {
		return a.cachedVersions, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: &arn})
	if err != nil {
		return nil, err
	}

	a.cachedVersions = resp.Versions
	a.versionsFetched.Store(true)
	return a.cachedVersions, nil
}

func (a *mqlAwsIamPolicy) defaultVersion() (*mqlAwsIamPolicyversion, error) {
	arn := a.Arn.Data

	versions, err := a.fetchPolicyVersions()
	if err != nil {
		return nil, err
	}

	for i := range versions {
		policyversion := versions[i]
		if policyversion.IsDefaultVersion {
			mqlAwsIamPolicyVersion, err := CreateResource(a.MqlRuntime, ResourceAwsIamPolicyversion,
				map[string]*llx.RawData{
					"arn":              llx.StringData(arn),
					"versionId":        llx.StringDataPtr(policyversion.VersionId),
					"isDefaultVersion": llx.BoolData(policyversion.IsDefaultVersion),
					"createdAt":        llx.TimeDataPtr(policyversion.CreateDate),
				})
			if err != nil {
				return nil, err
			}
			return mqlAwsIamPolicyVersion.(*mqlAwsIamPolicyversion), nil
		}
	}
	return nil, errors.New("unable to find default policy version")
}

func (a *mqlAwsIamPolicy) versions() ([]any, error) {
	arn := a.Arn.Data

	versions, err := a.fetchPolicyVersions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range versions {
		policyversion := versions[i]

		mqlAwsIamPolicyVersion, err := CreateResource(a.MqlRuntime, ResourceAwsIamPolicyversion,
			map[string]*llx.RawData{
				"arn":              llx.StringData(arn),
				"versionId":        llx.StringDataPtr(policyversion.VersionId),
				"isDefaultVersion": llx.BoolData(policyversion.IsDefaultVersion),
				"createdAt":        llx.TimeDataPtr(policyversion.CreateDate),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, mqlAwsIamPolicyVersion)
	}

	return res, nil
}

func (a *mqlAwsIamPolicyversion) id() (string, error) {
	arn := a.Arn.Data

	versionid := a.VersionId.Data

	return arn + "/" + versionid, nil
}

type mqlAwsIamPolicyversionInternal struct {
	rawDocOnce sync.Once
	rawDoc     string
	rawDocErr  error
}

// rawDocument fetches the policy version document as it is returned by the IAM
// API: a URL-encoded JSON string. Callers decode and parse it as needed. The
// result is cached so that document() and statements(), which both rely on it,
// share a single GetPolicyVersion call.
func (a *mqlAwsIamPolicyversion) rawDocument() (string, error) {
	a.rawDocOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

		svc := conn.Iam("")
		ctx := context.Background()

		arn := a.Arn.Data
		versionid := a.VersionId.Data

		policyVersion, err := svc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: &arn,
			VersionId: &versionid,
		})
		if err != nil {
			a.rawDocErr = err
			return
		}

		if policyVersion == nil || policyVersion.PolicyVersion == nil || policyVersion.PolicyVersion.Document == nil {
			a.rawDocErr = errors.New("could not retrieve the policy document")
			return
		}
		a.rawDoc = *policyVersion.PolicyVersion.Document
	})
	return a.rawDoc, a.rawDocErr
}

func (a *mqlAwsIamPolicyversion) document() (any, error) {
	rawDoc, err := a.rawDocument()
	if err != nil {
		return "", err
	}
	decodedValue, err := url.QueryUnescape(rawDoc)
	if err != nil {
		return "", err
	}
	policyDoc := awspolicy.IamPolicyDocument{}
	err = json.Unmarshal([]byte(decodedValue), &policyDoc)
	if err != nil {
		return "", err
	}
	dict, err := convert.JsonToDict(policyDoc)
	if err != nil {
		return "", err
	}
	return dict, nil
}

// isServiceLinkedRolePath reports whether an IAM role path marks the role as
// service-linked. IAM does not return a flag for this; the path prefix is the
// documented signal. Shared by roles() and initAwsIamRole so the two cannot
// disagree about the same role.
func isServiceLinkedRolePath(path string) bool {
	return strings.HasPrefix(path, "/aws-service-role/")
}

func initAwsIamRole(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// Already materialized by an earlier reference or by the list that
	// built it: NewResource consults the cache only after this init
	// returns, so without this the same target is fetched once per
	// referring resource and the result thrown away.
	if cached := cachedArgByArn(runtime, ResourceAwsIamRole, args); cached != nil {
		return args, cached, nil
	}

	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch aws iam role")
	}

	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	var rolename string
	if args["name"] == nil && args["arn"] != nil {
		a, err := arn.Parse(args["arn"].Value.(string))
		if err != nil {
			return nil, nil, err
		}
		// The ARN resource can include a path (e.g., "role/service-role/my-role").
		// IAM GetRole requires just the role name, not the path.
		resource := strings.TrimPrefix(a.Resource, "role/")
		if idx := strings.LastIndex(resource, "/"); idx != -1 {
			rolename = resource[idx+1:]
		} else {
			rolename = resource
		}
	}
	if args["name"] != nil {
		rolename = args["name"].Value.(string)
	}

	if rolename != "" {
		resp, err := svc.GetRole(ctx, &iam.GetRoleInput{
			RoleName: &rolename,
		})
		if err != nil {
			return nil, nil, err
		}

		if resp == nil || resp.Role == nil {
			return nil, nil, fmt.Errorf("aws iam role %q not found", rolename)
		}
		role := resp.Role

		policyDocumentMap := decodeIamPolicyDocument(role.AssumeRolePolicyDocument)

		args["arn"] = llx.StringDataPtr(role.Arn)
		args["id"] = llx.StringDataPtr(role.RoleId)
		args["name"] = llx.StringDataPtr(role.RoleName)
		args["description"] = llx.StringDataPtr(role.Description)
		args["tags"] = llx.MapData(iamTagsToMap(role.Tags), types.String)
		args["createdAt"] = llx.TimeDataPtr(role.CreateDate)
		args["assumeRolePolicyDocument"] = llx.MapData(policyDocumentMap, types.Any)
		var permBoundaryArn string
		if role.PermissionsBoundary != nil {
			permBoundaryArn = convert.ToValue(role.PermissionsBoundary.PermissionsBoundaryArn)
		}
		args["maxSessionDuration"] = llx.IntDataDefault(role.MaxSessionDuration, 3600)
		args["permissionsBoundaryArn"] = llx.StringData(permBoundaryArn)
		args["path"] = llx.StringDataPtr(role.Path)
		// Leaving this unset reported null for every role reached through the
		// init, and because the resource the init builds is cached under the
		// role ARN, a query that touched aws.iam.role(...) also degraded
		// isServiceLinked to null for aws.iam.roles in the same scan.
		args["isServiceLinked"] = llx.BoolData(isServiceLinkedRolePath(convert.ToValue(role.Path)))
		return args, nil, nil
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, errors.New("could not determine role name to fetch aws iam role")
}

func (a *mqlAwsIamRole) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsIamRole) permissionsBoundary() (*mqlAwsIamPolicy, error) {
	// ListRoles explicitly does not return PermissionsBoundary (see the SDK docs
	// on ListRoles), so roles() always wrote "" into permissionsBoundaryArn.
	// Because llx.StringData("") still marks the field StateIsSet, gating on
	// PermissionsBoundaryArn.IsSet() made the GetRole fallback unreachable and
	// every role reported "no permissions boundary". Track provenance with a
	// dedicated flag instead, exactly as aws.iam.user does.
	if !a.permissionsBoundaryArnSet {
		// getRoleDetails memoizes GetRole, so this shares one call with
		// lastUsedAt/lastUsedRegion instead of issuing a second one.
		resp, err := a.getRoleDetails()
		if err != nil {
			return nil, err
		}
		if resp != nil && resp.Role != nil && resp.Role.PermissionsBoundary != nil {
			a.permissionsBoundaryArn = convert.ToValue(resp.Role.PermissionsBoundary.PermissionsBoundaryArn)
		}
		a.permissionsBoundaryArnSet = true
		a.PermissionsBoundaryArn = plugin.TValue[string]{Data: a.permissionsBoundaryArn, State: plugin.StateIsSet}
	}
	boundaryArn := a.permissionsBoundaryArn

	if boundaryArn == "" {
		a.PermissionsBoundary.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	mqlPolicy, err := NewResource(a.MqlRuntime, "aws.iam.policy",
		map[string]*llx.RawData{"arn": llx.StringData(boundaryArn)})
	if err != nil {
		return nil, err
	}
	return mqlPolicy.(*mqlAwsIamPolicy), nil
}

type mqlAwsIamRoleInternal struct {
	cachedRole  *iam.GetRoleOutput
	roleFetched bool
	roleLock    sync.Mutex
	// permissionsBoundaryArn/-Set mirror the aws.iam.user pattern: ListRoles
	// never returns PermissionsBoundary, so the eager value is meaningless and
	// only a GetRole-sourced value may be trusted.
	permissionsBoundaryArn    string
	permissionsBoundaryArnSet bool
}

// getRoleDetails fetches and memoizes the full role via GetRole. The account-wide
// ListRoles call that roles() uses to enumerate never populates RoleLastUsed, so
// lastUsedAt and lastUsedRegion have to come from GetRole. The result is cached
// so both fields share a single API call, and the call is only made when one
// of those fields is actually queried. The two getters can be evaluated
// concurrently, so lock unconditionally rather than double-checking the flag.
func (a *mqlAwsIamRole) getRoleDetails() (*iam.GetRoleOutput, error) {
	a.roleLock.Lock()
	defer a.roleLock.Unlock()
	if a.roleFetched {
		return a.cachedRole, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()

	roleName := a.Name.Data
	resp, err := svc.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if err != nil {
		return nil, err
	}
	a.cachedRole = resp
	a.roleFetched = true
	return resp, nil
}

func (a *mqlAwsIamRole) lastUsedAt() (*time.Time, error) {
	resp, err := a.getRoleDetails()
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Role == nil || resp.Role.RoleLastUsed == nil {
		return nil, nil
	}
	return resp.Role.RoleLastUsed.LastUsedDate, nil
}

func (a *mqlAwsIamRole) lastUsedRegion() (string, error) {
	resp, err := a.getRoleDetails()
	if err != nil {
		return "", err
	}
	if resp == nil || resp.Role == nil || resp.Role.RoleLastUsed == nil {
		return "", nil
	}
	return convert.ToValue(resp.Role.RoleLastUsed.Region), nil
}

func (a *mqlAwsIamRole) attachedPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	rolename := a.Name.Data

	res := []any{}
	params := &iam.ListAttachedRolePoliciesInput{
		RoleName: &rolename,
	}
	paginator := iam.NewListAttachedRolePoliciesPaginator(svc, params)
	for paginator.HasMorePages() {
		roleAttachedPolicies, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, attachedPolicy := range roleAttachedPolicies.AttachedPolicies {
			mqlAwsIamPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsIamPolicy,
				map[string]*llx.RawData{"arn": llx.StringDataPtr(attachedPolicy.PolicyArn)})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAwsIamPolicy)
		}
	}

	return res, nil
}

func (a *mqlAwsIamRole) inlinePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	policyNames, err := listRoleInlinePolicyNames(context.Background(), conn.Iam(""), a.Name.Data)
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(policyNames), nil
}

// usedByInstances returns the EC2 instances that use this role through an
// instance profile. EC2 references an instance *profile*, which in turn contains
// roles. It derives the role's instance profiles from the account-wide instance
// profile list (a single ListInstanceProfiles call cached and shared across all
// role evaluations, rather than a per-role ListInstanceProfilesForRole call),
// then scans the cached instance list for ones whose profile is among them.
func (a *mqlAwsIamRole) usedByInstances() ([]any, error) {
	roleArn := a.Arn.Data

	iamObj, err := CreateResource(a.MqlRuntime, ResourceAwsIam, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	profiles := iamObj.(*mqlAwsIam).GetInstanceProfiles()
	if profiles.Error != nil {
		return nil, profiles.Error
	}

	profileArns := map[string]struct{}{}
	for _, p := range profiles.Data {
		prof, ok := p.(*mqlAwsIamInstanceProfile)
		if !ok {
			continue
		}
		for _, role := range prof.rolesCache {
			if role.Arn != nil && *role.Arn == roleArn {
				profileArns[prof.Arn.Data] = struct{}{}
				break
			}
		}
	}
	if len(profileArns) == 0 {
		return []any{}, nil
	}

	obj, err := CreateResource(a.MqlRuntime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	instances := obj.(*mqlAwsEc2).GetInstances()
	if instances.Error != nil {
		return nil, instances.Error
	}
	res := []any{}
	for _, it := range instances.Data {
		inst, ok := it.(*mqlAwsEc2Instance)
		if !ok {
			continue
		}
		prof := inst.instanceCache.IamInstanceProfile
		if prof == nil || prof.Arn == nil {
			continue
		}
		if _, match := profileArns[*prof.Arn]; match {
			res = append(res, inst)
		}
	}
	return res, nil
}

type mqlAwsIamGroupInternal struct {
	usernamesFetched atomic.Bool
	usernamesCache   []any
	usernamesLock    sync.Mutex
}

// createIamGroup builds a group resource straight from a ListGroups summary,
// which already carries every stored field. Group membership (usernames) is
// not in that summary and is loaded lazily, so listing groups no longer makes
// a GetGroup call per group.
func (a *mqlAwsIam) createIamGroup(group *iamtypes.Group) (plugin.Resource, error) {
	if group == nil {
		return nil, errors.New("no iam group provided")
	}
	return CreateResource(a.MqlRuntime, ResourceAwsIamGroup,
		map[string]*llx.RawData{
			"arn":       llx.StringDataPtr(group.Arn),
			"id":        llx.StringDataPtr(group.GroupId),
			"name":      llx.StringDataPtr(group.GroupName),
			"createdAt": llx.TimeDataPtr(group.CreateDate),
			"path":      llx.StringDataPtr(group.Path),
		})
}

func initAwsIamGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// The lookup is name-driven (GetGroup); discovery sets the asset name to
	// the IAM group name.
	if len(args) == 0 {
		if name := getAssetName(runtime, connection.PlatformIamGroup); name != "" {
			args["name"] = llx.StringData(name)
		}
	}
	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch aws iam group")
	}

	// Same as the user init: resolve from the account's group list first. This
	// one has no cache check at all, so without it every reference to a group
	// paid for its own GetGroup.
	// args["x"] on an absent key is a nil *llx.RawData; dereferencing it panics
	// the provider and takes the whole scan with it, and only one of the two is
	// guaranteed present here.
	wantName := ""
	if args["name"] != nil {
		wantName, _ = args["name"].Value.(string)
	}
	wantArn := ""
	if args["arn"] != nil {
		wantArn, _ = args["arn"].Value.(string)
	}
	if wantName != "" || wantArn != "" {
		if grp := iamGroupFromList(runtime, wantName, wantArn); grp != nil {
			return args, grp, nil
		}
	}

	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	if args["name"] != nil {
		groupname := args["name"].Value.(string)
		usernames := []any{}
		var grp *iamtypes.Group
		paginator := iam.NewGetGroupPaginator(svc, &iam.GetGroupInput{
			GroupName: &groupname,
		})
		for paginator.HasMorePages() {
			resp, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, nil, err
			}
			grp = resp.Group
			for _, user := range resp.Users {
				usernames = append(usernames, convert.ToValue(user.UserName))
			}
		}
		if grp == nil {
			return nil, nil, fmt.Errorf("aws.iam.group %q not found", groupname)
		}

		args["arn"] = llx.StringDataPtr(grp.Arn)
		args["id"] = llx.StringDataPtr(grp.GroupId)
		args["name"] = llx.StringDataPtr(grp.GroupName)
		args["createdAt"] = llx.TimeDataPtr(grp.CreateDate)
		args["path"] = llx.StringDataPtr(grp.Path)

		mqlGroup, err := CreateResource(runtime, ResourceAwsIamGroup, args)
		if err != nil {
			return nil, nil, err
		}
		// We already paid for the membership list in GetGroup; seed the cache so
		// reading usernames during the asset scan doesn't make a second call.
		g := mqlGroup.(*mqlAwsIamGroup)
		g.usernamesCache = usernames
		g.usernamesFetched.Store(true)
		return args, g, nil
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.iam.group with arn %q not found", args["arn"].Value)
}

func (a *mqlAwsIamGroup) id() (string, error) {
	return a.Arn.Data, nil
}

// usernames lists the group's members. ListGroups (used to build the group in
// the first place) does not return membership, so this lazily calls GetGroup
// only when the field is actually read.
func (a *mqlAwsIamGroup) usernames() ([]any, error) {
	if a.usernamesFetched.Load() {
		return a.usernamesCache, nil
	}
	a.usernamesLock.Lock()
	defer a.usernamesLock.Unlock()
	if a.usernamesFetched.Load() {
		return a.usernamesCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Iam("")
	ctx := context.Background()
	groupname := a.Name.Data

	res := []any{}
	paginator := iam.NewGetGroupPaginator(svc, &iam.GetGroupInput{
		GroupName: &groupname,
	})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, user := range resp.Users {
			res = append(res, convert.ToValue(user.UserName))
		}
	}

	a.usernamesCache = res
	a.usernamesFetched.Store(true)
	return res, nil
}

func (a *mqlAwsIamGroup) attachedPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	groupname := a.Name.Data

	res := []any{}
	params := &iam.ListAttachedGroupPoliciesInput{
		GroupName: &groupname,
	}
	paginator := iam.NewListAttachedGroupPoliciesPaginator(svc, params)
	for paginator.HasMorePages() {
		groupAttachedPolicies, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, attachedPolicy := range groupAttachedPolicies.AttachedPolicies {
			mqlAwsIamPolicy, err := CreateResource(a.MqlRuntime, ResourceAwsIamPolicy,
				map[string]*llx.RawData{"arn": llx.StringDataPtr(attachedPolicy.PolicyArn)})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAwsIamPolicy)
		}
	}

	return res, nil
}

func (a *mqlAwsIamGroup) inlinePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	policyNames, err := listGroupInlinePolicyNames(context.Background(), conn.Iam(""), a.Name.Data)
	if err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(policyNames), nil
}

func (a *mqlAwsIamUser) groups() ([]any, error) {
	if a.groupsFetched.Load() {
		return a.groupsCache, nil
	}
	a.groupsLock.Lock()
	defer a.groupsLock.Unlock()
	if a.groupsFetched.Load() {
		return a.groupsCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	username := a.Name.Data

	res := []any{}
	params := &iam.ListGroupsForUserInput{
		UserName: &username,
	}
	paginator := iam.NewListGroupsForUserPaginator(svc, params)
	for paginator.HasMorePages() {
		userGroups, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, group := range userGroups.Groups {
			res = append(res, convert.ToValue(group.GroupName))
		}
	}

	a.groupsCache = res
	a.groupsFetched.Store(true)
	return res, nil
}

func (a *mqlAwsIamUser) loginProfile() (*mqlAwsIamLoginProfile, error) {
	if a.loginProfileFetched.Load() {
		if a.loginProfileCache == nil {
			a.LoginProfile.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return a.loginProfileCache, nil
	}
	a.loginProfileLock.Lock()
	defer a.loginProfileLock.Unlock()
	if a.loginProfileFetched.Load() {
		if a.loginProfileCache == nil {
			a.LoginProfile.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return a.loginProfileCache, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()
	name := a.Name.Data

	profile, err := svc.GetLoginProfile(ctx, &iam.GetLoginProfileInput{
		UserName: &name,
	})

	var ae smithy.APIError
	if errors.As(err, &ae) {
		if ae.ErrorCode() == "NoSuchEntity" {
			a.loginProfileFetched.Store(true)
			a.LoginProfile.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
	}
	if err != nil {
		return nil, err
	}

	date := profile.LoginProfile.CreateDate
	if date == nil {
		return nil, errors.New("login profile doesn't have a createDate")
	}

	o, err := CreateResource(a.MqlRuntime, ResourceAwsIamLoginProfile, map[string]*llx.RawData{
		"__id":                  llx.StringData(a.Arn.Data + "/loginProfile"),
		"createdAt":             llx.TimeData(*date),
		"passwordResetRequired": llx.BoolData(profile.LoginProfile.PasswordResetRequired),
	})
	if err != nil {
		return nil, err
	}
	a.loginProfileCache = o.(*mqlAwsIamLoginProfile)
	a.loginProfileFetched.Store(true)
	return a.loginProfileCache, nil
}

// id returns the user-qualified cache key set at construction. This was
// previously named `init`, which the code generator never registers, so the
// resource had an empty __id and every user shared one login profile. Keying on
// the creation timestamp would also collide for users created in the same second.
func (a *mqlAwsIamLoginProfile) id() (string, error) {
	return a.__id, nil
}

func initAwsIamInstanceProfile(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn or id required to fetch aws iam instance profile")
	}
	var instanceProfileName string
	if args["arn"] != nil {
		a, err := arn.Parse(args["arn"].Value.(string))
		if err != nil {
			return nil, nil, err
		}
		// The ARN resource can include a path (e.g., "instance-profile/path/name").
		// GetInstanceProfile requires just the name, not the path.
		resource := strings.TrimPrefix(a.Resource, "instance-profile/")
		if idx := strings.LastIndex(resource, "/"); idx != -1 {
			instanceProfileName = resource[idx+1:]
		} else {
			instanceProfileName = resource
		}
	}

	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	if instanceProfileName != "" {
		resp, err := svc.GetInstanceProfile(ctx, &iam.GetInstanceProfileInput{
			InstanceProfileName: &instanceProfileName,
		})
		if err != nil {
			return nil, nil, err
		}

		if resp == nil || resp.InstanceProfile == nil {
			return nil, nil, fmt.Errorf("aws iam instance profile %q not found", instanceProfileName)
		}
		ip := resp.InstanceProfile
		res, err := CreateResource(runtime, ResourceAwsIamInstanceProfile, map[string]*llx.RawData{
			"arn":                 llx.StringDataPtr(ip.Arn),
			"createdAt":           llx.TimeDataPtr(ip.CreateDate),
			"instanceProfileId":   llx.StringDataPtr(ip.InstanceProfileId),
			"instanceProfileName": llx.StringDataPtr(ip.InstanceProfileName),
			"tags":                llx.MapData(iamTagsToMap(ip.Tags), types.String),
		})
		if err != nil {
			return nil, nil, err
		}
		res.(*mqlAwsIamInstanceProfile).rolesCache = ip.Roles
		return args, res, nil
	}
	return nil, nil, errors.New("arn required to fetch aws iam instance profile")
}

type mqlAwsIamSamlProviderInternal struct {
	listCreateDate *time.Time
	listValidUntil *time.Time
	details        *iam.GetSAMLProviderOutput
	lock           sync.Mutex
}

type mqlAwsIamOidcProviderInternal struct {
	details *iam.GetOpenIDConnectProviderOutput
	lock    sync.Mutex
}

func (a *mqlAwsIam) samlProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	// List all SAML providers
	listResp, err := svc.ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{})
	if err != nil {
		return nil, errors.Wrap(err, "could not gather aws iam saml providers")
	}

	// For each SAML provider, fetch detailed information
	for _, provider := range listResp.SAMLProviderList {
		if provider.Arn == nil {
			continue
		}

		mqlSamlProvider, err := CreateResource(a.MqlRuntime, ResourceAwsIamSamlProvider,
			map[string]*llx.RawData{
				"arn": llx.StringDataPtr(provider.Arn),
			})
		if err != nil {
			return nil, err
		}

		samlProvider := mqlSamlProvider.(*mqlAwsIamSamlProvider)
		samlProvider.listCreateDate = provider.CreateDate
		samlProvider.listValidUntil = provider.ValidUntil

		res = append(res, mqlSamlProvider)
	}

	return res, nil
}

func (a *mqlAwsIam) oidcProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	res := []any{}
	// List all OIDC providers
	listResp, err := svc.ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{})
	if err != nil {
		return nil, errors.Wrap(err, "could not gather aws iam oidc providers")
	}

	// Create resource with ARN only; details will be fetched on-demand
	for _, provider := range listResp.OpenIDConnectProviderList {
		if provider.Arn == nil {
			continue
		}

		mqlOidcProvider, err := CreateResource(a.MqlRuntime, ResourceAwsIamOidcProvider,
			map[string]*llx.RawData{
				"arn": llx.StringDataPtr(provider.Arn),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, mqlOidcProvider)
	}

	return res, nil
}

func (a *mqlAwsIamSamlProvider) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsIamSamlProvider) name() (string, error) {
	arnVal := a.Arn.Data
	if arnVal == "" {
		return "", errors.New("arn is empty")
	}

	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return "", err
	}

	return strings.TrimPrefix(parsed.Resource, "saml-provider/"), nil
}

func (a *mqlAwsIamSamlProvider) createdAt() (*time.Time, error) {
	if a.listCreateDate != nil {
		return a.listCreateDate, nil
	}

	details, err := a.fetchSamlProviderDetails()
	if err != nil {
		return nil, err
	}

	return details.CreateDate, nil
}

func (a *mqlAwsIamSamlProvider) validUntil() (*time.Time, error) {
	if a.listValidUntil != nil {
		return a.listValidUntil, nil
	}

	details, err := a.fetchSamlProviderDetails()
	if err != nil {
		return nil, err
	}

	return details.ValidUntil, nil
}

func (a *mqlAwsIamSamlProvider) metadataDocument() (string, error) {
	details, err := a.fetchSamlProviderDetails()
	if err != nil {
		return "", err
	}

	return convert.ToValue(details.SAMLMetadataDocument), nil
}

func (a *mqlAwsIamSamlProvider) tags() (map[string]any, error) {
	details, err := a.fetchSamlProviderDetails()
	if err != nil {
		return nil, err
	}

	return iamTagsToMap(details.Tags), nil
}

func (a *mqlAwsIamOidcProvider) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsIamOidcProvider) url() (string, error) {
	details, err := a.fetchOidcProviderDetails()
	if err != nil {
		return "", err
	}

	return convert.ToValue(details.Url), nil
}

func (a *mqlAwsIamOidcProvider) clientIds() ([]any, error) {
	details, err := a.fetchOidcProviderDetails()
	if err != nil {
		return nil, err
	}

	return convert.SliceAnyToInterface(details.ClientIDList), nil
}

func (a *mqlAwsIamOidcProvider) thumbprints() ([]any, error) {
	details, err := a.fetchOidcProviderDetails()
	if err != nil {
		return nil, err
	}

	return convert.SliceAnyToInterface(details.ThumbprintList), nil
}

func (a *mqlAwsIamOidcProvider) createdAt() (*time.Time, error) {
	details, err := a.fetchOidcProviderDetails()
	if err != nil {
		return nil, err
	}

	return details.CreateDate, nil
}

func (a *mqlAwsIamOidcProvider) tags() (map[string]any, error) {
	details, err := a.fetchOidcProviderDetails()
	if err != nil {
		return nil, err
	}

	return iamTagsToMap(details.Tags), nil
}

func (a *mqlAwsIamOidcProvider) fetchOidcProviderDetails() (*iam.GetOpenIDConnectProviderOutput, error) {
	if a.details != nil {
		return a.details, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.details != nil {
		return a.details, nil
	}

	arnVal := a.Arn.Data
	if arnVal == "" {
		return nil, errors.New("arn is empty")
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	resp, err := svc.GetOpenIDConnectProvider(ctx, &iam.GetOpenIDConnectProviderInput{
		OpenIDConnectProviderArn: &arnVal,
	})
	if err != nil {
		return nil, err
	}

	a.details = resp

	return resp, nil
}

func (a *mqlAwsIamSamlProvider) fetchSamlProviderDetails() (*iam.GetSAMLProviderOutput, error) {
	if a.details != nil {
		return a.details, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.details != nil {
		return a.details, nil
	}

	arnVal := a.Arn.Data
	if arnVal == "" {
		return nil, errors.New("arn is empty")
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Iam("")
	ctx := context.Background()

	resp, err := svc.GetSAMLProvider(ctx, &iam.GetSAMLProviderInput{
		SAMLProviderArn: &arnVal,
	})
	if err != nil {
		return nil, err
	}

	a.details = resp
	if a.listCreateDate == nil {
		a.listCreateDate = resp.CreateDate
	}
	if a.listValidUntil == nil {
		a.listValidUntil = resp.ValidUntil
	}

	return resp, nil
}
