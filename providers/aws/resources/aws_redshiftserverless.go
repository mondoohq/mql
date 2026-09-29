// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsRedshiftserverless) id() (string, error) {
	return "aws.redshiftserverless", nil
}

// --- workgroups ---

func (a *mqlAwsRedshiftserverless) workgroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "redshiftserverless", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.RedshiftServerless(region)
		res := []any{}
		paginator := redshiftserverless.NewListWorkgroupsPaginator(svc, &redshiftserverless.ListWorkgroupsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, wg := range page.Workgroups {
				mqlWg, err := newMqlRedshiftServerlessWorkgroup(a.MqlRuntime, conn.AccountId(), region, wg)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlWg)
			}
		}
		return res, nil
	})
}

// redshiftServerlessConfigParameters keys the workgroup configuration
// parameters by name.
func redshiftServerlessConfigParameters(params []rsstypes.ConfigParameter) map[string]any {
	res := make(map[string]any, len(params))
	for _, p := range params {
		if p.ParameterKey == nil {
			continue
		}
		res[*p.ParameterKey] = convert.ToValue(p.ParameterValue)
	}
	return res
}

func newMqlRedshiftServerlessWorkgroup(runtime *plugin.Runtime, accountID, region string, wg rsstypes.Workgroup) (*mqlAwsRedshiftserverlessWorkgroup, error) {
	var endpointAddress *string
	var port *int32 = wg.Port
	if wg.Endpoint != nil {
		endpointAddress = wg.Endpoint.Address
		if wg.Endpoint.Port != nil {
			port = wg.Endpoint.Port
		}
	}
	crossAccountVpcs := make([]any, 0, len(wg.CrossAccountVpcs))
	for _, v := range wg.CrossAccountVpcs {
		crossAccountVpcs = append(crossAccountVpcs, v)
	}

	res, err := CreateResource(runtime, ResourceAwsRedshiftserverlessWorkgroup, map[string]*llx.RawData{
		"__id":                             llx.StringDataPtr(wg.WorkgroupArn),
		"arn":                              llx.StringDataPtr(wg.WorkgroupArn),
		"id":                               llx.StringDataPtr(wg.WorkgroupId),
		"name":                             llx.StringDataPtr(wg.WorkgroupName),
		"region":                           llx.StringData(region),
		"status":                           llx.StringDataPtr(nonEmptyEnum(wg.Status)),
		"publiclyAccessible":               llx.BoolDataPtr(wg.PubliclyAccessible),
		"enhancedVpcRouting":               llx.BoolDataPtr(wg.EnhancedVpcRouting),
		"endpointAddress":                  llx.StringDataPtr(endpointAddress),
		"port":                             llx.IntDataPtr(port),
		"configParameters":                 llx.MapData(redshiftServerlessConfigParameters(wg.ConfigParameters), types.String),
		"baseCapacity":                     llx.IntDataPtr(wg.BaseCapacity),
		"maxCapacity":                      llx.IntDataPtr(wg.MaxCapacity),
		"crossAccountVpcIds":               llx.ArrayData(crossAccountVpcs, types.String),
		"customDomainName":                 llx.StringDataPtr(wg.CustomDomainName),
		"customDomainCertificateExpiresAt": llx.TimeDataPtr(wg.CustomDomainCertificateExpiryTime),
		"ipAddressType":                    llx.StringDataPtr(wg.IpAddressType),
		"trackName":                        llx.StringDataPtr(wg.TrackName),
		"workgroupVersion":                 llx.StringDataPtr(wg.WorkgroupVersion),
		"patchVersion":                     llx.StringDataPtr(wg.PatchVersion),
		"createdAt":                        llx.TimeDataPtr(wg.CreationDate),
	})
	if err != nil {
		return nil, err
	}
	mqlWg := res.(*mqlAwsRedshiftserverlessWorkgroup)
	mqlWg.cacheNamespaceName = convert.ToValue(wg.NamespaceName)
	mqlWg.cacheSubnetIds = wg.SubnetIds
	mqlWg.cacheCertificateArn = convert.ToValue(wg.CustomDomainCertificateArn)
	sgArns := make([]string, 0, len(wg.SecurityGroupIds))
	for _, sg := range wg.SecurityGroupIds {
		sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sg))
	}
	mqlWg.setSecurityGroupArns(sgArns)
	return mqlWg, nil
}

type mqlAwsRedshiftserverlessWorkgroupInternal struct {
	securityGroupIdHandler
	cacheNamespaceName  string
	cacheSubnetIds      []string
	cacheCertificateArn string
}

func (a *mqlAwsRedshiftserverlessWorkgroup) id() (string, error) {
	return a.Arn.Data, nil
}

// namespace resolves the workgroup's namespace from the namespace list, which
// is read once for all workgroups rather than once per workgroup.
func (a *mqlAwsRedshiftserverlessWorkgroup) namespace() (*mqlAwsRedshiftserverlessNamespace, error) {
	if a.cacheNamespaceName == "" {
		a.Namespace.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	obj, err := CreateResource(a.MqlRuntime, ResourceAwsRedshiftserverless, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	namespaces := obj.(*mqlAwsRedshiftserverless).GetNamespaces()
	if namespaces.Error != nil {
		return nil, namespaces.Error
	}
	for _, raw := range namespaces.Data {
		ns := raw.(*mqlAwsRedshiftserverlessNamespace)
		if ns.Name.Data == a.cacheNamespaceName && ns.Region.Data == a.Region.Data {
			return ns, nil
		}
	}
	a.Namespace.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsRedshiftserverlessWorkgroup) subnets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, subnetID := range a.cacheSubnetIds {
		if subnetID == "" {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.Region.Data, conn.AccountId(), subnetID)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsRedshiftserverlessWorkgroup) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsRedshiftserverlessWorkgroup) customDomainCertificate() (*mqlAwsAcmCertificate, error) {
	if a.cacheCertificateArn == "" {
		a.CustomDomainCertificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate, map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheCertificateArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsRedshiftserverlessWorkgroup) tags() (map[string]any, error) {
	return redshiftServerlessTags(a.MqlRuntime, a.Region.Data, a.Arn.Data, &a.Tags)
}

func redshiftServerlessTags(runtime *plugin.Runtime, region, resourceArn string, field *plugin.TValue[map[string]any]) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.RedshiftServerless(region)
	out, err := svc.ListTagsForResource(context.Background(), &redshiftserverless.ListTagsForResourceInput{
		ResourceArn: &resourceArn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				field.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("redshift-serverless:ListTagsForResource"))
		}
		return nil, err
	}
	res := map[string]any{}
	for _, t := range out.Tags {
		if t.Key != nil {
			res[*t.Key] = convert.ToValue(t.Value)
		}
	}
	return res, nil
}

// --- namespaces ---

func (a *mqlAwsRedshiftserverless) namespaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "redshiftserverless", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.RedshiftServerless(region)
		res := []any{}
		paginator := redshiftserverless.NewListNamespacesPaginator(svc, &redshiftserverless.ListNamespacesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, ns := range page.Namespaces {
				mqlNs, err := newMqlRedshiftServerlessNamespace(a.MqlRuntime, region, ns)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlNs)
			}
		}
		return res, nil
	})
}

func newMqlRedshiftServerlessNamespace(runtime *plugin.Runtime, region string, ns rsstypes.Namespace) (*mqlAwsRedshiftserverlessNamespace, error) {
	logExports := make([]any, 0, len(ns.LogExports))
	for _, l := range ns.LogExports {
		logExports = append(logExports, string(l))
	}
	res, err := CreateResource(runtime, ResourceAwsRedshiftserverlessNamespace, map[string]*llx.RawData{
		"__id":          llx.StringDataPtr(ns.NamespaceArn),
		"arn":           llx.StringDataPtr(ns.NamespaceArn),
		"id":            llx.StringDataPtr(ns.NamespaceId),
		"name":          llx.StringDataPtr(ns.NamespaceName),
		"region":        llx.StringData(region),
		"status":        llx.StringDataPtr(nonEmptyEnum(ns.Status)),
		"dbName":        llx.StringDataPtr(ns.DbName),
		"adminUsername": llx.StringDataPtr(ns.AdminUsername),
		"logExports":    llx.ArrayData(logExports, types.String),
		"createdAt":     llx.TimeDataPtr(ns.CreationDate),
	})
	if err != nil {
		return nil, err
	}
	mqlNs := res.(*mqlAwsRedshiftserverlessNamespace)
	mqlNs.cacheKmsKeyId = redshiftServerlessKmsKeyRef(ns.KmsKeyId)
	mqlNs.cacheAdminSecretArn = convert.ToValue(ns.AdminPasswordSecretArn)
	mqlNs.cacheAdminSecretKmsKeyId = redshiftServerlessKmsKeyRef(ns.AdminPasswordSecretKmsKeyId)
	mqlNs.cacheDefaultIamRoleArn = convert.ToValue(ns.DefaultIamRoleArn)
	mqlNs.cacheIamRoleArns = redshiftServerlessIamRoleArns(ns.IamRoles)
	return mqlNs, nil
}

type mqlAwsRedshiftserverlessNamespaceInternal struct {
	cacheKmsKeyId            *string
	cacheAdminSecretArn      string
	cacheAdminSecretKmsKeyId *string
	cacheDefaultIamRoleArn   string
	cacheIamRoleArns         []string
}

func (a *mqlAwsRedshiftserverlessNamespace) id() (string, error) {
	return a.Arn.Data, nil
}

// redshiftServerlessKmsKeyRef returns the key reference of a namespace, or
// nil when the namespace uses an AWS owned key, which the service reports by
// the name AWS_OWNED_KMS_KEY rather than by a key ID.
func redshiftServerlessKmsKeyRef(v *string) *string {
	if v == nil || *v == "" || *v == "AWS_OWNED_KMS_KEY" {
		return nil
	}
	return v
}

var redshiftServerlessIamRoleArnRe = regexp.MustCompile(`iamRoleArn=(arn:[^,)\s]+)`)

// redshiftServerlessIamRoleArns extracts role ARNs from the namespace's
// iamRoles list. The service reports each role either as a bare ARN or
// wrapped as `IamRole(applyStatus=in-sync, iamRoleArn=arn:...)`.
func redshiftServerlessIamRoleArns(roles []string) []string {
	res := make([]string, 0, len(roles))
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if strings.HasPrefix(r, "arn:") {
			res = append(res, r)
			continue
		}
		if m := redshiftServerlessIamRoleArnRe.FindStringSubmatch(r); m != nil {
			res = append(res, m[1])
		}
	}
	return res
}

func (a *mqlAwsRedshiftserverlessNamespace) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheKmsKeyId, a.Region.Data, &a.KmsKey.State)
}

func (a *mqlAwsRedshiftserverlessNamespace) adminPasswordSecretKmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheAdminSecretKmsKeyId, a.Region.Data, &a.AdminPasswordSecretKmsKey.State)
}

func (a *mqlAwsRedshiftserverlessNamespace) adminPasswordSecret() (*mqlAwsSecretsmanagerSecret, error) {
	if a.cacheAdminSecretArn == "" {
		a.AdminPasswordSecret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsSecretsmanagerSecret, map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheAdminSecretArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

func (a *mqlAwsRedshiftserverlessNamespace) iamRoles() ([]any, error) {
	res := []any{}
	for _, roleArn := range a.cacheIamRoleArns {
		role, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{
			"arn": llx.StringData(roleArn),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, role)
	}
	return res, nil
}

func (a *mqlAwsRedshiftserverlessNamespace) defaultIamRole() (*mqlAwsIamRole, error) {
	if a.cacheDefaultIamRoleArn == "" {
		a.DefaultIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsIamRole, map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheDefaultIamRoleArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsRedshiftserverlessNamespace) tags() (map[string]any, error) {
	return redshiftServerlessTags(a.MqlRuntime, a.Region.Data, a.Arn.Data, &a.Tags)
}
