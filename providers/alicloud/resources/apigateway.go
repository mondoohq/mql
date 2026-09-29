// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	cloudapiclient "github.com/alibabacloud-go/cloudapi-20160714/v5/client"
	tea "github.com/alibabacloud-go/tea/tea"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

const (
	// apiGatewayGroupPageSize is the largest page DescribeApiGroups accepts.
	apiGatewayGroupPageSize = 50
	// apiGatewayApiPageSize is the largest page DescribeApis accepts.
	apiGatewayApiPageSize = 100
)

func (r *mqlAlicloudApigateway) id() (string, error) {
	return "alicloud.apigateway", nil
}

func (r *mqlAlicloudApigateway) groups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.ApiGatewayClient(region)
		if err != nil {
			return nil, err
		}

		page := int32(1)
		for {
			resp, err := client.DescribeApiGroups(&cloudapiclient.DescribeApiGroupsRequest{
				PageNumber: tea.Int32(page),
				PageSize:   tea.Int32(apiGatewayGroupPageSize),
			})
			if err != nil {
				// A first-page error is a region the credential cannot read, or
				// one without API Gateway; keep the other regions. A later-page
				// error is real, so surface it rather than truncating the list.
				if page == 1 {
					logSkippedRegion(err, "API Gateway", region)
					break
				}
				return nil, classifyAlicloudError(err, "apigateway:DescribeApiGroups")
			}
			if resp == nil || resp.Body == nil || resp.Body.ApiGroupAttributes == nil {
				break
			}
			items := resp.Body.ApiGroupAttributes.ApiGroupAttribute
			for _, g := range items {
				if g == nil || tea.StringValue(g.GroupId) == "" {
					continue
				}
				group, err := newApiGatewayGroup(r.MqlRuntime, region, g)
				if err != nil {
					return nil, err
				}
				res = append(res, group)
			}
			if ecsPageDone(len(items), page, apiGatewayGroupPageSize, resp.Body.TotalCount) {
				break
			}
			page++
		}
	}
	return res, nil
}

func newApiGatewayGroup(runtime *plugin.Runtime, region string, g *cloudapiclient.DescribeApiGroupsResponseBodyApiGroupAttributesApiGroupAttribute) (*mqlAlicloudApigatewayGroup, error) {
	tags := map[string]any{}
	if g.Tags != nil {
		for _, t := range g.Tags.TagInfo {
			if t == nil || tea.StringValue(t.Key) == "" {
				continue
			}
			tags[tea.StringValue(t.Key)] = tea.StringValue(t.Value)
		}
	}
	res, err := CreateResource(runtime, "alicloud.apigateway.group", map[string]*llx.RawData{
		"__id":          llx.StringData(region + "/" + tea.StringValue(g.GroupId)),
		"regionId":      llx.StringData(region),
		"groupId":       llx.StringDataPtr(g.GroupId),
		"groupName":     llx.StringDataPtr(g.GroupName),
		"description":   llx.StringDataPtr(g.Description),
		"basePath":      llx.StringDataPtr(g.BasePath),
		"httpsPolicy":   llx.StringDataPtr(g.HttpsPolicy),
		"subDomain":     llx.StringDataPtr(g.SubDomain),
		"instanceId":    llx.StringDataPtr(g.InstanceId),
		"instanceType":  llx.StringDataPtr(g.InstanceType),
		"trafficLimit":  llx.IntDataPtr(g.TrafficLimit),
		"illegalStatus": llx.StringDataPtr(g.IllegalStatus),
		"billingStatus": llx.StringDataPtr(g.BillingStatus),
		"createdTime":   llx.TimeDataPtr(parseAlicloudTime(g.CreatedTime)),
		"modifiedTime":  llx.TimeDataPtr(parseAlicloudTime(g.ModifiedTime)),
		"tags":          llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudApigatewayGroup), nil
}

// mqlAlicloudApigatewayGroupInternal memoizes the group detail, which carries
// the status, domain, and custom domain fields the listing omits.
type mqlAlicloudApigatewayGroupInternal struct {
	detailLock    sync.Mutex
	detailFetched bool
	detail        *cloudapiclient.DescribeApiGroupResponseBody
}

func (r *mqlAlicloudApigatewayGroup) id() (string, error) {
	return r.RegionId.Data + "/" + r.GroupId.Data, nil
}

// detailFor loads the group detail once. An error is not memoized, so a later
// access retries.
func (r *mqlAlicloudApigatewayGroup) detailFor() (*cloudapiclient.DescribeApiGroupResponseBody, error) {
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched {
		return r.detail, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ApiGatewayClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeApiGroup(&cloudapiclient.DescribeApiGroupRequest{
		GroupId: tea.String(r.GroupId.Data),
	})
	if err != nil {
		return nil, classifyAlicloudError(err, "apigateway:DescribeApiGroup")
	}
	if resp != nil {
		r.detail = resp.Body
	}
	r.detailFetched = true
	return r.detail, nil
}

func (r *mqlAlicloudApigatewayGroup) status() (string, error) {
	d, err := r.detailFor()
	if err != nil {
		return "", err
	}
	if d == nil || d.Status == nil {
		r.Status.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *d.Status, nil
}

func (r *mqlAlicloudApigatewayGroup) vpcDomain() (string, error) {
	d, err := r.detailFor()
	if err != nil {
		return "", err
	}
	if d == nil || d.VpcDomain == nil {
		r.VpcDomain.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *d.VpcDomain, nil
}

func (r *mqlAlicloudApigatewayGroup) innerDomainDisabled() (bool, error) {
	d, err := r.detailFor()
	if err != nil {
		return false, err
	}
	if d == nil || d.DisableInnerDomain == nil {
		r.InnerDomainDisabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *d.DisableInnerDomain, nil
}

func (r *mqlAlicloudApigatewayGroup) customDomains() ([]any, error) {
	d, err := r.detailFor()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if d == nil || d.CustomDomains == nil {
		return res, nil
	}
	for _, item := range d.CustomDomains.DomainItem {
		if item == nil || tea.StringValue(item.DomainName) == "" {
			continue
		}
		// The certificate body and private key are never part of this
		// response; only the certificate's name and validity window are read.
		domain, err := CreateResource(r.MqlRuntime, "alicloud.apigateway.customDomain", map[string]*llx.RawData{
			"__id":                  llx.StringData(r.RegionId.Data + "/" + r.GroupId.Data + "/" + tea.StringValue(item.DomainName)),
			"domainName":            llx.StringDataPtr(item.DomainName),
			"domainType":            llx.StringDataPtr(item.CustomDomainType),
			"bindingStatus":         llx.StringDataPtr(item.DomainBindingStatus),
			"stageName":             llx.StringDataPtr(item.BindStageName),
			"certificateName":       llx.StringDataPtr(item.CertificateName),
			"certificateValidFrom":  llx.TimeDataPtr(epochAuto(item.CertificateValidStart)),
			"certificateValidUntil": llx.TimeDataPtr(epochAuto(item.CertificateValidEnd)),
			"httpRedirectToHttps":   llx.BoolData(tea.BoolValue(item.IsHttpRedirectToHttps)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, domain)
	}
	return res, nil
}

func (r *mqlAlicloudApigatewayGroup) apis() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ApiGatewayClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}

	res := []any{}
	page := int32(1)
	for {
		resp, err := client.DescribeApis(&cloudapiclient.DescribeApisRequest{
			GroupId:    tea.String(r.GroupId.Data),
			PageNumber: tea.Int32(page),
			PageSize:   tea.Int32(apiGatewayApiPageSize),
		})
		if err != nil {
			return nil, classifyAlicloudError(err, "apigateway:DescribeApis")
		}
		if resp == nil || resp.Body == nil || resp.Body.ApiSummarys == nil {
			break
		}
		items := resp.Body.ApiSummarys.ApiSummary
		for _, a := range items {
			if a == nil || tea.StringValue(a.ApiId) == "" {
				continue
			}
			var deployed []*cloudapiclient.DescribeApisResponseBodyApiSummarysApiSummaryDeployedInfosDeployedInfo
			if a.DeployedInfos != nil {
				deployed = a.DeployedInfos.DeployedInfo
			}
			resource, err := CreateResource(r.MqlRuntime, "alicloud.apigateway.api", map[string]*llx.RawData{
				"__id":           llx.StringData(r.RegionId.Data + "/" + r.GroupId.Data + "/" + tea.StringValue(a.ApiId)),
				"regionId":       llx.StringData(r.RegionId.Data),
				"apiId":          llx.StringDataPtr(a.ApiId),
				"apiName":        llx.StringDataPtr(a.ApiName),
				"description":    llx.StringDataPtr(a.Description),
				"apiMethod":      llx.StringDataPtr(a.ApiMethod),
				"apiPath":        llx.StringDataPtr(a.ApiPath),
				"visibility":     llx.StringDataPtr(a.Visibility),
				"deployedStages": llx.ArrayData(apiGatewayDeployedStages(deployed), types.String),
				"createdTime":    llx.TimeDataPtr(parseAlicloudTime(a.CreatedTime)),
				"modifiedTime":   llx.TimeDataPtr(parseAlicloudTime(a.ModifiedTime)),
			})
			if err != nil {
				return nil, err
			}
			api := resource.(*mqlAlicloudApigatewayApi)
			api.parentGroup = r
			res = append(res, api)
		}
		if ecsPageDone(len(items), page, apiGatewayApiPageSize, resp.Body.TotalCount) {
			break
		}
		page++
	}
	return res, nil
}

// apiGatewayDeployedStages lists the stages an API is currently deployed to.
// The listing also reports stages the API was taken off, so only entries whose
// status is DEPLOYED count.
func apiGatewayDeployedStages(infos []*cloudapiclient.DescribeApisResponseBodyApiSummarysApiSummaryDeployedInfosDeployedInfo) []any {
	res := []any{}
	for _, info := range infos {
		if info == nil || tea.StringValue(info.StageName) == "" {
			continue
		}
		if !strings.EqualFold(tea.StringValue(info.DeployedStatus), "DEPLOYED") {
			continue
		}
		res = append(res, tea.StringValue(info.StageName))
	}
	return res
}

// mqlAlicloudApigatewayApiInternal holds the group the API was listed from and
// memoizes the API definition, which is where the authentication and network
// settings live.
type mqlAlicloudApigatewayApiInternal struct {
	parentGroup *mqlAlicloudApigatewayGroup

	detailLock    sync.Mutex
	detailFetched bool
	detail        *cloudapiclient.DescribeApiResponseBody
}

func (r *mqlAlicloudApigatewayApi) group() (*mqlAlicloudApigatewayGroup, error) {
	if r.parentGroup == nil {
		r.Group.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.parentGroup, nil
}

// detailFor loads the API definition once. Only the authentication, protocol,
// and backend-kind settings are read from it: constant and service parameters
// can carry backend credentials and are never exposed. An error is not
// memoized, so a later access retries.
func (r *mqlAlicloudApigatewayApi) detailFor() (*cloudapiclient.DescribeApiResponseBody, error) {
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched {
		return r.detail, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.ApiGatewayClient(r.RegionId.Data)
	if err != nil {
		return nil, err
	}
	req := &cloudapiclient.DescribeApiRequest{ApiId: tea.String(r.ApiId.Data)}
	if r.parentGroup != nil {
		req.GroupId = tea.String(r.parentGroup.GroupId.Data)
	}
	resp, err := client.DescribeApi(req)
	if err != nil {
		return nil, classifyAlicloudError(err, "apigateway:DescribeApi")
	}
	if resp != nil {
		r.detail = resp.Body
	}
	r.detailFetched = true
	return r.detail, nil
}

func (r *mqlAlicloudApigatewayApi) authType() (string, error) {
	d, err := r.detailFor()
	if err != nil {
		return "", err
	}
	if d == nil || d.AuthType == nil {
		r.AuthType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *d.AuthType, nil
}

func (r *mqlAlicloudApigatewayApi) appCodeAuthType() (string, error) {
	d, err := r.detailFor()
	if err != nil {
		return "", err
	}
	if d == nil || d.AppCodeAuthType == nil {
		r.AppCodeAuthType.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *d.AppCodeAuthType, nil
}

func (r *mqlAlicloudApigatewayApi) allowSignatureMethod() (string, error) {
	d, err := r.detailFor()
	if err != nil {
		return "", err
	}
	if d == nil || d.AllowSignatureMethod == nil {
		r.AllowSignatureMethod.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *d.AllowSignatureMethod, nil
}

func (r *mqlAlicloudApigatewayApi) forceNonceCheck() (bool, error) {
	d, err := r.detailFor()
	if err != nil {
		return false, err
	}
	if d == nil || d.ForceNonceCheck == nil {
		r.ForceNonceCheck.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *d.ForceNonceCheck, nil
}

func (r *mqlAlicloudApigatewayApi) internetDisabled() (bool, error) {
	d, err := r.detailFor()
	if err != nil {
		return false, err
	}
	if d == nil || d.DisableInternet == nil {
		r.InternetDisabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *d.DisableInternet, nil
}

func (r *mqlAlicloudApigatewayApi) requestProtocol() (string, error) {
	d, err := r.detailFor()
	if err != nil {
		return "", err
	}
	if d == nil || d.RequestConfig == nil || d.RequestConfig.RequestProtocol == nil {
		r.RequestProtocol.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *d.RequestConfig.RequestProtocol, nil
}

func (r *mqlAlicloudApigatewayApi) backendProtocol() (string, error) {
	d, err := r.detailFor()
	if err != nil {
		return "", err
	}
	if d == nil || d.ServiceConfig == nil || d.ServiceConfig.ServiceProtocol == nil {
		r.BackendProtocol.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *d.ServiceConfig.ServiceProtocol, nil
}

// apiGatewayFlag reads one of the API Gateway settings the API returns as the
// string TRUE or FALSE. A missing or unrecognized value yields nil.
func apiGatewayFlag(v *string) *bool {
	if v == nil {
		return nil
	}
	switch strings.ToUpper(strings.TrimSpace(*v)) {
	case "TRUE":
		b := true
		return &b
	case "FALSE":
		b := false
		return &b
	}
	return nil
}

func (r *mqlAlicloudApigatewayApi) backendVpcEnabled() (bool, error) {
	d, err := r.detailFor()
	if err != nil {
		return false, err
	}
	var flag *bool
	if d != nil && d.ServiceConfig != nil {
		flag = apiGatewayFlag(d.ServiceConfig.ServiceVpcEnable)
	}
	if flag == nil {
		r.BackendVpcEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *flag, nil
}
