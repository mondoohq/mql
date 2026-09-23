// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/vpclattice"
	vpclatticetypes "github.com/aws/aws-sdk-go-v2/service/vpclattice/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsVpclattice) id() (string, error) {
	return "aws.vpclattice", nil
}

func (a *mqlAwsVpclatticeServiceNetwork) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsVpclatticeServiceNetworkVpcAssociation) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsVpclatticeService) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsVpclatticeListener) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsVpclatticeTargetGroup) id() (string, error) {
	return a.Arn.Data, nil
}

// vpcLatticeRegionalSkip reports whether a regional error means the region has
// nothing to say, rather than a real failure. VPC Lattice is not available in
// every region.
func vpcLatticeRegionalSkip(err error, region string) bool {
	if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
		log.Debug().Str("region", region).Msg("skipping vpc lattice for region")
		return true
	}
	return false
}

func (a *mqlAwsVpclattice) serviceNetworks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getServiceNetworks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsVpclattice) getServiceNetworks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.VpcLattice(region)
			ctx := context.Background()
			res := []any{}
			paginator := vpclattice.NewListServiceNetworksPaginator(svc, &vpclattice.ListServiceNetworksInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if vpcLatticeRegionalSkip(err, region) {
						return res, nil
					}
					return nil, err
				}
				for _, sn := range page.Items {
					mqlSn, err := CreateResource(a.MqlRuntime, ResourceAwsVpclatticeServiceNetwork,
						map[string]*llx.RawData{
							"arn":                        llx.StringDataPtr(sn.Arn),
							"id":                         llx.StringDataPtr(sn.Id),
							"name":                       llx.StringDataPtr(sn.Name),
							"region":                     llx.StringData(region),
							"numberOfAssociatedServices": llx.IntDataDefault(sn.NumberOfAssociatedServices, 0),
							"numberOfAssociatedVpcs":     llx.IntDataDefault(sn.NumberOfAssociatedVPCs, 0),
							"createdAt":                  llx.TimeDataPtr(sn.CreatedAt),
							"lastUpdatedAt":              llx.TimeDataPtr(sn.LastUpdatedAt),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSn)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsVpclatticeServiceNetworkInternal struct {
	detailOnce sync.Once
	detail     *vpclattice.GetServiceNetworkOutput
	detailErr  error
}

// networkDetail fetches GetServiceNetwork once and shares it. Only authType is
// read from it today, but the list response carries none of that call's fields,
// so any second one (sharingConfig, for instance) would otherwise cost another
// round trip per service network.
func (a *mqlAwsVpclatticeServiceNetwork) networkDetail() (*vpclattice.GetServiceNetworkOutput, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.VpcLattice(a.Region.Data)
		resp, err := svc.GetServiceNetwork(context.Background(), &vpclattice.GetServiceNetworkInput{
			ServiceNetworkIdentifier: &a.Id.Data,
		})
		if err != nil {
			a.detailErr = classifyAwsError(err, "vpc-lattice:GetServiceNetwork")
			return
		}
		a.detail = resp
	})
	return a.detail, a.detailErr
}

// authType decides whether callers of the service network are authenticated at
// all, and the list response does not carry it.
func (a *mqlAwsVpclatticeServiceNetwork) authType() (string, error) {
	detail, err := a.networkDetail()
	if err != nil {
		return "", err
	}
	return string(detail.AuthType), nil
}

// authPolicy returns the raw auth policy document. A service network with no
// auth policy returns an empty string rather than an error: having none is a
// normal state, and it is the answer the caller is asking for.
func (a *mqlAwsVpclatticeServiceNetwork) authPolicy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.VpcLattice(a.Region.Data)
	return vpcLatticeAuthPolicy(svc, a.Arn.Data)
}

func (a *mqlAwsVpclatticeServiceNetwork) authPolicyStatements() ([]any, error) {
	policy := a.GetAuthPolicy()
	if policy.Error != nil {
		return nil, policy.Error
	}
	return newPolicyStatementResources(a.MqlRuntime, a.Arn.Data+"/authPolicy", policy.Data)
}

func (a *mqlAwsVpclatticeServiceNetwork) hasWildcardAuthPolicy() (bool, error) {
	statements := a.GetAuthPolicyStatements()
	if statements.Error != nil {
		return false, statements.Error
	}
	return statementsAllowWildcard(statements.Data)
}

// vpcLatticeAuthPolicy fetches an auth policy document for a service network or
// service. Having no auth policy is a normal state that the API reports as
// ResourceNotFoundException, so that is returned as an empty document rather
// than an error: "no policy" is the answer the caller is asking for.
func vpcLatticeAuthPolicy(svc *vpclattice.Client, resourceArn string) (string, error) {
	resp, err := svc.GetAuthPolicy(context.Background(), &vpclattice.GetAuthPolicyInput{
		ResourceIdentifier: &resourceArn,
	})
	if err != nil {
		var notFound *vpclatticetypes.ResourceNotFoundException
		if errors.As(err, &notFound) {
			return "", nil
		}
		return "", classifyAwsError(err, "vpc-lattice:GetAuthPolicy")
	}
	return convert.ToValue(resp.Policy), nil
}

func (a *mqlAwsVpclatticeServiceNetwork) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return vpcLatticeTags(conn.VpcLattice(a.Region.Data), a.Arn.Data)
}

// vpcLatticeTags lists the tags on a VPC Lattice resource.
func vpcLatticeTags(svc *vpclattice.Client, resourceArn string) (map[string]any, error) {
	resp, err := svc.ListTagsForResource(context.Background(), &vpclattice.ListTagsForResourceInput{
		ResourceArn: &resourceArn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "vpc-lattice:ListTagsForResource")
	}
	tags := map[string]any{}
	for k, v := range resp.Tags {
		tags[k] = v
	}
	return tags, nil
}

func (a *mqlAwsVpclatticeServiceNetwork) vpcAssociations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.VpcLattice(a.Region.Data)
	ctx := context.Background()

	res := []any{}
	paginator := vpclattice.NewListServiceNetworkVpcAssociationsPaginator(svc,
		&vpclattice.ListServiceNetworkVpcAssociationsInput{ServiceNetworkIdentifier: &a.Id.Data})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "vpc-lattice:ListServiceNetworkVpcAssociations")
		}
		for _, assoc := range page.Items {
			mqlAssoc, err := CreateResource(a.MqlRuntime, ResourceAwsVpclatticeServiceNetworkVpcAssociation,
				map[string]*llx.RawData{
					"arn":               llx.StringDataPtr(assoc.Arn),
					"id":                llx.StringDataPtr(assoc.Id),
					"status":            llx.StringData(string(assoc.Status)),
					"createdBy":         llx.StringDataPtr(assoc.CreatedBy),
					"privateDnsEnabled": llx.BoolDataPtr(assoc.PrivateDnsEnabled),
					"createdAt":         llx.TimeDataPtr(assoc.CreatedAt),
				})
			if err != nil {
				return nil, err
			}
			mqlAssoc.(*mqlAwsVpclatticeServiceNetworkVpcAssociation).cacheVpcId = convert.ToValue(assoc.VpcId)
			res = append(res, mqlAssoc)
		}
	}
	return res, nil
}

type mqlAwsVpclatticeServiceNetworkVpcAssociationInternal struct {
	cacheVpcId string
}

func (a *mqlAwsVpclatticeServiceNetworkVpcAssociation) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpc,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheVpcId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsVpclattice) services() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getServices(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsVpclattice) getServices(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.VpcLattice(region)
			ctx := context.Background()
			res := []any{}
			paginator := vpclattice.NewListServicesPaginator(svc, &vpclattice.ListServicesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if vpcLatticeRegionalSkip(err, region) {
						return res, nil
					}
					return nil, err
				}
				for _, s := range page.Items {
					mqlSvc, err := CreateResource(a.MqlRuntime, ResourceAwsVpclatticeService,
						map[string]*llx.RawData{
							"arn":           llx.StringDataPtr(s.Arn),
							"id":            llx.StringDataPtr(s.Id),
							"name":          llx.StringDataPtr(s.Name),
							"region":        llx.StringData(region),
							"status":        llx.StringData(string(s.Status)),
							"createdAt":     llx.TimeDataPtr(s.CreatedAt),
							"lastUpdatedAt": llx.TimeDataPtr(s.LastUpdatedAt),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSvc)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsVpclatticeServiceInternal struct {
	detailOnce sync.Once
	detail     *vpclattice.GetServiceOutput
	detailErr  error
}

// serviceDetail fetches GetService once and shares it, since authType, the
// custom domain, the DNS entry, and the certificate all come from that one call.
func (a *mqlAwsVpclatticeService) serviceDetail() (*vpclattice.GetServiceOutput, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.VpcLattice(a.Region.Data)
		resp, err := svc.GetService(context.Background(), &vpclattice.GetServiceInput{
			ServiceIdentifier: &a.Id.Data,
		})
		if err != nil {
			a.detailErr = classifyAwsError(err, "vpc-lattice:GetService")
			return
		}
		a.detail = resp
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsVpclatticeService) authType() (string, error) {
	detail, err := a.serviceDetail()
	if err != nil {
		return "", err
	}
	return string(detail.AuthType), nil
}

func (a *mqlAwsVpclatticeService) customDomainName() (string, error) {
	detail, err := a.serviceDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.CustomDomainName), nil
}

func (a *mqlAwsVpclatticeService) dnsEntry() (any, error) {
	detail, err := a.serviceDetail()
	if err != nil {
		return nil, err
	}
	if detail.DnsEntry == nil {
		a.DnsEntry.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return map[string]any{
		"domainName":   convert.ToValue(detail.DnsEntry.DomainName),
		"hostedZoneId": convert.ToValue(detail.DnsEntry.HostedZoneId),
	}, nil
}

func (a *mqlAwsVpclatticeService) certificate() (*mqlAwsAcmCertificate, error) {
	detail, err := a.serviceDetail()
	if err != nil {
		return nil, err
	}
	certArn := convert.ToValue(detail.CertificateArn)
	if certArn == "" {
		a.Certificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate,
		map[string]*llx.RawData{"arn": llx.StringData(certArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsVpclatticeService) authPolicy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return vpcLatticeAuthPolicy(conn.VpcLattice(a.Region.Data), a.Arn.Data)
}

func (a *mqlAwsVpclatticeService) authPolicyStatements() ([]any, error) {
	policy := a.GetAuthPolicy()
	if policy.Error != nil {
		return nil, policy.Error
	}
	return newPolicyStatementResources(a.MqlRuntime, a.Arn.Data+"/authPolicy", policy.Data)
}

func (a *mqlAwsVpclatticeService) hasWildcardAuthPolicy() (bool, error) {
	statements := a.GetAuthPolicyStatements()
	if statements.Error != nil {
		return false, statements.Error
	}
	return statementsAllowWildcard(statements.Data)
}

func (a *mqlAwsVpclatticeService) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return vpcLatticeTags(conn.VpcLattice(a.Region.Data), a.Arn.Data)
}

func (a *mqlAwsVpclatticeService) listeners() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.VpcLattice(a.Region.Data)
	ctx := context.Background()

	res := []any{}
	paginator := vpclattice.NewListListenersPaginator(svc, &vpclattice.ListListenersInput{
		ServiceIdentifier: &a.Id.Data,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "vpc-lattice:ListListeners")
		}
		for _, listener := range page.Items {
			mqlListener, err := CreateResource(a.MqlRuntime, ResourceAwsVpclatticeListener,
				map[string]*llx.RawData{
					"arn":           llx.StringDataPtr(listener.Arn),
					"id":            llx.StringDataPtr(listener.Id),
					"name":          llx.StringDataPtr(listener.Name),
					"protocol":      llx.StringData(string(listener.Protocol)),
					"port":          llx.IntDataDefault(listener.Port, 0),
					"createdAt":     llx.TimeDataPtr(listener.CreatedAt),
					"lastUpdatedAt": llx.TimeDataPtr(listener.LastUpdatedAt),
				})
			if err != nil {
				return nil, err
			}
			mqlListener.(*mqlAwsVpclatticeListener).region = a.Region.Data
			res = append(res, mqlListener)
		}
	}
	return res, nil
}

func (a *mqlAwsVpclattice) targetGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTargetGroups(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsVpclattice) getTargetGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.VpcLattice(region)
			ctx := context.Background()
			res := []any{}
			paginator := vpclattice.NewListTargetGroupsPaginator(svc, &vpclattice.ListTargetGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if vpcLatticeRegionalSkip(err, region) {
						return res, nil
					}
					return nil, err
				}
				for _, tg := range page.Items {
					mqlTg, err := CreateResource(a.MqlRuntime, ResourceAwsVpclatticeTargetGroup,
						map[string]*llx.RawData{
							"arn":           llx.StringDataPtr(tg.Arn),
							"id":            llx.StringDataPtr(tg.Id),
							"name":          llx.StringDataPtr(tg.Name),
							"region":        llx.StringData(region),
							"type":          llx.StringData(string(tg.Type)),
							"status":        llx.StringData(string(tg.Status)),
							"protocol":      llx.StringData(string(tg.Protocol)),
							"port":          llx.IntDataDefault(tg.Port, 0),
							"ipAddressType": llx.StringData(string(tg.IpAddressType)),
							"createdAt":     llx.TimeDataPtr(tg.CreatedAt),
							"lastUpdatedAt": llx.TimeDataPtr(tg.LastUpdatedAt),
						})
					if err != nil {
						return nil, err
					}
					internal := mqlTg.(*mqlAwsVpclatticeTargetGroup)
					internal.cacheVpcId = convert.ToValue(tg.VpcIdentifier)
					internal.cacheServiceArns = tg.ServiceArns
					res = append(res, mqlTg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsVpclatticeTargetGroupInternal struct {
	cacheVpcId       string
	cacheServiceArns []string
}

func (a *mqlAwsVpclatticeTargetGroup) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return vpcLatticeTags(conn.VpcLattice(a.Region.Data), a.Arn.Data)
}

// mqlAwsVpclatticeListenerInternal carries the region of the service the
// listener belongs to. A listener has no region of its own in the API response,
// but tags are fetched through a regional client.
type mqlAwsVpclatticeListenerInternal struct {
	region string
}

func (a *mqlAwsVpclatticeListener) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return vpcLatticeTags(conn.VpcLattice(a.region), a.Arn.Data)
}

// services resolves the services routing traffic to this target group. A target
// group can be shared by several services, so this is the reverse of walking
// service listeners and is what shows a backend's full set of callers.
//
// aws.vpclattice.service has no by-ARN init, so these match against the
// account's service list rather than being constructed from the ARN alone --
// building them directly would yield resources with every field but arn unset.
// The list is enumerated once and cached on the aws.vpclattice singleton.
func (a *mqlAwsVpclatticeTargetGroup) services() ([]any, error) {
	wanted := map[string]struct{}{}
	for _, svcArn := range a.cacheServiceArns {
		if svcArn != "" {
			wanted[svcArn] = struct{}{}
		}
	}
	if len(wanted) == 0 {
		return []any{}, nil
	}

	obj, err := CreateResource(a.MqlRuntime, ResourceAwsVpclattice, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	services := obj.(*mqlAwsVpclattice).GetServices()
	if services.Error != nil {
		return nil, services.Error
	}

	res := []any{}
	for _, s := range services.Data {
		svc, ok := s.(*mqlAwsVpclatticeService)
		if !ok {
			continue
		}
		if _, found := wanted[svc.Arn.Data]; found {
			res = append(res, svc)
		}
	}
	return res, nil
}

// vpc is null for a LAMBDA target group, which has no VPC of its own.
func (a *mqlAwsVpclatticeTargetGroup) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpc,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheVpcId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}
