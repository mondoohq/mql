// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsTransfer) id() (string, error) {
	return "aws.transfer", nil
}

func (a *mqlAwsTransfer) servers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getServers(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsTransfer) getServers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("transfer>getServers>calling aws with region %s", region)

			svc := conn.Transfer(region)
			ctx := context.Background()
			res := []any{}

			paginator := transfer.NewListServersPaginator(svc, &transfer.ListServersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("Transfer Family is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, server := range page.Servers {
					mqlServer, err := CreateResource(a.MqlRuntime, "aws.transfer.server",
						map[string]*llx.RawData{
							"__id":         llx.StringDataPtr(server.Arn),
							"arn":          llx.StringDataPtr(server.Arn),
							"serverId":     llx.StringDataPtr(server.ServerId),
							"region":       llx.StringData(region),
							"endpointType": llx.StringData(string(server.EndpointType)),
							"state":        llx.StringData(string(server.State)),
							"userCount":    llx.IntData(int64(convert.ToValue(server.UserCount))),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlServer)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsTransferServer) id() (string, error) {
	return a.Arn.Data, nil
}

func initAwsTransferServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// During a discovered-asset scan the resource is queried with no args; recover
	// the server's region and id from the ARN carried on the asset.
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformTransferServer); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch transfer server")
	}

	arnVal := args["arn"].Value.(string)

	if cached := cachedByArn(runtime, ResourceAwsTransferServer, arnVal); cached != nil {
		return args, cached, nil
	}

	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return nil, nil, err
	}
	region := parsed.Region
	serverId := strings.TrimPrefix(parsed.Resource, "server/")

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Transfer(region)
	ctx := context.Background()
	resp, err := svc.DescribeServer(ctx, &transfer.DescribeServerInput{ServerId: &serverId})
	if err != nil {
		return nil, nil, err
	}
	if resp == nil || resp.Server == nil {
		return nil, nil, errors.New("aws transfer server not found: " + serverId)
	}

	s := resp.Server
	mqlServer, err := CreateResource(runtime, "aws.transfer.server",
		map[string]*llx.RawData{
			"__id":         llx.StringData(arnVal),
			"arn":          llx.StringData(arnVal),
			"serverId":     llx.StringDataPtr(s.ServerId),
			"region":       llx.StringData(region),
			"endpointType": llx.StringData(string(s.EndpointType)),
			"state":        llx.StringData(string(s.State)),
			"userCount":    llx.IntData(int64(convert.ToValue(s.UserCount))),
		})
	if err != nil {
		return nil, nil, err
	}

	// Pre-populate the DescribeServer cache so the computed fields (protocols,
	// logging role, certificate, etc.) don't trigger a second API call.
	server := mqlServer.(*mqlAwsTransferServer)
	server.fetched = true
	server.descResp = resp
	return nil, server, nil
}

type mqlAwsTransferServerInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *transfer.DescribeServerOutput
}

func (a *mqlAwsTransferServer) fetchDetail() (*transfer.DescribeServerOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Transfer(region)
	ctx := context.Background()

	serverId := a.ServerId.Data
	resp, err := svc.DescribeServer(ctx, &transfer.DescribeServerInput{
		ServerId: &serverId,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Server == nil {
		return nil, fmt.Errorf("describe server returned empty response for %q", serverId)
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsTransferServer) domain() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Server.Domain), nil
}

func (a *mqlAwsTransferServer) identityProviderType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Server.IdentityProviderType), nil
}

func (a *mqlAwsTransferServer) loggingRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.Server.LoggingRole == nil || *resp.Server.LoggingRole == "" {
		a.LoggingRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(resp.Server.LoggingRole),
		})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsTransferServer) protocols() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	protocols := make([]any, 0, len(resp.Server.Protocols))
	for _, p := range resp.Server.Protocols {
		protocols = append(protocols, string(p))
	}
	return protocols, nil
}

func (a *mqlAwsTransferServer) ipAddressType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Server.IpAddressType), nil
}

func (a *mqlAwsTransferServer) securityPolicyName() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Server.SecurityPolicyName), nil
}

func (a *mqlAwsTransferServer) certificate() (*mqlAwsAcmCertificate, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	certArn := convert.ToValue(resp.Server.Certificate)
	if certArn == "" {
		a.Certificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlCert, err := NewResource(a.MqlRuntime, "aws.acm.certificate",
		map[string]*llx.RawData{
			"arn": llx.StringData(certArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlCert.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsTransferServer) tags() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	tags := make(map[string]any)
	for _, tag := range resp.Server.Tags {
		tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
	}
	return tags, nil
}

func (a *mqlAwsTransferServer) structuredLogDestinations() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	destinations := make([]any, 0, len(resp.Server.StructuredLogDestinations))
	for _, d := range resp.Server.StructuredLogDestinations {
		destinations = append(destinations, d)
	}
	return destinations, nil
}

func transferTagsToMap(tags []transfertypes.Tag) map[string]any {
	return tagsToMap(tags, func(t transfertypes.Tag) *string { return t.Key }, func(t transfertypes.Tag) *string { return t.Value })
}

// Connectors

type mqlAwsTransferConnectorInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *transfer.DescribeConnectorOutput
}

func (a *mqlAwsTransferConnector) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsTransfer) connectors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConnectors(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsTransfer) getConnectors(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("transfer>getConnectors>calling aws with region %s", region)
			svc := conn.Transfer(region)
			ctx := context.Background()
			res := []any{}

			paginator := transfer.NewListConnectorsPaginator(svc, &transfer.ListConnectorsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Transfer connectors API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}
				for _, conn := range page.Connectors {
					mqlConn, err := CreateResource(a.MqlRuntime, "aws.transfer.connector",
						map[string]*llx.RawData{
							"__id":        llx.StringDataPtr(conn.Arn),
							"arn":         llx.StringDataPtr(conn.Arn),
							"connectorId": llx.StringDataPtr(conn.ConnectorId),
							"region":      llx.StringData(region),
							"url":         llx.StringDataPtr(conn.Url),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlConn)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsTransferConnector) fetchDetail() (*transfer.DescribeConnectorOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Transfer(region)
	connectorId := a.ConnectorId.Data
	resp, err := svc.DescribeConnector(context.Background(), &transfer.DescribeConnectorInput{
		ConnectorId: &connectorId,
	})
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Connector == nil {
		return nil, errors.New("DescribeConnector returned no connector for " + connectorId)
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsTransferConnector) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Connector.Status), nil
}

func (a *mqlAwsTransferConnector) egressType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Connector.EgressType), nil
}

func (a *mqlAwsTransferConnector) ipAddressType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Connector.IpAddressType), nil
}

func (a *mqlAwsTransferConnector) errorMessage() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Connector.ErrorMessage), nil
}

func (a *mqlAwsTransferConnector) securityPolicyName() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Connector.SecurityPolicyName), nil
}

func (a *mqlAwsTransferConnector) accessRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	roleArn := convert.ToValue(resp.Connector.AccessRole)
	if roleArn == "" {
		a.AccessRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role", map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsTransferConnector) loggingRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	roleArn := convert.ToValue(resp.Connector.LoggingRole)
	if roleArn == "" {
		a.LoggingRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role", map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsTransferConnector) serviceManagedEgressIpAddresses() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(resp.Connector.ServiceManagedEgressIpAddresses))
	for _, ip := range resp.Connector.ServiceManagedEgressIpAddresses {
		out = append(out, ip)
	}
	return out, nil
}

func (a *mqlAwsTransferConnector) tags() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return transferTagsToMap(resp.Connector.Tags), nil
}

// Web Apps

type mqlAwsTransferWebAppInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *transfer.DescribeWebAppOutput
}

func (a *mqlAwsTransferWebApp) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsTransfer) webApps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getWebApps(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsTransfer) getWebApps(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("transfer>getWebApps>calling aws with region %s", region)
			svc := conn.Transfer(region)
			ctx := context.Background()
			res := []any{}

			paginator := transfer.NewListWebAppsPaginator(svc, &transfer.ListWebAppsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Transfer web apps API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}
				for _, app := range page.WebApps {
					mqlApp, err := CreateResource(a.MqlRuntime, "aws.transfer.webApp",
						map[string]*llx.RawData{
							"__id":           llx.StringDataPtr(app.Arn),
							"arn":            llx.StringDataPtr(app.Arn),
							"webAppId":       llx.StringDataPtr(app.WebAppId),
							"region":         llx.StringData(region),
							"endpointType":   llx.StringData(string(app.EndpointType)),
							"accessEndpoint": llx.StringDataPtr(app.AccessEndpoint),
							"webAppEndpoint": llx.StringDataPtr(app.WebAppEndpoint),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlApp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsTransferWebApp) fetchDetail() (*transfer.DescribeWebAppOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Transfer(region)
	webAppId := a.WebAppId.Data
	resp, err := svc.DescribeWebApp(context.Background(), &transfer.DescribeWebAppInput{WebAppId: &webAppId})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsTransferWebApp) tags() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return transferTagsToMap(resp.WebApp.Tags), nil
}

// Workflows

type mqlAwsTransferWorkflowInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *transfer.DescribeWorkflowOutput
}

func (a *mqlAwsTransferWorkflow) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsTransfer) workflows() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getWorkflows(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsTransfer) getWorkflows(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("transfer>getWorkflows>calling aws with region %s", region)
			svc := conn.Transfer(region)
			ctx := context.Background()
			res := []any{}

			paginator := transfer.NewListWorkflowsPaginator(svc, &transfer.ListWorkflowsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Transfer workflows API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}
				for _, wf := range page.Workflows {
					mqlWf, err := CreateResource(a.MqlRuntime, "aws.transfer.workflow",
						map[string]*llx.RawData{
							"__id":        llx.StringDataPtr(wf.Arn),
							"arn":         llx.StringDataPtr(wf.Arn),
							"workflowId":  llx.StringDataPtr(wf.WorkflowId),
							"region":      llx.StringData(region),
							"description": llx.StringDataPtr(wf.Description),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlWf)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsTransferWorkflow) fetchDetail() (*transfer.DescribeWorkflowOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Transfer(region)
	workflowId := a.WorkflowId.Data
	resp, err := svc.DescribeWorkflow(context.Background(), &transfer.DescribeWorkflowInput{WorkflowId: &workflowId})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsTransferWorkflow) steps() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(resp.Workflow.Steps)
}

func (a *mqlAwsTransferWorkflow) onExceptionSteps() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(resp.Workflow.OnExceptionSteps)
}

func (a *mqlAwsTransferWorkflow) tags() (map[string]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return transferTagsToMap(resp.Workflow.Tags), nil
}
