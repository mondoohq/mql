// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

const (
	// serviceLastAccessedPollInterval and serviceLastAccessedTimeout bound the
	// wait on an IAM service-last-accessed report job.
	serviceLastAccessedPollInterval = 500 * time.Millisecond
	serviceLastAccessedTimeout      = 45 * time.Second
)

// lastAccessedServicesForArn collects the IAM service-last-accessed report for
// one user, group, role, or policy. IAM produces the report asynchronously: the
// generate call returns a job id and the get call reports IN_PROGRESS until the
// job finishes. It polls up to serviceLastAccessedTimeout and returns an error
// rather than a short list when the job has not finished, so an incomplete
// report is never read as "no service was ever used".
func lastAccessedServicesForArn(ctx context.Context, runtime *plugin.Runtime, svc *iam.Client, entityArn string) ([]any, error) {
	job, err := svc.GenerateServiceLastAccessedDetails(ctx, &iam.GenerateServiceLastAccessedDetailsInput{
		Arn: &entityArn,
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	var marker *string
	deadline := time.Now().Add(serviceLastAccessedTimeout)
	for {
		details, err := svc.GetServiceLastAccessedDetails(ctx, &iam.GetServiceLastAccessedDetailsInput{
			JobId:  job.JobId,
			Marker: marker,
		})
		if err != nil {
			return nil, err
		}

		switch details.JobStatus {
		case iamtypes.JobStatusTypeInProgress:
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("timed out waiting for the IAM service last accessed report for %s", entityArn)
			}
			time.Sleep(serviceLastAccessedPollInterval)
			continue
		case iamtypes.JobStatusTypeFailed:
			return nil, fmt.Errorf("IAM could not generate the service last accessed report for %s: %s",
				entityArn, jobErrorDetails(details.Error))
		}

		for i := range details.ServicesLastAccessed {
			service := details.ServicesLastAccessed[i]
			mqlService, err := CreateResource(runtime, ResourceAwsIamServiceLastAccessed,
				map[string]*llx.RawData{
					"__id":                       llx.StringData(entityArn + "/serviceLastAccessed/" + convert.ToValue(service.ServiceNamespace)),
					"serviceName":                llx.StringDataPtr(service.ServiceName),
					"serviceNamespace":           llx.StringDataPtr(service.ServiceNamespace),
					"lastAuthenticatedAt":        llx.TimeDataPtr(service.LastAuthenticated),
					"lastAuthenticatedEntity":    llx.StringDataPtr(service.LastAuthenticatedEntity),
					"lastAuthenticatedRegion":    llx.StringDataPtr(service.LastAuthenticatedRegion),
					"totalAuthenticatedEntities": llx.IntDataDefault(service.TotalAuthenticatedEntities, 0),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlService)
		}

		if !details.IsTruncated {
			return res, nil
		}
		marker = details.Marker
	}
}

// jobErrorDetails renders the reason IAM gave for a failed report job.
func jobErrorDetails(details *iamtypes.ErrorDetails) string {
	if details == nil {
		return "no reason reported"
	}
	return fmt.Sprintf("%s (%s)", convert.ToValue(details.Message), convert.ToValue(details.Code))
}

func (a *mqlAwsIamRole) lastAccessedServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return lastAccessedServicesForArn(context.Background(), a.MqlRuntime, conn.Iam(""), a.Arn.Data)
}

func (a *mqlAwsIamUser) lastAccessedServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return lastAccessedServicesForArn(context.Background(), a.MqlRuntime, conn.Iam(""), a.Arn.Data)
}

func (a *mqlAwsIamGroup) lastAccessedServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return lastAccessedServicesForArn(context.Background(), a.MqlRuntime, conn.Iam(""), a.Arn.Data)
}

func (a *mqlAwsIamPolicy) lastAccessedServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return lastAccessedServicesForArn(context.Background(), a.MqlRuntime, conn.Iam(""), a.Arn.Data)
}
