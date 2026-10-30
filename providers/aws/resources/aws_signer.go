// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/signer"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsSigner) id() (string, error) {
	return "aws.signer", nil
}

func (a *mqlAwsSigner) signingProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSigningProfiles(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result == nil {
			continue
		}
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSigner) getSigningProfiles(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Signer(region)
			ctx := context.Background()
			res := []any{}

			params := &signer.ListSigningProfilesInput{}
			paginator := signer.NewListSigningProfilesPaginator(svc, params)
			for paginator.HasMorePages() {
				profiles, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, p := range profiles.Profiles {
					certArn := ""
					if p.SigningMaterial != nil {
						certArn = convert.ToValue(p.SigningMaterial.CertificateArn)
					}
					validityType := ""
					validityValue := 0
					if p.SignatureValidityPeriod != nil {
						validityType = string(p.SignatureValidityPeriod.Type)
						validityValue = int(p.SignatureValidityPeriod.Value)
					}
					mqlProfile, err := CreateResource(a.MqlRuntime, "aws.signer.signingProfile",
						map[string]*llx.RawData{
							"__id":                   llx.StringData(convert.ToValue(p.Arn)),
							"arn":                    llx.StringDataPtr(p.Arn),
							"profileName":            llx.StringDataPtr(p.ProfileName),
							"profileVersion":         llx.StringDataPtr(p.ProfileVersion),
							"profileVersionArn":      llx.StringDataPtr(p.ProfileVersionArn),
							"platformId":             llx.StringDataPtr(p.PlatformId),
							"platformDisplayName":    llx.StringDataPtr(p.PlatformDisplayName),
							"status":                 llx.StringData(string(p.Status)),
							"signatureValidityType":  llx.StringData(validityType),
							"signatureValidityValue": llx.IntData(validityValue),
							"signingParameters":      llx.MapData(toInterfaceMap(p.SigningParameters), types.String),
							"region":                 llx.StringData(region),
							"tags":                   llx.MapData(toInterfaceMap(p.Tags), types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlProfile.(*mqlAwsSignerSigningProfile).cacheSigningMaterialCertificateArn = certArn
					res = append(res, mqlProfile)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSignerSigningProfile) signingMaterialCertificate() (*mqlAwsAcmCertificate, error) {
	arnVal := a.cacheSigningMaterialCertificateArn
	if arnVal == "" {
		a.SigningMaterialCertificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

type mqlAwsSignerSigningProfileInternal struct {
	cacheSigningMaterialCertificateArn string
}
