// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	acmpcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsPrivateca) id() (string, error) {
	return "aws.privateca", nil
}

func (a *mqlAwsPrivateca) certificateAuthorities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCertificateAuthorities(conn), 5)
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

func (a *mqlAwsPrivateca) getCertificateAuthorities(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Acmpca(region)
			ctx := context.Background()
			res := []any{}

			paginator := acmpca.NewListCertificateAuthoritiesPaginator(svc, &acmpca.ListCertificateAuthoritiesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("acm-pca is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, ca := range page.CertificateAuthorities {
					mqlCA, err := newMqlPrivatecaCertificateAuthority(a.MqlRuntime, ca, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCA)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsPrivatecaCertificateAuthority(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws privateca certificate authority")
	}
	arnVal, ok := args["arn"].Value.(string)
	if !ok {
		return nil, nil, errors.New("arn must be a string")
	}

	obj, err := CreateResource(runtime, "aws.privateca", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	privateca := obj.(*mqlAwsPrivateca)

	cas := privateca.GetCertificateAuthorities()
	if cas.Error != nil {
		return nil, nil, cas.Error
	}
	for _, raw := range cas.Data {
		ca := raw.(*mqlAwsPrivatecaCertificateAuthority)
		if ca.Arn.Data == arnVal {
			return args, ca, nil
		}
	}
	return nil, nil, fmt.Errorf("aws.privateca.certificateAuthority with arn %q not found", arnVal)
}

func newMqlPrivatecaCertificateAuthority(runtime *plugin.Runtime, ca acmpcatypes.CertificateAuthority, region string) (*mqlAwsPrivatecaCertificateAuthority, error) {
	var subject any
	if ca.CertificateAuthorityConfiguration != nil {
		subject, _ = convert.JsonToDict(ca.CertificateAuthorityConfiguration.Subject)
	}
	var revConfig any
	if ca.RevocationConfiguration != nil {
		revConfig, _ = convert.JsonToDict(ca.RevocationConfiguration)
	}

	var keyAlgorithm, signingAlgorithm string
	if ca.CertificateAuthorityConfiguration != nil {
		keyAlgorithm = string(ca.CertificateAuthorityConfiguration.KeyAlgorithm)
		signingAlgorithm = string(ca.CertificateAuthorityConfiguration.SigningAlgorithm)
	}

	res, err := CreateResource(runtime, "aws.privateca.certificateAuthority",
		map[string]*llx.RawData{
			"__id":                       llx.StringDataPtr(ca.Arn),
			"arn":                        llx.StringDataPtr(ca.Arn),
			"region":                     llx.StringData(region),
			"status":                     llx.StringData(string(ca.Status)),
			"type":                       llx.StringData(string(ca.Type)),
			"usageMode":                  llx.StringData(string(ca.UsageMode)),
			"serial":                     llx.StringDataPtr(ca.Serial),
			"keyAlgorithm":               llx.StringData(keyAlgorithm),
			"signingAlgorithm":           llx.StringData(signingAlgorithm),
			"subject":                    llx.DictData(subject),
			"revocationConfiguration":    llx.DictData(revConfig),
			"keyStorageSecurityStandard": llx.StringData(string(ca.KeyStorageSecurityStandard)),
			"ownerAccount":               llx.StringDataPtr(ca.OwnerAccount),
			"notBefore":                  llx.TimeDataPtr(ca.NotBefore),
			"notAfter":                   llx.TimeDataPtr(ca.NotAfter),
			"createdAt":                  llx.TimeDataPtr(ca.CreatedAt),
			"lastStateChangeAt":          llx.TimeDataPtr(ca.LastStateChangeAt),
			"failureReason":              llx.StringData(string(ca.FailureReason)),
		})
	if err != nil {
		return nil, err
	}
	mqlCA := res.(*mqlAwsPrivatecaCertificateAuthority)
	mqlCA.cacheRegion = region
	return mqlCA, nil
}

type mqlAwsPrivatecaCertificateAuthorityInternal struct {
	cacheRegion   string
	fetchedCert   bool
	certLock      sync.Mutex
	certData      string
	certChainData string
}

func (a *mqlAwsPrivatecaCertificateAuthority) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsPrivatecaCertificateAuthority) fetchCertificate() error {
	if a.fetchedCert {
		return nil
	}
	a.certLock.Lock()
	defer a.certLock.Unlock()
	if a.fetchedCert {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Acmpca(a.cacheRegion)
	ctx := context.Background()

	arn := a.Arn.Data
	resp, err := svc.GetCertificateAuthorityCertificate(ctx, &acmpca.GetCertificateAuthorityCertificateInput{
		CertificateAuthorityArn: &arn,
	})
	if err != nil {
		// CA may not have a certificate yet (PENDING_CERTIFICATE state)
		var rnfe *acmpcatypes.ResourceNotFoundException
		if errors.As(err, &rnfe) {
			a.fetchedCert = true
			return nil
		}
		return err
	}

	if resp.Certificate != nil {
		a.certData = *resp.Certificate
	}
	if resp.CertificateChain != nil {
		a.certChainData = *resp.CertificateChain
	}
	a.fetchedCert = true
	return nil
}

func (a *mqlAwsPrivatecaCertificateAuthority) certificate() (string, error) {
	if err := a.fetchCertificate(); err != nil {
		return "", err
	}
	return a.certData, nil
}

func (a *mqlAwsPrivatecaCertificateAuthority) certificateChain() (string, error) {
	if err := a.fetchCertificate(); err != nil {
		return "", err
	}
	return a.certChainData, nil
}

func (a *mqlAwsPrivatecaCertificateAuthority) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Acmpca(a.cacheRegion)
	ctx := context.Background()

	arn := a.Arn.Data
	res := map[string]any{}
	var nextToken *string
	for {
		resp, err := svc.ListTags(ctx, &acmpca.ListTagsInput{
			CertificateAuthorityArn: &arn,
			NextToken:               nextToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "acm-pca:ListTags")
		}
		for _, tag := range resp.Tags {
			if tag.Key != nil && tag.Value != nil {
				res[*tag.Key] = *tag.Value
			}
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

func (a *mqlAwsPrivatecaCertificateAuthority) policy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Acmpca(a.cacheRegion)
	ctx := context.Background()

	arn := a.Arn.Data
	resp, err := svc.GetPolicy(ctx, &acmpca.GetPolicyInput{
		ResourceArn: &arn,
	})
	if err != nil {
		var rnfe *acmpcatypes.ResourceNotFoundException
		if errors.As(err, &rnfe) {
			return "", nil
		}
		return "", classifyAwsError(err, "acm-pca:GetPolicy")
	}
	if resp.Policy != nil {
		return *resp.Policy, nil
	}
	return "", nil
}
