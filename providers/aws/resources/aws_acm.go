// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsAcm) id() (string, error) {
	return "aws.acm", nil
}

func (a *mqlAwsAcm) certificates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCertificates(conn), 5)
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

func (a *mqlAwsAcm) getCertificates(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Acm(region)
			ctx := context.Background()
			res := []any{}

			// Without an explicit KeyTypes filter ACM applies its default, which
			// "returns only RSA_1024 and RSA_2048 certificates that have at least
			// one domain" -- silently hiding every EC_* and RSA_3072/4096
			// certificate. That drops the modern, AWS-recommended key types while
			// leaving the weak ones visible, so the resource looks populated and
			// an expiry or weak-key audit passes over an incomplete set.
			params := &acm.ListCertificatesInput{
				Includes: &acmtypes.Filters{KeyTypes: acmtypes.KeyAlgorithm("").Values()},
			}
			paginator := acm.NewListCertificatesPaginator(svc, params)
			for paginator.HasMorePages() {
				certs, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, cert := range certs.CertificateSummaryList {
					mqlCert, err := NewResource(a.MqlRuntime, "aws.acm.certificate", map[string]*llx.RawData{
						"arn": llx.StringDataPtr(cert.CertificateArn),
					})
					if err != nil {
						return nil, err
					}

					res = append(res, mqlCert)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsAcmCertificate) id() (string, error) {
	return a.Arn.Data, nil
}

func initAwsAcmCertificate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws acm certificate")
	}

	arnVal := args["arn"].Value.(string)
	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return args, nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)

	svc := conn.Acm(region)
	ctx := context.Background()
	certDetails, err := svc.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: &arnVal})
	if err != nil {
		return nil, nil, err
	}
	certTags, err := svc.ListTagsForCertificate(ctx, &acm.ListTagsForCertificateInput{CertificateArn: &arnVal})
	if err != nil {
		return nil, nil, err
	}

	args["arn"] = llx.StringData(arnVal)
	args["createdAt"] = llx.TimeDataPtr(certDetails.Certificate.CreatedAt)
	args["domainName"] = llx.StringDataPtr(certDetails.Certificate.DomainName)
	args["importedAt"] = llx.TimeDataPtr(certDetails.Certificate.ImportedAt)
	args["issuedAt"] = llx.TimeDataPtr(certDetails.Certificate.IssuedAt)
	args["issuer"] = llx.StringDataPtr(certDetails.Certificate.Issuer)
	args["keyAlgorithm"] = llx.StringData(string(certDetails.Certificate.KeyAlgorithm))
	args["notAfter"] = llx.TimeDataPtr(certDetails.Certificate.NotAfter)
	args["notBefore"] = llx.TimeDataPtr(certDetails.Certificate.NotBefore)
	args["serial"] = llx.StringDataPtr(certDetails.Certificate.Serial)
	args["source"] = llx.StringData(string(certDetails.Certificate.Type))
	args["status"] = llx.StringData(string(certDetails.Certificate.Status))
	args["subject"] = llx.StringDataPtr(certDetails.Certificate.Subject)
	args["tags"] = llx.MapData(CertTagsToMapTags(certTags.Tags), types.String)
	args["renewalEligible"] = llx.BoolData(certDetails.Certificate.RenewalEligibility == acmtypes.RenewalEligibilityEligible)
	args["signatureAlgorithm"] = llx.StringDataPtr(certDetails.Certificate.SignatureAlgorithm)
	inUseBy := make([]any, 0, len(certDetails.Certificate.InUseBy))
	for _, u := range certDetails.Certificate.InUseBy {
		inUseBy = append(inUseBy, u)
	}
	args["inUseBy"] = llx.ArrayData(inUseBy, types.String)
	domainValidationOptions, err := convert.JsonToDictSlice(certDetails.Certificate.DomainValidationOptions)
	if err != nil {
		return nil, nil, err
	}
	args["domainValidationOptions"] = llx.ArrayData(domainValidationOptions, types.Dict)

	cert := certDetails.Certificate
	args["subjectAlternativeNames"] = llx.ArrayData(convert.SliceAnyToInterface(cert.SubjectAlternativeNames), types.String)

	keyUsages := make([]any, 0, len(cert.KeyUsages))
	for _, ku := range cert.KeyUsages {
		keyUsages = append(keyUsages, string(ku.Name))
	}
	args["keyUsages"] = llx.ArrayData(keyUsages, types.String)

	extKeyUsages := make([]any, 0, len(cert.ExtendedKeyUsages))
	for _, eku := range cert.ExtendedKeyUsages {
		extKeyUsages = append(extKeyUsages, map[string]any{
			"name": string(eku.Name),
			"oid":  convert.ToValue(eku.OID),
		})
	}
	args["extendedKeyUsages"] = llx.ArrayData(extKeyUsages, types.Dict)

	exportable := false
	if cert.Options != nil {
		exportable = cert.Options.Export == acmtypes.CertificateExportEnabled
	}
	args["exportable"] = llx.BoolData(exportable)

	renewalSummary, err := convert.JsonToDict(cert.RenewalSummary)
	if err != nil {
		return nil, nil, err
	}
	args["renewalSummary"] = llx.DictData(renewalSummary)

	args["failureReason"] = llx.StringData(string(cert.FailureReason))
	args["revocationReason"] = llx.StringData(string(cert.RevocationReason))
	args["revokedAt"] = llx.TimeDataPtr(cert.RevokedAt)
	args["awsManagedBy"] = llx.StringData(string(cert.ManagedBy))

	res, err := CreateResource(runtime, "aws.acm.certificate", args)
	if err != nil {
		return nil, nil, err
	}
	mqlCert := res.(*mqlAwsAcmCertificate)
	mqlCert.cacheCertificateAuthorityArn = cert.CertificateAuthorityArn
	return args, mqlCert, nil
}

type mqlAwsAcmCertificateInternal struct {
	cacheCertificateAuthorityArn *string
}

func (a *mqlAwsAcmCertificate) certificateAuthority() (*mqlAwsPrivatecaCertificateAuthority, error) {
	if a.cacheCertificateAuthorityArn == nil || *a.cacheCertificateAuthorityArn == "" {
		a.CertificateAuthority.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlCA, err := NewResource(a.MqlRuntime, "aws.privateca.certificateAuthority",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheCertificateAuthorityArn)})
	if err != nil {
		return nil, err
	}
	return mqlCA.(*mqlAwsPrivatecaCertificateAuthority), nil
}

func CertTagsToMapTags(tags []acmtypes.Tag) map[string]any {
	return tagsToMap(tags, func(t acmtypes.Tag) *string { return t.Key }, func(t acmtypes.Tag) *string { return t.Value })
}

func (a *mqlAwsAcmCertificate) certificate() (plugin.Resource, error) {
	certArn := a.Arn.Data
	region, err := GetRegionFromArn(certArn)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Acm(region)
	ctx := context.Background()
	cert, err := svc.GetCertificate(ctx, &acm.GetCertificateInput{CertificateArn: &certArn})
	if err != nil {
		return nil, err
	}
	if cert.Certificate == nil {
		return nil, nil
	}
	certificates, err := a.MqlRuntime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(*cert.Certificate),
	})
	if err != nil {
		return nil, err
	}

	list, err := a.MqlRuntime.GetSharedData("certificates", certificates.MqlID(), "list")
	if err != nil {
		return nil, err
	}
	items, ok := list.Value.([]any)
	if !ok || len(items) == 0 {
		return nil, errors.New("no certificate data returned")
	}
	res, ok := items[0].(plugin.Resource)
	if !ok {
		return nil, errors.New("unexpected certificate data type")
	}
	return res, nil
}
