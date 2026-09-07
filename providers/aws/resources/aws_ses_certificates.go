// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sesv2_types "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/aws/connection"
)

// sesIdentityCertificateCacheID builds the cache key for one S/MIME
// certificate association.
//
// The identity leads because the same address may be associated on more than
// one identity, and the certificate ARN follows the address because an
// identity carries two associations for one address during a rotation: the
// outgoing certificate DEPROVISIONING alongside the incoming one
// PROVISIONING. Keying on the address alone would collapse those two into
// one, reporting whichever arrived first and hiding the other.
func sesIdentityCertificateCacheID(identityArn, fromAddress, certificateArn string) string {
	return fmt.Sprintf("%s/certificate/%s/%s", identityArn, fromAddress, certificateArn)
}

// certificates lists the S/MIME signing certificates associated with the
// identity.
//
// This costs one ListEmailIdentityCertificates call per identity, so it stays
// behind its own accessor rather than joining the identity lister, and behind
// its own lock rather than fetchDetails, so an account querying only the DKIM
// fields never pays for it.
func (a *mqlAwsSesIdentity) certificates() ([]any, error) {
	if a.certificatesFetched {
		return a.cachedCertificates, nil
	}
	a.certificatesLock.Lock()
	defer a.certificatesLock.Unlock()
	if a.certificatesFetched {
		return a.cachedCertificates, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sesv2(a.region)
	ctx := context.Background()
	identityArn := a.Arn.Data
	identityName := a.cacheName

	res := []any{}
	paginator := sesv2.NewListEmailIdentityCertificatesPaginator(svc, &sesv2.ListEmailIdentityCertificatesInput{
		EmailIdentity: &identityName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("identity", identityName).Msg("access denied listing SES email identity certificates")
				break
			}
			if IsServiceNotAvailableInRegionError(err) {
				log.Debug().Str("region", a.region).Msg("SES email identity certificates are not available in region")
				break
			}
			return nil, err
		}
		for _, cert := range page.Certificates {
			mqlCert, err := newMqlAwsSesIdentityCertificate(a.MqlRuntime, identityArn, cert)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCert)
		}
	}

	a.certificatesFetched = true
	a.cachedCertificates = res
	return res, nil
}

// sesCertificateArgs maps one certificate association onto its resource
// fields.
//
// CertificateArn, FromAddress and CertificateExpiryTime are all optional on
// the wire. The Ptr helpers keep an absent value null rather than reporting
// the empty string as an ARN or the zero time as a real expiry in the year 1,
// which any "expires within N days" check would read as long expired.
func sesCertificateArgs(identityArn string, cert sesv2_types.IdentityCertificate) map[string]*llx.RawData {
	certArn := ""
	if cert.CertificateArn != nil {
		certArn = *cert.CertificateArn
	}
	fromAddress := ""
	if cert.FromAddress != nil {
		fromAddress = *cert.FromAddress
	}

	return map[string]*llx.RawData{
		"__id":                  llx.StringData(sesIdentityCertificateCacheID(identityArn, fromAddress, certArn)),
		"arn":                   llx.StringDataPtr(cert.CertificateArn),
		"fromAddress":           llx.StringDataPtr(cert.FromAddress),
		"status":                llx.StringData(string(cert.Status)),
		"certificateExpiryTime": llx.TimeDataPtr(cert.CertificateExpiryTime),
	}
}

func newMqlAwsSesIdentityCertificate(runtime *plugin.Runtime, identityArn string, cert sesv2_types.IdentityCertificate) (plugin.Resource, error) {
	return CreateResource(runtime, "aws.ses.identity.certificate", sesCertificateArgs(identityArn, cert))
}

func (a *mqlAwsSesIdentityCertificate) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsSesIdentityCertificate) certificate() (*mqlAwsAcmCertificate, error) {
	if !a.Arn.IsSet() || a.Arn.Data == "" {
		a.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.acm.certificate",
		map[string]*llx.RawData{"arn": llx.StringData(a.Arn.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}
