// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/fastly/go-fastly/v10/fastly"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlFastlyTlsActivationInternal struct {
	// cert is the certificate the activation serves, pulled inline with the
	// activation so the certificate accessor needs no extra request.
	cert *fastly.CustomTLSCertificate
}

func newTLSSubscription(runtime *plugin.Runtime, s *fastly.TLSSubscription) (*mqlFastlyTlsSubscription, error) {
	commonName := ""
	if s.CommonName != nil {
		commonName = s.CommonName.ID
	}

	res, err := CreateResource(runtime, ResourceFastlyTlsSubscription, map[string]*llx.RawData{
		"__id":                 llx.StringData(s.ID),
		"id":                   llx.StringData(s.ID),
		"state":                llx.StringData(s.State),
		"certificateAuthority": llx.StringData(s.CertificateAuthority),
		"commonName":           llx.StringData(commonName),
		"domains":              stringSlice(tlsDomainNames(s.Domains)),
		"createdAt":            llx.TimeDataPtr(s.CreatedAt),
		"updatedAt":            llx.TimeDataPtr(s.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFastlyTlsSubscription), nil
}

func (r *mqlFastlyTlsSubscription) id() (string, error) {
	return r.Id.Data, nil
}

func newTLSCertificate(runtime *plugin.Runtime, c *fastly.CustomTLSCertificate) (*mqlFastlyTlsCertificate, error) {
	res, err := CreateResource(runtime, ResourceFastlyTlsCertificate, map[string]*llx.RawData{
		"__id":               llx.StringData(c.ID),
		"id":                 llx.StringData(c.ID),
		"name":               llx.StringData(c.Name),
		"issuedTo":           llx.StringData(c.IssuedTo),
		"issuer":             llx.StringData(c.Issuer),
		"serialNumber":       llx.StringData(c.SerialNumber),
		"signatureAlgorithm": llx.StringData(c.SignatureAlgorithm),
		"notBefore":          llx.TimeDataPtr(c.NotBefore),
		"notAfter":           llx.TimeDataPtr(c.NotAfter),
		"replace":            llx.BoolData(c.Replace),
		"domains":            stringSlice(tlsDomainNames(c.Domains)),
		"createdAt":          llx.TimeDataPtr(c.CreatedAt),
		"updatedAt":          llx.TimeDataPtr(c.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFastlyTlsCertificate), nil
}

func (r *mqlFastlyTlsCertificate) id() (string, error) {
	return r.Id.Data, nil
}

func newTLSActivation(runtime *plugin.Runtime, a *fastly.TLSActivation) (*mqlFastlyTlsActivation, error) {
	domain := ""
	if a.Domain != nil {
		domain = a.Domain.ID
	}

	res, err := CreateResource(runtime, ResourceFastlyTlsActivation, map[string]*llx.RawData{
		"__id":      llx.StringData(a.ID),
		"id":        llx.StringData(a.ID),
		"domain":    llx.StringData(domain),
		"createdAt": llx.TimeDataPtr(a.CreatedAt),
	})
	if err != nil {
		return nil, err
	}
	act := res.(*mqlFastlyTlsActivation)
	act.cert = a.Certificate
	return act, nil
}

func (r *mqlFastlyTlsActivation) id() (string, error) {
	return r.Id.Data, nil
}

// certificate resolves the certificate the activation serves from the data
// pulled inline with the activation.
func (r *mqlFastlyTlsActivation) certificate() (*mqlFastlyTlsCertificate, error) {
	if r.cert == nil {
		r.Certificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newTLSCertificate(r.MqlRuntime, r.cert)
}

// tlsDomainNames extracts the hostnames from a list of TLS domains. A TLS
// domain's ID is the domain name.
func tlsDomainNames(domains []*fastly.TLSDomain) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		if d == nil {
			continue
		}
		out = append(out, d.ID)
	}
	return out
}
