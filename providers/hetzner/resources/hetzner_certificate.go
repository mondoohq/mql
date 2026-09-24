// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlHetznerCertificateInternal struct {
	cacheServerIDs       []int64
	cacheLoadBalancerIDs []int64
}

// parsedCertificate holds the security-relevant fields extracted from a
// certificate's PEM body. Zero values are used when the body is absent or
// unparseable so audits can distinguish "unknown" from a real value.
type parsedCertificate struct {
	keyAlgorithm       string
	keyBits            int64
	signatureAlgorithm string
	issuer             string
	subject            string
	serialNumber       string
	isCa               bool
	selfSigned         bool
}

// parseCertificatePEM decodes the leaf certificate from a PEM body and pulls
// out the fields we surface for TLS hygiene audits. It returns the zero value
// when the body is empty or cannot be parsed.
func parseCertificatePEM(pemBody string) parsedCertificate {
	var out parsedCertificate
	block, _ := pem.Decode([]byte(pemBody))
	if block == nil {
		return out
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return out
	}
	out.keyAlgorithm = c.PublicKeyAlgorithm.String()
	out.signatureAlgorithm = c.SignatureAlgorithm.String()
	out.issuer = c.Issuer.String()
	out.subject = c.Subject.String()
	out.isCa = c.IsCA
	// Self-signed means the certificate is both self-issued (identical issuer
	// and subject DER) and carries a signature that verifies against its own
	// public key. The signature check rules out a cross-signed certificate,
	// which shares issuer and subject names but is signed by a different key.
	if bytes.Equal(c.RawIssuer, c.RawSubject) &&
		c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil {
		out.selfSigned = true
	}
	if c.SerialNumber != nil {
		out.serialNumber = c.SerialNumber.String()
	}
	switch key := c.PublicKey.(type) {
	case *rsa.PublicKey:
		out.keyBits = int64(key.N.BitLen())
	case *ecdsa.PublicKey:
		out.keyBits = int64(key.Curve.Params().BitSize)
	case ed25519.PublicKey:
		out.keyBits = 256
	}
	return out
}

func (r *mqlHetznerCertificate) id() (string, error) {
	return fmt.Sprintf("hetzner.certificate/%d", r.Id.Data), nil
}

// allCertificates lists every project certificate exactly once and caches the
// raw result on the hetzner namespace resource, mirroring allServers. Both the
// certificates() field and the load balancer certificate union resolve through
// here, so a project-wide sweep costs a single Certificate.List.
func (h *mqlHetzner) allCertificates() ([]*hcloud.Certificate, error) {
	h.certificatesOnce.Do(func() {
		c := conn(h.MqlRuntime)
		h.certificatesList, h.certificatesErr = paginate(func(opts hcloud.ListOpts) ([]*hcloud.Certificate, *hcloud.Response, error) {
			return c.Client().Certificate.List(ctx(), hcloud.CertificateListOpts{ListOpts: opts})
		})
	})
	return h.certificatesList, h.certificatesErr
}

func (h *mqlHetzner) certificates() ([]any, error) {
	items, err := h.allCertificates()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, cert := range items {
		res, err := newMqlHetznerCertificate(h.MqlRuntime, cert)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlHetznerCertificate(runtime *plugin.Runtime, cert *hcloud.Certificate) (*mqlHetznerCertificate, error) {
	status := map[string]any{}
	if cert.Status != nil {
		status["issuance"] = string(cert.Status.Issuance)
		status["renewal"] = string(cert.Status.Renewal)
		if cert.Status.Error != nil {
			status["error"] = cert.Status.Error.Error()
		}
	}
	var serverIDs, lbIDs []int64
	for _, ref := range cert.UsedBy {
		switch string(ref.Type) {
		case "server":
			serverIDs = append(serverIDs, ref.ID)
		case "load_balancer":
			lbIDs = append(lbIDs, ref.ID)
		}
	}

	parsed := parseCertificatePEM(cert.Certificate)

	res, err := CreateResource(runtime, "hetzner.certificate", map[string]*llx.RawData{
		"__id":               llx.StringData(fmt.Sprintf("hetzner.certificate/%d", cert.ID)),
		"id":                 llx.IntData(cert.ID),
		"name":               llx.StringData(cert.Name),
		"type":               llx.StringData(string(cert.Type)),
		"fingerprint":        llx.StringData(cert.Fingerprint),
		"certificate":        llx.StringData(cert.Certificate),
		"keyAlgorithm":       llx.StringData(parsed.keyAlgorithm),
		"keyBits":            llx.IntData(parsed.keyBits),
		"signatureAlgorithm": llx.StringData(parsed.signatureAlgorithm),
		"issuer":             llx.StringData(parsed.issuer),
		"subject":            llx.StringData(parsed.subject),
		"serialNumber":       llx.StringData(parsed.serialNumber),
		"isCa":               llx.BoolData(parsed.isCa),
		"selfSigned":         llx.BoolData(parsed.selfSigned),
		"notValidBefore":     llx.TimeDataPtr(timePtr(cert.NotValidBefore)),
		"notValidAfter":      llx.TimeDataPtr(timePtr(cert.NotValidAfter)),
		"domainNames":        stringArrayData(cert.DomainNames),
		"status":             llx.DictData(status),
		"created":            llx.TimeDataPtr(timePtr(cert.Created)),
		"labels":             labelData(cert.Labels),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerCertificate)
	m.cacheServerIDs = serverIDs
	m.cacheLoadBalancerIDs = lbIDs
	return m, nil
}

func (m *mqlHetznerCertificate) servers() ([]any, error) {
	out := make([]any, 0, len(m.cacheServerIDs))
	for _, id := range m.cacheServerIDs {
		ref, err := NewResource(m.MqlRuntime, "hetzner.server", map[string]*llx.RawData{
			"id": llx.IntData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func (m *mqlHetznerCertificate) loadBalancers() ([]any, error) {
	out := make([]any, 0, len(m.cacheLoadBalancerIDs))
	for _, id := range m.cacheLoadBalancerIDs {
		ref, err := NewResource(m.MqlRuntime, "hetzner.loadBalancer", map[string]*llx.RawData{
			"id": llx.IntData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}

func initHetznerCertificate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, err := requireIDArg(args, "certificate")
	if err != nil {
		return nil, nil, err
	}
	cert, _, err := conn(runtime).Client().Certificate.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if cert == nil {
		return nil, nil, notFoundErr("certificate", id)
	}
	res, err := newMqlHetznerCertificate(runtime, cert)
	return args, res, err
}
