// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/vmware/govmomi/vapi/rest"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/vsphere/connection"
)

const (
	certPathTLS        = "/api/vcenter/certificate-management/vcenter/tls"
	certPathSigning    = "/api/vcenter/certificate-management/vcenter/signing-certificate"
	certPathTrustRoots = "/api/vcenter/certificate-management/vcenter/trusted-root-chains"
)

func (v *mqlVsphere) certificates() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	rc, err := conn.RestClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vAPI: %w", err)
	}

	seen := map[string]struct{}{}
	res := []any{}
	var machineSSLIssuer string

	// Machine SSL certificate (the reverse-proxy certificate).
	var tlsResp struct {
		Cert string `json:"cert"`
	}
	if err := restGet(ctx, rc, certPathTLS, &tlsResp); err != nil {
		log.Debug().Err(err).Msg("vsphere> failed to read machine SSL certificate")
	} else {
		for _, c := range parsePEMCerts(tlsResp.Cert) {
			machineSSLIssuer = c.Issuer.String()
			v.appendCert(&res, seen, "MACHINE_SSL_CERT", c)
		}
	}

	// SSO/STS token-signing certificate (leaf of the active signing chain).
	var signingResp struct {
		ActiveCertChain struct {
			CertChain []string `json:"cert_chain"`
		} `json:"active_cert_chain"`
		SigningCertChains []struct {
			CertChain []string `json:"cert_chain"`
		} `json:"signing_cert_chains"`
	}
	if err := restGet(ctx, rc, certPathSigning, &signingResp); err != nil {
		log.Debug().Err(err).Msg("vsphere> failed to read signing certificate")
	} else {
		chain := signingResp.ActiveCertChain.CertChain
		if len(chain) == 0 && len(signingResp.SigningCertChains) > 0 {
			chain = signingResp.SigningCertChains[0].CertChain
		}
		for _, p := range chain {
			for _, c := range parsePEMCerts(p) {
				v.appendCert(&res, seen, "SIGNING_CERT", c)
			}
		}
	}

	// Trusted root certificates (the VMCA root signs solution and host certs;
	// the root whose subject signed the machine SSL cert is the VMCA root).
	// The list endpoint returns chain identifiers; across vCenter versions
	// these come back either as plain strings (["id1","id2"]) or as summary
	// objects ([{"chain":"id1"}]), so decode each element tolerantly.
	var rootList []json.RawMessage
	if err := restGet(ctx, rc, certPathTrustRoots, &rootList); err != nil {
		log.Debug().Err(err).Msg("vsphere> failed to list trusted root chains")
	} else {
		for _, raw := range rootList {
			chainID := decodeChainID(raw)
			if chainID == "" {
				continue
			}
			var detail struct {
				CertChain struct {
					CertChain []string `json:"cert_chain"`
				} `json:"cert_chain"`
			}
			if err := restGet(ctx, rc, certPathTrustRoots+"/"+chainID, &detail); err != nil {
				log.Debug().Err(err).Str("chain", chainID).Msg("vsphere> failed to read trusted root chain")
				continue
			}
			for _, p := range detail.CertChain.CertChain {
				for _, c := range parsePEMCerts(p) {
					certType := "TRUSTED_ROOT"
					if machineSSLIssuer != "" && c.Subject.String() == c.Issuer.String() && c.Subject.String() == machineSSLIssuer {
						certType = "VMCA_ROOT"
					}
					v.appendCert(&res, seen, certType, c)
				}
			}
		}
	}

	return res, nil
}

// decodeChainID extracts a trusted-root-chain identifier from one list
// element, accepting either a plain string ("id") or a summary object
// ({"chain":"id"}) depending on the vCenter version's serialization.
func decodeChainID(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		Chain string `json:"chain"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Chain
	}
	return ""
}

// restGet performs an authenticated GET against a vAPI path and decodes the
// JSON response into out.
func restGet(ctx context.Context, rc *rest.Client, path string, out any) error {
	req := rc.Resource(path).Request(http.MethodGet)
	return rc.Do(ctx, req, out)
}

// parsePEMCerts decodes every CERTIFICATE block in a PEM bundle into x509
// certificates, skipping blocks that fail to parse.
func parsePEMCerts(pemData string) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := []byte(pemData)
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, c)
		}
	}
	return certs
}

// appendCert builds a vsphere.certificate resource for the given x509
// certificate, deduplicating on the (type, thumbprint) identity.
func (v *mqlVsphere) appendCert(res *[]any, seen map[string]struct{}, certType string, c *x509.Certificate) {
	sum := sha256.Sum256(c.Raw)
	thumbprint := hex.EncodeToString(sum[:])
	id := certType + ":" + thumbprint
	if _, ok := seen[id]; ok {
		return
	}
	seen[id] = struct{}{}

	mqlCert, err := CreateResource(v.MqlRuntime, "vsphere.certificate", map[string]*llx.RawData{
		"__id":               llx.StringData(id),
		"id":                 llx.StringData(id),
		"type":               llx.StringData(certType),
		"subject":            llx.StringData(c.Subject.String()),
		"issuer":             llx.StringData(c.Issuer.String()),
		"notBefore":          llx.TimeData(c.NotBefore),
		"notAfter":           llx.TimeData(c.NotAfter),
		"serialNumber":       llx.StringData(c.SerialNumber.String()),
		"thumbprint":         llx.StringData(thumbprint),
		"signatureAlgorithm": llx.StringData(c.SignatureAlgorithm.String()),
	})
	if err != nil {
		log.Debug().Err(err).Msg("vsphere> failed to create certificate resource")
		return
	}
	*res = append(*res, mqlCert)
}
