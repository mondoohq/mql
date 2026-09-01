// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/checksums"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/network/resources/certificates"
	"go.mondoo.com/mql/v13/types"
)

func pkixnameToMql(runtime *plugin.Runtime, name pkix.Name, id string) (*mqlPkixName, error) {
	names := map[string]any{}
	for i := range name.Names {
		key := name.Names[i].Type.String()
		names[key] = fmt.Sprintf("%v", name.Names[i].Value)
	}

	extraNames := map[string]any{}
	for i := range name.ExtraNames {
		key := name.ExtraNames[i].Type.String()
		extraNames[key] = fmt.Sprintf("%v", name.ExtraNames[i].Value)
	}

	r, err := CreateResource(runtime, "pkix.name", map[string]*llx.RawData{
		"id":                 llx.StringData(id),
		"dn":                 llx.StringData(name.String()),
		"serialNumber":       llx.StringData(name.SerialNumber),
		"commonName":         llx.StringData(name.CommonName),
		"country":            llx.ArrayData(llx.TArr2Raw(name.Country), types.String),
		"organization":       llx.ArrayData(llx.TArr2Raw(name.Organization), types.String),
		"organizationalUnit": llx.ArrayData(llx.TArr2Raw(name.OrganizationalUnit), types.String),
		"locality":           llx.ArrayData(llx.TArr2Raw(name.Locality), types.String),
		"province":           llx.ArrayData(llx.TArr2Raw(name.Province), types.String),
		"streetAddress":      llx.ArrayData(llx.TArr2Raw(name.StreetAddress), types.String),
		"postalCode":         llx.ArrayData(llx.TArr2Raw(name.PostalCode), types.String),
		"names":              llx.MapData(names, types.String),
		"extraNames":         llx.MapData(extraNames, types.String),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlPkixName), nil
}

func ExtensionValueToReadableFormat(ext pkix.Extension) (string, error) {
	readableValue := string(ext.Value)
	switch {
	case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14}): // Subject Key Identifier
		var subjectKeyID []byte
		if _, err := asn1.Unmarshal(ext.Value, &subjectKeyID); err != nil {
			log.Warn().Err(err).Msg("Error unmarshalling Subject Key ID")
		} else {
			log.Debug().Msg("Extension Identified as Subject Key ID")
			hexString := strings.ToUpper(hex.EncodeToString(subjectKeyID))

			var pairs []string
			for i := 0; i < len(hexString); i += 2 {
				pairs = append(pairs, hexString[i:i+2])
			}

			readableValue = strings.Join(pairs, ":")
		}
	case ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}): // Subject Alternative Name
		var rawValues []asn1.RawValue
		if _, err := asn1.Unmarshal(ext.Value, &rawValues); err != nil {
			log.Warn().Err(err).Msg("Error unmarshalling Subject Alternative Name")
		} else {
			log.Debug().Msg("Extension Identified as Subject Alternative Name")
			var sans []string
			for _, raw := range rawValues {
				sans = append(sans, string(raw.Bytes))
			}
			readableValue = strings.Join(sans, " | ")
		}
	default:
		log.Debug().Msg("Unknown or unhandled extension")
	}
	return readableValue, nil
}

func pkixextensionToMql(runtime *plugin.Runtime, ext pkix.Extension, fingerprint string, id string) (*mqlPkixExtension, error) {
	value, err := ExtensionValueToReadableFormat(ext)
	if err != nil {
		value = string(ext.Value)
	}
	r, err := CreateResource(runtime, "pkix.extension", map[string]*llx.RawData{
		"id":         llx.StringData(id),
		"identifier": llx.StringData(fingerprint + ":" + id),
		"critical":   llx.BoolData(ext.Critical),
		"value":      llx.StringData(value),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlPkixExtension), nil
}

func (r *mqlCertificates) id() (string, error) {
	return checksums.New.Add(r.Pem.Data).String(), nil
}

type mqlCertificatesInternal struct {
	lock    sync.Mutex
	parsed  bool
	certs   []*x509.Certificate
	skipped int
	err     error
}

// parsePem decodes the bundle once and shares the result between list and
// unparseable. Blocks that x509 rejects are skipped rather than failing the
// whole bundle: trust stores in the wild carry roots Go will not parse, and
// losing every root because of one of them leaves audits with nothing to read.
func (r *mqlCertificates) parsePem() ([]*x509.Certificate, int, error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	if !r.parsed {
		r.parsed = true

		pem := r.GetPem()
		if pem.Error != nil {
			r.err = errors.New("certificates are missing pem data: " + pem.Error.Error())
		} else {
			r.certs, r.skipped, r.err = certificates.ParseCertsFromPEMPartial(strings.NewReader(pem.Data))
			if r.err != nil {
				r.err = errors.New("certificate has invalid pem data: " + r.err.Error())
			} else if r.skipped > 0 {
				log.Warn().Int("skipped", r.skipped).Int("parsed", len(r.certs)).
					Msg("skipped certificates that could not be parsed")
			}
		}
	}

	return r.certs, r.skipped, r.err
}

func (r *mqlCertificates) list() ([]any, error) {
	certs, _, err := r.parsePem()
	if err != nil {
		return nil, err
	}

	return CertificatesToMqlCertificates(r.MqlRuntime, certs)
}

func (r *mqlCertificates) unparseable() (int64, error) {
	_, skipped, err := r.parsePem()
	if err != nil {
		return 0, err
	}

	return int64(skipped), nil
}

// CertificatesToMqlCertificates takes a collection of x509 certs
// and converts it into MQL certificate objects
func CertificatesToMqlCertificates(runtime *plugin.Runtime, certs []*x509.Certificate) ([]any, error) {
	res := []any{}
	// to create certificate resources
	for i := range certs {
		cert := certs[i]

		if cert == nil {
			continue
		}

		certdata, err := certificates.EncodeCertAsPEM(cert)
		if err != nil {
			return nil, err
		}

		r, err := CreateResource(runtime, "certificate", map[string]*llx.RawData{
			"pem": llx.StringData(string(certdata)),
			// NOTE: if we do not set the hash here, it will generate the cache content before we can store it
			// we are using the hashes for the id, therefore it is required during creation
			"fingerprints": llx.MapData(certificates.Fingerprints(cert), types.String),
		})
		if err != nil {
			return nil, err
		}

		c := r.(*mqlCertificate)
		c.cert = plugin.TValue[*x509.Certificate]{
			Data:  cert,
			State: plugin.StateIsSet,
		}

		res = append(res, c)
	}
	return res, nil
}

func (r *mqlCertificate) id() (string, error) {
	fp := r.GetFingerprints()
	if fp.Error != nil {
		return "", fp.Error
	}
	x, ok := fp.Data["sha256"]
	if !ok {
		return "", errors.New("missing sha256 fingerprints for certificate")
	}

	return "certificate:" + x.(string), nil
}

// oidSCTList is the OID for the Certificate Transparency SCT List extension (1.3.6.1.4.1.11129.2.4.2)
var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

func certificateHasSCTs(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSCTList) {
			return true
		}
	}
	return false
}

func publicKeyBitSize(cert *x509.Certificate) int64 {
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return int64(key.N.BitLen())
	case *ecdsa.PublicKey:
		return int64(key.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

type mqlCertificateInternal struct {
	cert             plugin.TValue[*x509.Certificate]
	allCertFieldsSet bool
	lock             sync.Mutex
}

func (s *mqlCertificate) parse() ([]*x509.Certificate, error) {
	pem := s.GetPem()
	if pem.Error != nil {
		return nil, errors.New("certificate is missing pem data: " + pem.Error.Error())
	}

	certs, err := certificates.ParseCertsFromPEM(strings.NewReader(pem.Data))
	if err != nil {
		return nil, errors.New("certificate has invalid pem data: " + err.Error())
	}

	return certs, nil
}

func (s *mqlCertificate) getGoCert() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cert.State&plugin.StateIsSet == 0 {
		certs, err := s.parse()
		if err != nil {
			s.cert = plugin.TValue[*x509.Certificate]{State: plugin.StateIsSet, Error: err}
			return err
		}

		if len(certs) > 1 {
			log.Error().Msg("pem for cert contains more than one certificate, ignore additional certificates")
		}

		s.cert = plugin.TValue[*x509.Certificate]{Data: certs[0], State: plugin.StateIsSet}
	}

	if !s.allCertFieldsSet {
		s.allCertFieldsSet = true

		cert := s.cert.Data
		s.Fingerprints = plugin.TValue[map[string]any]{Data: certificates.Fingerprints(cert), State: plugin.StateIsSet}
		s.Serial = plugin.TValue[string]{Data: certificates.HexEncodeToHumanString(cert.SerialNumber.Bytes()), State: plugin.StateIsSet}
		s.SubjectKeyID = plugin.TValue[string]{Data: certificates.HexEncodeToHumanString(cert.SubjectKeyId), State: plugin.StateIsSet}
		s.AuthorityKeyID = plugin.TValue[string]{Data: certificates.HexEncodeToHumanString(cert.AuthorityKeyId), State: plugin.StateIsSet}
		s.Version = plugin.TValue[int64]{Data: int64(cert.Version), State: plugin.StateIsSet}
		s.IsCA = plugin.TValue[bool]{Data: cert.IsCA, State: plugin.StateIsSet}
		s.NotBefore = plugin.TValue[*time.Time]{Data: &cert.NotBefore, State: plugin.StateIsSet}
		s.NotAfter = plugin.TValue[*time.Time]{Data: &cert.NotAfter, State: plugin.StateIsSet}
		diff := cert.NotAfter.Unix() - time.Now().Unix()
		expiresIn := llx.DurationToTime(diff)
		s.ExpiresIn = plugin.TValue[*time.Time]{Data: &expiresIn, State: plugin.StateIsSet}
		s.SigningAlgorithm = plugin.TValue[string]{Data: cert.SignatureAlgorithm.String(), State: plugin.StateIsSet}
		s.Signature = plugin.TValue[string]{Data: hex.EncodeToString(cert.Signature), State: plugin.StateIsSet}
		s.CrlDistributionPoints = plugin.TValue[[]any]{Data: llx.TArr2Raw(cert.CRLDistributionPoints), State: plugin.StateIsSet}
		s.OcspServer = plugin.TValue[[]any]{Data: llx.TArr2Raw(cert.OCSPServer), State: plugin.StateIsSet}
		s.IssuingCertificateUrl = plugin.TValue[[]any]{Data: llx.TArr2Raw(cert.IssuingCertificateURL), State: plugin.StateIsSet}
		s.PublicKeyAlgorithm = plugin.TValue[string]{Data: cert.PublicKeyAlgorithm.String(), State: plugin.StateIsSet}
		s.PublicKeyBits = plugin.TValue[int64]{Data: publicKeyBitSize(cert), State: plugin.StateIsSet}
		s.IsExpired = plugin.TValue[bool]{Data: time.Now().After(cert.NotAfter), State: plugin.StateIsSet}
		s.HasSCTs = plugin.TValue[bool]{Data: certificateHasSCTs(cert), State: plugin.StateIsSet}
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			s.MaxPathLen = plugin.TValue[int64]{Data: int64(cert.MaxPathLen), State: plugin.StateIsSet}
		} else {
			s.MaxPathLen = plugin.TValue[int64]{State: plugin.StateIsSet | plugin.StateIsNull}
		}
	}

	// in case the cert was already set, use the cached error state
	return s.cert.Error
}

func (s *mqlCertificate) fingerprints() (map[string]any, error) {
	return nil, s.getGoCert()
}

func (s *mqlCertificate) serial() (string, error) {
	// TODO: we may want return bytes and leave the printing to runtime
	return "", s.getGoCert()
}

func (s *mqlCertificate) subjectKeyID() (string, error) {
	// TODO: we may want return bytes and leave the printing to runtime
	return "", s.getGoCert()
}

func (s *mqlCertificate) authorityKeyID() (string, error) {
	// TODO: we may want return bytes and leave the printing to runtime
	return "", s.getGoCert()
}

func (s *mqlCertificate) subject() (*mqlPkixName, error) {
	if err := s.getGoCert(); err != nil {
		return nil, err
	}

	fingerprint := hex.EncodeToString(certificates.Sha256Hash(s.cert.Data))
	mqlSubject, err := pkixnameToMql(s.MqlRuntime, s.cert.Data.Subject, fingerprint+":subject")
	if err != nil {
		return nil, err
	}
	return mqlSubject, nil
}

func (s *mqlCertificate) issuer() (*mqlPkixName, error) {
	if err := s.getGoCert(); err != nil {
		return nil, err
	}

	fingerprint := hex.EncodeToString(certificates.Sha256Hash(s.cert.Data))
	mqlIssuer, err := pkixnameToMql(s.MqlRuntime, s.cert.Data.Issuer, fingerprint+":issuer")
	if err != nil {
		return nil, err
	}
	return mqlIssuer, nil
}

func (s *mqlCertificate) version() (int64, error) {
	return 0, s.getGoCert()
}

func (s *mqlCertificate) isCA() (bool, error) {
	return false, s.getGoCert()
}

func (s *mqlCertificate) notBefore() (*time.Time, error) {
	return nil, s.getGoCert()
}

func (s *mqlCertificate) notAfter() (*time.Time, error) {
	return nil, s.getGoCert()
}

func (s *mqlCertificate) expiresIn() (*time.Time, error) {
	return nil, s.getGoCert()
}

var keyusageNames = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "DigitalSignature",
	x509.KeyUsageContentCommitment: "ContentCommitment",
	x509.KeyUsageKeyEncipherment:   "KeyEncipherment",
	x509.KeyUsageDataEncipherment:  "DataEncipherment",
	x509.KeyUsageKeyAgreement:      "KeyAgreement",
	x509.KeyUsageCertSign:          "CertificateSign",
	x509.KeyUsageCRLSign:           "CRLSign",
	x509.KeyUsageEncipherOnly:      "EncipherOnly",
	x509.KeyUsageDecipherOnly:      "DecipherOnly",
}

func (s *mqlCertificate) keyUsage() ([]any, error) {
	if err := s.getGoCert(); err != nil {
		return nil, err
	}

	res := []any{}
	for k := range keyusageNames {
		if s.cert.Data.KeyUsage&k != 0 {
			res = append(res, keyusageNames[k])
		}
	}

	return res, nil
}

var extendendkeyusageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                            "Any",
	x509.ExtKeyUsageServerAuth:                     "ServerAuth",
	x509.ExtKeyUsageClientAuth:                     "ClientAuth",
	x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
	x509.ExtKeyUsageEmailProtection:                "EmailProtection",
	x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
	x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
	x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
	x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
	x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
	x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
	x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
}

func (s *mqlCertificate) extendedKeyUsage() ([]any, error) {
	if err := s.getGoCert(); err != nil {
		return nil, err
	}

	res := []any{}
	for i := range s.cert.Data.ExtKeyUsage {
		entry := s.cert.Data.ExtKeyUsage[i]
		val, ok := extendendkeyusageNames[entry]
		if !ok {
			return nil, fmt.Errorf("unknown extended key usage %d", s.cert.Data.KeyUsage)
		}
		res = append(res, val)
	}
	return res, nil
}

func (s *mqlCertificate) extensions() ([]any, error) {
	if err := s.getGoCert(); err != nil {
		return nil, err
	}

	cert := s.cert.Data
	res := []any{}
	fingerprint := hex.EncodeToString(certificates.Sha256Hash(cert))
	for i := range cert.Extensions {
		extension := cert.Extensions[i]
		ext, err := pkixextensionToMql(s.MqlRuntime, extension, fingerprint, extension.Id.String())
		if err != nil {
			return nil, err
		}
		res = append(res, ext)
	}
	return res, nil
}

func (s *mqlCertificate) sanExtension() (*mqlPkixSanExtension, error) {
	if err := s.getGoCert(); err != nil {
		return nil, err
	}

	cert := s.cert.Data
	fingerprint := hex.EncodeToString(certificates.Sha256Hash(cert))
	extension := certificates.GetSanExtension(cert)
	if extension == nil {
		s.SanExtension.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	ext, err := pkixextensionToMql(s.MqlRuntime, *extension, fingerprint, extension.Id.String())
	if err != nil {
		return nil, err
	}

	dnsNames, emailAddresses, ipAddresses, URIs, err := certificates.ParseSANExtension(extension.Value)
	if err != nil {
		return nil, err
	}

	ipAddressesValues := []any{}
	for i := range ipAddresses {
		ipAddressesValues = append(ipAddressesValues, ipAddresses[i].String())
	}

	uriValues := []any{}
	for i := range URIs {
		uriValues = append(uriValues, URIs[i].String())
	}

	r, err := CreateResource(s.MqlRuntime, "pkix.sanExtension", map[string]*llx.RawData{
		"extension":      llx.ResourceData(ext, "pkix.extension"),
		"dnsNames":       llx.ArrayData(convert.SliceAnyToInterface(dnsNames), types.String),
		"ipAddresses":    llx.ArrayData(ipAddressesValues, types.String),
		"emailAddresses": llx.ArrayData(convert.SliceAnyToInterface(emailAddresses), types.String),
		"uris":           llx.ArrayData(uriValues, types.String),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlPkixSanExtension), nil
}

func (s *mqlCertificate) policyIdentifier() ([]any, error) {
	if err := s.getGoCert(); err != nil {
		return nil, err
	}

	cert := s.cert.Data
	res := []any{}
	for i := range cert.PolicyIdentifiers {
		res = append(res, cert.PolicyIdentifiers[i].String())
	}
	return res, nil
}

func (s *mqlCertificate) signingAlgorithm() (string, error) {
	return "", s.getGoCert()
}

func (s *mqlCertificate) signature() (string, error) {
	// TODO: return bytes
	return "", s.getGoCert()
}

func (s *mqlCertificate) crlDistributionPoints() ([]any, error) {
	return nil, s.getGoCert()
}

func (s *mqlCertificate) ocspServer() ([]any, error) {
	return nil, s.getGoCert()
}

func (s *mqlCertificate) issuingCertificateUrl() ([]any, error) {
	return nil, s.getGoCert()
}

// A certificate parsed from PEM rather than served over a connection has no
// revocation check behind it, so all three fields report that nothing was
// determined. The tls resource populates them directly when it builds a
// certificate from a chain it checked.
func (s *mqlCertificate) isRevoked() (bool, error) {
	s.IsRevoked.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (s *mqlCertificate) revokedAt() (*time.Time, error) {
	s.RevokedAt.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (s *mqlCertificate) revocationChecked() (bool, error) {
	return false, nil
}

func (s *mqlCertificate) isVerified() (bool, error) {
	return false, nil
}

func (s *mqlCertificate) publicKeyAlgorithm() (string, error) {
	return "", s.getGoCert()
}

func (s *mqlCertificate) publicKeyBits() (int64, error) {
	return 0, s.getGoCert()
}

func (s *mqlCertificate) isExpired() (bool, error) {
	return false, s.getGoCert()
}

func (s *mqlCertificate) hasSCTs() (bool, error) {
	return false, s.getGoCert()
}

func (s *mqlCertificate) maxPathLen() (int64, error) {
	return 0, s.getGoCert()
}

func (r *mqlPkixName) id() (string, error) {
	return r.Id.Data, nil
}

func (r *mqlPkixExtension) id() (string, error) {
	return r.Identifier.Data, nil
}

func (r *mqlPkixSanExtension) id() (string, error) {
	return r.Extension.Data.Identifier.Data, nil
}
