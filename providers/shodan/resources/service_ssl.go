// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"github.com/shadowscatcher/shodan/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// buildTlsResource takes the SSL/TLS data Shodan emits for a single banner and
// produces a `shodan.host.tls` resource (with its certificate sub-resource
// attached).
func buildTlsResource(runtime *plugin.Runtime, ip string, port int, ssl *models.SSL) (*mqlShodanHostTls, error) {
	if ssl == nil {
		return nil, nil
	}

	versions := convert.SliceAnyToInterface(ssl.Versions)
	supported := make([]any, 0, len(ssl.Versions))
	for _, v := range ssl.Versions {
		// Shodan emits "TLSv1.2" for supported and "-TLSv1.0" for unsupported
		// versions. We want a clean list of supported versions.
		if !strings.HasPrefix(v, "-") {
			supported = append(supported, v)
		}
	}

	negotiates := func(needle string) bool {
		for _, v := range ssl.Versions {
			if strings.EqualFold(v, needle) {
				return true
			}
		}
		return false
	}

	sslv2 := negotiates("SSLv2")
	sslv3 := negotiates("SSLv3")
	tlsv10 := negotiates("TLSv1") || negotiates("TLSv1.0")
	tlsv11 := negotiates("TLSv1.1")
	tlsv12 := negotiates("TLSv1.2")
	tlsv13 := negotiates("TLSv1.3")
	hasInsecureProto := sslv2 || sslv3 || tlsv10 || tlsv11

	// SSL.Cert is a value type (not a pointer), so &ssl.Cert is always non-nil.
	// Banners with no parsed certificate (e.g. plaintext-on-TLS-port probes) leave
	// it zero-valued — skip building a phantom cert full of empty strings.
	var cert *mqlShodanHostCert
	if !isEmptySslCert(&ssl.Cert) {
		c, err := buildCertResource(runtime, ip, port, &ssl.Cert)
		if err != nil {
			return nil, err
		}
		cert = c
	}

	res, err := CreateResource(runtime, "shodan.host.tls", map[string]*llx.RawData{
		"__id":                llx.StringData(fmt.Sprintf("shodan.host.tls/%s/%d", ip, port)),
		"ip":                  llx.StringData(ip),
		"port":                llx.IntData(int64(port)),
		"versions":            llx.ArrayData(versions, types.String),
		"supportedVersions":   llx.ArrayData(supported, types.String),
		"sslv2":               llx.BoolData(sslv2),
		"sslv3":               llx.BoolData(sslv3),
		"tlsv10":              llx.BoolData(tlsv10),
		"tlsv11":              llx.BoolData(tlsv11),
		"tlsv12":              llx.BoolData(tlsv12),
		"tlsv13":              llx.BoolData(tlsv13),
		"hasInsecureProtocol": llx.BoolData(hasInsecureProto),
		"alpn":                llx.ArrayData(convert.SliceAnyToInterface(ssl.Alpn), types.String),
		"cipherName":          llx.StringData(ssl.Cipher.Name),
		"cipherBits":          llx.IntData(int64(ssl.Cipher.Bits)),
		"cipherVersion":       llx.StringData(ssl.Cipher.Version),
		"hasWeakCipher":       llx.BoolData(isWeakCipher(ssl.Cipher.Name, ssl.Cipher.Bits)),
		"cert":                optionalResource(cert),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlShodanHostTls), nil
}

// weakCipherPatterns lists substrings of cipher names commonly considered weak
// or broken. Matches case-insensitive. PSK is intentionally omitted because it
// is a key-exchange mechanism (legitimate in IoT and private-network TLS), not
// a broken primitive — narrow PSK_WITH_NULL/PSK_WITH_RC4 combinations are
// caught by the NULL/RC4 patterns below.
var weakCipherPatterns = []string{
	"NULL", "EXPORT", "ANON", "RC4", "DES", "3DES", "IDEA", "MD5",
}

func isWeakCipher(name string, bits int) bool {
	if name == "" {
		return false
	}
	upper := strings.ToUpper(name)
	for _, p := range weakCipherPatterns {
		if strings.Contains(upper, p) {
			return true
		}
	}
	if bits > 0 && bits < 128 {
		return true
	}
	return false
}

// isEmptySslCert reports whether the cert struct carries no parsed X.509 data.
// Shodan emits an empty cert object when the SSL probe didn't return one, so we
// use this to avoid creating a phantom resource full of empty strings.
func isEmptySslCert(cert *models.SslCert) bool {
	if cert == nil {
		return true
	}
	return cert.Subject.CN == "" &&
		cert.Issuer.CN == "" &&
		cert.Fingerprint.SHA256 == "" &&
		cert.Fingerprint.SHA1 == "" &&
		cert.Issued == "" &&
		cert.Expires == ""
}

// buildCertResource extracts the X.509 details Shodan publishes for a banner.
func buildCertResource(runtime *plugin.Runtime, ip string, port int, cert *models.SslCert) (*mqlShodanHostCert, error) {
	if cert == nil {
		return nil, nil
	}

	issued := optionalShodanTime(cert.Issued)
	expires := optionalShodanTime(cert.Expires)

	subjectCN := cert.Subject.CN
	subjectO := cert.Subject.O
	issuerCN := cert.Issuer.CN
	issuerO := cert.Issuer.O

	// A certificate is "self-signed" when the subject DN matches the issuer DN.
	// We approximate via subject CN == issuer CN (and matching org if set),
	// since Shodan does not expose the full DN equality flag.
	selfSigned := subjectCN != "" && subjectCN == issuerCN && subjectO == issuerO

	res, err := CreateResource(runtime, "shodan.host.cert", map[string]*llx.RawData{
		"__id":              llx.StringData(fmt.Sprintf("shodan.host.cert/%s/%d/%s", ip, port, cert.Fingerprint.SHA256)),
		"fingerprintSha256": llx.StringData(cert.Fingerprint.SHA256),
		"fingerprintSha1":   llx.StringData(cert.Fingerprint.SHA1),
		"expired":           llx.BoolData(cert.Expired),
		"issued":            issued,
		"expires":           expires,
		"subjectCN":         llx.StringData(subjectCN),
		"subjectO":          llx.StringData(subjectO),
		"issuerCN":          llx.StringData(issuerCN),
		"issuerO":           llx.StringData(issuerO),
		"sigAlg":            llx.StringData(cert.SigAlg),
		"pubkeyType":        llx.StringData(cert.Pubkey.Type),
		"pubkeyBits":        llx.IntData(int64(cert.Pubkey.Bits)),
		"serial":            llx.StringData(cert.Serial.String()),
		"version":           llx.IntData(int64(cert.Version)),
		"selfSigned":        llx.BoolData(selfSigned),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlShodanHostCert), nil
}
