// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// LabelIntuneDeviceID is the platform label holding the Microsoft Intune
	// managed device ID, taken from the device's Intune MDM certificate.
	LabelIntuneDeviceID = "microsoft.com/intune-device-id"
	// LabelEntraTenantID is the platform label holding the Microsoft Entra
	// tenant ID the device is enrolled in.
	LabelEntraTenantID = "microsoft.com/entra-tenant-id"
	// LabelEntraDeviceID is the platform label holding the Microsoft Entra
	// device ID, taken from the device's Entra device certificate.
	LabelEntraDeviceID = "microsoft.com/entra-device-id"

	// intuneMDMIssuerCN is the issuing CA of the Intune MDM device certificate.
	// Matched exactly: other Intune-issued certificates on a device carry
	// similar names and are not the enrollment identity.
	intuneMDMIssuerCN = "Microsoft Intune MDM Device CA"
	// entraDeviceIssuerCN is the issuer common name of the Entra device
	// certificate created when a device joins Entra.
	entraDeviceIssuerCN = "MS-Organization-Access"
)

var (
	// oidIntuneTenantID is the Intune MDM certificate extension carrying the
	// tenant ID as a 16-byte GUID.
	oidIntuneTenantID = asn1.ObjectIdentifier{1, 2, 840, 113556, 5, 14}
	// oidEntraTenantID is the Entra device certificate extension carrying the
	// tenant ID as a 16-byte GUID.
	oidEntraTenantID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 5, 284, 5}
)

// DeviceIdentity is the Microsoft identity of a Windows device, as read from
// the public device certificates in the local machine's personal store.
type DeviceIdentity struct {
	IntuneDeviceID string
	EntraTenantID  string
	EntraDeviceID  string
}

// Empty reports whether no identity was found.
func (d DeviceIdentity) Empty() bool {
	return d.IntuneDeviceID == "" && d.EntraTenantID == "" && d.EntraDeviceID == ""
}

// SetLabels writes the non-empty identity fields as platform labels.
func (d DeviceIdentity) SetLabels(pf *inventory.Platform) {
	if pf.Labels == nil {
		pf.Labels = map[string]string{}
	}
	if d.IntuneDeviceID != "" {
		pf.Labels[LabelIntuneDeviceID] = d.IntuneDeviceID
	}
	if d.EntraTenantID != "" {
		pf.Labels[LabelEntraTenantID] = d.EntraTenantID
	}
	if d.EntraDeviceID != "" {
		pf.Labels[LabelEntraDeviceID] = d.EntraDeviceID
	}
}

// IntunePlatformID returns the Intune platform ID for the device, or "" when
// the device ID or the tenant ID is unknown. The ID is scoped by tenant because
// an Intune device ID is only meaningful within its tenant.
func (d DeviceIdentity) IntunePlatformID() string {
	if d.IntuneDeviceID == "" || d.EntraTenantID == "" {
		return ""
	}
	return "//platformid.api.mondoo.app/runtime/intune/tenants/" + d.EntraTenantID + "/devices/" + d.IntuneDeviceID
}

// IdentityDetectable reports whether the Microsoft device identity is read on
// this Windows edition: workstations (product-type "1") and Windows 11
// Enterprise Multi-Session, which reports product-type "3".
//
// Callers need this to tell "not a member" from "never looked". A server is not
// asked for its certificates, so absent identity labels there say nothing about
// whether the device is Entra-joined, and a consumer must report null rather
// than a measured false.
func IdentityDetectable(pf *inventory.Platform) bool {
	if pf == nil {
		return false
	}
	isWorkstation := pf.Labels["windows.mondoo.com/product-type"] == "1"
	isWindows11MultiSession := pf.Labels["windows.mondoo.com/product-type"] == "3" &&
		strings.Contains(pf.Title, "Windows 11") &&
		strings.Contains(pf.Title, "Multi-Session")
	return isWorkstation || isWindows11MultiSession
}

// DeviceIdentityFromLabels reads a previously detected identity from the
// platform labels.
func DeviceIdentityFromLabels(pf *inventory.Platform) DeviceIdentity {
	if pf == nil || pf.Labels == nil {
		return DeviceIdentity{}
	}
	return DeviceIdentity{
		IntuneDeviceID: pf.Labels[LabelIntuneDeviceID],
		EntraTenantID:  pf.Labels[LabelEntraTenantID],
		EntraDeviceID:  pf.Labels[LabelEntraDeviceID],
	}
}

// ParseDeviceCertificates derives the device identity from DER-encoded
// certificates of the local machine's personal store. Certificates that are
// not an Intune MDM or Entra device certificate are ignored, as are malformed
// ones. preferIntuneID, when set, picks the Intune certificate matching the
// device's enrollment ID if several are present (e.g. during renewal).
func ParseDeviceCertificates(ders [][]byte, preferIntuneID string) DeviceIdentity {
	var intune []parsedCert
	var entra []parsedCert
	for _, der := range ders {
		c, err := parseCert(der)
		if err != nil {
			continue
		}
		switch c.issuerCN {
		case intuneMDMIssuerCN:
			intune = append(intune, c)
		case entraDeviceIssuerCN:
			entra = append(entra, c)
		}
	}

	var id DeviceIdentity
	if c, ok := pickCert(intune, strings.ToLower(preferIntuneID)); ok {
		id.IntuneDeviceID = c.subjectGUID
		id.EntraTenantID = c.extGUID(oidIntuneTenantID)
	}
	if c, ok := pickCert(entra, ""); ok {
		id.EntraDeviceID = c.subjectGUID
		if id.EntraTenantID == "" {
			id.EntraTenantID = c.extGUID(oidEntraTenantID)
		}
	}
	return id
}

// pickCert returns the only distinct identity among certs, or the one matching
// prefer. Several distinct identities without a match are ambiguous, and no
// identity is reported rather than a guessed one.
func pickCert(certs []parsedCert, prefer string) (parsedCert, bool) {
	distinct := map[string]parsedCert{}
	for _, c := range certs {
		if c.subjectGUID == "" {
			continue
		}
		distinct[c.subjectGUID] = c
	}
	if c, ok := distinct[prefer]; ok && prefer != "" {
		return c, true
	}
	if len(distinct) == 1 {
		for _, c := range distinct {
			return c, true
		}
	}
	return parsedCert{}, false
}

type parsedCert struct {
	issuerCN    string
	subjectGUID string
	extensions  []pkix.Extension
}

func (c parsedCert) extGUID(oid asn1.ObjectIdentifier) string {
	for _, e := range c.extensions {
		if e.Id.Equal(oid) {
			return guidFromExtension(e.Value)
		}
	}
	return ""
}

// The structures below decode only the fields needed here. crypto/x509 is not
// used because it rejects certificates with a negative serial number, which
// some Microsoft device certificate chains contain; the serial is irrelevant
// for reading the subject, issuer and extensions.
type rawCertificate struct {
	TBS                rawTBSCertificate
	SignatureAlgorithm asn1.RawValue
	Signature          asn1.BitString
}

type rawTBSCertificate struct {
	Version            int `asn1:"optional,explicit,default:0,tag:0"`
	SerialNumber       asn1.RawValue
	SignatureAlgorithm asn1.RawValue
	Issuer             asn1.RawValue
	Validity           asn1.RawValue
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	IssuerUniqueID     asn1.BitString   `asn1:"optional,tag:1"`
	SubjectUniqueID    asn1.BitString   `asn1:"optional,tag:2"`
	Extensions         []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func parseCert(der []byte) (parsedCert, error) {
	var raw rawCertificate
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return parsedCert{}, err
	}
	if len(rest) != 0 {
		return parsedCert{}, errors.New("trailing data after certificate")
	}
	issuer, err := commonName(raw.TBS.Issuer.FullBytes)
	if err != nil {
		return parsedCert{}, err
	}
	subject, err := commonName(raw.TBS.Subject.FullBytes)
	if err != nil {
		return parsedCert{}, err
	}
	return parsedCert{
		issuerCN:    issuer,
		subjectGUID: normalizeGUID(subject),
		extensions:  raw.TBS.Extensions,
	}, nil
}

func commonName(name []byte) (string, error) {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(name, &rdns); err != nil {
		return "", err
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdns)
	return n.CommonName, nil
}

// guidFromExtension decodes a 16-byte GUID from an extension value. The value
// is either the 16 raw bytes or an OCTET STRING wrapping them; Microsoft uses
// both, and sometimes a non-minimal length encoding that encoding/asn1 rejects.
func guidFromExtension(v []byte) string {
	if len(v) == 16 {
		return guidFromMicrosoftBytes(v)
	}
	if len(v) < 2 || v[0] != 0x04 {
		return ""
	}
	n, off := int(v[1]), 2
	if v[1]&0x80 != 0 {
		lenBytes := int(v[1] & 0x7f)
		if lenBytes == 0 || lenBytes > 2 || len(v) < 2+lenBytes {
			return ""
		}
		n = 0
		for _, b := range v[2 : 2+lenBytes] {
			n = n<<8 | int(b)
		}
		off = 2 + lenBytes
	}
	if n != 16 || len(v) != off+16 {
		return ""
	}
	return guidFromMicrosoftBytes(v[off:])
}

// guidFromMicrosoftBytes formats a GUID stored in Microsoft byte order: the
// first three fields are little-endian, the last two are big-endian.
func guidFromMicrosoftBytes(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	o := []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
	return normalizeGUID(formatGUID(o))
}

func formatGUID(b []byte) string {
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// normalizeGUID returns s as a lowercase dashed GUID, or "" when s is not a
// GUID or is the all-zero GUID.
func normalizeGUID(s string) string {
	s = strings.ToLower(strings.TrimSpace(strings.Trim(s, "{}")))
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return ""
	}
	raw := strings.ReplaceAll(s, "-", "")
	if _, err := hex.DecodeString(raw); err != nil || len(raw) != 32 {
		return ""
	}
	if strings.Trim(raw, "0") == "" {
		return ""
	}
	return s
}
