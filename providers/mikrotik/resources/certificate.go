// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// routerOSTimeLayouts are the timestamp shapes RouterOS uses for certificate
// validity dates. RouterOS 7 reports ISO-style dates while RouterOS 6 reports
// the abbreviated-month form, and either may or may not carry a time zone.
// The month names RouterOS emits are lowercase; time.Parse matches month names
// case-insensitively, but only when the layout spells the chunk as "Jan", so a
// lowercase layout would silently degrade to a literal match on January.
var routerOSTimeLayouts = []string{
	"2006-01-02 15:04:05",
	"2006-01-02 15:04:05 MST",
	"2006-01-02T15:04:05Z07:00",
	"Jan/02/2006 15:04:05",
	"Jan/02/2006 15:04:05 MST",
}

// parseRouterOSTime converts a RouterOS timestamp to a time, returning nil for
// a value the device did not report or that none of the known layouts match.
// A nil result must stay null in the schema: coercing it to the zero time
// would report the year 1 as a real certificate date.
func parseRouterOSTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range routerOSTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// commonNameOf extracts the CN component of a distinguished name as RouterOS
// reports it, for example "C=US,O=Example,CN=Example CA".
func commonNameOf(dn string) string {
	for part := range strings.SplitSeq(dn, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "CN="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// certificateExpired reports whether a certificate's validity window has
// closed, or nil when the device did not report a date that could be read.
func certificateExpired(invalidAfter string, now time.Time) *bool {
	t := parseRouterOSTime(invalidAfter)
	if t == nil {
		return nil
	}
	expired := now.After(*t)
	return &expired
}

// certificateSelfSigned reports whether a certificate was issued by its own
// subject, or nil when either the issuer or the subject common name is
// missing, since neither absence proves the certificate has a real issuer.
func certificateSelfSigned(issuer, commonName string) *bool {
	issuerCN := commonNameOf(issuer)
	if issuerCN == "" || commonName == "" {
		return nil
	}
	self := issuerCN == commonName
	return &self
}

func certificateArgs(row map[string]string, now time.Time) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":            llx.StringData(rowID("mikrotik.certificate/", row, row["name"])),
		"name":            llx.StringData(row["name"]),
		"commonName":      llx.StringData(row["common-name"]),
		"subjectAltName":  llx.StringData(row["subject-alt-name"]),
		"issuer":          llx.StringData(row["issuer"]),
		"serialNumber":    llx.StringData(row["serial-number"]),
		"fingerprint":     llx.StringData(row["fingerprint"]),
		"keyType":         llx.StringData(row["key-type"]),
		"keySize":         intField(row, "key-size"),
		"digestAlgorithm": llx.StringData(row["digest-algorithm"]),
		"keyUsage":        listField(row, "key-usage"),
		"invalidBefore":   llx.TimeDataPtr(parseRouterOSTime(row["invalid-before"])),
		"invalidAfter":    llx.TimeDataPtr(parseRouterOSTime(row["invalid-after"])),
		"expiresAfter":    llx.StringData(row["expires-after"]),
		"expired":         llx.BoolDataPtr(certificateExpired(row["invalid-after"], now)),
		"selfSigned":      llx.BoolDataPtr(certificateSelfSigned(row["issuer"], row["common-name"])),
		// the private key itself is never read; only whether the device has one
		"hasPrivateKey": boolField(row, "private-key"),
		"trusted":       boolField(row, "trusted"),
		"crl":           boolField(row, "crl"),
		"smartCardKey":  boolField(row, "smart-card-key"),
		"akid":          llx.StringData(row["akid"]),
		"skid":          llx.StringData(row["skid"]),
	}
}

func newMikrotikCertificate(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.certificate", certificateArgs(row, time.Now()))
}

func (r *mqlMikrotik) certificates() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/certificate")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikCertificate)
}

// initMikrotikCertificate resolves a certificate looked up by name against the
// already-cached /certificate listing, so a service cross-reference costs a map
// scan rather than a device round-trip per service.
func initMikrotikCertificate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 || args["name"] == nil {
		return args, nil, nil
	}
	name, ok := args["name"].Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}
	rows, err := mikrotikConn(runtime).Print("/certificate")
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if row["name"] == name {
			return certificateArgs(row, time.Now()), nil, nil
		}
	}
	return nil, nil, fmt.Errorf("mikrotik.certificate %q is not in the device certificate store", name)
}

// certificateByName resolves a certificate reference carried by another
// resource. RouterOS writes "none" into a certificate property that has no
// certificate bound, so that sentinel resolves to null rather than to a
// certificate literally named "none".
func certificateByName(runtime *plugin.Runtime, name string) (*mqlMikrotikCertificate, error) {
	res, err := NewResource(runtime, "mikrotik.certificate", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikCertificate), nil
}

// certificateRefName normalizes the RouterOS "none" sentinel used by a
// certificate property with nothing bound to it.
func certificateRefName(v string) string {
	if v == "none" {
		return ""
	}
	return strings.TrimSpace(v)
}

// --- ip.service.certificateRef ---

type mqlMikrotikIpServiceInternal struct {
	cacheCertificate string
}

func (r *mqlMikrotikIpService) certificateRef() (*mqlMikrotikCertificate, error) {
	if r.cacheCertificate == "" {
		r.CertificateRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return certificateByName(r.MqlRuntime, r.cacheCertificate)
}
