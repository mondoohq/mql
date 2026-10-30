// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/resources/dnsshake"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/dnssec"
)

// dnssec reports how the zone is signed, from the record sweep params already
// performed.
//
// Everything here is zone configuration and comes out of records the sweep
// already fetched, so widening it costs no extra queries. Whether a resolution
// of the zone actually validated is a different question with a different
// answer, and lives in dnssecValidation.
func (d *mqlDns) dnssec(params any) (*mqlDnsDnssecConfig, error) {
	paramsM, _ := params.(map[string]any)

	keyRecords := dnskeyRecordsFromParams(paramsM)

	keys := make([]any, 0, len(keyRecords))
	algoSet := map[int64]struct{}{}
	for _, key := range keyRecords {
		flags := int(key.Flags)
		keyResource, err := CreateResource(d.MqlRuntime, "dns.dnssecKey", map[string]*llx.RawData{
			"__id":          llx.StringData(fmt.Sprintf("dns.dnssecKey/%s/%d/%d/%s", d.Fqdn.Data, key.Algorithm, key.Flags, key.PublicKey)),
			"flags":         llx.IntData(int64(flags)),
			"protocol":      llx.IntData(int64(key.Protocol)),
			"algorithm":     llx.IntData(int64(key.Algorithm)),
			"algorithmName": llx.StringData(dnssec.AlgorithmName(int(key.Algorithm))),
			"keyLength":     llx.IntData(int64(dnssec.PublicKeyBits(int(key.Algorithm), key.PublicKey))),
			"publicKey":     llx.StringData(key.PublicKey),
			"keySigningKey": llx.BoolData(dnssec.IsKeySigningKey(flags)),
			"zoneKey":       llx.BoolData(dnssec.IsZoneKey(flags)),
			"revoked":       llx.BoolData(dnssec.IsRevoked(flags)),
		})
		if err != nil {
			return nil, err
		}
		keys = append(keys, keyResource)
		algoSet[int64(key.Algorithm)] = struct{}{}
	}

	algorithms := make([]any, 0, len(algoSet))
	for a := range algoSet {
		algorithms = append(algorithms, a)
	}
	slices.SortFunc(algorithms, func(a, b any) int {
		return cmp.Compare(a.(int64), b.(int64))
	})

	// The DS records live in the parent zone; a query for them at this name is
	// answered by the parent, which is what makes the delegation visible from
	// here at all.
	dsRecordsRaw := dsRecordsFromParams(paramsM)
	dsRecords := make([]any, 0, len(dsRecordsRaw))
	allDsMatch := len(dsRecordsRaw) > 0
	for _, ds := range dsRecordsRaw {
		matches := delegationMatchesKey(ds, keyRecords)
		if !matches {
			allDsMatch = false
		}

		res, err := CreateResource(d.MqlRuntime, "dns.dsRecord", map[string]*llx.RawData{
			"__id":                llx.StringData(fmt.Sprintf("dns.dsRecord/%s/%d/%d/%s", d.Fqdn.Data, ds.Algorithm, ds.DigestType, ds.Digest)),
			"algorithm":           llx.IntData(int64(ds.Algorithm)),
			"algorithmName":       llx.StringData(dnssec.AlgorithmName(int(ds.Algorithm))),
			"digestType":          llx.IntData(int64(ds.DigestType)),
			"digestTypeName":      llx.StringData(dnssec.DigestTypeName(int(ds.DigestType))),
			"digest":              llx.StringData(ds.Digest),
			"matchesPublishedKey": llx.BoolData(matches),
		})
		if err != nil {
			return nil, err
		}
		dsRecords = append(dsRecords, res)
	}

	// A signed zone proves a name absent with either NSEC or NSEC3, and the
	// only positive signal for NSEC3 is the NSEC3PARAM record. An unsigned zone
	// proves nothing, so it reports neither rather than defaulting to NSEC.
	denialOfExistence := ""
	nsec3 := nsec3ParamFromParams(paramsM)
	switch {
	case nsec3 != nil:
		denialOfExistence = "NSEC3"
	case len(keyRecords) > 0:
		denialOfExistence = "NSEC"
	}

	var nsec3Iterations, nsec3SaltLength, nsec3HashAlgorithm int64
	nsec3OptOut := false
	if nsec3 != nil {
		nsec3Iterations = int64(nsec3.Iterations)
		nsec3SaltLength = int64(dnssec.NSEC3SaltLength(nsec3.Salt))
		nsec3HashAlgorithm = int64(nsec3.Hash)
		nsec3OptOut = dnssec.NSEC3OptOut(int(nsec3.Flags))
	}

	res, err := CreateResource(d.MqlRuntime, "dns.dnssecConfig", map[string]*llx.RawData{
		"__id":               llx.StringData("dns.dnssecConfig/" + d.Fqdn.Data),
		"enabled":            llx.BoolData(len(keys) > 0),
		"keys":               llx.ArrayData(keys, types.Resource("dns.dnssecKey")),
		"algorithms":         llx.ArrayData(algorithms, types.Int),
		"delegationSigned":   llx.BoolData(len(dsRecordsRaw) > 0),
		"dsRecords":          llx.ArrayData(dsRecords, types.Resource("dns.dsRecord")),
		"dsDigestsMatchKeys": llx.BoolData(allDsMatch),
		"denialOfExistence":  llx.StringData(denialOfExistence),
		"nsec3Iterations":    llx.IntData(nsec3Iterations),
		"nsec3SaltLength":    llx.IntData(nsec3SaltLength),
		"nsec3OptOut":        llx.BoolData(nsec3OptOut),
		"nsec3HashAlgorithm": llx.IntData(nsec3HashAlgorithm),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDnsDnssecConfig), nil
}

// delegationMatchesKey reports whether a DS record digests one of the keys the
// zone publishes.
//
// A parent that still publishes a DS for a rolled key is the failure this
// catches: the zone looks correctly signed from the inside and fails to
// validate everywhere else.
func delegationMatchesKey(ds *dns.DS, keys []*dns.DNSKEY) bool {
	for _, key := range keys {
		digest, err := dnssec.DSDigest(
			key.Hdr.Name,
			int(key.Flags), int(key.Protocol), int(key.Algorithm),
			key.PublicKey,
			int(ds.DigestType),
		)
		if err != nil {
			continue
		}
		if strings.EqualFold(digest, ds.Digest) {
			return true
		}
	}
	return false
}

// recordsFromParams re-parses one record type out of a params dict back into
// wire records.
//
// The sweep stores each answer as its presentation-format rdata, so getting a
// typed record back means reassembling the line the rdata came from. A record
// that does not parse is skipped rather than taking the whole set down with
// it: one malformed DNSKEY should cost that key, not every key in the zone.
func recordsFromParams(paramsM map[string]any, recordType string) []dns.RR {
	records := []dns.RR{}
	if paramsM == nil {
		return records
	}

	entry, ok := paramsM[recordType].(map[string]any)
	if !ok || entry["rCode"] != dns.RcodeToString[dns.RcodeSuccess] {
		return records
	}

	name, _ := entry["name"].(string)
	class, _ := entry["class"].(string)
	var ttl int64
	if v, ok := dictTTL(entry); ok {
		ttl = v
	}
	rdata, _ := entry["rData"].([]any)

	for i := range rdata {
		value, ok := rdata[i].(string)
		if !ok {
			continue
		}

		line := name + "\t" + strconv.FormatInt(ttl, 10) + "\t" + class + "\t" + recordType + "\t" + value
		rr, err := dns.NewRR(line)
		if err != nil || rr == nil {
			continue
		}
		records = append(records, rr)
	}

	return records
}

// dnskeyRecordsFromParams reads the zone's published DNSKEY records.
func dnskeyRecordsFromParams(paramsM map[string]any) []*dns.DNSKEY {
	keys := []*dns.DNSKEY{}
	for _, rr := range recordsFromParams(paramsM, "DNSKEY") {
		if key, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// dsRecordsFromParams reads the DS records the parent zone publishes for this
// zone.
func dsRecordsFromParams(paramsM map[string]any) []*dns.DS {
	records := []*dns.DS{}
	for _, rr := range recordsFromParams(paramsM, "DS") {
		if ds, ok := rr.(*dns.DS); ok {
			records = append(records, ds)
		}
	}
	return records
}

// nsec3ParamFromParams reads the zone's NSEC3PARAM record, which is the only
// positive statement that a zone uses NSEC3 rather than NSEC. Returns nil when
// the zone publishes none.
func nsec3ParamFromParams(paramsM map[string]any) *dns.NSEC3PARAM {
	for _, rr := range recordsFromParams(paramsM, "NSEC3PARAM") {
		if p, ok := rr.(*dns.NSEC3PARAM); ok {
			return p
		}
	}
	return nil
}

// dnssecVerdicts maps the four fields that are read off the answer's signatures.
//
// All four are unknown when the resolver did not honor the DNSSEC OK bit: it
// then returns the same unsigned-looking answer for a signed zone and an
// unsigned one, so reporting false would assert that a zone is unsigned on the
// strength of an answer that was never going to carry a signature. dnssecOk
// itself, the response code and the resolver's authenticated-data flag are
// facts about the exchange rather than about the zone, so they stay populated
// and the reason remains readable.
func dnssecVerdicts(validation *dnsshake.DnssecValidation, signaturesCurrentlyValid bool) (
	signed *llx.RawData, signaturesVerified *llx.RawData,
	chainOfTrustValidated *llx.RawData, currentlyValid *llx.RawData,
) {
	if !validation.DnssecOk {
		return llx.NilData, llx.NilData, llx.NilData, llx.NilData
	}

	return llx.BoolData(len(validation.Signatures) > 0),
		llx.BoolData(validation.SignaturesVerified),
		llx.BoolData(validation.ChainOfTrustValidated),
		llx.BoolData(signaturesCurrentlyValid)
}

// dnssecValidation resolves the domain with DNSSEC requested and reports what
// the resolution actually produced.
//
// Unlike dnssec, this is not derived from the record sweep: it issues its own
// queries with the DNSSEC OK bit set, because the sweep does not ask for
// DNSSEC records and so never sees a signature.
func (d *mqlDns) dnssecValidation(fqdn string) (*mqlDnsDnssecValidationResult, error) {
	// An asset scanned by IP address has no name to validate. Report nothing
	// rather than validating the root zone, which would describe "." instead of
	// the asset.
	if fqdn == "" {
		d.DnssecValidation.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	shaker, err := dnsshake.New(fqdn)
	if err != nil {
		return nil, err
	}

	// A is what an operator means by "does resolving this name validate". SOA
	// is the fallback for a name that publishes no address, because every zone
	// apex has one and an empty answer would otherwise read as an unsigned
	// zone.
	validation, err := shaker.ValidateDnssec("A", "SOA")
	if err != nil {
		return nil, err
	}

	now := time.Now()

	signatures := make([]any, 0, len(validation.Signatures))
	signerSet := map[string]struct{}{}
	algoSet := map[int64]struct{}{}
	signaturesCurrentlyValid := len(validation.Signatures) > 0
	var earliestExpiry time.Time

	for _, sig := range validation.Signatures {
		window := sig.Window()
		if !window.Valid(now) {
			signaturesCurrentlyValid = false
		}
		if earliestExpiry.IsZero() || sig.Expiration.Before(earliestExpiry) {
			earliestExpiry = sig.Expiration
		}
		signerSet[sig.SignerName] = struct{}{}
		algoSet[int64(sig.Algorithm)] = struct{}{}

		expiresIn := llx.DurationToTime(int64(window.RemainingValidity(now).Seconds()))
		inception := sig.Inception
		expiration := sig.Expiration

		res, err := CreateResource(d.MqlRuntime, "dns.rrsigRecord", map[string]*llx.RawData{
			"__id": llx.StringData(fmt.Sprintf("dns.rrsigRecord/%s/%s/%s/%d/%s",
				fqdn, sig.Name, sig.TypeCovered, sig.Algorithm, sig.Fingerprint)),
			"name":          llx.StringData(sig.Name),
			"typeCovered":   llx.StringData(sig.TypeCovered),
			"algorithm":     llx.IntData(int64(sig.Algorithm)),
			"algorithmName": llx.StringData(sig.AlgorithmName),
			"labels":        llx.IntData(int64(sig.Labels)),
			"originalTtl":   llx.IntData(sig.OriginalTTL),
			"inception":     llx.TimeData(inception),
			"expiration":    llx.TimeData(expiration),
			"expiresIn":     llx.TimeData(expiresIn),
			"expired":       llx.BoolData(window.Expired(now)),
			"notYetValid":   llx.BoolData(window.NotYetValid(now)),
			"signerName":    llx.StringData(sig.SignerName),
		})
		if err != nil {
			return nil, err
		}
		signatures = append(signatures, res)
	}

	signerNames := make([]any, 0, len(signerSet))
	for name := range signerSet {
		signerNames = append(signerNames, name)
	}
	slices.SortFunc(signerNames, func(a, b any) int {
		return strings.Compare(a.(string), b.(string))
	})

	algorithms := make([]any, 0, len(algoSet))
	for a := range algoSet {
		algorithms = append(algorithms, a)
	}
	slices.SortFunc(algorithms, func(a, b any) int {
		return cmp.Compare(a.(int64), b.(int64))
	})

	// Both expiry fields stay null when nothing was signed, rather than
	// reporting the zero time as a real date in the year 1.
	earliestExpiryData := llx.NilData
	expiresInData := llx.NilData
	if !earliestExpiry.IsZero() {
		earliestExpiryData = llx.TimeData(earliestExpiry)
		remaining := llx.DurationToTime(int64(earliestExpiry.Sub(now).Seconds()))
		expiresInData = llx.TimeData(remaining)
	}

	signedData, signaturesVerifiedData, chainOfTrustValidatedData, signaturesCurrentlyValidData :=
		dnssecVerdicts(validation, signaturesCurrentlyValid)

	res, err := CreateResource(d.MqlRuntime, "dns.dnssecValidationResult", map[string]*llx.RawData{
		"__id":                     llx.StringData("dns.dnssecValidationResult/" + fqdn),
		"name":                     llx.StringData(validation.Name),
		"recordType":               llx.StringData(validation.RecordType),
		"responseCode":             llx.StringData(validation.ResponseCode),
		"dnssecOk":                 llx.BoolData(validation.DnssecOk),
		"authenticatedData":        llx.BoolData(validation.AuthenticatedData),
		"signed":                   signedData,
		"signatures":               llx.ArrayData(signatures, types.Resource("dns.rrsigRecord")),
		"signaturesVerified":       signaturesVerifiedData,
		"chainOfTrustValidated":    chainOfTrustValidatedData,
		"chain":                    llx.ArrayData(llx.TArr2Raw(validation.Chain), types.String),
		"brokenAtZone":             llx.StringData(validation.BrokenAtZone),
		"signerNames":              llx.ArrayData(signerNames, types.String),
		"signatureAlgorithms":      llx.ArrayData(algorithms, types.Int),
		"earliestSignatureExpiry":  earliestExpiryData,
		"signatureExpiresIn":       expiresInData,
		"signaturesCurrentlyValid": signaturesCurrentlyValidData,
		"error":                    llx.StringData(validation.Error),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDnsDnssecValidationResult), nil
}
