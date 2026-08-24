// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/network/connection"
	"go.mondoo.com/mql/v13/providers/network/resources/dnsshake"
	"go.mondoo.com/mql/v13/providers/network/resources/domain"
	"go.mondoo.com/mql/v13/types"
	"go.mondoo.com/mql/v13/utils/sortx"
)

func (d *mqlDomainName) id() (string, error) {
	return "domainName/" + d.Fqdn.Data, nil
}

func initDomainName(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	fqdn, ok := args["fqdn"]
	if !ok {
		conn := runtime.Connection.(*connection.HostConnection)
		fqdn = llx.StringData(conn.FQDN())
		args["fqdn"] = fqdn
	}

	if fqdn == nil {
		return nil, nil, errors.New("domainName resource requires fqdn argument")
	}

	dn, err := domain.Parse(fqdn.Value.(string))
	if err != nil {
		return nil, nil, err
	}

	args["effectiveTLDPlusOne"] = llx.StringData(dn.EffectiveTLDPlusOne)
	args["tld"] = llx.StringData(dn.TLD)
	args["tldIcannManaged"] = llx.BoolData(dn.IcannManagedTLD)
	args["labels"] = llx.ArrayData(llx.TArr2Raw[string](dn.Labels), types.String)

	return args, nil, nil
}

func (d *mqlDns) id() (string, error) {
	return "dns/" + d.Fqdn.Data, nil
}

func initDns(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	_, ok := args["fqdn"]
	if !ok {
		conn := runtime.Connection.(*connection.HostConnection)
		fqdn := llx.StringData(conn.FQDN())

		// Check whether the fqdn is valid
		// In case of ssh connections, this could also be an ip address
		ip := net.ParseIP(fqdn.Value.(string))
		if ip == nil {
			args["fqdn"] = fqdn
		} else {
			args["fqdn"] = llx.StringData("")
		}
	}

	return args, nil, nil
}

// zone reports the apex of the zone that contains the domain, as a dns resource
// for that name.
//
// The records that describe a zone as a whole (DNSKEY, NS, SOA) exist at its
// apex and nowhere else inside it, so a question about how a zone is signed, or
// how many nameservers serve it, has an answer at this name and no answer at
// any other name the zone contains. Reading those fields through here answers
// for the containing zone; comparing fqdn against the returned fqdn tells an
// apex from a name that merely sits inside a zone.
//
// The zone is null rather than an error when the name belongs to no zone, which
// covers an unregistered domain and a scan target given as an IP address (see
// params for the empty-fqdn substitution). A failed query is still an error: a
// resolver outage must not read as a name that has no zone.
func (d *mqlDns) zone(fqdn string) (*mqlDns, error) {
	if fqdn == "" {
		d.Zone.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	dnsShaker, err := dnsshake.New(fqdn)
	if err != nil {
		return nil, err
	}

	zone, err := dnsShaker.Zone()
	if err != nil {
		return nil, err
	}
	if zone == "" {
		d.Zone.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// An apex is its own zone. NewResource consults the runtime cache, so this
	// resolves back to the receiver rather than building a second resource for
	// the same name, and the record sweep behind it is shared either way.
	res, err := NewResource(d.MqlRuntime, "dns", map[string]*llx.RawData{
		"fqdn": llx.StringData(zone),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlDns), nil
}

func (d *mqlDns) params(fqdn string) (any, error) {
	// initDns substitutes an empty fqdn when the scan target is an IP address
	// rather than a hostname. Querying an empty name resolves the DNS ROOT ZONE,
	// so every derived field described "." instead of the asset: scanning an IP
	// reported DNSSEC as enabled, NS redundancy as satisfied and no wildcards
	// present, none of which had anything to do with the target. Return no data
	// instead, so those checks report nothing rather than something wrong.
	if fqdn == "" {
		return nil, nil
	}

	dnsShaker, err := dnsshake.New(fqdn)
	if err != nil {
		return nil, err
	}

	records, err := dnsShaker.Query()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(records)
}

// authoritativeParams resolves the same records as params, but against the
// nameservers authoritative for the zone instead of a caching resolver.
//
// The answers are identical except for the TTL, which is the point: a caching
// resolver reports the time left on its cached entry, so a record configured
// with a TTL of 300 answers 300, then 208, then 144 as that entry ages. Any
// check asserting on a TTL has to read it from here, or it flaps purely on when
// the scan happened to run.
func (d *mqlDns) authoritativeParams(fqdn string) (any, error) {
	if fqdn == "" {
		return nil, nil
	}

	dnsShaker, err := dnsshake.New(fqdn)
	if err != nil {
		return nil, err
	}

	records, err := dnsShaker.QueryAuthoritative()
	if err != nil {
		return nil, err
	}

	return convert.JsonToDict(records)
}

// dictTTL reads a DNS record's TTL out of a record map produced by
// convert.JsonToDict (json.Marshal then Unmarshal of a dnsshake.DnsRecord).
// The map key is therefore the json tag "ttl" (not the Go field name "TTL"),
// and every JSON number decodes to float64, not int64. Reading "TTL" or
// asserting .(int64) is why the TTL was silently dropped (and would panic if
// the key were fixed without the type). Returns (0, false) when absent.
func dictTTL(m map[string]any) (int64, bool) {
	v, ok := m["ttl"].(float64)
	if !ok {
		return 0, false
	}
	return int64(v), true
}

func (d *mqlDns) records(params any) ([]any, error) {
	return d.recordsFromParams(params)
}

// authoritativeRecords parses the same shape as records, from answers the
// authoritative nameservers gave rather than a caching resolver. The records
// are the same; their TTLs are the configured values.
func (d *mqlDns) authoritativeRecords(authoritativeParams any) ([]any, error) {
	return d.recordsFromParams(authoritativeParams)
}

func (d *mqlDns) recordsFromParams(params any) ([]any, error) {
	// NOTE: mql does not cache the results of GetRecords since it has an input argument
	// Iterations over map keys are not deterministic and therefore we need to sort the keys

	// params is nil when there is no name to query, which is the case for an
	// asset scanned by IP address. Report no data rather than an error: the
	// query genuinely has no answer, and surfacing "incorrect structure of
	// params received" there is misleading, since nothing is malformed.
	if params == nil {
		return nil, nil
	}

	paramsM, ok := params.(map[string]any)
	if !ok {
		return nil, errors.New("incorrect structure of params received")
	}

	// convert responses to dns types
	resultMap := make(map[string]*mqlDnsRecord)
	for k := range paramsM {
		r, ok := paramsM[k].(map[string]any)
		if !ok {
			return nil, errors.New("incorrect structure of params entries received")
		}

		// filter by successful dns records
		if r["rCode"] != dns.RcodeToString[dns.RcodeSuccess] {
			continue
		}

		var ttl *llx.RawData
		if v, ok := dictTTL(r); ok {
			ttl = llx.IntData(v)
		} else {
			ttl = llx.NilData
		}
		o, err := CreateResource(d.MqlRuntime, "dns.record", map[string]*llx.RawData{
			"name":  llx.StringData(r["name"].(string)),
			"ttl":   ttl,
			"class": llx.StringData(r["class"].(string)),
			"type":  llx.StringData(r["type"].(string)),
			"rdata": llx.ArrayData(llx.TArr2Raw(r["rData"].([]any)), types.String),
		})
		if err != nil {
			return nil, err
		}

		record := o.(*mqlDnsRecord)
		resultMap[record.__id] = record
	}

	keys := sortx.Keys(resultMap)
	res := []any{}
	for i := range keys {
		res = append(res, resultMap[keys[i]])
	}

	return res, nil
}

func (d *mqlDnsRecord) id() (string, error) {
	return "dns.record/" + d.Name.Data + "/" + d.Class.Data + "/" + d.Type.Data, nil
}

func (d *mqlDns) mx(params any) ([]any, error) {
	paramsM, ok := params.(map[string]any)
	if !ok {
		return []any{}, nil
	}

	mxEntries := []any{}
	record, ok := paramsM["MX"]
	if !ok {
		return mxEntries, nil
	}

	r := record.(map[string]any)

	var name, c, t string
	var ttl int64
	var rdata []any

	if r["name"] != nil {
		name = r["name"].(string)
	}

	if r["class"] != nil {
		c = r["class"].(string)
	}

	if r["type"] != nil {
		t = r["type"].(string)
	}

	if v, ok := dictTTL(r); ok {
		ttl = v
	}

	if r["rData"] != nil {
		rdata = r["rData"].([]any)
	}

	for j := range rdata {
		entry := rdata[j].(string)

		// use dns package to parse mx entry
		s := name + "\t" + strconv.FormatInt(ttl, 10) + "\t" + c + "\t" + t + "\t" + entry
		got, err := dns.NewRR(s)
		if err != nil {
			return nil, err
		}

		switch v := got.(type) {
		case *dns.MX:
			mxEntry, err := CreateResource(d.MqlRuntime, "dns.mxRecord", map[string]*llx.RawData{
				"name":       llx.StringData(name),
				"preference": llx.IntData(int64(v.Preference)),
				"domainName": llx.StringData(v.Mx),
			})
			if err != nil {
				return nil, err
			}
			mxEntries = append(mxEntries, mxEntry)
		}
	}

	return mxEntries, nil
}

func (d *mqlDnsMxRecord) id() (string, error) {
	return "dns.mx/" + d.Name.Data + "+" + d.DomainName.Data, nil
}

func (d *mqlDns) dkim(params any) ([]any, error) {
	paramsM, ok := params.(map[string]any)
	if !ok {
		return []any{}, nil
	}

	dkimEntries := []any{}

	record, ok := paramsM["TXT"]
	if !ok {
		return dkimEntries, nil
	}

	r := record.(map[string]any)

	var name string
	var rdata []any

	if r["name"] != nil {
		name = r["name"].(string)
	}

	if r["rData"] != nil {
		rdata = r["rData"].([]any)
	}

	for j := range rdata {
		entry := rdata[j].(string)
		entry = strings.TrimSpace(entry)

		if !strings.HasPrefix(entry, "v=DKIM1;") {
			continue
		}

		dkimRepr, err := dnsshake.NewDkimPublicKeyRepresentation(entry)
		if err != nil {
			return nil, err
		}

		o, err := CreateResource(d.MqlRuntime, "dns.dkimRecord", map[string]*llx.RawData{
			"domain":         llx.StringData(name),
			"dnsTxt":         llx.StringData(entry),
			"version":        llx.StringData(dkimRepr.Version),
			"hashAlgorithms": llx.ArrayData(llx.TArr2Raw(dkimRepr.HashAlgorithms), types.String),
			"keyType":        llx.StringData(dkimRepr.KeyType),
			"notes":          llx.StringData(dkimRepr.Notes),
			"publicKeyData":  llx.StringData(dkimRepr.PublicKeyData),
			"serviceTypes":   llx.ArrayData(llx.TArr2Raw(dkimRepr.ServiceType), types.String),
			"flags":          llx.ArrayData(llx.TArr2Raw(dkimRepr.Flags), types.String),
		})
		if err != nil {
			return nil, err
		}
		record := o.(*mqlDnsDkimRecord)
		record.dkim = dkimRepr
		dkimEntries = append(dkimEntries, record)
	}

	return dkimEntries, nil
}

type mqlDnsDkimRecordInternal struct {
	dkim *dnsshake.DkimPublicKeyRepresentation
}

func (d *mqlDnsDkimRecord) id() (string, error) {
	hasher := sha256.New()
	hasher.Write([]byte(d.DnsTxt.Data))
	sha256 := hex.EncodeToString(hasher.Sum(nil))
	return "dns.dkim/" + d.Domain.Data + "/" + sha256, nil
}

func (d *mqlDnsDkimRecord) valid() (bool, error) {
	if d.dkim == nil {
		return false, errors.New("could not load dkim data")
	}

	ok, _, _ := d.dkim.Valid()
	return ok, nil
}

// parseSPF extracts the version, ordered mechanisms, and the qualifier of the
// operative `all` mechanism from an SPF TXT record. SPF mechanisms are
// evaluated left to right and `all` always matches, so the first `all` term is
// the operative one and any later all-like terms are unreachable.
func parseSPF(txt string) (version string, mechanisms []string, allQualifier string) {
	mechanisms = []string{}
	for i, f := range strings.Fields(txt) {
		if i == 0 {
			version = strings.TrimPrefix(f, "v=")
			continue
		}
		mechanisms = append(mechanisms, f)

		if allQualifier != "" {
			continue // first `all` wins; ignore any later all-like terms
		}
		lower := strings.ToLower(f)
		switch {
		case lower == "all":
			allQualifier = "+" // a bare `all` uses the default pass qualifier
		case len(lower) == 4 && lower[1:] == "all" && strings.ContainsRune("+-~?", rune(lower[0])):
			allQualifier = lower[0:1]
		}
	}
	return version, mechanisms, allQualifier
}

func (d *mqlDns) spf(params any) ([]any, error) {
	entries := []any{}

	paramsM, ok := params.(map[string]any)
	if !ok {
		return entries, nil
	}
	record, ok := paramsM["TXT"].(map[string]any)
	if !ok || record["rCode"] != dns.RcodeToString[dns.RcodeSuccess] {
		return entries, nil
	}

	name, _ := record["name"].(string)
	rdata, _ := record["rData"].([]any)
	for j := range rdata {
		entry, ok := rdata[j].(string)
		if !ok {
			continue
		}
		entry = strings.TrimSpace(entry)
		if !strings.HasPrefix(strings.ToLower(entry), "v=spf1") {
			continue
		}

		version, mechanisms, allQualifier := parseSPF(entry)
		res, err := CreateResource(d.MqlRuntime, "dns.spfRecord", map[string]*llx.RawData{
			"__id":         llx.StringData("dns.spf/" + name + "/" + entry),
			"dnsTxt":       llx.StringData(entry),
			"version":      llx.StringData(version),
			"mechanisms":   llx.ArrayData(llx.TArr2Raw(mechanisms), types.String),
			"allQualifier": llx.StringData(allQualifier),
		})
		if err != nil {
			return nil, err
		}
		entries = append(entries, res)
	}
	return entries, nil
}

// parseDMARC splits a DMARC TXT record into its lowercased tag map.
func parseDMARC(txt string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(txt, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		tags[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
	}
	return tags
}

func dmarcUris(raw string) []any {
	uris := []any{}
	if raw == "" {
		return uris
	}
	for _, u := range strings.Split(raw, ",") {
		if u = strings.TrimSpace(u); u != "" {
			uris = append(uris, u)
		}
	}
	return uris
}

func (d *mqlDns) dmarc() (*mqlDnsDmarcRecord, error) {
	// DMARC policy is published at the _dmarc subdomain, not on the base name.
	dmarcFqdn := "_dmarc." + d.Fqdn.Data
	shaker, err := dnsshake.New(dmarcFqdn)
	if err != nil {
		return nil, err
	}
	records, err := shaker.Query("TXT")
	if err != nil {
		return nil, err
	}

	var dmarcTxt string
	if rec, ok := records["TXT"]; ok && rec.RCode == dns.RcodeToString[dns.RcodeSuccess] {
		for _, entry := range rec.RData {
			entry = strings.TrimSpace(entry)
			if strings.HasPrefix(strings.ToLower(entry), "v=dmarc1") {
				dmarcTxt = entry
				break
			}
		}
	}

	if dmarcTxt == "" {
		d.Dmarc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	tags := parseDMARC(dmarcTxt)

	percentage := int64(100) // DMARC defaults pct to 100 when the tag is absent
	if pct, ok := tags["pct"]; ok {
		if n, err := strconv.ParseInt(pct, 10, 64); err == nil {
			percentage = n
		}
	}

	res, err := CreateResource(d.MqlRuntime, "dns.dmarcRecord", map[string]*llx.RawData{
		"__id":                llx.StringData("dns.dmarc/" + dmarcFqdn),
		"dnsTxt":              llx.StringData(dmarcTxt),
		"version":             llx.StringData(tags["v"]),
		"policy":              llx.StringData(tags["p"]),
		"subdomainPolicy":     llx.StringData(tags["sp"]),
		"aggregateReportUris": llx.ArrayData(dmarcUris(tags["rua"]), types.String),
		"forensicReportUris":  llx.ArrayData(dmarcUris(tags["ruf"]), types.String),
		"percentage":          llx.IntData(percentage),
		"spfAlignment":        llx.StringData(tags["aspf"]),
		"dkimAlignment":       llx.StringData(tags["adkim"]),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDnsDmarcRecord), nil
}

// addressesFromRecords extracts the resolved IPv4 (A) and IPv6 (AAAA) addresses
// from a targeted dnsshake query result, skipping unsuccessful lookups.
func addressesFromRecords(records map[string]dnsshake.DnsRecord) []string {
	addrs := []string{}
	for _, key := range []string{"A", "AAAA"} {
		entry, ok := records[key]
		if !ok || entry.RCode != dns.RcodeToString[dns.RcodeSuccess] {
			continue
		}
		for _, s := range entry.RData {
			if s != "" {
				addrs = append(addrs, s)
			}
		}
	}
	return addrs
}

// addressesFromParams extracts the resolved IPv4 (A) and IPv6 (AAAA) addresses
// from a dns params dict.
func addressesFromParams(params any) ([]string, error) {
	paramsM, ok := params.(map[string]any)
	if !ok {
		return nil, errors.New("incorrect structure of params received")
	}

	addrs := []string{}
	for _, key := range []string{"A", "AAAA"} {
		entry, ok := paramsM[key].(map[string]any)
		if !ok {
			continue
		}
		rdata, ok := entry["rData"].([]any)
		if !ok {
			continue
		}
		for _, v := range rdata {
			if s, ok := v.(string); ok && s != "" {
				addrs = append(addrs, s)
			}
		}
	}
	return addrs, nil
}

// reverse is deprecated in favor of reverseRecords.
//
// It derives its addresses from params, and params calls dnsshake.Query() with
// no arguments, which fans out to every entry in the type table — 81 record
// types, issued as parallel goroutines. That is affordable once for the scanned
// asset, where every other field reuses the same result, but not when a policy
// instantiates dns() per element of a list: a check iterating five mail
// exchangers cost roughly 405 concurrent queries, enough for resolvers to
// rate-limit and for PTR lookups to come back empty intermittently, which is
// indistinguishable from a genuinely missing PTR record.
//
// Kept as-is so existing policies keep working unchanged; use reverseRecords,
// which resolves the same addresses with two targeted queries.
func (d *mqlDns) reverse(params any) ([]any, error) {
	addrs, err := addressesFromParams(params)
	if err != nil {
		return nil, err
	}
	return d.ptrRecordsFor(addrs)
}

// reverseRecords resolves the fqdn's own addresses and looks up the PTR for each.
//
// Queries A and AAAA directly rather than deriving them from params, so it stays
// affordable to instantiate per element of a list. See reverse for what that
// costs and why it matters.
func (d *mqlDns) reverseRecords(fqdn string) ([]any, error) {
	if fqdn == "" {
		return nil, nil
	}

	shaker, err := dnsshake.New(fqdn)
	if err != nil {
		return nil, err
	}

	addrRecords, err := shaker.Query("A", "AAAA")
	if err != nil {
		return nil, err
	}

	return d.ptrRecordsFor(addressesFromRecords(addrRecords))
}

// ptrRecordsFor looks up the PTR record for each address and returns them as
// dns.record resources, sorted for deterministic output.
func (d *mqlDns) ptrRecordsFor(addrs []string) ([]any, error) {
	resultMap := make(map[string]*mqlDnsRecord)
	for _, addr := range addrs {
		// dns.ReverseAddr builds the in-addr.arpa (IPv4) or ip6.arpa (IPv6)
		// name; it returns an error for malformed addresses, which we skip.
		arpa, err := dns.ReverseAddr(addr)
		if err != nil {
			continue
		}

		shaker, err := dnsshake.New(arpa)
		if err != nil {
			return nil, err
		}

		records, err := shaker.Query("PTR")
		if err != nil {
			return nil, err
		}

		ptr, ok := records["PTR"]
		if !ok || ptr.RCode != dns.RcodeToString[dns.RcodeSuccess] {
			continue
		}

		o, err := CreateResource(d.MqlRuntime, "dns.record", map[string]*llx.RawData{
			"name":  llx.StringData(ptr.Name),
			"ttl":   llx.IntData(ptr.TTL),
			"class": llx.StringData(ptr.Class),
			"type":  llx.StringData(ptr.Type),
			"rdata": llx.ArrayData(llx.TArr2Raw(ptr.RData), types.String),
		})
		if err != nil {
			return nil, err
		}

		record := o.(*mqlDnsRecord)
		resultMap[record.__id] = record
	}

	keys := sortx.Keys(resultMap)
	res := []any{}
	for i := range keys {
		res = append(res, resultMap[keys[i]])
	}
	return res, nil
}
