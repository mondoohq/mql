// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"go.mondoo.com/mql/v13/utils/multierr"
)

type DnsClient struct {
	config *dns.ClientConfig
	fqdn   string
	sync   sync.Mutex

	// lookupHost resolves a nameserver's name to addresses, defaulting to
	// net.LookupHost. It is a field so a test can serve the whole delegation
	// walk from its own fixture: authoritativeNameservers is otherwise
	// untestable, because the nameserver names a fixture hands back would have
	// to resolve through the host's real resolver.
	lookupHost func(string) ([]string, error)
}

// resolveHost resolves a nameserver name, through the injected resolver when a
// test supplied one.
func (d *DnsClient) resolveHost(name string) ([]string, error) {
	if d.lookupHost != nil {
		return d.lookupHost(name)
	}
	return net.LookupHost(name)
}

type DnsRecord struct {
	// DNS name
	Name string `json:"name"`
	// Time-To-Live (TTL) in seconds
	TTL int64 `json:"ttl"`
	// DNS class
	Class string `json:"class"`
	// DNS type
	Type string `json:"type"`
	// Resource Data
	RData []string `json:"rData"`
	// DNS Response Code
	RCode string `json:"rCode"`
	// Error during dns request
	Error error `json:"error"`
}

func New(fqdn string) (*DnsClient, error) {
	// use Google DNS for now
	config := &dns.ClientConfig{}
	config.Servers = []string{"8.8.8.8", "8.8.4.4"}
	config.Search = []string{}
	config.Port = "53"
	config.Ndots = 1
	config.Timeout = 5
	config.Attempts = 2

	// try to load unix dns server
	// TODO: this does not work on windows https://github.com/go-acme/lego/issues/1015
	resolveFile := "/etc/resolv.conf"
	_, err := os.Stat(resolveFile)
	if err == nil {
		rConfig, err := dns.ClientConfigFromFile(resolveFile)
		// Only adopt the host's resolv.conf if it actually lists a nameserver.
		// A resolv.conf with only `search`/`options` lines parses without error
		// but yields an empty Servers slice, and queryDnsType indexes Servers[0]
		// unconditionally, which would panic. Keeping the default resolver avoids
		// crashing the scan on such hosts.
		if err == nil && len(rConfig.Servers) > 0 {
			config = rConfig
		}
	}

	return &DnsClient{
		fqdn:   fqdn,
		config: config,
	}, nil
}

// stringToType is a map of strings to each RR type.
var stringToType = map[string]uint16{
	"A":          dns.TypeA,
	"AAAA":       dns.TypeAAAA,
	"AFSDB":      dns.TypeAFSDB,
	"ANY":        dns.TypeANY,
	"APL":        dns.TypeAPL,
	"ATMA":       dns.TypeATMA,
	"AVC":        dns.TypeAVC,
	"AXFR":       dns.TypeAXFR,
	"CAA":        dns.TypeCAA,
	"CDNSKEY":    dns.TypeCDNSKEY,
	"CDS":        dns.TypeCDS,
	"CERT":       dns.TypeCERT,
	"CNAME":      dns.TypeCNAME,
	"CSYNC":      dns.TypeCSYNC,
	"DHCID":      dns.TypeDHCID,
	"DLV":        dns.TypeDLV,
	"DNAME":      dns.TypeDNAME,
	"DNSKEY":     dns.TypeDNSKEY,
	"DS":         dns.TypeDS,
	"EID":        dns.TypeEID,
	"EUI48":      dns.TypeEUI48,
	"EUI64":      dns.TypeEUI64,
	"GID":        dns.TypeGID,
	"GPOS":       dns.TypeGPOS,
	"HINFO":      dns.TypeHINFO,
	"HIP":        dns.TypeHIP,
	"HTTPS":      dns.TypeHTTPS,
	"ISDN":       dns.TypeISDN,
	"IXFR":       dns.TypeIXFR,
	"KEY":        dns.TypeKEY,
	"KX":         dns.TypeKX,
	"L32":        dns.TypeL32,
	"L64":        dns.TypeL64,
	"LOC":        dns.TypeLOC,
	"LP":         dns.TypeLP,
	"MAILA":      dns.TypeMAILA,
	"MAILB":      dns.TypeMAILB,
	"MB":         dns.TypeMB,
	"MD":         dns.TypeMD,
	"MF":         dns.TypeMF,
	"MG":         dns.TypeMG,
	"MINFO":      dns.TypeMINFO,
	"MR":         dns.TypeMR,
	"MX":         dns.TypeMX,
	"NAPTR":      dns.TypeNAPTR,
	"NID":        dns.TypeNID,
	"NIMLOC":     dns.TypeNIMLOC,
	"NINFO":      dns.TypeNINFO,
	"NS":         dns.TypeNS,
	"NSEC":       dns.TypeNSEC,
	"NSEC3":      dns.TypeNSEC3,
	"NSEC3PARAM": dns.TypeNSEC3PARAM,
	"NULL":       dns.TypeNULL,
	"NXT":        dns.TypeNXT,
	"None":       dns.TypeNone,
	"OPENPGPKEY": dns.TypeOPENPGPKEY,
	"OPT":        dns.TypeOPT,
	"PTR":        dns.TypePTR,
	"PX":         dns.TypePX,
	"RKEY":       dns.TypeRKEY,
	"RP":         dns.TypeRP,
	"RRSIG":      dns.TypeRRSIG,
	"RT":         dns.TypeRT,
	"Reserved":   dns.TypeReserved,
	"SIG":        dns.TypeSIG,
	"SMIMEA":     dns.TypeSMIMEA,
	"SOA":        dns.TypeSOA,
	"SPF":        dns.TypeSPF,
	"SRV":        dns.TypeSRV,
	"SSHFP":      dns.TypeSSHFP,
	"SVCB":       dns.TypeSVCB,
	"TA":         dns.TypeTA,
	"TALINK":     dns.TypeTALINK,
	"TKEY":       dns.TypeTKEY,
	"TLSA":       dns.TypeTLSA,
	"TSIG":       dns.TypeTSIG,
	"TXT":        dns.TypeTXT,
	"UID":        dns.TypeUID,
	"UINFO":      dns.TypeUINFO,
	"UNSPEC":     dns.TypeUNSPEC,
	"URI":        dns.TypeURI,
	"X25":        dns.TypeX25,
	"ZONEMD":     dns.TypeZONEMD,
	"NSAP-PTR":   dns.TypeNSAPPTR,
}

func (d *DnsClient) Query(dnsTypes ...string) (map[string]DnsRecord, error) {
	if len(dnsTypes) == 0 {
		for k := range stringToType {
			dnsTypes = append(dnsTypes, k)
		}
	}

	var workers sync.WaitGroup
	var errs multierr.Errors

	res := map[string]DnsRecord{}
	for i := range dnsTypes {
		dnsType := dnsTypes[i]

		workers.Add(1)
		go func() {
			defer workers.Done()

			records, err := d.queryDnsType(d.fqdn, dnsType)
			if err != nil {
				d.sync.Lock()
				errs.Add(err)
				d.sync.Unlock()
				return
			}

			d.sync.Lock()
			for k := range records {
				res[k] = records[k]
			}
			d.sync.Unlock()
		}()
	}

	workers.Wait()
	return res, errs.Deduplicate()
}

func (d *DnsClient) queryDnsType(fqdn string, t string) (map[string]DnsRecord, error) {
	return d.queryDnsTypeAt(d.config.Servers[0], true, fqdn, t)
}

// QueryAuthoritative resolves the requested types against the nameservers that
// are authoritative for the zone, rather than through a caching resolver.
//
// Use it when the answer's TTL matters. A caching resolver returns the time
// remaining on its cached entry, so a record configured with a TTL of 300
// answers 300, then 208, then 144 as the entry ages. Only the authoritative
// server reports the configured value, which is the one worth asserting on.
//
// Returns an error when the zone's nameservers cannot be determined, rather
// than silently falling back to the caching resolver: a caller that asked for
// authoritative data should not be handed cached data instead.
func (d *DnsClient) QueryAuthoritative(dnsTypes ...string) (map[string]DnsRecord, error) {
	servers, err := d.authoritativeNameservers()
	if err != nil {
		return nil, err
	}

	if len(dnsTypes) == 0 {
		for k := range stringToType {
			dnsTypes = append(dnsTypes, k)
		}
	}

	var workers sync.WaitGroup
	var errs multierr.Errors

	res := map[string]DnsRecord{}
	for i := range dnsTypes {
		dnsType := dnsTypes[i]

		workers.Add(1)
		go func() {
			defer workers.Done()

			// Try each nameserver in turn: an individual one may refuse, be
			// unreachable, or lag behind its peers, and any authoritative server
			// for the zone is an equally valid source for the record.
			var lastErr error
			for _, server := range servers {
				records, err := d.queryDnsTypeAt(server, false, d.fqdn, dnsType)
				if err != nil {
					lastErr = err
					continue
				}

				d.sync.Lock()
				for k := range records {
					res[k] = records[k]
				}
				d.sync.Unlock()
				return
			}

			if lastErr != nil {
				d.sync.Lock()
				errs.Add(lastErr)
				d.sync.Unlock()
			}
		}()
	}

	workers.Wait()
	return res, errs.Deduplicate()
}

// queryNS asks for the NS records at a name, retrying across the configured
// resolvers before reporting failure.
//
// walkToDelegation treats a query that did not happen as a reason to stop
// rather than to climb, because climbing would answer with whichever ancestor
// did respond and hide the delegation below it. That is only sound if a query
// that could have been answered was: queryDnsTypeAt sends one datagram to one
// server and reports a lost reply as a failure, so a single dropped UDP packet
// would otherwise end the walk and surface as an error on every field behind
// it. A resolver is asked config.Attempts times, and every configured resolver
// is asked, so the error means no resolver could answer rather than that one
// packet went missing.
//
// Only a transport failure is retried. Any answer is the resolver having
// answered, NXDOMAIN and a response carrying no NS records included, and what
// it means is the caller's decision.
func (d *DnsClient) queryNS(zone string) (map[string]DnsRecord, error) {
	if len(d.config.Servers) == 0 {
		return nil, errors.New("no resolver configured to query NS for " + zone)
	}

	attempts := d.config.Attempts
	if attempts < 1 {
		attempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		for _, server := range d.config.Servers {
			records, err := d.queryDnsTypeAt(server, true, zone, "NS")
			if err != nil {
				lastErr = err
				continue
			}

			// queryDnsTypeAt reports a transport failure inside the record
			// rather than as an error, so this is where a lost reply looks like
			// one.
			if ns, ok := records["NS"]; ok && ns.Error != nil {
				lastErr = ns.Error
				continue
			}

			return records, nil
		}
	}

	return nil, errors.Wrapf(lastErr, "querying NS for %s", zone)
}

// walkToDelegation walks up the labels of the client's fqdn and reports the
// closest enclosing name that answers with NS records of its own, together with
// those records.
//
// NS records live at a zone apex and at the delegation points within it, not at
// every name a zone contains, so a query for "www.example.com" answers with no
// NS records and the walk continues at "example.com", which does. The walk
// stops before the root so a name that resolves nowhere reports not-found
// rather than the root servers, which would answer referrals instead of the
// records the caller wants.
//
// accept decides whether a name that answered is the one the caller wanted;
// returning false continues the walk. It is how authoritativeNameservers keeps
// climbing past a delegation whose nameservers do not resolve, while Zone,
// which only needs the name, stops at the first one.
func (d *DnsClient) walkToDelegation(accept func(zone string, ns DnsRecord) bool) (string, bool, error) {
	name := dns.Fqdn(d.fqdn)
	if name == "." {
		return "", false, errors.New("cannot determine the authoritative zone without a domain name")
	}

	for labels := dns.SplitDomainName(name); len(labels) > 0; labels = labels[1:] {
		zone := strings.Join(labels, ".")

		records, err := d.queryNS(zone)
		if err != nil {
			return "", false, err
		}

		ns, ok := records["NS"]
		if !ok || ns.RCode != dns.RcodeToString[dns.RcodeSuccess] || len(ns.RData) == 0 {
			continue
		}

		if !accept(zone, ns) {
			continue
		}

		return zone, true, nil
	}

	return "", false, nil
}

// Zone reports the apex of the zone that contains the client's fqdn: the
// closest enclosing name that is served as a zone of its own.
//
// This is the name the zone-wide configuration belongs to. DNSKEY, NS and SOA
// records exist at a zone apex and nowhere else inside the zone, so a question
// about how a zone is signed, or how many nameservers serve it, has an answer
// at this name and no answer at any other name the zone contains.
//
// It is found by delegation rather than by the public suffix list, which is
// what makes it the zone the name actually belongs to rather than the
// registrable domain. The two agree for "www.example.com", whose zone is
// "example.com"; they differ for a delegated subdomain such as
// "corp.example.com", which is its own zone, signed with its own keys and
// served by its own nameservers.
//
// It reports an empty zone, and no error, for a name that nothing answers for
// as a zone: an unregistered domain has no apex to report, which is a fact
// about the name rather than a failure to establish it. A query that fails is
// the error case, and is reported as one, so a resolver outage is never
// mistaken for a name that belongs to no zone.
func (d *DnsClient) Zone() (string, error) {
	zone, found, err := d.walkToDelegation(func(string, DnsRecord) bool { return true })
	if err != nil {
		return "", err
	}
	if !found {
		return "", nil
	}
	return zone, nil
}

// authoritativeNameservers finds the addresses of the nameservers serving the
// zone that contains the client's fqdn.
func (d *DnsClient) authoritativeNameservers() ([]string, error) {
	var addrs []string

	_, found, err := d.walkToDelegation(func(_ string, ns DnsRecord) bool {
		addrs = addrs[:0]
		for _, host := range ns.RData {
			// Nameservers are named, so each one needs resolving to an address
			// before it can be queried. Skip any that do not resolve; as long as
			// one does, the zone is reachable.
			ips, err := d.resolveHost(strings.TrimSuffix(host, "."))
			if err != nil {
				continue
			}
			addrs = append(addrs, ips...)
		}
		return len(addrs) > 0
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("no authoritative nameserver found for " + d.fqdn)
	}

	return addrs, nil
}

// queryDnsTypeAt performs the lookup against a named server.
//
// recursion decides who resolves the name: true asks a caching resolver to do
// the work, false requires the server to answer from its own zone data. The
// distinction matters for TTLs. A caching resolver reports the time remaining
// on its cached entry, counting down toward zero, so the same query returns a
// different TTL depending on when it is asked. An authoritative server reports
// the value configured in the zone.
func (d *DnsClient) queryDnsTypeAt(server string, recursion bool, fqdn string, t string) (map[string]DnsRecord, error) {
	dnsType, ok := stringToType[t]
	if !ok {
		return nil, errors.New("unknown dns type")
	}
	dnsTypText := dns.Type(dnsType).String()

	res := map[string]DnsRecord{}

	c := &dns.Client{}
	m := &dns.Msg{}
	m.SetEdns0(4096, false)
	m.SetQuestion(dns.Fqdn(fqdn), dnsType)
	m.RecursionDesired = recursion

	address := net.JoinHostPort(server, d.config.Port)
	r, _, err := c.Exchange(m, address)

	// An answer too large for a datagram comes back with the truncation bit set
	// and, depending on how far over the limit it is, either an empty answer
	// section or an unpack error. Either way the records are only reachable over
	// TCP, so retry there before deciding what the name publishes.
	//
	// Without this a name with a few kilobytes of TXT reports no TXT record at
	// all, which is indistinguishable from a name that publishes none: the type
	// never makes it into the result map, so records, spf and dkim all report
	// the name as having nothing rather than reporting that the lookup failed.
	//
	// The unpack error is a separate trigger rather than a consequence of the
	// truncation bit. A response whose header counts more records than the body
	// carries fails to unpack with the bit clear, and the partially parsed
	// message still comes back alongside the error, so testing the bit alone
	// would leave that case on the floor.
	if r != nil && (r.Truncated || err != nil) {
		tcp := &dns.Client{Net: "tcp"}
		if retried, _, tcpErr := tcp.Exchange(m, address); tcpErr == nil {
			r, err = retried, nil
		}
	}

	if err != nil {
		res[dnsTypText] = DnsRecord{
			Type:  dnsTypText,
			Error: err,
		}
		return res, nil
	}

	if r.Rcode != dns.RcodeSuccess {
		res[dnsTypText] = DnsRecord{
			Type:  dnsTypText,
			RCode: dns.RcodeToString[r.Rcode],
		}
		return res, nil
	}

	// extract more information if dns request was successful
	for i := range r.Answer {
		a := r.Answer[i]

		typ := dns.Type(a.Header().Rrtype).String()

		var rec DnsRecord

		rec, ok := res[typ]
		if !ok {
			rec = DnsRecord{
				Name:  a.Header().Name,
				Type:  typ,
				Class: dns.Class(a.Header().Class).String(),
				TTL:   int64(a.Header().Ttl),
				RData: []string{},
				RCode: dns.RcodeToString[r.Rcode],
			}
		}

		switch v := a.(type) {
		case *dns.A:
			rec.RData = append(rec.RData, v.A.String())
		case *dns.NS:
			rec.RData = append(rec.RData, v.Ns)
		case *dns.MD:
			rec.RData = append(rec.RData, v.Md)
		case *dns.MF:
			rec.RData = append(rec.RData, v.Mf)
		case *dns.CNAME:
			rec.RData = append(rec.RData, v.Target)
		case *dns.MB:
			rec.RData = append(rec.RData, v.Mb)
		case *dns.MG:
			rec.RData = append(rec.RData, v.Mg)
		case *dns.MR:
			rec.RData = append(rec.RData, v.Mr)
		case *dns.NULL:
			rec.RData = append(rec.RData, v.Data)
		case *dns.PTR:
			rec.RData = append(rec.RData, v.Ptr)
		case *dns.TXT:
			rec.RData = append(rec.RData, strings.Join(v.Txt, ""))
		case *dns.EID:
			rec.RData = append(rec.RData, v.Endpoint)
		case *dns.NIMLOC:
			rec.RData = append(rec.RData, v.Locator)
		case *dns.SPF:
			rec.RData = append(rec.RData, strings.Join(v.Txt, ""))
		case *dns.UINFO:
			rec.RData = append(rec.RData, v.Uinfo)
		case *dns.UID:
			rec.RData = append(rec.RData, strconv.FormatInt(int64(v.Uid), 10))
		case *dns.GID:
			rec.RData = append(rec.RData, strconv.FormatInt(int64(v.Gid), 10))
		case *dns.EUI48:
			rec.RData = append(rec.RData, strconv.FormatInt(int64(v.Address), 10))
		case *dns.EUI64:
			rec.RData = append(rec.RData, strconv.FormatInt(int64(v.Address), 10))
		case *dns.AVC:
			rec.RData = append(rec.RData, strings.Join(v.Txt, ""))
		default:
			rec.RData = append(rec.RData, strings.TrimPrefix(v.String(), v.Header().String()))
		}

		res[typ] = rec
	}
	return res, nil
}
