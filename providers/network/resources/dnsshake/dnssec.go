// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dnsshake

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"go.mondoo.com/mql/v13/utils/dnssec"
)

// DnssecValidation is the outcome of a DNSSEC-validating resolution.
//
// It answers a different question from the DNSKEY records a zone publishes.
// A zone can publish keys, publish good keys, and still fail to validate,
// because the delegation its parent holds points at a key that is gone or
// because the signatures have quietly stopped being renewed. Nothing here
// fails the whole lookup: an unsigned zone, an unreachable resolver and a
// genuinely broken chain each report their own state, with Error saying which
// happened, so a scan across a mixed fleet still finishes.
type DnssecValidation struct {
	// Name that was queried, in fully qualified form.
	Name string
	// RecordType that was queried.
	RecordType string
	// ResponseCode of the validating query.
	ResponseCode string
	// DnssecOk reports whether the response carried the DNSSEC OK bit back,
	// meaning the resolver understood the request for DNSSEC records.
	DnssecOk bool
	// AuthenticatedData is the resolver's own verdict that it validated the
	// answer. It is empty from a resolver that does not validate, which is why
	// ChainOfTrustValidated is computed here rather than taken on trust.
	AuthenticatedData bool
	// Signatures covering the answer.
	Signatures []DnssecSignature
	// SignaturesVerified reports whether every signature over the answer
	// verified against a key the signing zone publishes. False when the answer
	// carried no signature at all.
	SignaturesVerified bool
	// ChainOfTrustValidated reports whether every link from the signing zone up
	// to the IANA root trust anchor was established.
	ChainOfTrustValidated bool
	// Chain lists the zones the walk traversed, from the signing zone upward.
	Chain []string
	// BrokenAtZone names the first zone whose link to its parent could not be
	// established. Empty when the chain validated.
	BrokenAtZone string
	// Error explains why validation did not complete. Empty on success.
	Error string
}

// DnssecSignature is one RRSIG covering a resolved record set.
//
// The key tag and the signature bytes are deliberately absent. Both change
// every time a zone is re-signed, so anything built on them reports a
// different answer on a schedule nobody chose. Fingerprint exists only to keep
// two otherwise identical signatures apart within a single response, which
// happens during a key rollover when two keys sign the same records.
type DnssecSignature struct {
	Name          string
	TypeCovered   string
	Algorithm     int
	AlgorithmName string
	Labels        int
	OriginalTTL   int64
	Inception     time.Time
	Expiration    time.Time
	SignerName    string
	Fingerprint   string
}

// Window returns the signature's validity period.
func (s DnssecSignature) Window() dnssec.SignatureWindow {
	return dnssec.SignatureWindow{Inception: s.Inception, Expiration: s.Expiration}
}

// maxChainDepth caps the walk from a signing zone to the root. A name has at
// most 127 labels, so a real chain is far shorter; the cap exists so a
// resolver that answers a DS query with a referral back to the same name
// cannot spin forever.
const maxChainDepth = 32

// rootAnchor is one IANA root zone trust anchor, as a DS digest over the root
// key signing key.
type rootAnchor struct {
	DigestType int
	Digest     string
}

// rootTrustAnchors are the IANA root zone trust anchors, the one thing in
// DNSSEC that cannot be learned from DNS itself.
//
// Both currently published anchors are listed, because a root key rollover
// publishes the incoming key alongside the outgoing one and either may be the
// one signing the root DNSKEY set on any given day. Verified against the live
// root zone rather than transcribed: each digest is the SHA-256 DS digest of a
// root key signing key that the root zone publishes today.
//
// These need updating at the next root key signing key rollover. Until then a
// chain that reaches the root and matches neither is genuinely not anchored.
var rootTrustAnchors = []rootAnchor{
	// KSK-2017, key tag 20326
	{DigestType: 2, Digest: "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d"},
	// KSK-2024, key tag 38696
	{DigestType: 2, Digest: "683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16"},
}

// resolveWithDnssec asks one resolver for the first of the record types that
// returns records, and reports which type answered.
//
// Checking is left enabled, so a resolver that validates answers SERVFAIL for a
// zone whose signatures do not verify rather than handing back data it would
// not itself accept.
func (d *DnsClient) resolveWithDnssec(server, name string, recordTypes []string) (*dns.Msg, string, uint16, error) {
	var (
		msg        *dns.Msg
		answerType string
		qtype      uint16
		lastErr    error
	)

	for _, recordType := range recordTypes {
		candidate, err := d.exchangeDnssec(server, name, stringToType[recordType], false)
		if err != nil {
			lastErr = err
			continue
		}
		if msg == nil {
			msg, qtype, answerType = candidate, stringToType[recordType], recordType
		}
		if len(candidate.Answer) > 0 {
			return candidate, recordType, stringToType[recordType], nil
		}
	}

	if msg == nil {
		return nil, "", 0, lastErr
	}
	return msg, answerType, qtype, nil
}

// ValidateDnssec resolves the client's name with DNSSEC requested and reports
// what came back.
//
// The record types are tried in order until one returns records. A name that
// publishes no address still lives in a zone that is either signed or not, and
// asking only for an address would report such a name as unsigned on the
// strength of an answer that was empty for an unrelated reason.
//
// It returns an error only when the caller asked for a record type that does
// not exist, or for none at all. Everything that can go wrong at resolution
// time is reported in the result, because an unsigned zone is a normal finding
// rather than a failure of the scan.
func (d *DnsClient) ValidateDnssec(recordTypes ...string) (*DnssecValidation, error) {
	if len(recordTypes) == 0 {
		return nil, errors.New("no dns record type requested")
	}
	for _, recordType := range recordTypes {
		if _, ok := stringToType[recordType]; !ok {
			return nil, errors.New("unknown dns type " + recordType)
		}
	}

	res := &DnssecValidation{
		Name:       dns.Fqdn(d.fqdn),
		RecordType: recordTypes[0],
		Signatures: []DnssecSignature{},
		Chain:      []string{},
	}

	if len(d.config.Servers) == 0 {
		res.Error = "no resolver is configured"
		return res, nil
	}

	// Try each configured resolver until one honors the DNSSEC OK bit. A
	// resolver that strips EDNS0 answers without signatures however the zone is
	// signed, so taking its answer as the verdict reports a correctly signed
	// zone as unsigned. The first response is kept either way, so a run where
	// no resolver honors DNSSEC still reports the response code it did get.
	var (
		server  string
		msg     *dns.Msg
		qtype   uint16
		lastErr error
	)
	for _, candidateServer := range d.config.Servers {
		candidate, candidateType, candidateQtype, err := d.resolveWithDnssec(candidateServer, res.Name, recordTypes)
		if err != nil {
			lastErr = err
			continue
		}

		if msg == nil {
			server, msg, qtype, res.RecordType = candidateServer, candidate, candidateQtype, candidateType
		}
		if responseHasDnssecOk(candidate) {
			server, msg, qtype, res.RecordType = candidateServer, candidate, candidateQtype, candidateType
			break
		}
	}

	if msg == nil {
		res.Error = "could not reach the resolver"
		if lastErr != nil {
			res.Error += ": " + lastErr.Error()
		}
		return res, nil
	}

	res.ResponseCode = dns.RcodeToString[msg.Rcode]
	res.AuthenticatedData = msg.AuthenticatedData
	res.DnssecOk = responseHasDnssecOk(msg)

	// No resolver returned DNSSEC records for a query that asked for them, so
	// the answer says nothing about the zone: a signed zone and an unsigned one
	// look identical from here. Stop rather than concluding from an unsigned
	// answer that the zone is unsigned, and leave the verdicts at their zero
	// values for the caller to report as unknown.
	if !res.DnssecOk {
		res.Error = "the resolver did not return DNSSEC records for a query that asked for them, " +
			"so nothing here describes how the zone is signed"
		return res, nil
	}

	// Reasons accumulate rather than overwrite. The resolver's refusal is
	// context, the walk's finding is the diagnosis, and reporting only the
	// first one leaves an operator knowing that a zone failed without knowing
	// which link failed.
	reasons := []string{}

	// A validating resolver withholds an answer it could not validate, so the
	// records that would explain why are exactly the ones it refused to send.
	// Re-ask with checking disabled to see them. Without this step a bogus zone
	// and an unreachable authoritative server are the same SERVFAIL.
	answer := msg
	if msg.Rcode != dns.RcodeSuccess {
		if cd, cdErr := d.exchangeDnssec(server, res.Name, qtype, true); cdErr == nil && cd.Rcode == dns.RcodeSuccess {
			answer = cd
			reasons = append(reasons, "the resolver rejected the answer as unvalidatable ("+res.ResponseCode+
				"); the records reported here come from a query with checking disabled")
		}
	}

	rrsigs := rrsigsIn(answer.Answer)
	for _, sig := range rrsigs {
		res.Signatures = append(res.Signatures, newDnssecSignature(sig))
	}

	if len(rrsigs) == 0 {
		reasons = append(reasons, "the answer carried no RRSIG record, so the zone is not signed")
		res.Error = strings.Join(reasons, "; ")
		return res, nil
	}

	verified, unreadable := d.verifySignatures(server, rrsigs, answer.Answer)
	res.SignaturesVerified = verified
	if !verified {
		if unreadable != "" {
			reasons = append(reasons, unreadable)
		} else {
			reasons = append(reasons, "no signature over the answer verified against a key its signing zone publishes")
		}
	}

	// The signing zone is where the chain starts. It is the RRSIG's signer,
	// not the queried name: a name deep inside a zone is signed by the zone
	// apex, and walking up from the name would look for a DS at every
	// intermediate label that is not a zone cut.
	chain, brokenAt, failure := d.walkChain(server, signingZone(res.Name, rrsigs))
	res.Chain = chain
	res.BrokenAtZone = brokenAt
	res.ChainOfTrustValidated = failure == "" && res.SignaturesVerified

	if failure != "" {
		reasons = append(reasons, failure)
	}

	res.Error = strings.Join(reasons, "; ")
	return res, nil
}

// signingZone picks the zone the chain walk starts from.
//
// A name that resolves through a CNAME into another zone comes back with
// signatures from more than one zone, and which of them the resolver puts
// first is not something to depend on. The signature over the queried name is
// the one whose chain the caller asked about, so it wins; anything else falls
// back to the first signature present.
func signingZone(name string, rrsigs []*dns.RRSIG) string {
	for _, sig := range rrsigs {
		if strings.EqualFold(sig.Hdr.Name, name) {
			return sig.SignerName
		}
	}
	return rrsigs[0].SignerName
}

// newDnssecSignature converts a wire RRSIG into the reported shape.
func newDnssecSignature(sig *dns.RRSIG) DnssecSignature {
	return DnssecSignature{
		Name:          sig.Hdr.Name,
		TypeCovered:   dns.Type(sig.TypeCovered).String(),
		Algorithm:     int(sig.Algorithm),
		AlgorithmName: dnssec.AlgorithmName(int(sig.Algorithm)),
		Labels:        int(sig.Labels),
		OriginalTTL:   int64(sig.OrigTtl),
		// RRSIG timestamps are unsigned 32-bit seconds since the epoch, which
		// this reads directly. RFC 4034 defines them with serial arithmetic so
		// that they keep working past 2106; that wrap is far enough away that
		// handling it would be untestable speculation.
		Inception:   time.Unix(int64(sig.Inception), 0).UTC(),
		Expiration:  time.Unix(int64(sig.Expiration), 0).UTC(),
		SignerName:  sig.SignerName,
		Fingerprint: fingerprintSignature(sig.Signature),
	}
}

// fingerprintSignature hashes the signature bytes so two signatures that agree
// on every reported field can still be told apart. The signature itself is
// never reported: it is large, it is meaningless to read, and it changes on
// every re-signing.
func fingerprintSignature(signature string) string {
	sum := sha256.Sum256([]byte(signature))
	return hex.EncodeToString(sum[:8])
}

// verifySignatures checks each signature over the answer against the keys its
// signing zone publishes.
//
// Every signature that covers something in the answer has to verify. Accepting
// the answer because one of several verified would pass a zone that is
// half-way through a botched rollover and serving signatures from a key it has
// already withdrawn.
//
// A signature covering a type that is not in the answer is skipped rather than
// failed: validating resolvers bundle extra RRSIGs (an NSEC signature
// alongside an A answer, say), and failing on those would report a correctly
// signed zone as unvalidated. Skipping is only safe because the count below
// requires at least one signature to have actually been checked -- otherwise an
// answer carrying nothing but irrelevant RRSIGs would verify vacuously.
// The second return explains a false result: it names the resolver when the key
// set could not be read, and is empty when the signatures were genuinely checked
// and did not verify.
func (d *DnsClient) verifySignatures(server string, rrsigs []*dns.RRSIG, answer []dns.RR) (bool, string) {
	keysByZone := map[string][]*dns.DNSKEY{}
	verified := 0

	for _, sig := range rrsigs {
		rrset := rrsetCoveredBy(sig, answer)
		if len(rrset) == 0 {
			continue
		}

		zone := sig.SignerName
		keys, ok := keysByZone[zone]
		if !ok {
			fetched, dnssecOk, err := d.dnskeys(server, zone)
			if err != nil || !dnssecOk {
				return false, "the resolver did not return the DNSKEY set for " + zone +
					", so the answer's signatures could not be checked"
			}
			keys = fetched
			keysByZone[zone] = keys
		}
		if len(keys) == 0 {
			return false, ""
		}

		if !verifyWithAnyKey(sig, keys, rrset) {
			return false, ""
		}
		verified++
	}

	return verified > 0, ""
}

// verifyWithAnyKey reports whether any of the zone's keys validates the
// signature. The key tag narrows the search inside miekg's Verify; it is used
// here and never reported, for the same reason it is not a field.
func verifyWithAnyKey(sig *dns.RRSIG, keys []*dns.DNSKEY, rrset []dns.RR) bool {
	for _, key := range keys {
		if err := sig.Verify(key, rrset); err == nil {
			return true
		}
	}
	return false
}

// walkChain follows the delegations from a signing zone up to the root.
//
// At every step two things must hold: the zone's DNSKEY set is signed by one
// of its own key signing keys, and the DS record its parent publishes matches
// one of those keys. The walk ends at the root, where there is no parent to
// ask and the keys are checked against the IANA trust anchors instead.
//
// Returns the zones visited, the zone the walk failed at, and a description of
// the failure. All three are empty-safe: a failure returns what was reached
// before it, which is what tells an operator whose zone to look at.
func (d *DnsClient) walkChain(server, zone string) (chain []string, brokenAt string, failure string) {
	chain = []string{}
	zone = dns.Fqdn(zone)

	for depth := 0; depth < maxChainDepth; depth++ {
		chain = append(chain, zone)

		keyMsg, err := d.exchangeDnssec(server, zone, dns.TypeDNSKEY, true)
		if err != nil {
			return chain, zone, "could not read the DNSKEY set for " + zone + ": " + err.Error()
		}

		// A resolver can honor the DNSSEC OK bit for one name and strip it for
		// the next, so the walk has to check every response rather than trusting
		// that the one which selected this resolver settled the question. An
		// answer with no DNSSEC records in it cannot support any finding about
		// the zone, and reporting one accuses the zone's operator of a break
		// that is on the path to the resolver.
		if !responseHasDnssecOk(keyMsg) {
			return chain, zone, "the resolver did not return DNSSEC records for the DNSKEY set of " + zone +
				", so the chain of trust could not be followed past it"
		}

		keys := dnskeysIn(keyMsg.Answer)
		if len(keys) == 0 {
			return chain, zone, zone + " publishes no DNSKEY record, so the chain of trust stops there"
		}

		// The DNSKEY set signs itself with a key signing key. Skipping this
		// check would accept a set of keys substituted wholesale.
		keySigs := rrsigsIn(keyMsg.Answer)
		if !verifyDnskeySet(keySigs, keys) {
			return chain, zone, "the DNSKEY set for " + zone + " is not signed by any key it publishes"
		}

		if zone == "." {
			if !matchesRootAnchor(keys) {
				return chain, zone, "the root DNSKEY set matches no known IANA root trust anchor"
			}
			return chain, "", ""
		}

		dsRecords, parent, err := d.delegationSigners(server, zone)
		if err != nil {
			return chain, zone, "could not read the DS record for " + zone + ": " + err.Error()
		}
		if len(dsRecords) == 0 {
			return chain, zone, "no DS record is published for " + zone + ", so the delegation is insecure and a validating resolver treats the zone as unsigned"
		}
		if !anyDelegationMatchesKey(dsRecords, keys) {
			return chain, zone, "no DS record published for " + zone + " matches a key it currently publishes, which breaks validation for resolvers while the zone still looks signed"
		}

		zone = parent
	}

	return chain, zone, "the chain of trust walk exceeded its depth limit"
}

// delegationSigners reads the DS records for a zone and the name of the parent
// that published them.
//
// The parent is taken from the signer of the DS record set rather than by
// stripping a label, because a label boundary is not always a zone cut. Where
// there is no signature to read it, stripping one label is the fallback.
func (d *DnsClient) delegationSigners(server, zone string) ([]*dns.DS, string, error) {
	msg, err := d.exchangeDnssec(server, zone, dns.TypeDS, true)
	if err != nil {
		return nil, "", err
	}

	// A recursive resolver answers a DS query from the Answer section. Some
	// configurations end up talking to the child zone's authoritative server
	// instead, which returns the DS in the Authority section of a referral, so
	// both are read here.
	sections := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns))
	sections = append(sections, msg.Answer...)
	sections = append(sections, msg.Ns...)

	records := []*dns.DS{}
	for _, rr := range sections {
		if ds, ok := rr.(*dns.DS); ok {
			records = append(records, ds)
		}
	}

	parent := parentZone(zone)
	for _, sig := range rrsigsIn(sections) {
		if sig.TypeCovered == dns.TypeDS && sig.SignerName != "" {
			parent = sig.SignerName
			break
		}
	}

	return records, parent, nil
}

// parentZone strips the leftmost label. The root is its own parent, which the
// caller never asks for because it stops at the root.
func parentZone(zone string) string {
	labels := dns.SplitDomainName(dns.Fqdn(zone))
	if len(labels) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(labels[1:], "."))
}

// verifyDnskeySet reports whether the DNSKEY set is signed by one of the keys
// in it, which is what makes the set self-consistent before its link to the
// parent is checked.
func verifyDnskeySet(sigs []*dns.RRSIG, keys []*dns.DNSKEY) bool {
	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrset = append(rrset, key)
	}

	for _, sig := range sigs {
		if sig.TypeCovered != dns.TypeDNSKEY {
			continue
		}
		if verifyWithAnyKey(sig, keys, rrset) {
			return true
		}
	}
	return false
}

// anyDelegationMatchesKey reports whether any DS record digests a key the zone
// currently publishes, which is the single link between a child zone and its
// parent.
//
// The digest is computed by the shared decoder rather than recomputed here, so
// the one implementation is the same one that reads a key off disk.
func anyDelegationMatchesKey(records []*dns.DS, keys []*dns.DNSKEY) bool {
	for _, ds := range records {
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
	}
	return false
}

// matchesRootAnchor reports whether the root zone publishes a key signing key
// that one of the IANA trust anchors covers.
func matchesRootAnchor(keys []*dns.DNSKEY) bool {
	for _, key := range keys {
		if !dnssec.IsKeySigningKey(int(key.Flags)) {
			continue
		}
		for _, anchor := range rootTrustAnchors {
			digest, err := dnssec.DSDigest(
				key.Hdr.Name,
				int(key.Flags), int(key.Protocol), int(key.Algorithm),
				key.PublicKey,
				anchor.DigestType,
			)
			if err != nil {
				continue
			}
			if strings.EqualFold(digest, anchor.Digest) {
				return true
			}
		}
	}
	return false
}

// dnskeys reads a zone's DNSKEY set, returning an empty slice rather than an
// error when it cannot be read, because every caller treats the two the same.
// The second return reports whether the response carried DNSSEC records at all.
// A resolver can honor the DNSSEC OK bit for one name and strip it for the next,
// and an empty key set from a stripped response is not evidence about the zone.
func (d *DnsClient) dnskeys(server, zone string) ([]*dns.DNSKEY, bool, error) {
	msg, err := d.exchangeDnssec(server, zone, dns.TypeDNSKEY, true)
	if err != nil {
		return nil, false, err
	}
	return dnskeysIn(msg.Answer), responseHasDnssecOk(msg), nil
}

// dnskeysIn picks the DNSKEY records out of a record set.
func dnskeysIn(records []dns.RR) []*dns.DNSKEY {
	keys := []*dns.DNSKEY{}
	for _, rr := range records {
		if key, ok := rr.(*dns.DNSKEY); ok {
			keys = append(keys, key)
		}
	}
	return keys
}

// rrsigsIn picks the RRSIG records out of a record set.
func rrsigsIn(records []dns.RR) []*dns.RRSIG {
	sigs := []*dns.RRSIG{}
	for _, rr := range records {
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs = append(sigs, sig)
		}
	}
	return sigs
}

// rrsetCoveredBy collects the records a signature covers: same owner name,
// same class, and the type the signature says it covers.
func rrsetCoveredBy(sig *dns.RRSIG, records []dns.RR) []dns.RR {
	rrset := []dns.RR{}
	for _, rr := range records {
		hdr := rr.Header()
		if hdr.Rrtype != sig.TypeCovered {
			continue
		}
		if hdr.Class != sig.Hdr.Class {
			continue
		}
		if !strings.EqualFold(hdr.Name, sig.Hdr.Name) {
			continue
		}
		rrset = append(rrset, rr)
	}
	return rrset
}

// responseHasDnssecOk reports whether the response carried the DNSSEC OK bit
// back. A resolver or middlebox that strips EDNS0 clears it, and that makes
// every other DNSSEC observation on the response meaningless rather than
// negative.
func responseHasDnssecOk(msg *dns.Msg) bool {
	opt := msg.IsEdns0()
	return opt != nil && opt.Do()
}

// exchangeDnssec issues a query with the DNSSEC OK bit set.
//
// checkingDisabled asks the resolver to hand back records it would otherwise
// withhold as unvalidatable, which is how the reason for a failure is read.
//
// DNSSEC answers routinely exceed what fits in a UDP datagram, so a truncated
// response is retried over TCP. Without that retry a signed zone with several
// keys reports no keys at all, which reads exactly like an unsigned zone.
func (d *DnsClient) exchangeDnssec(server, fqdn string, qtype uint16, checkingDisabled bool) (*dns.Msg, error) {
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.SetEdns0(4096, true)
	m.RecursionDesired = true
	m.CheckingDisabled = checkingDisabled

	address := net.JoinHostPort(server, d.config.Port)

	// A zero timeout in dns.Client means no deadline at all, so a resolver
	// that accepts the packet and never answers would hang the scan.
	timeout := time.Duration(d.config.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	c := &dns.Client{Timeout: timeout}
	r, _, err := c.Exchange(m, address)
	if err != nil {
		return nil, err
	}

	if r.Truncated {
		tcp := &dns.Client{Net: "tcp", Timeout: timeout}
		if r2, _, err2 := tcp.Exchange(m, address); err2 == nil {
			return r2, nil
		}
	}

	return r, nil
}
