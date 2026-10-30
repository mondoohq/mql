// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/network/connection"
	"go.mondoo.com/mql/providers/network/resources"
	"go.mondoo.com/mql/utils/syncx"
)

func TestResource_DNS(t *testing.T) {
	res := x.TestQuery(t, "dns(\"mondoo.com\").mx")
	assert.NotEmpty(t, res)
}

// dnsLiveQuery runs a live DNS query for a test and returns the first result's
// data. It skips the test when the lookup itself errors, so the inherently
// network-dependent DNS tests don't fail on restricted or flaky CI networks.
// Parsing correctness is covered by the deterministic tests in
// dns_internal_test.go.
func dnsLiveQuery(t *testing.T, query string) *llx.RawData {
	t.Helper()
	res := x.TestQuery(t, query)
	require.NotEmpty(t, res)
	if res[0].Data.Error != nil {
		t.Skipf("skipping: live DNS lookup unavailable (%s): %v", query, res[0].Data.Error)
	}
	return res[0].Data
}

func TestResource_DnsDnssec(t *testing.T) {
	// cloudflare.com is reliably DNSSEC-signed. The enabled flag probes whether
	// the live DNSKEY lookup completed (empty on restricted/flaky CI networks);
	// skip rather than fail in that case. The remaining assertions then verify
	// the keys and algorithms parsed correctly.
	if dnsLiveQuery(t, `dns("cloudflare.com").dnssec.enabled`).Value != true {
		t.Skip("skipping: live DNSKEY lookup returned no data")
	}

	keys := dnsLiveQuery(t, `dns("cloudflare.com").dnssec.keys.all(algorithm > 0 && publicKey != "")`)
	assert.Equal(t, true, keys.Value)

	algos := dnsLiveQuery(t, `dns("cloudflare.com").dnssec.algorithms`)
	assert.NotEmpty(t, algos.Value)
}

// dnssecAssertions are the distinct properties of a DNSSEC-validating
// resolution this schema is meant to make expressible.
//
// They exist as a list because the whole point of the surface is that these
// are separate questions. A resolution that returns signatures is not a
// resolution that validated; a zone that publishes keys is not a zone its
// parent delegates to; a chain that links to the root says nothing about how
// long the signatures have left.
var dnssecAssertions = []string{
	// Did the query itself carry DNSSEC at all
	`dns("example.com").dnssecValidation.dnssecOk`,
	`dns("example.com").dnssecValidation.responseCode == "NOERROR"`,
	// What the answer carried
	`dns("example.com").dnssecValidation.signed`,
	`dns("example.com").dnssecValidation.signaturesVerified`,
	`dns("example.com").dnssecValidation.authenticatedData`,
	`dns("example.com").dnssecValidation.chainOfTrustValidated`,
	`dns("example.com").dnssecValidation.brokenAtZone == ""`,
	`dns("example.com").dnssecValidation.signerNames.length > 0`,
	// Signature parameters and freshness
	`dns("example.com").dnssecValidation.signatureAlgorithms.all(_ >= 8)`,
	`dns("example.com").dnssecValidation.signaturesCurrentlyValid`,
	`dns("example.com").dnssecValidation.signatures.none(expired)`,
	`dns("example.com").dnssecValidation.signatures.none(notYetValid)`,
	`dns("example.com").dnssecValidation.signatureExpiresIn > time.day * 7`,
	// The delegation the parent publishes
	`dns("example.com").dnssec.enabled`,
	`dns("example.com").dnssec.delegationSigned`,
	`dns("example.com").dnssec.dsDigestsMatchKeys`,
	`dns("example.com").dnssec.dsRecords.all(digestType >= 2)`,
	// How absence is proven
	`dns("example.com").dnssec.denialOfExistence == "NSEC3"`,
	`dns("example.com").dnssec.nsec3Iterations == 0`,
	`dns("example.com").dnssec.nsec3SaltLength == 0`,
	`dns("example.com").dnssec.nsec3OptOut == false`,
	// The keys themselves
	`dns("example.com").dnssec.keys.all(zoneKey)`,
	`dns("example.com").dnssec.keys.none(revoked)`,
	`dns("example.com").dnssec.keys.all(keyLength >= 2048)`,
	`dns("example.com").dnssec.algorithms.none(_ == 5)`,
}

// TestDnssecAssertionsCompileDistinctly is the reason the schema is this wide.
//
// Checks are keyed by the checksum of their compiled code, so two audits
// asserting the same predicate are one audit: the second and every one after
// it silently vanish from the report, leaving a policy that looks complete and
// scores once. A DNSSEC surface that only answers "is the zone signed" forces
// exactly that collapse on any policy that has more than one thing to say
// about a validating resolution.
//
// This pins that each property is reachable on its own terms. If a future
// change makes two of these compile to the same code, they stop being two
// checks, and this test is where that gets caught rather than in a report with
// missing rows.
func TestDnssecAssertionsCompileDistinctly(t *testing.T) {
	byChecksum := map[string][]string{}

	for _, query := range dnssecAssertions {
		bundle, err := x.Compile(query)
		require.NoError(t, err, "query must compile: %s", query)
		require.NotNil(t, bundle.CodeV2)
		byChecksum[bundle.CodeV2.Id] = append(byChecksum[bundle.CodeV2.Id], query)
	}

	for checksum, queries := range byChecksum {
		assert.Lenf(t, queries, 1,
			"these assertions collapse into one check (checksum %s): %v", checksum, queries)
	}

	assert.Len(t, byChecksum, len(dnssecAssertions),
		"every assertion must be its own check")
	assert.GreaterOrEqual(t, len(byChecksum), 19,
		"the surface must express at least 19 independent DNSSEC assertions")
}

func TestResource_DnsDnssecValidation(t *testing.T) {
	// cloudflare.com is signed, delegated, and validates to the root. The
	// dnssecOk flag probes whether the DNSSEC-aware lookup completed at all,
	// which it does not on a network that strips EDNS0; skip rather than fail
	// there, since that says nothing about the zone.
	if dnsLiveQuery(t, `dns("cloudflare.com").dnssecValidation.dnssecOk`).Value != true {
		t.Skip("skipping: the resolver did not return DNSSEC records")
	}

	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssecValidation.signed`).Value)
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssecValidation.signaturesVerified`).Value)
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssecValidation.chainOfTrustValidated`).Value)

	// The walk reaches the root, which is what "chain of trust" means.
	chain := dnsLiveQuery(t, `dns("cloudflare.com").dnssecValidation.chain`)
	assert.Contains(t, chain.Value, ".")

	// Nothing broke, so nothing is named as broken.
	assert.Equal(t, "", dnsLiveQuery(t, `dns("cloudflare.com").dnssecValidation.brokenAtZone`).Value)
	assert.Equal(t, "", dnsLiveQuery(t, `dns("cloudflare.com").dnssecValidation.error`).Value)
}

// TestResource_DnsDnssecValidationUnsigned pins the failure contract that
// matters most: an unsigned zone must report an unvalidated resolution, not an
// error that aborts the scan and not a vacuous pass.
func TestResource_DnsDnssecValidationUnsigned(t *testing.T) {
	if dnsLiveQuery(t, `dns("google.com").dnssecValidation.dnssecOk`).Value != true {
		t.Skip("skipping: the resolver did not return DNSSEC records")
	}

	// google.com publishes no DNSKEY, so there is nothing to validate.
	if dnsLiveQuery(t, `dns("google.com").dnssec.enabled`).Value != false {
		t.Skip("skipping: the reference unsigned zone is now signed")
	}

	assert.Equal(t, false, dnsLiveQuery(t, `dns("google.com").dnssecValidation.signed`).Value)
	assert.Equal(t, false, dnsLiveQuery(t, `dns("google.com").dnssecValidation.chainOfTrustValidated`).Value)

	// An empty signature list makes signatures.none(expired) pass vacuously,
	// so the surface carries a field that is false when there is nothing
	// signed. Without it, an unsigned zone satisfies a freshness check.
	assert.Equal(t, false, dnsLiveQuery(t, `dns("google.com").dnssecValidation.signaturesCurrentlyValid`).Value)

	// The reason is inspectable rather than thrown.
	errMsg := dnsLiveQuery(t, `dns("google.com").dnssecValidation.error`)
	assert.NotEmpty(t, errMsg.Value)
}

func TestResource_DnsDnssecConfigDelegation(t *testing.T) {
	if dnsLiveQuery(t, `dns("cloudflare.com").dnssec.enabled`).Value != true {
		t.Skip("skipping: live DNSKEY lookup returned no data")
	}

	// A signed zone whose parent publishes a matching DS is the whole chain in
	// one hop, and both halves are separately assertable.
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssec.delegationSigned`).Value)
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssec.dsDigestsMatchKeys`).Value)
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssec.dsRecords.all(matchesPublishedKey)`).Value)

	// Key length is derived from the key material, and every published key
	// reports one rather than a zero standing in for unknown.
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssec.keys.all(keyLength > 0)`).Value)
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssec.keys.all(algorithmName != "")`).Value)
	assert.Equal(t, true, dnsLiveQuery(t, `dns("cloudflare.com").dnssec.keys.all(zoneKey)`).Value)

	// A signed zone proves absence one way or the other, never neither.
	deniesAbsence := dnsLiveQuery(t, `dns("cloudflare.com").dnssec.denialOfExistence.in(["NSEC","NSEC3"])`)
	assert.Equal(t, true, deniesAbsence.Value)
}

// TestResource_DnsDnssecConfigUnsigned pins that an unsigned zone reports
// nothing rather than a plausible default. Reporting NSEC for a zone that
// proves nothing would be an invented value, and a check reading it would pass
// on a zone with no DNSSEC at all.
func TestResource_DnsDnssecConfigUnsigned(t *testing.T) {
	if dnsLiveQuery(t, `dns("google.com").dnssec.enabled`).Value != false {
		t.Skip("skipping: the reference unsigned zone is now signed")
	}

	assert.Equal(t, "", dnsLiveQuery(t, `dns("google.com").dnssec.denialOfExistence`).Value)
	assert.Equal(t, false, dnsLiveQuery(t, `dns("google.com").dnssec.delegationSigned`).Value)
	assert.Equal(t, false, dnsLiveQuery(t, `dns("google.com").dnssec.dsDigestsMatchKeys`).Value)
	assert.Empty(t, dnsLiveQuery(t, `dns("google.com").dnssec.keys`).Value)
}

func TestResource_DnsSpf(t *testing.T) {
	// google.com publishes an SPF record with a terminating ~all. The presence
	// of an spf1 record probes whether the lookup completed; the assertion then
	// verifies the parsed all-qualifier.
	if dnsLiveQuery(t, `dns("google.com").spf.any(version == "spf1")`).Value != true {
		t.Skip("skipping: live SPF lookup returned no data")
	}

	q := dnsLiveQuery(t, `dns("google.com").spf.all(allQualifier.in(["+","-","~","?"]))`)
	assert.Equal(t, true, q.Value)
}

func TestResource_DnsDmarc(t *testing.T) {
	// google.com publishes a DMARC record at _dmarc.google.com. Presence of the
	// record probes whether the lookup completed; the assertions then verify the
	// parsed version and policy.
	if dnsLiveQuery(t, `dns("google.com").dmarc != null`).Value != true {
		t.Skip("skipping: live DMARC lookup returned no data")
	}

	assert.Equal(t, "DMARC1", dnsLiveQuery(t, `dns("google.com").dmarc.version`).Value)

	pol := dnsLiveQuery(t, `dns("google.com").dmarc.policy.in(["none","quarantine","reject"])`)
	assert.Equal(t, true, pol.Value)
}

func TestResource_DomainName(t *testing.T) {
	res := x.TestQuery(t, "domainName")
	assert.NotEmpty(t, res)
	res = x.TestQuery(t, "domainName(\"mondoo.com\").tld")
	assert.Equal(t, "com", string(res[0].Result().Data.Value))
}

func TestResource_DnsFqdn(t *testing.T) {
	testCases := []struct {
		hostName   string
		expectedId string
	}{
		{
			hostName:   "127.0.0.1",
			expectedId: "dns/",
		},
		{
			hostName:   "3.127.139.132",
			expectedId: "dns/",
		},
		{
			hostName:   "www.mondoo.com",
			expectedId: "dns/www.mondoo.com",
		},
		{
			hostName:   "ec2-3-127-139-132.eu-central-1.compute.amazonaws.com",
			expectedId: "dns/ec2-3-127-139-132.eu-central-1.compute.amazonaws.com",
		},
	}

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}

	for _, tc := range testCases {
		conf := &inventory.Config{
			Host: tc.hostName,
		}
		runtime.Connection = connection.NewHostConnection(1, &inventory.Asset{}, conf)

		dns, err := resources.NewResource(
			runtime,
			"dns",
			map[string]*llx.RawData{},
		)
		require.NoError(t, err)
		require.Equal(t, tc.expectedId, dns.MqlID())
	}
}
