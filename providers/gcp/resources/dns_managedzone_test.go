// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/dns/v1"
)

func TestManagedZoneServiceDirectoryNamespaceUrl(t *testing.T) {
	tests := []struct {
		name string
		cfg  *dns.ManagedZoneServiceDirectoryConfig
		want string
	}{
		{
			name: "no config",
			cfg:  nil,
			want: "",
		},
		{
			// A config block with no namespace still means the zone is not
			// backed by Service Directory. Dereferencing it would panic and
			// take the whole scan with it.
			name: "config present but namespace absent",
			cfg:  &dns.ManagedZoneServiceDirectoryConfig{},
			want: "",
		},
		{
			name: "namespace url reported",
			cfg: &dns.ManagedZoneServiceDirectoryConfig{
				Namespace: &dns.ManagedZoneServiceDirectoryConfigNamespace{
					NamespaceUrl: "https://servicedirectory.googleapis.com/v1/projects/p/locations/l/namespaces/n",
				},
			},
			want: "https://servicedirectory.googleapis.com/v1/projects/p/locations/l/namespaces/n",
		},
		{
			name: "namespace present with empty url",
			cfg: &dns.ManagedZoneServiceDirectoryConfig{
				Namespace: &dns.ManagedZoneServiceDirectoryConfigNamespace{},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, managedZoneServiceDirectoryNamespaceUrl(tt.cfg))
		})
	}
}

func TestManagedZoneReverseLookupEnabled(t *testing.T) {
	// The API carries no boolean here: an empty but non-nil config block is how
	// it reports a reverse-lookup zone. Reading a field instead of the block's
	// presence would report every such zone as disabled.
	assert.False(t, managedZoneReverseLookupEnabled(nil))
	assert.True(t, managedZoneReverseLookupEnabled(&dns.ManagedZoneReverseLookupConfig{}))
	assert.True(t, managedZoneReverseLookupEnabled(&dns.ManagedZoneReverseLookupConfig{Kind: "dns#managedZoneReverseLookupConfig"}))
}

func TestIsWeakDnssecAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm string
		want      bool
	}{
		// The Cloud DNS API returns the mnemonic lower-cased, which is the
		// form that reaches this predicate from DnsKeys.List.
		{"rsasha1", true},
		{"RSASHA1", true},
		{"RsaSha1", true},
		{"rsasha1-nsec3-sha1", true},
		{"RSASHA1-NSEC3-SHA1", true},
		{" rsasha1 ", true},
		{"rsasha256", false},
		{"rsasha512", false},
		{"ecdsap256sha256", false},
		{"ecdsap384sha384", false},
		// A future algorithm we do not know about must not be reported as
		// weak; the finding has to be evidence, not a default.
		{"ed25519", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			assert.Equal(t, tt.want, isWeakDnssecAlgorithm(tt.algorithm))
		})
	}
}

// TestDnsKeysHaveWeakAlgorithm covers the predicate that replaced the read of
// DnssecConfig.DefaultKeySpecs. The key specs describe how new keys are
// generated, so a zone whose live keys were rolled to a different algorithm was
// audited against data that no longer described it.
func TestDnsKeysHaveWeakAlgorithm(t *testing.T) {
	tests := []struct {
		name string
		keys []*dns.DnsKey
		want bool
	}{
		{
			name: "no keys",
			keys: nil,
			want: false,
		},
		{
			name: "empty list",
			keys: []*dns.DnsKey{},
			want: false,
		},
		{
			name: "modern ksk and zsk",
			keys: []*dns.DnsKey{
				{Algorithm: "ecdsap256sha256", Type: "keySigning", IsActive: true},
				{Algorithm: "ecdsap256sha256", Type: "zoneSigning", IsActive: true},
			},
			want: false,
		},
		{
			name: "active rsasha1 key signing key",
			keys: []*dns.DnsKey{
				{Algorithm: "rsasha1", Type: "keySigning", IsActive: true},
				{Algorithm: "rsasha256", Type: "zoneSigning", IsActive: true},
			},
			want: true,
		},
		{
			name: "weak key is the zone signing key only",
			keys: []*dns.DnsKey{
				{Algorithm: "rsasha256", Type: "keySigning", IsActive: true},
				{Algorithm: "rsasha1", Type: "zoneSigning", IsActive: true},
			},
			want: true,
		},
		{
			// A deactivated key stays published in the DNSKEY record set and
			// resolvers still validate existing signatures against it, so a
			// zone mid-rollover is not yet clean.
			name: "inactive rsasha1 key still counts",
			keys: []*dns.DnsKey{
				{Algorithm: "ecdsap256sha256", Type: "keySigning", IsActive: true},
				{Algorithm: "rsasha1", Type: "keySigning", IsActive: false},
			},
			want: true,
		},
		{
			name: "nil entry is skipped, not dereferenced",
			keys: []*dns.DnsKey{nil, {Algorithm: "rsasha256", IsActive: true}},
			want: false,
		},
		{
			name: "nil entry alongside a weak key",
			keys: []*dns.DnsKey{nil, {Algorithm: "rsasha1", IsActive: true}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dnsKeysHaveWeakAlgorithm(tt.keys))
		})
	}
}

// TestDnsKeysHaveWeakAlgorithmIgnoresDefaultKeySpecs is the regression the fix
// exists for: the zone was created with a modern default key spec but is signed
// today with an RSASHA1 key, so reading the spec reports the zone as fine while
// reading the live keys finds the weakness.
func TestDnsKeysHaveWeakAlgorithmIgnoresDefaultKeySpecs(t *testing.T) {
	zone := &dns.ManagedZone{
		Name: "example-zone",
		DnssecConfig: &dns.ManagedZoneDnsSecConfig{
			State: "on",
			DefaultKeySpecs: []*dns.DnsKeySpec{
				{Algorithm: "ecdsap256sha256", KeyLength: 256, KeyType: "keySigning"},
				{Algorithm: "ecdsap256sha256", KeyLength: 256, KeyType: "zoneSigning"},
			},
		},
	}
	// The zone-level config says the zone is modern.
	for _, spec := range zone.DnssecConfig.DefaultKeySpecs {
		assert.False(t, isWeakDnssecAlgorithm(spec.Algorithm))
	}
	// The keys actually published say otherwise.
	liveKeys := []*dns.DnsKey{
		{Algorithm: "rsasha1", KeyLength: 2048, Type: "keySigning", IsActive: true},
		{Algorithm: "ecdsap256sha256", KeyLength: 256, Type: "zoneSigning", IsActive: true},
	}
	assert.True(t, dnsKeysHaveWeakAlgorithm(liveKeys))
}

func TestDnsKeyIdentity(t *testing.T) {
	assert.Equal(t, "12345", dnsKeyIdentity(&dns.DnsKey{Id: "12345", KeyTag: 999, Type: "keySigning"}))
	// Without a server id, two keys in the same zone must not collapse onto
	// one cache entry.
	ksk := dnsKeyIdentity(&dns.DnsKey{KeyTag: 999, Type: "keySigning"})
	zsk := dnsKeyIdentity(&dns.DnsKey{KeyTag: 999, Type: "zoneSigning"})
	assert.Equal(t, "999/keySigning", ksk)
	assert.NotEqual(t, ksk, zsk)
}
