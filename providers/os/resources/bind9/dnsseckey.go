// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bind9

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.mondoo.com/mql/v13/utils/dnssec"
)

// DNSSECKey is one key pair written by dnssec-keygen.
//
// Everything here comes from the file name and the header of the public key
// file. No DNS record parsing is involved, and the private key is never read —
// its path is carried so its mode and owner can be checked, nothing more.
type DNSSECKey struct {
	// Zone the key was generated for, without the trailing dot.
	Zone string
	// KeyTag is the numeric id in the file name.
	KeyTag int
	// Algorithm is the DNSSEC algorithm number, e.g. 13 for ECDSAP256SHA256.
	Algorithm int
	// KeySigningKey is true for a KSK, false for a ZSK. Taken from the DNSKEY
	// flags field rather than the comment, because the comment is prose and
	// the flags are the record.
	KeySigningKey bool
	// Created is when dnssec-keygen generated the key. Zero when the file
	// records no Created: line.
	Created time.Time
}

// dnssecKeyFile matches the name dnssec-keygen writes:
//
//	Kexample.com.+013+53434.key
//
// The zone keeps its trailing dot in the file name; it is trimmed for the
// field, because a check comparing against bind9.zone.name would otherwise
// never match.
var dnssecKeyFile = regexp.MustCompile(`^K(.+)\.\+(\d{3})\+(\d{5})\.key$`)

// IsDNSSECKeyFile reports whether a file name is a dnssec-keygen public key.
func IsDNSSECKeyFile(name string) bool {
	return dnssecKeyFile.MatchString(name)
}

// dnskeyFlags finds the flags field of a DNSKEY record. The record reads
//
//	example.com. IN DNSKEY 257 3 13 <base64>
//
// and the class is optional, so the flags are located relative to the DNSKEY
// token rather than by column.
var dnskeyFlags = regexp.MustCompile(`\bDNSKEY\s+(\d+)\s`)

// dnssecCreated matches the header line dnssec-keygen writes:
//
//	; Created: 20260816141610 (Sun Aug 16 14:16:10 2026)
var dnssecCreated = regexp.MustCompile(`^;\s*Created:\s*(\d{14})`)

// ParseDNSSECKeyFile reads what a public key file says about itself. The name
// is parsed for the zone, algorithm and tag; the content for the flags and the
// creation date.
//
// A file whose name does not match is not a key file and returns nil, so a
// directory holding other things can be walked without filtering it first.
func ParseDNSSECKeyFile(name, content string) *DNSSECKey {
	m := dnssecKeyFile.FindStringSubmatch(name)
	if m == nil {
		return nil
	}

	// The three capture groups are \d{3} and \d{5} after a successful match,
	// so these cannot fail; the errors are ignored deliberately rather than
	// carried as a failure mode that cannot occur.
	algorithm, _ := strconv.Atoi(m[2])
	keyTag, _ := strconv.Atoi(m[3])

	key := &DNSSECKey{
		Zone:      strings.TrimSuffix(m[1], "."),
		Algorithm: algorithm,
		KeyTag:    keyTag,
	}

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if c := dnssecCreated.FindStringSubmatch(line); c != nil && key.Created.IsZero() {
			// dnssec-keygen writes the timestamp in UTC.
			if t, err := time.Parse("20060102150405", c[1]); err == nil {
				key.Created = t.UTC()
			}
			continue
		}

		if strings.HasPrefix(line, ";") {
			continue
		}

		if f := dnskeyFlags.FindStringSubmatch(line); f != nil {
			flags, err := strconv.Atoi(f[1])
			if err != nil {
				continue
			}
			// The Secure Entry Point bit is set for a key signing key and
			// clear for a zone signing key. Comparing against 257 exactly
			// would miss a key with the revoke bit also set. The same flags
			// field arrives in a DNSKEY record read off the wire, so the bit
			// test lives in utils/dnssec and is shared with that reader
			// rather than written out twice.
			key.KeySigningKey = dnssec.IsKeySigningKey(flags)
		}
	}

	return key
}

// PrivateKeyPath returns the private half's path for a public key path. The
// file may not exist: a key signing key is commonly generated once and its
// private half kept off the server that publishes the zone, so the caller
// checks rather than assuming a pair.
func PrivateKeyPath(publicPath string) string {
	return strings.TrimSuffix(publicPath, ".key") + ".private"
}
