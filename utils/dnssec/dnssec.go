// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package dnssec decodes the DNSSEC record fields that a resolver response and
// an on-disk key file both carry.
//
// Everything here is a pure function over values already in hand: no network,
// no filesystem, no clock of its own. That is the point. The same DNSKEY
// semantics show up in two unrelated places, a key file written by
// dnssec-keygen and a DNSKEY record read off the wire, and the flag bits,
// algorithm numbers and key lengths mean the same thing in both. Decoding them
// twice is how the two copies drift, and the flag bits are exactly the detail
// one copy gets right and the other does not.
//
// I/O stays with the caller. Reading a file, issuing a query, or reaching a
// resolver is provider-specific; interpreting the bytes that come back is not.
package dnssec

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"
	"time"
)

// DNSKEY flags field bits (RFC 4034 section 2.1.1, RFC 5011 section 3).
//
// The flags are a bit field, not an enumeration. Comparing a whole flags value
// against 257 is the common mistake: a key signing key that has also been
// revoked reads 385, and an equality test silently reclassifies it as a zone
// signing key.
const (
	// FlagSecureEntryPoint marks a key used to sign the zone's DNSKEY RRset,
	// that is, a key signing key. Bit 15 of the flags field.
	FlagSecureEntryPoint = 1
	// FlagRevoke marks a key its owner has withdrawn (RFC 5011). Bit 8.
	FlagRevoke = 0x80
	// FlagZoneKey marks a key usable to sign zone data. Bit 7. A DNSKEY
	// without it is not a zone key and must not validate zone records.
	FlagZoneKey = 0x100
)

// IsKeySigningKey reports whether the Secure Entry Point bit is set, which
// makes the key a key signing key rather than a zone signing key.
func IsKeySigningKey(flags int) bool { return flags&FlagSecureEntryPoint != 0 }

// IsZoneKey reports whether the key may be used to sign zone data.
func IsZoneKey(flags int) bool { return flags&FlagZoneKey != 0 }

// IsRevoked reports whether the key carries the RFC 5011 revoke bit.
func IsRevoked(flags int) bool { return flags&FlagRevoke != 0 }

// algorithmNames maps DNSSEC algorithm numbers to their IANA mnemonics.
//
// Sourced from the IANA DNS Security Algorithm Numbers registry; the
// recommendations for which of these to use or retire are RFC 8624.
var algorithmNames = map[int]string{
	1:   "RSAMD5",
	2:   "DH",
	3:   "DSA",
	5:   "RSASHA1",
	6:   "DSA-NSEC3-SHA1",
	7:   "RSASHA1-NSEC3-SHA1",
	8:   "RSASHA256",
	10:  "RSASHA512",
	12:  "ECC-GOST",
	13:  "ECDSAP256SHA256",
	14:  "ECDSAP384SHA384",
	15:  "ED25519",
	16:  "ED448",
	17:  "SM2SM3",
	23:  "ECC-GOST12",
	252: "INDIRECT",
	253: "PRIVATEDNS",
	254: "PRIVATEOID",
}

// AlgorithmName returns the IANA mnemonic for a DNSSEC algorithm number, or an
// empty string when the number is unassigned. Callers that need a value for
// every input should fall back to the number itself.
func AlgorithmName(algorithm int) string { return algorithmNames[algorithm] }

// digestTypeNames maps DS digest type numbers to their IANA mnemonics.
var digestTypeNames = map[int]string{
	1: "SHA-1",
	2: "SHA-256",
	3: "GOST R 34.11-94",
	4: "SHA-384",
	5: "GOST R 34.11-2012",
	6: "SM3",
}

// DigestTypeName returns the IANA mnemonic for a DS digest type number, or an
// empty string when the number is unassigned.
func DigestTypeName(digestType int) string { return digestTypeNames[digestType] }

// PublicKeyBits returns the key length in bits for a base64-encoded DNSKEY
// public key, given the key's algorithm.
//
// The length is derived from the key material rather than assumed from the
// algorithm, so a truncated or malformed key does not report a confident wrong
// size. Returns 0 when the length cannot be determined: an unassigned
// algorithm, a key that does not decode, or an RSA key whose exponent header
// runs past the end of the buffer. Zero means unknown, never zero-length, so
// treat it as "no answer" rather than as a very short key.
func PublicKeyBits(algorithm int, publicKey string) int {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(publicKey), ""))
	if err != nil || len(raw) == 0 {
		return 0
	}

	switch algorithm {
	case 1, 5, 7, 8, 10: // RSA, RFC 3110
		return rsaModulusBits(raw)
	case 3, 6: // DSA, RFC 2536: key size is 512 + T*64, where T is the first byte
		if raw[0] > 8 {
			return 0
		}
		return 512 + int(raw[0])*64
	case 12, 13, 14, 17, 23:
		// ECDSA and the GOST/SM2 curves publish the uncompressed point as
		// x||y with no leading format byte, so the field size is half of it.
		return len(raw) * 8 / 2
	case 15, 16: // EdDSA publishes the encoded point directly
		return len(raw) * 8
	default:
		return 0
	}
}

// rsaModulusBits reads an RFC 3110 RSA public key and returns the modulus
// length in bits. The wire format is a one-byte exponent length, or a zero
// byte followed by a two-byte exponent length when the exponent is 256 bytes
// or longer, then the exponent, then the modulus.
func rsaModulusBits(raw []byte) int {
	var explen int
	var offset int

	switch {
	case raw[0] != 0:
		explen = int(raw[0])
		offset = 1
	case len(raw) >= 3:
		explen = int(binary.BigEndian.Uint16(raw[1:3]))
		offset = 3
	default:
		return 0
	}

	if explen == 0 || offset+explen >= len(raw) {
		return 0
	}
	return (len(raw) - offset - explen) * 8
}

// DSDigest computes the DS digest of a DNSKEY, per RFC 4034 section 5.1.4:
// the hash of the key's canonical owner name followed by the DNSKEY RDATA.
//
// This is what links a child zone's key to the delegation its parent
// publishes. Comparing the result against the digest in a DS record is the
// only way to tell a published DS apart from one left behind by a key that has
// since been rolled, which is the difference between a chain of trust that
// resolves and one that breaks.
//
// The digest is returned as lowercase hex. DS records are usually presented in
// uppercase, so compare case-insensitively.
func DSDigest(owner string, flags, protocol, algorithm int, publicKey string, digestType int) (string, error) {
	h, err := digestHash(digestType)
	if err != nil {
		return "", err
	}

	name, err := CanonicalName(owner)
	if err != nil {
		return "", err
	}

	key, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(publicKey), ""))
	if err != nil {
		return "", errors.New("dnssec: public key is not valid base64")
	}
	if len(key) == 0 {
		return "", errors.New("dnssec: public key is empty")
	}

	rdata := make([]byte, 4, 4+len(key))
	binary.BigEndian.PutUint16(rdata[0:2], uint16(flags))
	rdata[2] = byte(protocol)
	rdata[3] = byte(algorithm)
	rdata = append(rdata, key...)

	h.Write(name)
	h.Write(rdata)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// digestHash returns the hash for a DS digest type. The GOST types are
// deliberately unsupported rather than silently wrong: RFC 8624 marks them
// MUST NOT, and Go ships no implementation of either.
func digestHash(digestType int) (hash.Hash, error) {
	switch digestType {
	case 1:
		return sha1.New(), nil //nolint:gosec // SHA-1 is what DS digest type 1 is defined as
	case 2:
		return sha256.New(), nil
	case 4:
		return sha512.New384(), nil
	default:
		return nil, errors.New("dnssec: unsupported DS digest type " + strconv.Itoa(digestType))
	}
}

// CanonicalName encodes a domain name in the uncompressed, lowercased wire
// form used for DNSSEC digests (RFC 4034 section 6.2): each label prefixed by
// its length, terminated by a zero byte.
//
// Escaped label separators (`\.`) are not decoded. They are legal but vanishing
// rare in a zone apex, which is the only name this is asked to encode.
func CanonicalName(name string) ([]byte, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return []byte{0}, nil
	}

	labels := strings.Split(name, ".")
	buf := make([]byte, 0, len(name)+2)
	for _, label := range labels {
		if label == "" {
			return nil, errors.New("dnssec: name contains an empty label: " + name)
		}
		if len(label) > 63 {
			return nil, errors.New("dnssec: name contains an over-long label: " + name)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	return append(buf, 0), nil
}

// NSEC3 flags field bits (RFC 5155 section 3.1.2).
const (
	// NSEC3FlagOptOut marks an NSEC3 record that may span unsigned
	// delegations, so a missing name cannot be proven absent.
	NSEC3FlagOptOut = 1
)

// NSEC3OptOut reports whether an NSEC3 or NSEC3PARAM flags field has the
// opt-out bit set.
func NSEC3OptOut(flags int) bool { return flags&NSEC3FlagOptOut != 0 }

// nsec3HashNames maps NSEC3 hash algorithm numbers to their mnemonics. Only
// one is assigned.
var nsec3HashNames = map[int]string{
	1: "SHA-1",
}

// NSEC3HashAlgorithmName returns the mnemonic for an NSEC3 hash algorithm
// number, or an empty string when unassigned.
func NSEC3HashAlgorithmName(algorithm int) string { return nsec3HashNames[algorithm] }

// NSEC3SaltLength returns the length in bytes of an NSEC3 salt given its
// presentation form. A zone with no salt writes `-`, which is zero bytes and
// not a one-character salt. Returns 0 for anything that is not valid hex.
func NSEC3SaltLength(salt string) int {
	salt = strings.TrimSpace(salt)
	if salt == "" || salt == "-" {
		return 0
	}
	raw, err := hex.DecodeString(salt)
	if err != nil {
		return 0
	}
	return len(raw)
}

// SignatureWindow is the validity period of an RRSIG: the moment its signature
// becomes usable and the moment it stops being usable.
//
// The window, rather than the signature itself, is what stays meaningful over
// time. Re-signing a zone replaces every signature and every key tag, so
// anything derived from those changes on a schedule the operator did not pick.
// How much validity is left does not: a zone re-signed every week with a
// 14-day window reports roughly the same remaining validity every time it is
// looked at, which is what makes it something to assert on.
type SignatureWindow struct {
	// Inception is when the signature became valid.
	Inception time.Time
	// Expiration is when the signature stops being valid.
	Expiration time.Time
}

// Expired reports whether the signature's validity has already ended.
func (w SignatureWindow) Expired(now time.Time) bool {
	return !w.Expiration.IsZero() && now.After(w.Expiration)
}

// NotYetValid reports whether the signature's validity has not yet begun,
// which a resolver treats exactly as harshly as an expired one.
func (w SignatureWindow) NotYetValid(now time.Time) bool {
	return !w.Inception.IsZero() && now.Before(w.Inception)
}

// Valid reports whether now falls inside the window.
func (w SignatureWindow) Valid(now time.Time) bool {
	return !w.Expired(now) && !w.NotYetValid(now)
}

// RemainingValidity returns how long the signature stays usable. It is
// negative once the signature has expired, and zero when no expiration is
// known.
func (w SignatureWindow) RemainingValidity(now time.Time) time.Duration {
	if w.Expiration.IsZero() {
		return 0
	}
	return w.Expiration.Sub(now)
}
