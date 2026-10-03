// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package java reads Java keystores and trust stores off disk.
//
// The certificates in a JKS store are not encrypted — only private keys are,
// and the store password protects an integrity digest rather than the contents.
// That is what lets a trust store be read without a credential, which in turn is
// what lets it be read from a container image or a mounted filesystem where
// nothing can be executed. A PKCS#12 store is different: its bags sit inside
// encrypted content, so reading one does need the password.
package java

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
	"unicode/utf16"

	"github.com/rs/zerolog/log"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	// FormatJKS is Sun's own keystore format, still what a JDK ships cacerts as.
	FormatJKS = "jks"
	// FormatJCEKS is the JCE variant. Same layout, different magic.
	FormatJCEKS = "jceks"
	// FormatPKCS12 is the standard format, the default for stores created by
	// keytool since JDK 9.
	FormatPKCS12 = "pkcs12"

	magicJKS   uint32 = 0xFEEDFEED
	magicJCEKS uint32 = 0xCECECECE

	// tagTrustedCert and tagPrivateKey are the two entry kinds JKS defines.
	tagPrivateKey  uint32 = 1
	tagTrustedCert uint32 = 2

	// A JKS file ends with a SHA-1 digest over its contents.
	jksDigestLen = 20

	// Guards against a corrupt or hostile length field turning into a huge
	// allocation. A certificate an order of magnitude smaller than this would
	// already be unusual.
	maxEntries  = 100_000
	maxAliasLen = 64 * 1024
	maxCertLen  = 16 * 1024 * 1024
	maxKeyLen   = 16 * 1024 * 1024
)

// DefaultPasswords are tried, in order, when a PKCS#12 store is read without one
// being given. "changeit" is the documented JDK default for cacerts and is
// published in Oracle's own documentation, so it is a default rather than a
// secret.
var DefaultPasswords = []string{"changeit", ""}

// ErrPasswordRequired reports a store whose contents could not be decrypted.
// It is deliberately distinct from "no entries": a caller that cannot tell them
// apart would report an unreadable store as an empty one, and an empty store
// satisfies every assertion made about its contents.
var ErrPasswordRequired = errors.New("keystore contents are encrypted and no password worked")

// ErrUnsupportedPKCS12 reports a store built with PKCS#12 features the reader
// does not implement, which no password will open.
//
// It no longer covers the common case it was written for. golang.org/x/crypto/
// pkcs12 verifies the integrity MAC before decrypting anything and accepts only
// SHA-1, so it could not open a store keytool has written since JDK 9; the
// reader here verifies SHA-256, SHA-384 and SHA-512 as well. The error stays
// because a store can still use something unimplemented, and because reporting
// that as a wrong password would send someone hunting for a credential that was
// never the problem.
var ErrUnsupportedPKCS12 = errors.New("PKCS#12 store uses features this reader does not implement")

// Entry is one alias in a keystore.
type Entry struct {
	Alias string
	// Trusted marks an entry holding someone else's certificate, as opposed to
	// one holding a private key and its chain. A trust store is made of these.
	Trusted bool
	// CreatedAt is the entry's creation date. JKS records one per entry; PKCS#12
	// does not, and it is left zero there.
	CreatedAt time.Time
	// Certs holds DER-encoded certificates. A trusted entry has exactly one; a
	// private-key entry carries its chain, which may be empty.
	Certs [][]byte
}

// Keystore is a parsed store.
type Keystore struct {
	Format  string
	Entries []Entry
}

// DetectFormat reports which format a store is in, from its first bytes. The
// magic numbers are unambiguous; anything else that starts an ASN.1 SEQUENCE is
// taken to be PKCS#12.
func DetectFormat(head []byte) (string, error) {
	if len(head) < 4 {
		return "", errors.New("not a keystore: file is too short")
	}
	switch binary.BigEndian.Uint32(head[:4]) {
	case magicJKS:
		return FormatJKS, nil
	case magicJCEKS:
		return FormatJCEKS, nil
	}
	// 0x30 is the ASN.1 tag for SEQUENCE, which is how a PKCS#12 PFX opens.
	if head[0] == 0x30 {
		return FormatPKCS12, nil
	}
	return "", fmt.Errorf("not a keystore: unrecognized leading bytes %#x", head[:4])
}

// Parse reads a store of any supported format. The password is only consulted
// for PKCS#12; a JKS store's certificates are readable without it.
func Parse(data []byte, password string) (*Keystore, error) {
	format, err := DetectFormat(data)
	if err != nil {
		return nil, err
	}

	switch format {
	case FormatJKS, FormatJCEKS:
		ks, err := ParseJKS(data)
		if err != nil {
			return nil, err
		}
		ks.Format = format
		return ks, nil
	case FormatPKCS12:
		return ParsePKCS12(data, password)
	}
	return nil, fmt.Errorf("unsupported keystore format %q", format)
}

// ParseJKS reads Sun's keystore format.
//
// The layout, in big-endian throughout: magic, version, entry count, then that
// many entries. Each entry is a tag, an alias, a creation timestamp in
// milliseconds, and then either a certificate (tag 2) or an encrypted private
// key followed by its chain (tag 1). A version 2 file names the certificate type
// before each certificate; version 1 does not. The file ends with a digest,
// which is not checked here — verifying it needs the store password, and the
// certificates are readable and meaningful without it.
func ParseJKS(data []byte) (*Keystore, error) {
	r := &reader{buf: data}

	magic, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if magic != magicJKS && magic != magicJCEKS {
		return nil, fmt.Errorf("not a JKS keystore: magic %#x", magic)
	}

	version, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("unsupported JKS version %d", version)
	}

	count, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if count > maxEntries {
		return nil, fmt.Errorf("JKS declares %d entries, refusing to read", count)
	}

	ks := &Keystore{Format: FormatJKS, Entries: make([]Entry, 0, count)}
	for i := uint32(0); i < count; i++ {
		entry, err := readJKSEntry(r, version)
		if err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		ks.Entries = append(ks.Entries, entry)
	}

	// What should remain is the trailing digest and nothing else. A different
	// amount means the entry count and the file disagree, so the entries read so
	// far cannot be trusted to be all of them — and a trust store that is short a
	// few certificates still satisfies every assertion made about the ones that
	// were read.
	if remaining := len(r.buf) - r.pos; remaining != jksDigestLen {
		return nil, fmt.Errorf("JKS is malformed: %d trailing bytes after %d entries, expected a %d-byte digest",
			remaining, count, jksDigestLen)
	}

	return ks, nil
}

func readJKSEntry(r *reader, version uint32) (Entry, error) {
	var entry Entry

	tag, err := r.uint32()
	if err != nil {
		return entry, err
	}

	alias, err := r.utf()
	if err != nil {
		return entry, err
	}
	entry.Alias = alias

	millis, err := r.uint64()
	if err != nil {
		return entry, err
	}
	// A zero timestamp means "not recorded" rather than the epoch, so it is left
	// as the zero time instead of becoming 1970.
	if millis != 0 {
		entry.CreatedAt = time.UnixMilli(int64(millis)).UTC()
	}

	switch tag {
	case tagTrustedCert:
		entry.Trusted = true
		der, err := readJKSCert(r, version)
		if err != nil {
			return entry, err
		}
		entry.Certs = [][]byte{der}

	case tagPrivateKey:
		// The key material itself is encrypted under the store password and is
		// deliberately not returned: an audit needs to know a key is present and
		// what chain vouches for it, never the key.
		keyLen, err := r.uint32()
		if err != nil {
			return entry, err
		}
		if keyLen > maxKeyLen {
			return entry, fmt.Errorf("private key length %d is implausible", keyLen)
		}
		if _, err := r.bytes(int(keyLen)); err != nil {
			return entry, err
		}

		chainLen, err := r.uint32()
		if err != nil {
			return entry, err
		}
		if chainLen > maxEntries {
			return entry, fmt.Errorf("chain length %d is implausible", chainLen)
		}
		for j := uint32(0); j < chainLen; j++ {
			der, err := readJKSCert(r, version)
			if err != nil {
				return entry, fmt.Errorf("chain certificate %d: %w", j, err)
			}
			entry.Certs = append(entry.Certs, der)
		}

	default:
		return entry, fmt.Errorf("unknown entry tag %d", tag)
	}

	return entry, nil
}

func readJKSCert(r *reader, version uint32) ([]byte, error) {
	if version == 2 {
		// The certificate type, "X.509" in every store seen in the wild. Read to
		// advance the cursor; the DER that follows says what it is.
		if _, err := r.utf(); err != nil {
			return nil, err
		}
	}
	length, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if length > maxCertLen {
		return nil, fmt.Errorf("certificate length %d is implausible", length)
	}
	return r.bytes(int(length))
}

// ParsePKCS12 reads the standard format. Unlike JKS the bags are encrypted, so
// this needs the password. When none is given the documented defaults are tried
// before giving up.
//
// The reader is software.sslmate.com/src/go-pkcs12 rather than
// golang.org/x/crypto/pkcs12, which verifies only SHA-1 MACs and so cannot open
// a store keytool has written since JDK 9. See readPKCS12 for why three entry
// points are tried rather than one.
func ParsePKCS12(data []byte, password string) (*Keystore, error) {
	passwords := DefaultPasswords
	if password != "" {
		passwords = append([]string{password}, DefaultPasswords...)
	}

	var lastErr error
	for _, candidate := range passwords {
		entries, err := readPKCS12(data, candidate)
		if err == nil {
			// The password is now known to be right. Walking the SafeBags
			// recovers what the entry points above drop: every alias, and
			// which certificates keytool marked as trusted. A store this walk
			// cannot read (an encryption scheme it does not implement) keeps
			// what the entry points returned.
			//
			// The two can differ in count: the walk reports every X.509
			// certificate bag, including a store's extra chain certificates
			// that DecodeChain folds into one list. That is logged rather
			// than hidden, so a divergence nobody expected is visible.
			bagEntries, bagErr := readPKCS12Bags(data, candidate)
			switch {
			case bagErr != nil:
				log.Debug().Err(bagErr).Msg("java> could not walk the PKCS#12 bags, keeping the entries without aliases")
			case len(bagEntries) == 0:
				log.Debug().Int("entries", len(entries)).Msg("java> the PKCS#12 bag walk found no certificates, keeping the entries without aliases")
			default:
				if len(bagEntries) != len(entries) {
					log.Debug().Int("bags", len(bagEntries)).Int("entries", len(entries)).Msg("java> the PKCS#12 bag walk and go-pkcs12 disagree on the entry count")
				}
				entries = bagEntries
			}
			return &Keystore{Format: FormatPKCS12, Entries: entries}, nil
		}
		lastErr = err

		// Something unimplemented fails identically for every password, so stop
		// rather than working through the list and then blaming the credential.
		// The reader types these, so this reads the type rather than the
		// message: the wording is an internal detail and would change without
		// notice.
		var notImplemented pkcs12.NotImplementedError
		if errors.As(err, &notImplemented) {
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedPKCS12, err)
		}

		// Any other error than a wrong password comes after go-pkcs12 verified
		// the integrity MAC: the password is right and the store has a shape
		// none of the entry points take, such as the CA bundle `openssl pkcs12
		// -export -nokeys` writes (one safe, no key). The bag walk reads it.
		// Should it fail too, or find no certificate (what -nocerts writes,
		// which must not read as an empty store), that is what the store is,
		// not a password problem.
		if !errors.Is(err, pkcs12.ErrIncorrectPassword) {
			bagEntries, bagErr := readPKCS12Bags(data, candidate)
			if bagErr == nil && len(bagEntries) > 0 {
				return &Keystore{Format: FormatPKCS12, Entries: bagEntries}, nil
			}
			return nil, fmt.Errorf("%w: %v", ErrUnsupportedPKCS12, err)
		}
	}

	return nil, fmt.Errorf("%w: %v", ErrPasswordRequired, lastErr)
}

// readPKCS12 reads the certificates of a store with the one entry point that
// fits its shape. No single one covers the three shapes that occur in practice:
//
//   - ToPEM carries friendlyName and localKeyId, the only go-pkcs12 entry
//     point that can recover an alias and tell a trust anchor from a
//     certificate that belongs to a private key's chain. It refuses any bag
//     attribute it does not know, including the one keytool writes on a
//     trusted certificate, which is why ParsePKCS12 walks the bags itself
//     (readPKCS12Bags) once one of these has accepted the password.
//   - DecodeTrustStore reads a store of trust anchors, the shape ToPEM refuses.
//     It reports no aliases.
//   - DecodeChain reads a keystore whose bags carry attributes ToPEM rejects.
//     Everything it returns belongs to the private key's chain.
//
// Only the error from DecodeChain describes the store. The other two reject by
// shape, and they report a shape they cannot handle as NotImplementedError as
// well: DecodeTrustStore answers "expected exactly 1 items in the authenticated
// safe" for an ordinary keystore. Classifying on that would report every
// keystore as unreadable. DecodeChain imposes the fewest constraints, so its
// failure is the store's rather than the entry point's.
func readPKCS12(data []byte, password string) ([]Entry, error) {
	if entries, err := pkcs12EntriesFromPEM(data, password); err == nil && len(entries) > 0 {
		return entries, nil
	}

	if certs, err := pkcs12.DecodeTrustStore(data, password); err == nil && len(certs) > 0 {
		entries := make([]Entry, 0, len(certs))
		for _, cert := range certs {
			// Every certificate in a trust store is a trust anchor by
			// definition. The alias is not recoverable through this path.
			entries = append(entries, Entry{Trusted: true, Certs: [][]byte{cert.Raw}})
		}
		return entries, nil
	}

	_, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(cas)+1)
	if leaf != nil {
		entries = append(entries, Entry{Certs: [][]byte{leaf.Raw}})
	}
	for _, ca := range cas {
		// These belong to the key's chain, not to the trust anchors, which is
		// the classification ToPEM reaches through localKeyId.
		entries = append(entries, Entry{Certs: [][]byte{ca.Raw}})
	}
	// DecodeChain is the last attempt, so what it read is the answer even when
	// that is nothing. It reports "certificate missing" for a store that holds
	// no certificate at all, so reaching here with an empty list means the
	// store parsed and its contents are genuinely empty.
	return entries, nil
}

// pkcs12EntriesFromPEM reads the store through ToPEM, the only entry point that
// carries the bag attributes an alias and a trust classification come from.
func pkcs12EntriesFromPEM(data []byte, password string) ([]Entry, error) {
	// ToPEM is deprecated because it labels a private key "PRIVATE KEY" while
	// encoding it as a raw RSA or EC key, which produces a PEM block nothing
	// else can read. That hazard is confined to key bags, and this reads only
	// certificate blocks and the bag attributes beside them, which the
	// replacement it names does not expose at all.
	blocks, err := pkcs12.ToPEM(data, password) //nolint:staticcheck // only certificate blocks and their attributes are read
	if err != nil {
		return nil, err
	}

	// A certificate that belongs to a private key's chain is not a trust
	// anchor, and PKCS#12 ties the two together with a localKeyId rather than
	// by position. Collect the keys' ids first so the certificates can be
	// classified the same way the JKS entry tags classify them.
	keyIDs := map[string]struct{}{}
	for _, block := range blocks {
		if block.Type == "PRIVATE KEY" {
			if id, ok := block.Headers["localKeyId"]; ok {
				keyIDs[id] = struct{}{}
			}
		}
	}

	var entries []Entry
	for _, block := range blocks {
		// Only certificates are surfaced. A shrouded key bag decodes to key
		// material, which has no place in a scan result.
		if block.Type != "CERTIFICATE" {
			continue
		}
		_, belongsToAKey := keyIDs[block.Headers["localKeyId"]]
		entries = append(entries, Entry{
			// friendlyName is where keytool records the alias. A store written
			// by something else may not set one, which is why the resource does
			// not identify an entry by its alias alone.
			Alias:   block.Headers["friendlyName"],
			Trusted: !belongsToAKey,
			Certs:   [][]byte{block.Bytes},
		})
	}
	return entries, nil
}

// reader walks a byte slice, refusing to run past the end.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) bytes(n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("negative length")
	}
	// The trailing digest is not an entry, so running into it means the entry
	// count and the file disagree.
	if r.pos+n > len(r.buf) {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *reader) uint32() (uint32, error) {
	b, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

func (r *reader) uint64() (uint64, error) {
	b, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// utf reads a Java modified-UTF-8 string: a uint16 length followed by that many
// bytes. The encoding differs from UTF-8 in two ways that matter — a NUL is
// written as the two bytes C0 80, and a character outside the BMP is written as
// a surrogate pair of three-byte sequences rather than one four-byte sequence.
// Aliases are ASCII in practice, but decoding properly costs little and a
// mis-decoded alias would be reported as a real one.
func (r *reader) utf() (string, error) {
	b, err := r.bytes(2)
	if err != nil {
		return "", err
	}
	length := int(binary.BigEndian.Uint16(b))
	if length > maxAliasLen {
		return "", fmt.Errorf("string length %d is implausible", length)
	}
	raw, err := r.bytes(length)
	if err != nil {
		return "", err
	}
	return decodeModifiedUTF8(raw)
}

func decodeModifiedUTF8(raw []byte) (string, error) {
	var out bytes.Buffer
	var pending rune // high surrogate awaiting its pair

	flushPending := func() {
		if pending != 0 {
			out.WriteRune(pending)
			pending = 0
		}
	}

	for i := 0; i < len(raw); {
		b := raw[i]
		switch {
		case b < 0x80:
			flushPending()
			out.WriteByte(b)
			i++
		case b&0xE0 == 0xC0:
			if i+1 >= len(raw) {
				return "", errors.New("truncated two-byte sequence")
			}
			r := rune(b&0x1F)<<6 | rune(raw[i+1]&0x3F)
			flushPending()
			out.WriteRune(r)
			i += 2
		case b&0xF0 == 0xE0:
			if i+2 >= len(raw) {
				return "", errors.New("truncated three-byte sequence")
			}
			r := rune(b&0x0F)<<12 | rune(raw[i+1]&0x3F)<<6 | rune(raw[i+2]&0x3F)
			switch {
			case utf16.IsSurrogate(r) && pending == 0:
				pending = r
			case utf16.IsSurrogate(r) && pending != 0:
				out.WriteRune(utf16.DecodeRune(pending, r))
				pending = 0
			default:
				flushPending()
				out.WriteRune(r)
			}
			i += 3
		default:
			return "", fmt.Errorf("invalid leading byte %#x", b)
		}
	}
	flushPending()

	return out.String(), nil
}
