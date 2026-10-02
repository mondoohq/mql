// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package java

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"unicode/utf16"
)

// The PKCS#12 reader in go-pkcs12 verifies the integrity MAC and decrypts the
// store, but none of its entry points report the bag attributes of a store
// keytool writes: ToPEM refuses the trusted-certificate attribute outright,
// and the other entry points return bare certificates. Those attributes are
// the only place a PKCS#12 store records an alias (friendlyName) and whether a
// certificate is a trust anchor (Oracle's trusted key usage) or part of a
// private key's chain (localKeyId). This file walks the SafeBags itself so
// both survive.

var (
	oidP12Data          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidP12EncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	oidP12KeyBag          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	oidP12ShroudedKeyBag  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	oidP12CertBag         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	oidP12SafeContentsBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}
	oidP12X509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}

	oidP12FriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidP12LocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	// oidJavaTrustedKeyUsage is the attribute keytool puts on a certificate it
	// stores as a trustedCertEntry.
	oidJavaTrustedKeyUsage = asn1.ObjectIdentifier{2, 16, 840, 1, 113894, 746875, 1, 1}

	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
	oidPBES2                         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2                        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithSHA1                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256                = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384                = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512                = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC                     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type p12PFX struct {
	Version  int
	AuthSafe p12ContentInfo
	MacData  asn1.RawValue `asn1:"optional"`
}

type p12ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type p12EncryptedData struct {
	Version              int
	EncryptedContentInfo p12EncryptedContentInfo
}

type p12EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           []byte `asn1:"tag:0,optional"`
}

type p12SafeBag struct {
	ID         asn1.ObjectIdentifier
	Value      asn1.RawValue     `asn1:"tag:0,explicit"`
	Attributes []p12BagAttribute `asn1:"set,optional"`
}

type p12BagAttribute struct {
	ID    asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"set"`
}

type p12CertBag struct {
	ID   asn1.ObjectIdentifier
	Data []byte `asn1:"tag:0,explicit"`
}

type p12PBEParams struct {
	Salt       []byte
	Iterations int
}

type p12PBES2Params struct {
	KDF              pkix.AlgorithmIdentifier
	EncryptionScheme pkix.AlgorithmIdentifier
}

type p12PBKDF2Params struct {
	Salt       asn1.RawValue
	Iterations int
	KeyLength  int                      `asn1:"optional"`
	PRF        pkix.AlgorithmIdentifier `asn1:"optional"`
}

// maxPBEIterations bounds the work a hostile store can demand. keytool writes
// 10,000 to 50,000; OpenSSL 2,048.
const maxPBEIterations = 10_000_000

// readPKCS12Bags returns one entry per certificate bag, in store order, with
// the alias and trust classification the bag attributes carry. It does not
// verify the integrity MAC: callers establish that the password is right first.
func readPKCS12Bags(data []byte, password string) ([]Entry, error) {
	var pfx p12PFX
	if err := unmarshalDER(data, &pfx); err != nil {
		return nil, fmt.Errorf("pkcs12: %w", err)
	}
	if !pfx.AuthSafe.ContentType.Equal(oidP12Data) {
		return nil, errors.New("pkcs12: only password-protected stores are supported")
	}
	var authSafeDER []byte
	if err := unmarshalDER(pfx.AuthSafe.Content.Bytes, &authSafeDER); err != nil {
		return nil, fmt.Errorf("pkcs12: authenticated safe: %w", err)
	}
	var authSafe []p12ContentInfo
	if err := unmarshalDER(authSafeDER, &authSafe); err != nil {
		return nil, fmt.Errorf("pkcs12: authenticated safe: %w", err)
	}

	var bags []p12SafeBag
	for _, ci := range authSafe {
		var contents []byte
		switch {
		case ci.ContentType.Equal(oidP12Data):
			if err := unmarshalDER(ci.Content.Bytes, &contents); err != nil {
				return nil, fmt.Errorf("pkcs12: safe contents: %w", err)
			}
		case ci.ContentType.Equal(oidP12EncryptedData):
			var ed p12EncryptedData
			if err := unmarshalDER(ci.Content.Bytes, &ed); err != nil {
				return nil, fmt.Errorf("pkcs12: encrypted data: %w", err)
			}
			var err error
			contents, err = pbeDecrypt(ed.EncryptedContentInfo.ContentEncryptionAlgorithm,
				ed.EncryptedContentInfo.EncryptedContent, password)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("pkcs12: unsupported content type %s", ci.ContentType)
		}

		found, err := safeBags(contents, 0)
		if err != nil {
			return nil, err
		}
		bags = append(bags, found...)
	}

	return classifyBags(bags)
}

// safeBags parses a SafeContents, descending into nested ones.
func safeBags(der []byte, depth int) ([]p12SafeBag, error) {
	if depth > 4 {
		return nil, errors.New("pkcs12: safe contents nested too deeply")
	}
	var bags []p12SafeBag
	if err := unmarshalDER(der, &bags); err != nil {
		return nil, fmt.Errorf("pkcs12: safe contents: %w", err)
	}
	var out []p12SafeBag
	for _, bag := range bags {
		if bag.ID.Equal(oidP12SafeContentsBag) {
			nested, err := safeBags(bag.Value.Bytes, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
			continue
		}
		out = append(out, bag)
	}
	return out, nil
}

// classifyBags turns certificate bags into entries the way Java's own PKCS#12
// reader does: a certificate carrying the trusted key usage attribute is a
// trustedCertEntry, one whose localKeyId matches a key bag belongs to that
// key's chain. A certificate with neither is a trust anchor in a store that
// holds no private key (what OpenSSL writes for a CA bundle) and a chain
// certificate in one that does.
func classifyBags(bags []p12SafeBag) ([]Entry, error) {
	keyIDs := map[string]struct{}{}
	hasKey := false
	for _, bag := range bags {
		if bag.ID.Equal(oidP12KeyBag) || bag.ID.Equal(oidP12ShroudedKeyBag) {
			hasKey = true
			if id, ok, err := localKeyID(bag); err != nil {
				return nil, err
			} else if ok {
				keyIDs[id] = struct{}{}
			}
		}
	}

	var entries []Entry
	for _, bag := range bags {
		if !bag.ID.Equal(oidP12CertBag) {
			continue
		}
		var cb p12CertBag
		if err := unmarshalDER(bag.Value.Bytes, &cb); err != nil {
			return nil, fmt.Errorf("pkcs12: certificate bag: %w", err)
		}
		// SDSI certificates and other kinds have no place in a keystore read.
		if !cb.ID.Equal(oidP12X509Certificate) {
			continue
		}

		alias, err := friendlyName(bag)
		if err != nil {
			return nil, err
		}
		id, hasID, err := localKeyID(bag)
		if err != nil {
			return nil, err
		}
		_, belongsToAKey := keyIDs[id]

		var trusted bool
		switch {
		case hasAttribute(bag, oidJavaTrustedKeyUsage):
			trusted = true
		case hasID && belongsToAKey:
			trusted = false
		default:
			trusted = !hasKey
		}

		entries = append(entries, Entry{Alias: alias, Trusted: trusted, Certs: [][]byte{cb.Data}})
	}
	return entries, nil
}

func hasAttribute(bag p12SafeBag, id asn1.ObjectIdentifier) bool {
	for _, attr := range bag.Attributes {
		if attr.ID.Equal(id) {
			return true
		}
	}
	return false
}

func friendlyName(bag p12SafeBag) (string, error) {
	for _, attr := range bag.Attributes {
		if !attr.ID.Equal(oidP12FriendlyName) {
			continue
		}
		var v asn1.RawValue
		if err := unmarshalDER(attr.Value.Bytes, &v); err != nil {
			return "", fmt.Errorf("pkcs12: friendlyName: %w", err)
		}
		if v.Tag != 30 { // BMPString
			return "", fmt.Errorf("pkcs12: friendlyName is ASN.1 tag %d, not a BMPString", v.Tag)
		}
		return decodeUTF16BE(v.Bytes)
	}
	return "", nil
}

func localKeyID(bag p12SafeBag) (string, bool, error) {
	for _, attr := range bag.Attributes {
		if !attr.ID.Equal(oidP12LocalKeyID) {
			continue
		}
		var id []byte
		if err := unmarshalDER(attr.Value.Bytes, &id); err != nil {
			return "", false, fmt.Errorf("pkcs12: localKeyId: %w", err)
		}
		return hex.EncodeToString(id), true, nil
	}
	return "", false, nil
}

func decodeUTF16BE(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", errors.New("pkcs12: odd-length BMPString")
	}
	var u []uint16
	for i := 0; i < len(b); i += 2 {
		u = append(u, binary.BigEndian.Uint16(b[i:]))
	}
	return string(utf16.Decode(u)), nil
}

// bmpPassword encodes a password the way PKCS#12 PBE keys it: UTF-16BE with a
// two-byte terminator (RFC 7292 appendix B.1).
func bmpPassword(password string) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(password)) {
		out = binary.BigEndian.AppendUint16(out, u)
	}
	return append(out, 0, 0)
}

// pbeDecrypt decrypts one EncryptedContentInfo with the schemes keytool and
// OpenSSL write: PBES2 with AES (keytool since JDK 8u301 and 11.0.12), and the
// PKCS#12 PBE schemes with RC2 or 3DES (older JDKs, OpenSSL before 3.0).
func pbeDecrypt(alg pkix.AlgorithmIdentifier, ciphertext []byte, password string) ([]byte, error) {
	if alg.Algorithm.Equal(oidPBES2) {
		block, iv, err := pbes2Cipher(alg, []byte(password))
		if err != nil {
			return nil, err
		}
		return cbcDecrypt(block, iv, ciphertext)
	}

	var keyLen int
	var newCipher func(key []byte) (cipher.Block, error)
	switch {
	case alg.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		keyLen, newCipher = 24, des.NewTripleDESCipher
	case alg.Algorithm.Equal(oidPBEWithSHAAnd128BitRC2CBC):
		keyLen, newCipher = 16, func(key []byte) (cipher.Block, error) { return newRC2(key, 128) }
	case alg.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		keyLen, newCipher = 5, func(key []byte) (cipher.Block, error) { return newRC2(key, 40) }
	default:
		return nil, fmt.Errorf("pkcs12: unsupported encryption algorithm %s", alg.Algorithm)
	}

	var params p12PBEParams
	if err := unmarshalDER(alg.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("pkcs12: PBE parameters: %w", err)
	}
	if params.Iterations < 1 || params.Iterations > maxPBEIterations {
		return nil, fmt.Errorf("pkcs12: implausible iteration count %d", params.Iterations)
	}

	// Some writers key an empty password as no bytes at all rather than as the
	// lone terminator the RFC specifies, so an empty password tries both.
	candidates := [][]byte{bmpPassword(password)}
	if password == "" {
		candidates = append(candidates, nil)
	}
	var lastErr error
	for _, pw := range candidates {
		key := pkcs12KDF(sha1.New, params.Salt, pw, params.Iterations, 1, keyLen)
		iv := pkcs12KDF(sha1.New, params.Salt, pw, params.Iterations, 2, 8)
		block, err := newCipher(key)
		if err != nil {
			return nil, err
		}
		plain, err := cbcDecrypt(block, iv, ciphertext)
		if err == nil {
			return plain, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func pbes2Cipher(alg pkix.AlgorithmIdentifier, password []byte) (cipher.Block, []byte, error) {
	var params p12PBES2Params
	if err := unmarshalDER(alg.Parameters.FullBytes, &params); err != nil {
		return nil, nil, fmt.Errorf("pkcs12: PBES2 parameters: %w", err)
	}
	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, nil, fmt.Errorf("pkcs12: unsupported PBES2 key derivation %s", params.KDF.Algorithm)
	}
	var kdf p12PBKDF2Params
	if err := unmarshalDER(params.KDF.Parameters.FullBytes, &kdf); err != nil {
		return nil, nil, fmt.Errorf("pkcs12: PBKDF2 parameters: %w", err)
	}
	if kdf.Salt.Tag != asn1.TagOctetString {
		return nil, nil, errors.New("pkcs12: only an explicit PBKDF2 salt is supported")
	}
	if kdf.Iterations < 1 || kdf.Iterations > maxPBEIterations {
		return nil, nil, fmt.Errorf("pkcs12: implausible iteration count %d", kdf.Iterations)
	}

	var prf func() hash.Hash
	switch {
	case len(kdf.PRF.Algorithm) == 0, kdf.PRF.Algorithm.Equal(oidHMACWithSHA1):
		prf = sha1.New
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA256):
		prf = sha256.New
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA384):
		prf = sha512.New384
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA512):
		prf = sha512.New
	default:
		return nil, nil, fmt.Errorf("pkcs12: unsupported PBKDF2 PRF %s", kdf.PRF.Algorithm)
	}

	var keyLen int
	switch {
	case params.EncryptionScheme.Algorithm.Equal(oidAES128CBC):
		keyLen = 16
	case params.EncryptionScheme.Algorithm.Equal(oidAES192CBC):
		keyLen = 24
	case params.EncryptionScheme.Algorithm.Equal(oidAES256CBC):
		keyLen = 32
	default:
		return nil, nil, fmt.Errorf("pkcs12: unsupported PBES2 cipher %s", params.EncryptionScheme.Algorithm)
	}
	var iv []byte
	if err := unmarshalDER(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, nil, fmt.Errorf("pkcs12: PBES2 IV: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, nil, fmt.Errorf("pkcs12: PBES2 IV is %d bytes", len(iv))
	}

	key, err := pbkdf2.Key(prf, string(password), kdf.Salt.Bytes, kdf.Iterations, keyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("pkcs12: PBKDF2: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	return block, iv, nil
}

var errPKCS12Decrypt = errors.New("pkcs12: decryption failed, wrong password or corrupt store")

func cbcDecrypt(block cipher.Block, iv, ciphertext []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
		return nil, errPKCS12Decrypt
	}
	plain := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ciphertext)

	pad := int(plain[len(plain)-1])
	if pad == 0 || pad > bs || !bytes.Equal(plain[len(plain)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		return nil, errPKCS12Decrypt
	}
	return plain[:len(plain)-pad], nil
}

// pkcs12KDF is the PKCS#12 key derivation (RFC 7292 appendix B.2). The PBE
// encryption schemes that use it are defined over SHA-1, so that is what the
// callers pass; it is how the store was keyed, not a choice made here. id
// selects the purpose: 1 for a key, 2 for an IV.
func pkcs12KDF(newHash func() hash.Hash, salt, password []byte, iterations int, id byte, size int) []byte {
	v := newHash().BlockSize()

	// fill repeats in until it is a whole number of v-byte blocks long.
	fill := func(in []byte) []byte {
		var out []byte
		for len(in) > 0 && (len(out) == 0 || len(out)%v != 0) {
			out = append(out, in[len(out)%len(in)])
		}
		return out
	}

	d := bytes.Repeat([]byte{id}, v)
	i := append(fill(salt), fill(password)...)

	var out []byte
	for len(out) < size {
		h := newHash()
		h.Write(d)
		h.Write(i)
		a := h.Sum(nil)
		for r := 1; r < iterations; r++ {
			h.Reset()
			h.Write(a)
			a = h.Sum(a[:0])
		}
		out = append(out, a...)

		// I_j = (I_j + B + 1) mod 2^(8v), for every v-byte block of I, where B
		// is A repeated to v bytes.
		b := fill(a)
		for j := 0; j < len(i); j += v {
			carry := uint16(1)
			for k := v - 1; k >= 0; k-- {
				sum := uint16(i[j+k]) + uint16(b[k]) + carry
				i[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
	}
	return out[:size]
}

// rc2Cipher is RC2 decryption (RFC 2268), which keytool before JDK 8u301 and
// 11.0.12 used to encrypt the certificates in a PKCS#12 store. Only decryption
// is implemented; nothing here writes a store.
type rc2Cipher struct {
	k [64]uint16
}

// rc2PITable is PITABLE from RFC 2268 section 2.
var rc2PITable = [256]byte{
	0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
	0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
	0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
	0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
	0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
	0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
	0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
	0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
	0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
	0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
	0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
	0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
	0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
	0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
	0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
	0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
}

// newRC2 expands key with an effective key length of t1 bits (RFC 2268
// section 2).
func newRC2(key []byte, t1 int) (*rc2Cipher, error) {
	if len(key) == 0 || len(key) > 128 {
		return nil, fmt.Errorf("pkcs12: RC2 key of %d bytes", len(key))
	}
	if t1 < 1 || t1 > 1024 {
		return nil, fmt.Errorf("pkcs12: RC2 effective key length of %d bits", t1)
	}
	var l [128]byte
	t := copy(l[:], key)
	t8 := (t1 + 7) / 8
	tm := byte(0xff >> uint(8*t8-t1))

	for i := t; i < 128; i++ {
		l[i] = rc2PITable[l[i-1]+l[i-t]]
	}
	l[128-t8] = rc2PITable[l[128-t8]&tm]
	for i := 127 - t8; i >= 0; i-- {
		l[i] = rc2PITable[l[i+1]^l[i+t8]]
	}

	c := &rc2Cipher{}
	for i := range c.k {
		c.k[i] = uint16(l[2*i]) | uint16(l[2*i+1])<<8
	}
	return c, nil
}

func (*rc2Cipher) BlockSize() int { return 8 }

func (*rc2Cipher) Encrypt(_, _ []byte) {
	panic("java: RC2 encryption is not implemented")
}

// Decrypt runs RFC 2268 section 4: five reverse mixing rounds, a reverse
// mashing round, six mixing, a mashing, and five mixing.
func (c *rc2Cipher) Decrypt(dst, src []byte) {
	var r [4]uint16
	for i := range r {
		r[i] = binary.LittleEndian.Uint16(src[2*i:])
	}

	j := 63
	shifts := [4]int{1, 2, 3, 5}
	mix := func() {
		for i := 3; i >= 0; i-- {
			r[i] = bits.RotateLeft16(r[i], -shifts[i])
			r[i] -= c.k[j] + (r[(i+3)%4] & r[(i+2)%4]) + (^r[(i+3)%4] & r[(i+1)%4])
			j--
		}
	}
	mash := func() {
		for i := 3; i >= 0; i-- {
			r[i] -= c.k[r[(i+3)%4]&63]
		}
	}

	for n := 0; n < 5; n++ {
		mix()
	}
	mash()
	for n := 0; n < 6; n++ {
		mix()
	}
	mash()
	for n := 0; n < 5; n++ {
		mix()
	}

	for i := range r {
		binary.LittleEndian.PutUint16(dst[2*i:], r[i])
	}
}

func unmarshalDER(in []byte, out any) error {
	rest, err := asn1.Unmarshal(in, out)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data")
	}
	return nil
}
