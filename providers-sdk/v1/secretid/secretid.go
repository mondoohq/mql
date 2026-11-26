// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package secretid computes the identity of a leaked secret: one
// canonicalization of the value and one keyed hash, shared by every producer
// that reports secrets (code scanners, host and cloud scanners), so that one
// credential found in many places is one record on the platform.
//
// The value itself never leaves the producer. What leaves is an HMAC-SHA256 of
// the canonical value under a per-space key, with a domain-separation string per
// identifier so that the identifiers are unrelated although they share a key.
//
// The output of this package is a cross-repository contract. Changing what it
// returns for a given input re-keys every secret on the platform, so a change
// to canonicalization or hashing is a new version (a new Version constant, new
// domain strings and new id prefix), never an edit of v1. The golden vectors
// in the package's tests pin v1; producers written in another language must
// reproduce them.
//
// The package performs no I/O and no logging.
package secretid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Version is the identity scheme implemented by this package. It is the
// prefix of every secret id and occurrence id ("v1:…"), so ids computed under
// two schemes never compare equal.
const Version = "v1"

// Domain-separation strings, one per identifier. They are part of the v1
// contract and must not change.
const (
	DomainSecretID   = "xgrep/secret-id/v1"
	DomainOccurrence = "xgrep/occurrence/v1"
	DomainLineHash   = "xgrep/line-hash/v1"
)

// lineHashSuffix marks a keyed line hash, after GitHub's `<hex>:<version>`
// convention for primaryLocationLineHash. The `k` tells it apart from the
// unkeyed line hash (`:1`), which is computed without a key.
const lineHashSuffix = ":k1"

// Lengths, in hex characters, of the encoded identifiers.
const (
	secretIDHexLen   = 64
	occurrenceHexLen = 32
	lineHashHexLen   = 16
)

// Secret types and credential classes that change canonicalization. These are
// the values of a rule's `secret-type` and `credential-class` metadata.
const (
	SecretTypePrivateKey        = "private-key"
	SecretTypeIBAN              = "iban"
	CredentialClassPersonalData = "personal-data"
)

var (
	// ErrEmptyValue is returned for an empty canonical value. Hashing it would
	// give every empty value one id and merge unrelated findings.
	ErrEmptyValue = errors.New("secretid: empty canonical value")
	// ErrInvalidInput is returned when a field of a composite identifier
	// contains a NUL byte, which separates the fields of the hashed input.
	ErrInvalidInput = errors.New("secretid: input contains a NUL byte")
)

// pemArmor matches a PEM (or PGP) armor line's marker, such as
// `-----BEGIN RSA PRIVATE KEY-----`. It matches the marker rather than the
// whole line so that a JSON-escaped key, where the marker and the body share
// one line joined by a literal `\n`, loses the marker the same way a plain
// key loses the line.
var pemArmor = regexp.MustCompile(`-----(?:BEGIN|END) [^-]*-----`)

// Canonical returns the canonical form of a secret value, the input to ID.
//
// secretType and credentialClass are the reporting rule's `secret-type` and
// `credential-class` metadata; they select the type-specific steps and are
// not part of the result, so two rules that match one value give one id.
//
//  1. Leading and trailing ASCII whitespace is stripped.
//  2. One matching pair of `"`, `'` or "`" around the value is stripped.
//  3. For secret type `private-key`: the BEGIN and END armor markers, the
//     literal two-character escapes `\n` and `\r`, and all ASCII whitespace are
//     removed, leaving the body. A key with LF or CRLF line endings, as a
//     JSON-escaped string, or reindented, is one value.
//  4. For credential class `personal-data`: spaces and `-` are removed; for
//     secret type `iban` ASCII letters are upper-cased. One number written
//     two ways is one value.
//
// Nothing else is folded: no other case folding and no Unicode normalization.
func Canonical(value, secretType, credentialClass string) string {
	v := trimASCIISpace(value)
	v = stripQuotes(v)

	if secretType == SecretTypePrivateKey {
		v = pemArmor.ReplaceAllString(v, "")
		v = strings.ReplaceAll(v, `\n`, "")
		v = strings.ReplaceAll(v, `\r`, "")
		v = removeASCIISpace(v)
	}

	if credentialClass == CredentialClassPersonalData {
		v = strings.Map(func(r rune) rune {
			if r == ' ' || r == '-' {
				return -1
			}
			return r
		}, v)
		if secretType == SecretTypeIBAN {
			v = upperASCII(v)
		}
	}
	return v
}

// ID returns the secret id of a canonical value under key k:
// "v1:" followed by the lowercase hex HMAC-SHA256 of
// DomainSecretID ‖ 0x00 ‖ canonical (64 hex characters).
//
// canonical must come from Canonical. An empty canonical value returns
// ErrEmptyValue; a nil or closed key returns ErrNoKey or ErrClosed.
func ID(k *Key, canonical string) (string, error) {
	if len(canonical) == 0 {
		return "", ErrEmptyValue
	}
	sum, err := k.mac(DomainSecretID, canonical)
	if err != nil {
		return "", err
	}
	return Version + ":" + hex.EncodeToString(sum)[:secretIDHexLen], nil
}

// IDs returns one secret id per key, in the order of keys. During a key
// rotation window a producer passes the current key first and the previous
// key second, and uploads the results as the current and the previous id.
// It fails if keys is empty or any key is nil or closed.
func IDs(keys []*Key, canonical string) ([]string, error) {
	if len(keys) == 0 {
		return nil, ErrNoKey
	}
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		id, err := ID(k, canonical)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// OccurrenceID returns the keyed id of one occurrence of a secret: "v1:"
// followed by the first 32 hex characters of the HMAC-SHA256 of
// DomainOccurrence ‖ 0x00 ‖ ruleID ‖ 0x00 ‖ path ‖ 0x00 ‖ line ‖ 0x00 ‖
// matchedCode.
//
// path is the path relative to the scanned root; backslash separators are
// turned into forward slashes so the id does not depend on the scanning OS.
// line is the decimal start line. matchedCode is the matched text before any
// redaction. ruleID and path must not contain a NUL byte (ErrInvalidInput).
func OccurrenceID(k *Key, ruleID, path string, line int, matchedCode string) (string, error) {
	if strings.IndexByte(ruleID, 0) >= 0 || strings.IndexByte(path, 0) >= 0 {
		return "", ErrInvalidInput
	}
	path = strings.ReplaceAll(path, `\`, "/")
	sum, err := k.mac(DomainOccurrence, ruleID, path, strconv.Itoa(line), matchedCode)
	if err != nil {
		return "", err
	}
	return Version + ":" + hex.EncodeToString(sum)[:occurrenceHexLen], nil
}

// LineHash returns the keyed, location-tolerant hash of a finding's primary
// line: the first 16 hex characters of the HMAC-SHA256 of
// DomainLineHash ‖ 0x00 ‖ the first line of matchedCode with surrounding
// whitespace trimmed, followed by ":k1". It replaces the unkeyed line hash on
// uploaded secret findings, which could be reversed by guessing a short line.
func LineHash(k *Key, matchedCode string) (string, error) {
	sum, err := k.mac(DomainLineHash, firstLineTrimmed(matchedCode))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum)[:lineHashHexLen] + lineHashSuffix, nil
}

// firstLineTrimmed returns the first line of s with surrounding whitespace
// trimmed. It is the same primary line the unkeyed line hash uses.
func firstLineTrimmed(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func isASCIISpace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

func trimASCIISpace(s string) string {
	start, end := 0, len(s)
	for start < end && isASCIISpace(s[start]) {
		start++
	}
	for end > start && isASCIISpace(s[end-1]) {
		end--
	}
	return s[start:end]
}

func removeASCIISpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if !isASCIISpace(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func stripQuotes(s string) string {
	if len(s) < 2 {
		return s
	}
	switch q := s[0]; q {
	case '"', '\'', '`':
		if s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

// mac computes HMAC-SHA256 under k of domain ‖ 0x00 ‖ fields joined by 0x00.
func (k *Key) mac(domain string, fields ...string) ([]byte, error) {
	if k == nil {
		return nil, ErrNoKey
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.closed {
		return nil, ErrClosed
	}
	h := hmac.New(sha256.New, k.b)
	h.Write([]byte(domain))
	for _, f := range fields {
		h.Write([]byte{0})
		h.Write([]byte(f))
	}
	return h.Sum(nil), nil
}
