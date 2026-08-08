// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package verify provides integrity (SHA256) and authenticity (minisign)
// verification for downloaded artifacts (provider plugins and binaries).
//
// The two gates are independent and composable:
//
//   - Checksum: a published SHA256SUMS manifest lists one hex digest per
//     file. The caller verifies that the bytes it downloaded hash to the
//     digest the manifest records for that exact filename.
//   - Signature: an optional detached minisign signature over the manifest
//     itself, verified against a public key pinned into the binary at build
//     time. This upgrades "the bytes match a digest we downloaded" into "the
//     bytes match a digest signed by us".
//
// Neither gate reaches out to the network; callers fetch the manifest and
// signature and hand the bytes in. This keeps the package pure and trivially
// unit-testable, and works in air-gapped fleets.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"

	"github.com/cockroachdb/errors"
)

// ErrChecksumMismatch is returned when an artifact's computed SHA256 does not
// match the digest recorded for it in the manifest. It is a distinct error so
// callers can tell "the download is corrupt/tampered" apart from transport or
// parsing failures and react accordingly (discard and retry vs. give up).
var ErrChecksumMismatch = errors.New("artifact checksum does not match the expected value")

// ErrChecksumNotFound is returned when the manifest does not contain an entry
// for the requested filename. Treated as a hard failure: a manifest that omits
// the file we downloaded cannot vouch for it.
var ErrChecksumNotFound = errors.New("no checksum entry for the requested file")

// SHA256SUMS is a parsed checksum manifest: a map from filename to its lower
// case hex-encoded SHA256 digest. The manifest format is the one emitted by
// both `shasum -a 256` (provider_bundler.sh) and goreleaser's checksum block:
// one entry per line, "<64-hex-digest><whitespace>[*]<filename>".
type SHA256SUMS struct {
	digests map[string]string
}

// ParseSHA256SUMS parses a checksum manifest. It is lenient about the exact
// whitespace and the binary-mode "*" marker that some tools prefix to the
// filename, and it tolerates blank lines and comments (lines starting with
// '#'). Only the base name of each recorded path is indexed, so a manifest
// that lists "dist/os_1.2.3_linux_amd64.tar.xz" still matches a lookup for
// "os_1.2.3_linux_amd64.tar.xz".
//
// A manifest that parses to zero usable entries is rejected: an empty manifest
// almost always means we fetched an error page or the wrong URL, and silently
// treating it as "nothing to check" would defeat the whole gate.
func ParseSHA256SUMS(data []byte) (*SHA256SUMS, error) {
	res := &SHA256SUMS{digests: map[string]string{}}

	for _, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split into the digest and the remainder (the filename, possibly
		// prefixed with the binary-mode "*" marker). Fields collapses runs of
		// whitespace so both the two-space GNU format and single-tab variants
		// parse the same way.
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, errors.Newf("malformed checksum line: %q", rawLine)
		}

		digest := strings.ToLower(fields[0])
		if !isHexSHA256(digest) {
			return nil, errors.Newf("invalid sha256 digest in checksum line: %q", rawLine)
		}

		// The filename is everything after the first field; rejoin so paths
		// containing spaces survive. Strip the optional "*" binary marker.
		name := strings.TrimSpace(strings.TrimPrefix(strings.Join(fields[1:], " "), "*"))
		if name == "" {
			return nil, errors.Newf("missing filename in checksum line: %q", rawLine)
		}

		// Index by base name so callers can look up the plain filename
		// regardless of whether the manifest recorded a relative path.
		res.digests[baseName(name)] = digest
	}

	if len(res.digests) == 0 {
		return nil, errors.New("checksum manifest contained no valid entries")
	}

	return res, nil
}

// Digest returns the recorded lower-case hex SHA256 for the given filename
// (matched by base name), and whether an entry exists.
func (s *SHA256SUMS) Digest(filename string) (string, bool) {
	d, ok := s.digests[baseName(filename)]
	return d, ok
}

// Verify streams the artifact from r, computes its SHA256, and compares it to
// the digest the manifest records for filename. It returns ErrChecksumNotFound
// if the manifest has no entry for the file, and ErrChecksumMismatch if the
// digests differ. On success it returns the computed digest so callers can log
// it.
//
// Verify reads r to EOF; callers that need the bytes afterwards should tee or
// buffer. The whole artifact must be hashed, so there is no early-out.
func (s *SHA256SUMS) Verify(filename string, r io.Reader) (string, error) {
	expected, ok := s.Digest(filename)
	if !ok {
		return "", errors.Wrapf(ErrChecksumNotFound, "file %q", filename)
	}

	actual, err := sha256Hex(r)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash artifact")
	}

	if actual != expected {
		return "", errors.Wrapf(ErrChecksumMismatch,
			"file %q: expected %s, computed %s", filename, expected, actual)
	}

	return actual, nil
}

// VerifyBytes is the in-memory convenience form of Verify.
func (s *SHA256SUMS) VerifyBytes(filename string, data []byte) (string, error) {
	return s.Verify(filename, strings.NewReader(string(data)))
}

// sha256Hex streams r through a SHA256 hasher and returns the lower-case hex
// digest.
func sha256Hex(r io.Reader) (string, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isHexSHA256 reports whether s is exactly 64 lower-case hex characters.
func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// baseName returns the final path element, handling both '/' and '\'
// separators so a Windows-style path in a manifest still matches.
func baseName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
