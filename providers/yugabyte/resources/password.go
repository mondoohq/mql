// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // MD5 is the format YSQL stores md5 passwords in
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// maxScramIterations bounds the work one SCRAM verification may cost. YSQL
// writes 4096 iterations; a stored hash claiming far more is not verified.
const maxScramIterations = 1 << 20

// ysqlPasswordMatches reports whether a password hash from pg_authid verifies
// with password. It understands the two formats YSQL stores:
//
//	SCRAM-SHA-256$<iterations>:<salt>$<StoredKey>:<ServerKey>
//	md5<md5(password || role name)>
//
// Any other value, such as a plain-text password some PostgreSQL versions
// kept or an empty hash, does not match.
func ysqlPasswordMatches(hash, role, password string) bool {
	switch {
	case strings.HasPrefix(hash, "SCRAM-SHA-256$"):
		return scramMatches(hash, password)
	case strings.HasPrefix(hash, "md5") && len(hash) == 35:
		sum := md5.Sum([]byte(password + role)) //nolint:gosec
		want := hex.EncodeToString(sum[:])
		return subtle.ConstantTimeCompare([]byte(hash[3:]), []byte(want)) == 1
	default:
		return false
	}
}

// scramMatches verifies a SCRAM-SHA-256 verifier (RFC 5802, RFC 7677) as
// PostgreSQL stores it: the client key derived from the password must hash
// to the StoredKey.
func scramMatches(verifier, password string) bool {
	rest, ok := strings.CutPrefix(verifier, "SCRAM-SHA-256$")
	if !ok {
		return false
	}
	params, keys, ok := strings.Cut(rest, "$")
	if !ok {
		return false
	}
	iterStr, saltB64, ok := strings.Cut(params, ":")
	if !ok {
		return false
	}
	storedB64, _, ok := strings.Cut(keys, ":")
	if !ok {
		return false
	}
	iterations, err := strconv.Atoi(iterStr)
	if err != nil || iterations <= 0 || iterations > maxScramIterations {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return false
	}
	storedKey, err := base64.StdEncoding.DecodeString(storedB64)
	if err != nil || len(storedKey) != sha256.Size {
		return false
	}
	// PostgreSQL applies SASLprep to the password; for the ASCII role names
	// checked here it is the identity.
	salted, err := pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, salted)
	mac.Write([]byte("Client Key"))
	clientKey := mac.Sum(nil)
	sum := sha256.Sum256(clientKey)
	return subtle.ConstantTimeCompare(sum[:], storedKey) == 1
}

// ycqlPasswordMatches reports whether a salted_hash from system_auth.roles
// verifies with password. YCQL stores a bcrypt hash and pads the column with
// NUL bytes, which are not part of the hash.
func ycqlPasswordMatches(saltedHash, password string) bool {
	hash := bytes.TrimRight([]byte(saltedHash), "\x00")
	if len(hash) == 0 {
		return false
	}
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}
