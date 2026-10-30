// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package authorizedkeys

import (
	"bufio"
	"crypto/dsa" //nolint:staticcheck // DSA is deprecated, but we still detect legacy DSA keys for crypto-posture auditing
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// most ssh keys include base64 padding, so lets use it too (not default in Go)
var RawStdEncoding = base64.StdEncoding.WithPadding(base64.StdPadding)

type Entry struct {
	Line    int64
	Key     ssh.PublicKey
	Label   string
	Options []string
}

func (e Entry) Base64Key() string {
	return RawStdEncoding.EncodeToString(e.Key.Marshal())
}

// Bits returns the key size in bits of the entry's public key. It unwraps SSH
// certificates to inspect the underlying key and returns 0 when the key type is
// unknown or does not expose an underlying crypto public key (e.g., security-key
// backed keys that do not implement ssh.CryptoPublicKey).
func (e Entry) Bits() int64 {
	key := e.Key
	if cert, ok := key.(*ssh.Certificate); ok {
		key = cert.Key
	}

	cryptoKey, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return 0
	}

	switch k := cryptoKey.CryptoPublicKey().(type) {
	case *rsa.PublicKey:
		return int64(k.N.BitLen())
	case *ecdsa.PublicKey:
		return int64(k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return 256
	case *dsa.PublicKey:
		return int64(k.P.BitLen())
	default:
		return 0
	}
}

// maxLineBytes bounds a single authorized_keys line. sshd reads the file
// with getline(3) and has no line limit, so a key after a long line (a large
// from= allow list, for example) is still accepted. The bound only keeps a
// pathological file from exhausting memory; a line over it fails the parse
// instead of silently dropping the keys that follow.
const maxLineBytes = 16 << 20

func Parse(r io.Reader) ([]Entry, error) {
	res := []Entry{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	// lineNo tracks the physical 1-based line in the file, so it must advance
	// for skipped blank/comment lines too — Entry.Line is meant to locate the
	// key in the file, not count key entries.
	lineNo := int64(0)
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()

		in := strings.TrimSpace(line)
		if len(in) == 0 || in[0] == '#' {
			continue
		}

		key, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, err
		}

		res = append(res, Entry{
			Line:    lineNo,
			Key:     key,
			Label:   comment,
			Options: options,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read authorized_keys line %d: %w", lineNo+1, err)
	}
	return res, nil
}
