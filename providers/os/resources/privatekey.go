// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/dsa" //nolint:staticcheck // DSA is deprecated, but we still detect legacy DSA keys for crypto-posture auditing
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"golang.org/x/crypto/ssh"
)

// mqlPrivatekeyInternal caches the parsed key details so the independently
// lazy-loaded publicKeyAlgorithm and publicKeyBits accessors don't each
// re-parse the payload. The result is computed inside parseOnce, whose
// happens-before guarantee makes the captured info/err safe to read afterward.
type mqlPrivatekeyInternal struct {
	parseOnce sync.Once
	parsed    privateKeyInfo
	parseErr  error
}

// privateKeyInfo is what can be learned about a private key without its
// passphrase. Algorithm is empty and Bits is 0 when they are not known.
type privateKeyInfo struct {
	Encrypted bool
	Algorithm string
	Bits      int64
}

// inspectPrivateKey reads the algorithm and size of a PEM or OpenSSH private
// key. An encrypted key is not an error: OpenSSH-format keys carry their public
// key in the clear, legacy PEM encryption still names the algorithm in the
// block type, and an encrypted PKCS#8 key reveals neither.
func inspectPrivateKey(data []byte) (privateKeyInfo, error) {
	key, err := ssh.ParseRawPrivateKey(data)
	if err == nil {
		algo, bits := privateKeyAlgorithmBits(key)
		return privateKeyInfo{Algorithm: algo, Bits: bits}, nil
	}

	var passphraseErr *ssh.PassphraseMissingError
	if errors.As(err, &passphraseErr) {
		info := privateKeyInfo{Encrypted: true}
		if passphraseErr.PublicKey != nil {
			if cpk, ok := passphraseErr.PublicKey.(ssh.CryptoPublicKey); ok {
				info.Algorithm, info.Bits = publicKeyAlgorithmBits(cpk.CryptoPublicKey())
			}
			return info, nil
		}
		if block, _ := pem.Decode(data); block != nil {
			info.Algorithm = pemBlockAlgorithm[block.Type]
		}
		return info, nil
	}

	// PKCS#8 encrypted keys (`openssl pkcs8 -topk8 -v2 aes256`) are not
	// supported by x/crypto/ssh; the algorithm sits inside the ciphertext.
	if block, _ := pem.Decode(data); block != nil && block.Type == "ENCRYPTED PRIVATE KEY" {
		return privateKeyInfo{Encrypted: true}, nil
	}
	return privateKeyInfo{}, err
}

// pemBlockAlgorithm maps legacy PEM block types, which stay readable when the
// body is encrypted, to the algorithm names publicKeyAlgorithm reports.
var pemBlockAlgorithm = map[string]string{
	"RSA PRIVATE KEY": "RSA",
	"EC PRIVATE KEY":  "ECDSA",
	"DSA PRIVATE KEY": "DSA",
}

func privateKeyAlgorithmBits(key any) (string, int64) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return "RSA", int64(k.N.BitLen())
	case *ecdsa.PrivateKey:
		return "ECDSA", int64(k.Curve.Params().BitSize)
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return "Ed25519", 256
	case *dsa.PrivateKey:
		return "DSA", int64(k.P.BitLen())
	default:
		return "", 0
	}
}

func publicKeyAlgorithmBits(key any) (string, int64) {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return "RSA", int64(k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA", int64(k.Curve.Params().BitSize)
	case ed25519.PublicKey:
		return "Ed25519", 256
	case *dsa.PublicKey:
		return "DSA", int64(k.P.BitLen())
	default:
		return "", 0
	}
}

func initPrivatekey(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in privatekey initialization, it must be a string")
		}
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
	}

	return args, nil, nil
}

func (r *mqlPrivatekey) id() (string, error) {
	// TODO: use path or hash depending on initialization

	file := r.GetFile()
	if file.Error != nil {
		return "", file.Error
	}
	if file.Data == nil {
		return "", errors.New("no file provided")
	}

	return "privatekey:" + file.Data.Path.Data, nil
}

// parseKey inspects the resource's PEM payload once and caches the result, so
// the independently lazy-loaded publicKeyAlgorithm and publicKeyBits accessors
// share a single parse per query.
func (r *mqlPrivatekey) parseKey() (privateKeyInfo, error) {
	r.parseOnce.Do(func() {
		pemData := r.GetPem()
		if pemData.Error != nil {
			r.parseErr = pemData.Error
			return
		}
		if pemData.Data == "" {
			return
		}
		r.parsed, r.parseErr = inspectPrivateKey([]byte(pemData.Data))
	})
	return r.parsed, r.parseErr
}

// seedParsedKey stores the result of an inspectPrivateKey call the caller has
// already made on this resource's PEM, so parseKey does not parse it again.
func (r *mqlPrivatekey) seedParsedKey(info privateKeyInfo, err error) {
	r.parseOnce.Do(func() {
		r.parsed, r.parseErr = info, err
	})
}

func (r *mqlPrivatekey) publicKeyAlgorithm() (string, error) {
	info, err := r.parseKey()
	if err != nil {
		return "", err
	}
	if info.Algorithm == "" {
		r.PublicKeyAlgorithm.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return info.Algorithm, nil
}

func (r *mqlPrivatekey) publicKeyBits() (int64, error) {
	info, err := r.parseKey()
	if err != nil {
		return 0, err
	}
	if info.Bits == 0 {
		r.PublicKeyBits.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return info.Bits, nil
}
