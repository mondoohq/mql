// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSshArgs(t *testing.T) {
	row := map[string]string{
		"forwarding-enabled":          "no",
		"always-allow-password-login": "false",
		"host-key-size":               "2048",
		"host-key-type":               "rsa",
		"strong-crypto":               "false",
		"allow-none-crypto":           "false",
	}
	args := sshArgs(row)

	assert.Equal(t, "mikrotik.ssh", args["__id"].Value)
	// the RouterOS default: strong crypto off, which leaves SHA1, CBC, and
	// 1024-bit Diffie-Hellman acceptable
	assert.Equal(t, false, args["strongCrypto"].Value)
	assert.Equal(t, false, args["allowNoneCrypto"].Value)
	assert.Equal(t, int64(2048), args["hostKeySize"].Value)
	assert.Equal(t, "rsa", args["hostKeyType"].Value)
	// forwarding-enabled is an enum on RouterOS, not a flag
	assert.Equal(t, "no", args["forwardingEnabled"].Value)
	// this RouterOS version does not expose cipher selection here
	assert.Nil(t, args["ciphers"].Value)
}

func TestSshArgsHardened(t *testing.T) {
	row := map[string]string{
		"forwarding-enabled":          "both",
		"always-allow-password-login": "yes",
		"host-key-size":               "4096",
		"host-key-type":               "ed25519",
		"strong-crypto":               "yes",
		"allow-none-crypto":           "yes",
		"ciphers":                     "chacha20-poly1305,aes256-gcm,aes128-ctr",
	}
	args := sshArgs(row)

	assert.Equal(t, true, args["strongCrypto"].Value)
	// allow-none-crypto permits an entirely unencrypted session
	assert.Equal(t, true, args["allowNoneCrypto"].Value)
	assert.Equal(t, true, args["alwaysAllowPasswordLogin"].Value)
	assert.Equal(t, "both", args["forwardingEnabled"].Value)
	assert.Equal(t, []any{"chacha20-poly1305", "aes256-gcm", "aes128-ctr"}, args["ciphers"].Value)
}

func TestSshArgsAbsentMenu(t *testing.T) {
	// nothing may read as a hardened setting when the device reported nothing
	args := sshArgs(map[string]string{})

	assert.Nil(t, args["strongCrypto"].Value)
	assert.Nil(t, args["allowNoneCrypto"].Value)
	assert.Nil(t, args["alwaysAllowPasswordLogin"].Value)
	assert.Nil(t, args["hostKeySize"].Value)
	assert.Nil(t, args["ciphers"].Value)
	assert.Equal(t, "", args["hostKeyType"].Value)
}

// TestSshArgsPasswordAuthentication covers releases that replaced
// always-allow-password-login with password-authentication.
func TestSshArgsPasswordAuthentication(t *testing.T) {
	for value, always := range map[string]bool{"yes": true, "yes-if-no-key": false, "no": false} {
		t.Run(value, func(t *testing.T) {
			args := sshArgs(map[string]string{"password-authentication": value, "strong-crypto": "true"})
			assert.Equal(t, value, args["passwordAuthentication"].Value)
			assert.Equal(t, always, args["alwaysAllowPasswordLogin"].Value)
			// the setting no longer exists on these releases
			assert.Nil(t, args["allowNoneCrypto"].Value)
		})
	}

	t.Run("live 7.23.2 row", func(t *testing.T) {
		row := liveRows(t, "ip-ssh.json")[0]
		args := sshArgs(row)
		assert.Equal(t, "yes-if-no-key", args["passwordAuthentication"].Value)
		assert.Equal(t, false, args["alwaysAllowPasswordLogin"].Value)
	})

	t.Run("old flag wins when present", func(t *testing.T) {
		args := sshArgs(map[string]string{"always-allow-password-login": "yes"})
		assert.Equal(t, true, args["alwaysAllowPasswordLogin"].Value)
		assert.Equal(t, "", args["passwordAuthentication"].Value)
	})
}
