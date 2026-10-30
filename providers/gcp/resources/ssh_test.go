// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testEd25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATxrDDkLHMi0EMdsCES8icnsrbj+2ra3lsm2cjefUA7 alice@laptop"
	testRSA2048Key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzWUJ5o5nE8AvOzLTV45xJ7b7U3vcH3idgxSQRGumbgXR0JY2O36R6Da6reu+sy1Nio3QjHNX/0prUscJli/N1F8g512wDFwhbFtIUW5J3J4Np2PuGJftxjD119w4uanp47E7kj76IX1TuS86RyZXAAlOJ3BWIrDR/TCoCEdYfCl8yydaIv8Ook5ip1qjZi7JP/RtXagiFOTtvbOmUBeTFz2hDalk6un+l0V4sOE3taULMfaFRwhBi+XeNlnfSmsl1+Bp/T3qJMxLsgRV1AEhwg6hestMGN49TB/YIogiMhAcM8ACF47HIxDMeoNxZJmuRg2tTkDLh4DAG02czba0l bob@host"
)

func TestParseInstanceSSHKeys(t *testing.T) {
	t.Run("username-prefixed keys across multiple lines", func(t *testing.T) {
		raw := "alice:" + testEd25519Key + "\nbob:" + testRSA2048Key
		got := parseInstanceSSHKeys(raw)
		require.Len(t, got, 2)

		first := got[0].(map[string]any)
		assert.Equal(t, "alice", first["username"])
		assert.Equal(t, "ssh-ed25519", first["algorithm"])
		assert.Equal(t, int64(256), first["bits"])
		assert.Equal(t, "alice@laptop", first["comment"])
		assert.Equal(t, testEd25519Key, first["publicKey"])

		second := got[1].(map[string]any)
		assert.Equal(t, "bob", second["username"])
		assert.Equal(t, "ssh-rsa", second["algorithm"])
		assert.Equal(t, int64(2048), second["bits"])
	})

	t.Run("skips blank and unparseable lines", func(t *testing.T) {
		raw := "\nalice:" + testEd25519Key + "\ngarbage-not-a-key\n   \n"
		got := parseInstanceSSHKeys(raw)
		require.Len(t, got, 1)
		assert.Equal(t, "alice", got[0].(map[string]any)["username"])
	})

	t.Run("key without username prefix", func(t *testing.T) {
		got := parseInstanceSSHKeys(testEd25519Key)
		require.Len(t, got, 1)
		assert.Equal(t, "", got[0].(map[string]any)["username"])
		assert.Equal(t, "ssh-ed25519", got[0].(map[string]any)["algorithm"])
	})

	t.Run("empty metadata yields empty slice", func(t *testing.T) {
		assert.Empty(t, parseInstanceSSHKeys(""))
	})
}
