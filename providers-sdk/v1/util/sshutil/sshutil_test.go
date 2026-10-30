// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sshutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	ed25519Key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIATxrDDkLHMi0EMdsCES8icnsrbj+2ra3lsm2cjefUA7 alice@laptop"
	rsa2048Key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzWUJ5o5nE8AvOzLTV45xJ7b7U3vcH3idgxSQRGumbgXR0JY2O36R6Da6reu+sy1Nio3QjHNX/0prUscJli/N1F8g512wDFwhbFtIUW5J3J4Np2PuGJftxjD119w4uanp47E7kj76IX1TuS86RyZXAAlOJ3BWIrDR/TCoCEdYfCl8yydaIv8Ook5ip1qjZi7JP/RtXagiFOTtvbOmUBeTFz2hDalk6un+l0V4sOE3taULMfaFRwhBi+XeNlnfSmsl1+Bp/T3qJMxLsgRV1AEhwg6hestMGN49TB/YIogiMhAcM8ACF47HIxDMeoNxZJmuRg2tTkDLh4DAG02czba0l"
	ecdsaKey   = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHoiyNRU8Tk5rBs6ve4wExUzriltXZ/bl8YiuPfd7nF1kC894F306jKgJE0/0JIWSIcMWKeu1o6+e6fa64TwYig= test"
)

func TestParsePublicKey(t *testing.T) {
	tests := []struct {
		name          string
		publicKey     string
		wantAlgorithm string
		wantBits      int64
	}{
		{"ed25519", ed25519Key, "ssh-ed25519", 256},
		{"rsa 2048", rsa2048Key, "ssh-rsa", 2048},
		{"ecdsa nistp256", ecdsaKey, "ecdsa-sha2-nistp256", 256},
		{"unparseable", "not a valid key", "", 0},
		{"empty", "", "", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algorithm, bits := ParsePublicKey(tt.publicKey)
			assert.Equal(t, tt.wantAlgorithm, algorithm)
			assert.Equal(t, tt.wantBits, bits)
		})
	}
}

func TestParseAuthorizedKey(t *testing.T) {
	t.Run("returns comment and ok for a valid key", func(t *testing.T) {
		algorithm, bits, comment, ok := ParseAuthorizedKey(ed25519Key)
		assert.True(t, ok)
		assert.Equal(t, "ssh-ed25519", algorithm)
		assert.Equal(t, int64(256), bits)
		assert.Equal(t, "alice@laptop", comment)
	})

	t.Run("ok is false for an unparseable line", func(t *testing.T) {
		_, _, _, ok := ParseAuthorizedKey("garbage")
		assert.False(t, ok)
	})
}
