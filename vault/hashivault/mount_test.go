// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hashivault

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestSecretPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
		key  string
		want string
	}{
		{
			name: "default mount",
			key:  "my-secret",
			want: "secret/data/my-secret",
		},
		{
			name: "custom mount",
			opts: []Option{WithMount("kv")},
			key:  "my-secret",
			want: "kv/data/my-secret",
		},
		{
			// Vault paths are written with and without slashes in docs and CLI
			// output, so accept either rather than producing "kv//data/x".
			name: "surrounding slashes are trimmed",
			opts: []Option{WithMount("/kv/")},
			key:  "my-secret",
			want: "kv/data/my-secret",
		},
		{
			// A mount is often read straight from configuration, so an unset
			// value must fall back rather than build an invalid path.
			name: "empty mount keeps the default",
			opts: []Option{WithMount("")},
			key:  "my-secret",
			want: "secret/data/my-secret",
		},
		{
			name: "nested key",
			opts: []Option{WithMount("kv")},
			key:  "team/service/token",
			want: "kv/data/team/service/token",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New("http://127.0.0.1:8200", "token", tc.opts...)
			assert.Equal(t, tc.want, v.secretPath(tc.key))
		})
	}
}

// A zero-value Vault must still produce a valid path: the struct is exported,
// so it can be constructed without New.
func TestSecretPathZeroValue(t *testing.T) {
	v := &Vault{}
	assert.Equal(t, "secret/data/my-secret", v.secretPath("my-secret"))
}

func TestRegisteredVaultUsesConfiguredMount(t *testing.T) {
	newVault := func(opts map[string]string) *Vault {
		v, err := vault.New(&vault.VaultConfiguration{
			Name:    "test",
			Type:    vault.VaultType_HashiCorp,
			Options: opts,
		})
		if err != nil {
			t.Fatalf("vault.New: %v", err)
		}
		hv, ok := v.(*Vault)
		if !ok {
			t.Fatalf("expected *hashivault.Vault, got %T", v)
		}
		return hv
	}

	t.Run("mount option is honoured", func(t *testing.T) {
		hv := newVault(map[string]string{
			"url":   "http://127.0.0.1:8200",
			"token": "token",
			"mount": "kv",
		})
		assert.Equal(t, "kv", hv.Mount)
		assert.Equal(t, "kv/data/x", hv.secretPath("x"))
	})

	// Existing configurations carry no "mount" key at all; they must keep
	// reading from secret/.
	t.Run("configuration without a mount is unchanged", func(t *testing.T) {
		hv := newVault(map[string]string{
			"url":   "http://127.0.0.1:8200",
			"token": "token",
		})
		assert.Equal(t, DefaultMount, hv.Mount)
		assert.Equal(t, "secret/data/x", hv.secretPath("x"))
	})
}
