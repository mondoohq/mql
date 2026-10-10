// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hashivault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

var errNotImplemented = errors.New("not implemented") //nolint:unused

// DefaultMount is the path Vault mounts the KV v2 secrets engine at unless it
// is enabled somewhere else.
const DefaultMount = "secret"

// Option configures the Vault client.
type Option func(*Vault)

// WithMount sets the path the KV v2 secrets engine is mounted at.
//
// Vault allows a KV v2 engine to be enabled at any path
// (`vault secrets enable -path=<path> kv-v2`), and Vault-compatible services
// do not all use the default: some mount the engine per instance, so the path
// is only known at configuration time.
//
// An empty mount leaves the default in place, so callers can pass an unset
// configuration value through without having to check it first.
func WithMount(mount string) Option {
	return func(v *Vault) {
		if m := strings.Trim(mount, "/"); m != "" {
			v.Mount = m
		}
	}
}

func New(serverURL string, token string, opts ...Option) *Vault {
	v := &Vault{
		Token: token,
		Mount: DefaultMount,
		APIConfig: api.Config{
			Address: serverURL,
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	log.Debug().
		Bool("token-sec", len(token) > 0).
		Str("mount", v.Mount).
		Msgf("Using HashiCorp Vault at %s", serverURL)
	return v
}

type Vault struct {
	// Token is the access token the Vault client uses to talk to the server.
	// See https://developer.hashicorp.com/vault/docs/concepts/tokens for more
	// information.
	Token string
	// Mount is the path the KV v2 secrets engine is mounted at, without
	// surrounding slashes. Defaults to DefaultMount.
	Mount string
	// APIConfig is used to configure the creation of the client.
	APIConfig api.Config
}

func (v *Vault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "Hashicorp Vault"}, nil
}

// Dial gets a Vault client.
func (v *Vault) client() (*api.Client, error) {
	c, err := api.NewClient(&v.APIConfig)
	if err != nil {
		return nil, err
	}
	if v.Token != "" {
		c.SetToken(v.Token)
	}
	return c, nil
}

// secretPath builds the KV v2 read path for a key: <mount>/data/<key>.
func (v *Vault) secretPath(key string) string {
	mount := v.Mount
	if mount == "" {
		mount = DefaultMount
	}
	return mount + "/data/" + key
}

// we need to remove the leading // from mrns, this should not be done here, therefore we just throw an error
func validKey(key string) error {
	if strings.HasPrefix(key, "/") {
		return errors.New("leading / are not allowed")
	}
	return nil
}

// https://developer.hashicorp.com/vault/tutorials/secrets-management/versioned-kv#write-secrets
func (v *Vault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	log.Debug().Str("secret", id.Key).Msg("gather secret from hashicorp-vault")
	c, err := v.client()
	if err != nil {
		return nil, err
	}

	err = validKey(id.Key)
	if err != nil {
		return nil, err
	}

	secret, err := c.Logical().Read(v.secretPath(id.Key))
	if err != nil {
		return nil, vault.NotFoundError
	}

	secretBytes, err := secretData(secret)
	if err != nil {
		return nil, err
	}

	return &vault.Secret{
		Key:      id.Key,
		Data:     secretBytes,
		Encoding: vault.SecretEncoding_encoding_json,
	}, nil
}

// secretData returns the map of metadata associated with the secret
func secretData(s *api.Secret) ([]byte, error) {
	if s == nil {
		return nil, nil
	}

	if s.Data == nil || (s.Data["data"] == nil) {
		return nil, nil
	}

	data, ok := s.Data["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unable to convert data field to expected format")
	}

	// when we resolve the secret in motor/discovery/resolve.go, we unmarshal to map[string]string, so things should match!
	secretData := make(map[string]string, len(data))
	for k, v := range data {
		typed, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("unable to convert data value %v to string", v)
		}
		secretData[k] = typed
	}

	return json.Marshal(secretData)
}

func (v *Vault) Set(ctx context.Context, cred *vault.Secret) (*vault.SecretID, error) {
	return nil, errors.New("not implemented")
}

func (v *Vault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	return nil, vault.NotImplementedError
}
