// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TransportOption(insecure bool) remote.Option {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if insecure {
		tr.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return remote.WithTransport(tr)
}

func AuthOption(ref string, credentials []*vault.Credential) remote.Option {
	for i := range credentials {
		cred := credentials[i]
		switch cred.Type {
		case vault.CredentialType_password:
			log.Debug().Msg("add password authentication")
			cfg := authn.AuthConfig{
				Username: cred.User,
				Password: string(cred.Secret),
			}
			return remote.WithAuth((authn.FromConfig(cfg)))
		case vault.CredentialType_bearer:
			log.Debug().Str("token", string(cred.Secret)).Msg("add bearer authentication")
			cfg := authn.AuthConfig{
				Username:      cred.User,
				RegistryToken: string(cred.Secret),
			}
			return remote.WithAuth((authn.FromConfig(cfg)))
		default:
			log.Warn().Msg("unknown credentials for container image")
			logger.DebugJSON(credentials)
		}
	}
	log.Debug().Msg("no credentials for container image, falling back to default auth")
	return remote.WithAuthFromKeychain(ConstructKeychain(ref))
}

func DefaultOpts(ref string, insecure bool) []remote.Option {
	return []remote.Option{AuthOption(ref, nil), TransportOption(insecure)}
}
