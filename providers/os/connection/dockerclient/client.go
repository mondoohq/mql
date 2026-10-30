// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package dockerclient constructs moby docker clients that honor both DOCKER_HOST
// and the active docker CLI context. It is a dependency-free leaf so every caller
// that talks to a local docker engine (discovery, container/image loading, the
// docker connection) can share one context-aware client builder without creating
// import cycles.
package dockerclient

import (
	"context"
	"io"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/context/docker"
	"github.com/docker/cli/cli/context/store"
	dopts "github.com/docker/cli/opts"
	"github.com/moby/moby/client"
	"github.com/moby/moby/client/pkg/versions"
	"github.com/rs/zerolog/log"
)

const (
	// defaultDockerContext is the context name that maps to the moby client's
	// own env/default-socket resolution (docker/cli command.DefaultContextName).
	defaultDockerContext = "default"
	// envOverrideContext selects the active docker context
	// (docker/cli command.EnvOverrideContext).
	envOverrideContext = "DOCKER_CONTEXT"
)

// FromDockerEnv builds client options from the environment, like [client.FromEnv],
// but it parses the DOCKER_HOST like the docker cli and not the docker go lib.
// DO NOT ASK why docker maintains two implementations.
//
// It also honors the active docker CLI context (the "currentContext" in
// ~/.docker/config.json or the DOCKER_CONTEXT env var). The moby client only
// knows DOCKER_HOST and its compiled-in default socket (/var/run/docker.sock),
// so without this a rootless daemon (socket under $XDG_RUNTIME_DIR, selected via
// `docker context use rootless`) or any remote context is never reached: the
// local lookup fails and image resolution silently falls through to the registry,
// which then reports a misleading "missing container registry credentials" error.
//
// client.Opt can no longer be re-applied to an already-constructed *client.Client
// (it now closes over an unexported clientConfig used only during construction), so
// unlike the old client.FromEnv-then-override dance, the CLI-compatible host parsing
// is folded in as its own Opt in the returned slice instead. This intentionally
// composes the same pieces client.FromEnv does (minus its host parsing, which we
// replace below) rather than calling client.FromEnv directly: if a future moby/moby
// release adds a new env-derived option to FromEnv, this list won't pick it up
// automatically and will need a manual update.
func FromDockerEnv() ([]client.Opt, error) {
	opts := []client.Opt{
		client.WithTLSClientConfigFromEnv(),
		client.WithAPIVersionFromEnv(),
	}

	// An explicit DOCKER_HOST always wins and pins us to env-based resolution,
	// mirroring the docker CLI (docker/cli command.resolveContextName): setting
	// DOCKER_HOST forces the "default" context.
	if host := os.Getenv(client.EnvOverrideHost); host != "" {
		parsedHost, err := dopts.ParseHost(false, host)
		if err != nil {
			return nil, err
		}
		return append(opts, client.WithHost(parsedHost)), nil
	}

	// Otherwise honor the active docker context. A failure here is non-fatal:
	// fall back to the moby client's default host rather than break connections
	// that would have worked against the default socket.
	ctxOpts, err := dockerContextClientOpts()
	if err != nil {
		log.Debug().Err(err).Msg("could not resolve docker context, using default docker host")
		return opts, nil
	}
	return append(opts, ctxOpts...), nil
}

// dockerContextClientOpts resolves client options (host plus any TLS or ssh
// transport) from the active docker CLI context. It returns nil opts when the
// default context is active, letting the moby client apply its own defaults.
func dockerContextClientOpts() ([]client.Opt, error) {
	ctxName := os.Getenv(envOverrideContext)
	if ctxName == "" {
		// LoadDefaultConfigFile never returns nil; on a parse error it logs to the
		// provided writer and returns an empty config (we discard the warning).
		ctxName = config.LoadDefaultConfigFile(io.Discard).CurrentContext
	}
	if ctxName == "" || ctxName == defaultDockerContext {
		return nil, nil
	}

	// Mirror docker/cli command.DefaultContextStoreConfig, registering just the
	// docker endpoint type (the only one we resolve). The context-metadata type
	// is unused here, so a generic map getter suffices.
	storeConfig := store.NewConfig(
		func() any { return &map[string]any{} },
		store.EndpointTypeGetter(docker.DockerEndpoint, func() any { return &docker.EndpointMeta{} }),
	)
	st := store.New(config.ContextStoreDir(), storeConfig)
	ctxMeta, err := st.GetMetadata(ctxName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read docker context %q", ctxName)
	}
	epMeta, err := docker.EndpointFromContext(ctxMeta)
	if err != nil {
		return nil, errors.Wrapf(err, "no docker endpoint in context %q", ctxName)
	}
	ep, err := docker.WithTLSData(st, ctxName, epMeta)
	if err != nil {
		return nil, err
	}
	return ep.ClientOpts()
}

// NewDockerClient builds a moby client that honors DOCKER_HOST and the active
// docker CLI context (see FromDockerEnv). Prefer this over client.New(client.FromEnv)
// everywhere, so rootless and remote-context daemons are reached consistently.
func NewDockerClient() (*client.Client, error) {
	opts, err := FromDockerEnv()
	if err != nil {
		return nil, err
	}
	// No explicit NegotiateAPIVersion call: the method was removed from *Client in
	// moby/moby's v29 client rewrite. API version negotiation now happens
	// automatically on the first request (WithAPIVersionNegotiation is a
	// documented no-op kept only for backward compatibility).
	return client.New(opts...)
}

// NewNegotiatedDockerClient builds a client like NewDockerClient and negotiates
// the API version with the daemon before returning it, including daemons older
// than the client library supports.
//
// The moby client negotiates on its first request, but only down to
// client.MinAPIVersion (1.40). A daemon below that, such as Docker 18.09 (API
// 1.39, the docker.io package on Debian 10), fails negotiation, the client
// discards that error, and the request goes out as client.MaxAPIVersion. The
// daemon rejects it with "client version 1.56 is too new". For that case the
// client is rebuilt pinned to the daemon's own version, which is what setting
// DOCKER_API_VERSION does by hand.
//
// A failed ping (no daemon, unreachable host) is not an error here: the client
// is returned unchanged and the first real request reports the failure, as it
// does for NewDockerClient. An explicit DOCKER_API_VERSION is always honored.
func NewNegotiatedDockerClient(ctx context.Context) (*client.Client, error) {
	opts, err := FromDockerEnv()
	if err != nil {
		return nil, err
	}
	cl, err := client.New(opts...)
	if err != nil {
		return nil, err
	}

	ping, err := cl.Ping(ctx, client.PingOptions{NegotiateAPIVersion: true})
	if err == nil || ping.APIVersion == "" || !versions.LessThan(ping.APIVersion, client.MinAPIVersion) {
		return cl, nil
	}

	log.Debug().Str("daemon_api_version", ping.APIVersion).Str("client_min_api_version", client.MinAPIVersion).
		Msg("docker daemon API version is below the client minimum, pinning the client to the daemon version")
	pinned, perr := client.New(append(opts, client.WithAPIVersion(ping.APIVersion))...)
	if perr != nil {
		return cl, nil
	}
	_ = cl.Close()
	return pinned, nil
}
