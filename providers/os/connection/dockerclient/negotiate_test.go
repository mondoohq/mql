// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package dockerclient_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/moby/moby/client"
	"github.com/moby/moby/client/pkg/versions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/dockerclient"
)

// containerListV139 is `GET /v1.39/containers/json?all=1` from Docker 18.09.1
// (docker.io on Debian 10), trimmed to the fields the docker resource reads.
const containerListV139 = `[{"Id":"5eb830502ee4b75880790f14d597aa62a0b0bcb2ba6276059fa368553218ec38","Names":["/mqltest"],"Image":"busybox:latest","ImageID":"sha256:aaef90e065235eb0b2d9938be85d1b81add2902cf89affe2cdfa19be33476ac0","Command":"sleep 86400","Created":1790573634,"Ports":[],"Labels":{},"State":"running","Status":"Up 11 minutes","HostConfig":{"NetworkMode":"default"},"Mounts":[]}]`

// fakeDaemon answers like a docker daemon whose highest API version is
// apiVersion: /_ping carries it in the Api-Version header, and a versioned
// request above it gets the 400 Docker returns (message text from Docker
// 18.09.1). It records the versioned path of every API request.
func fakeDaemon(t *testing.T, apiVersion string) (*httptest.Server, *[]string) {
	t.Helper()
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Api-Version", apiVersion)
		w.Header().Set("Ostype", "linux")
		if r.URL.Path == "/_ping" {
			_, _ = w.Write([]byte("OK"))
			return
		}
		paths = append(paths, r.URL.Path)
		reqVersion, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/v"), "/")
		if versions.GreaterThan(reqVersion, apiVersion) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `{"message":"client version %s is too new. Maximum supported API version is %s"}`, reqVersion, apiVersion)
			return
		}
		if rest == "containers/json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(containerListV139))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &paths
}

func pointAtDaemon(t *testing.T, srv *httptest.Server) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	t.Setenv("DOCKER_CONTEXT", "")
	t.Setenv("DOCKER_API_VERSION", "")
	t.Setenv("DOCKER_HOST", "tcp://"+strings.TrimPrefix(srv.URL, "http://"))
}

func TestNegotiatedClientPinsDaemonBelowClientMinimum(t *testing.T) {
	srv, paths := fakeDaemon(t, "1.39")
	pointAtDaemon(t, srv)

	cl, err := dockerclient.NewNegotiatedDockerClient(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "1.39", cl.ClientVersion())

	res, err := cl.ContainerList(context.Background(), client.ContainerListOptions{All: true})
	require.NoError(t, err)
	require.Len(t, res.Items, 1)
	assert.Equal(t, []string{"/mqltest"}, res.Items[0].Names)
	assert.Equal(t, "busybox:latest", res.Items[0].Image)
	assert.Equal(t, []string{"/v1.39/containers/json"}, *paths)
}

// Pins the behavior NewDockerClient has always had against current daemons, so
// the up-front negotiation can not change which version is spoken to them.
func TestNegotiatedClientMatchesLibraryNegotiation(t *testing.T) {
	for _, tc := range []struct{ daemon, want string }{
		{daemon: "1.40", want: "1.40"}, // client.MinAPIVersion itself
		{daemon: "1.47", want: "1.47"}, // lower than the client maximum
		{daemon: client.MaxAPIVersion, want: client.MaxAPIVersion},
		{daemon: "9.99", want: client.MaxAPIVersion}, // newer than the client
	} {
		t.Run(tc.daemon, func(t *testing.T) {
			srv, paths := fakeDaemon(t, tc.daemon)
			pointAtDaemon(t, srv)

			cl, err := dockerclient.NewNegotiatedDockerClient(context.Background())
			require.NoError(t, err)
			assert.Equal(t, tc.want, cl.ClientVersion())
			_, err = cl.ContainerList(context.Background(), client.ContainerListOptions{})
			require.NoError(t, err)

			lazy, err := dockerclient.NewDockerClient()
			require.NoError(t, err)
			_, err = lazy.ContainerList(context.Background(), client.ContainerListOptions{})
			require.NoError(t, err)
			assert.Equal(t, cl.ClientVersion(), lazy.ClientVersion())
			assert.Equal(t, []string{"/v" + tc.want + "/containers/json", "/v" + tc.want + "/containers/json"}, *paths)
		})
	}
}

func TestNegotiatedClientHonorsDockerAPIVersion(t *testing.T) {
	srv, _ := fakeDaemon(t, "1.47")
	pointAtDaemon(t, srv)
	t.Setenv("DOCKER_API_VERSION", "1.41")

	cl, err := dockerclient.NewNegotiatedDockerClient(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "1.41", cl.ClientVersion())
}

func TestNegotiatedClientWithoutDaemon(t *testing.T) {
	srv, _ := fakeDaemon(t, "1.47")
	pointAtDaemon(t, srv)
	srv.Close() // nothing listens on DOCKER_HOST any more

	cl, err := dockerclient.NewNegotiatedDockerClient(context.Background())
	require.NoError(t, err, "an unreachable daemon is reported by the first request, not by the constructor")
	_, err = cl.ContainerList(context.Background(), client.ContainerListOptions{})
	assert.Error(t, err)
}
