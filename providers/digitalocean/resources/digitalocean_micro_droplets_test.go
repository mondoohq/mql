// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMicroDropletIsPublic(t *testing.T) {
	cases := []struct {
		name       string
		networking godo.MicroVMNetworking
		want       bool
	}{
		{"public mode is reachable", godo.MicroVMNetworkingPublic, true},
		{"vpc mode is not", godo.MicroVMNetworkingVPC, false},
		// A placement the API does not name must not read as private. An
		// instance we cannot place is reported as exposed so it surfaces in
		// an audit rather than passing silently.
		{"unknown mode errs toward exposure", godo.MicroVMNetworkingUnknown, true},
		{"empty mode errs toward exposure", godo.MicroVMNetworking(""), true},
		// Only the literal vpc placement makes an instance private, so the
		// comparison must not be defeated by casing.
		{"uppercase vpc is still vpc", godo.MicroVMNetworking("VPC"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, microDropletIsPublic(c.networking))
		})
	}
}

func TestMicroDropletArgs(t *testing.T) {
	enabled := true
	md := &godo.MicroVM{
		ID:         "md-1",
		Name:       "api",
		Region:     "nyc3",
		State:      godo.MicroVMStateRunning,
		Size:       &godo.MicroVMSize{CPU: 1, Memory: 1024},
		Networking: godo.MicroVMNetworkingVPC,
		Source:     &godo.MicroVMSource{OCIRef: "registry.digitalocean.com/team/api:1.4"},
		URLs:       []godo.MicroVMURL{{Hostname: "md-1.micro.example.com", Default: true}},
		AutoPause:  &godo.AutoPauseConfig{Enabled: &enabled, IdleTimeout: "5m"},
		AutoResume: &enabled,
		Created:    "2026-01-02T15:04:05Z",
	}

	args, err := microDropletArgs(md)
	require.NoError(t, err)

	assert.Equal(t, "digitalocean.microDroplet/md-1", args["__id"].Value)
	assert.Equal(t, "md-1", args["id"].Value)
	assert.Equal(t, "api", args["name"].Value)
	assert.Equal(t, "nyc3", args["region"].Value)
	assert.Equal(t, "running", args["state"].Value)
	assert.Equal(t, "vpc", args["networking"].Value)
	assert.Equal(t, "registry.digitalocean.com/team/api:1.4", args["image"].Value)
	assert.Equal(t, "md-1.micro.example.com", args["endpoint"].Value)
	// The API reports no size slug any more, so the deprecated field is null
	// rather than a string made up from the CPU and memory values.
	assert.Nil(t, args["size"].Value)
	assert.Equal(t, true, args["autoPauseEnabled"].Value)
	assert.Equal(t, "5m", args["autoPauseIdleTimeout"].Value)
	assert.Equal(t, true, args["autoResumeEnabled"].Value)
	assert.NotNil(t, args["createdAt"].Value)
}

func TestMicroDropletArgs_AbsentOptionals(t *testing.T) {
	// A MicroDroplet with no auto-pause block configured. The absent
	// pointers must decode to the safe reading — the instance does not pause
	// itself — rather than to a null that would make `autoPauseEnabled &&
	// autoResumeEnabled` pass vacuously.
	args, err := microDropletArgs(&godo.MicroVM{
		ID:         "md-2",
		Networking: godo.MicroVMNetworkingPublic,
	})
	require.NoError(t, err)

	// An instance started from a checkpoint carries no image reference and
	// one with no URLs serves on no address.
	assert.Equal(t, "", args["image"].Value)
	assert.Equal(t, "", args["endpoint"].Value)

	assert.Equal(t, false, args["autoPauseEnabled"].Value)
	assert.Equal(t, "", args["autoPauseIdleTimeout"].Value)
	assert.Equal(t, false, args["autoResumeEnabled"].Value)
	// An absent timestamp must stay null. Decoding "" to the zero time would
	// report 1 January year 1 as a real creation date.
	assert.Nil(t, args["createdAt"].Value)
}

func TestMicroDropletArgs_EmptyIDRejected(t *testing.T) {
	// An empty id would build the cache key "digitalocean.microDroplet/",
	// which every id-less instance would share, so the whole listing would
	// collapse onto whichever arrived first.
	_, err := microDropletArgs(&godo.MicroVM{Name: "no-id"})
	require.Error(t, err)
}

func TestMicroVMEndpoint(t *testing.T) {
	// The default URL wins even when it is not listed first.
	assert.Equal(t, "app.example.com", microVMEndpoint([]godo.MicroVMURL{
		{Hostname: "md-1.micro.example.com"},
		{Hostname: "app.example.com", Default: true},
	}))
	// Without a default, the first URL is the address.
	assert.Equal(t, "md-1.micro.example.com", microVMEndpoint([]godo.MicroVMURL{
		{Hostname: "md-1.micro.example.com"},
		{Hostname: "app.example.com"},
	}))
	assert.Equal(t, "", microVMEndpoint(nil))
}
