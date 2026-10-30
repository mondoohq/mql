// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainerArgs(t *testing.T) {
	row := map[string]string{
		".id":           "*1",
		"name":          "agent",
		"tag":           "registry.example.com/tools/agent:1.4",
		"os":            "linux",
		"arch":          "arm64",
		"root-dir":      "usb1/containers/agent",
		"mounts":        "conf,data",
		"dns":           "192.0.2.53",
		"cmd":           "/entry.sh",
		"hostname":      "agent",
		"workdir":       "/",
		"status":        "running",
		"logging":       "yes",
		"start-on-boot": "yes",
	}
	args := containerArgs(row)

	assert.Equal(t, "mikrotik.container/*1", args["__id"].Value)
	assert.Equal(t, "registry.example.com/tools/agent:1.4", args["tag"].Value)
	assert.Equal(t, "running", args["status"].Value)
	assert.Equal(t, []any{"conf", "data"}, args["mounts"].Value)
	assert.Equal(t, true, args["logging"].Value)
	// a container that starts on boot outlives a reboot
	assert.Equal(t, true, args["startOnBoot"].Value)
}

func TestContainerArgsAbsentAttributes(t *testing.T) {
	args := containerArgs(map[string]string{"name": "bare", "tag": "example:latest"})

	assert.Equal(t, "mikrotik.container/bare/example:latest", args["__id"].Value)
	assert.Nil(t, args["mounts"].Value)
	assert.Nil(t, args["logging"].Value)
	assert.Nil(t, args["startOnBoot"].Value)
}

func TestContainerConfigArgs(t *testing.T) {
	args := containerConfigArgs(map[string]string{
		"registry-url": "https://registry.example.com",
		"tmpdir":       "usb1/pull",
		"layer-dir":    "usb1/layers",
		"ram-high":     "0",
		"username":     "puller",
		"password":     "not-a-real-password",
	})

	assert.Equal(t, "mikrotik.container.config", args["__id"].Value)
	assert.Equal(t, "https://registry.example.com", args["registryUrl"].Value)
	assert.Equal(t, true, args["hasRegistryCredentials"].Value)

	// the registry credentials never reach the result
	assert.NotContains(t, args, "username")
	assert.NotContains(t, args, "password")
	for field, v := range args {
		assert.NotEqual(t, "not-a-real-password", v.Value, "field %q leaked the password", field)
		assert.NotEqual(t, "puller", v.Value, "field %q leaked the user name", field)
	}
}

func TestContainerConfigArgsAbsentMenu(t *testing.T) {
	// a device without the container package answers nothing at all
	args := containerConfigArgs(map[string]string{})

	assert.Nil(t, args["hasRegistryCredentials"].Value)
	assert.Equal(t, "", args["registryUrl"].Value)
}

func TestRadiusClientArgs(t *testing.T) {
	row := map[string]string{
		".id":                  "*1",
		"service":              "login,ppp",
		"address":              "198.51.100.30",
		"protocol":             "udp",
		"require-message-auth": "no",
		"secret":               "not-a-real-secret",
		"authentication-port":  "1812",
		"accounting-port":      "1813",
		"timeout":              "300ms",
		"accounting-backup":    "no",
		"disabled":             "false",
	}
	args := radiusClientArgs(row)

	assert.Equal(t, "mikrotik.radius.client/*1", args["__id"].Value)
	// with login present, device administration itself goes through RADIUS
	assert.Equal(t, []any{"login", "ppp"}, args["services"].Value)
	assert.Equal(t, "198.51.100.30", args["address"].Value)
	// require-message-auth off leaves the device open to response forgery
	assert.Equal(t, "no", args["requireMessageAuth"].Value)
	assert.Equal(t, true, args["hasSecret"].Value)
	assert.Equal(t, int64(1812), args["authenticationPort"].Value)
	assert.Equal(t, false, args["accountingBackup"].Value)
	// the certificate name is carried only by certificate, never as a
	// field that duplicates it
	assert.NotContains(t, args, "certificate")

	// the shared secret never reaches the result
	assert.NotContains(t, args, "secret")
	for field, v := range args {
		assert.NotEqual(t, "not-a-real-secret", v.Value, "field %q leaked the shared secret", field)
	}
}

func TestRadiusClientArgsAbsentAttributes(t *testing.T) {
	args := radiusClientArgs(map[string]string{"address": "198.51.100.30"})

	assert.Equal(t, "mikrotik.radius.client/198.51.100.30/", args["__id"].Value)
	assert.Nil(t, args["services"].Value)
	// an unreported require-message-auth must not read as configured
	assert.Equal(t, "", args["requireMessageAuth"].Value)
	assert.Nil(t, args["hasSecret"].Value)
	assert.Nil(t, args["disabled"].Value)
}

func TestUserAaaArgs(t *testing.T) {
	args := userAaaArgs(map[string]string{
		"use-radius":     "yes",
		"default-group":  "read",
		"accounting":     "yes",
		"interim-update": "0s",
		"exclude-groups": "full",
	})

	assert.Equal(t, "mikrotik.user.aaa", args["__id"].Value)
	// with RADIUS on, the local account list is not the real access surface
	assert.Equal(t, true, args["useRadius"].Value)
	assert.Equal(t, "read", args["defaultGroup"].Value)
	assert.Equal(t, true, args["accounting"].Value)
	assert.Equal(t, []any{"full"}, args["excludeGroups"].Value)
}

func TestUserAaaArgsAbsentMenu(t *testing.T) {
	args := userAaaArgs(map[string]string{})

	assert.Nil(t, args["useRadius"].Value)
	assert.Nil(t, args["accounting"].Value)
	assert.Nil(t, args["excludeGroups"].Value)
}
