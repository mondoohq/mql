// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	web "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v6"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestRuntimeSettingsForPreferredOs pins the capitalization of the wire values.
//
// StackPreferredOs is "Linux" / "Windows". The switch used to compare against
// the lowercase literals "linux" / "windows", which are valid StackPreferredOs
// values and so compiled, but matched neither arm — so the settings stayed nil,
// every minor version of every stack was skipped, and availableRuntimes
// returned an empty list on every subscription.
func TestRuntimeSettingsForPreferredOs(t *testing.T) {
	linux := &web.WebAppRuntimeSettings{RuntimeVersion: new("NODE|18-lts")}
	windows := &web.WebAppRuntimeSettings{RuntimeVersion: new("ASPNET|v4.8")}
	settings := &web.WebAppRuntimes{LinuxRuntimeSettings: linux, WindowsRuntimeSettings: windows}

	got, os := runtimeSettingsForPreferredOs(webOsPtr(web.StackPreferredOsLinux), settings)
	assert.Same(t, linux, got)
	assert.Equal(t, "linux", os)

	got, os = runtimeSettingsForPreferredOs(webOsPtr(web.StackPreferredOsWindows), settings)
	assert.Same(t, windows, got)
	assert.Equal(t, "windows", os)

	// The lowercase spellings are what the bug compared against. They are not
	// values the API emits, and they must not resolve to settings.
	got, os = runtimeSettingsForPreferredOs(webOsPtr(web.StackPreferredOs("linux")), settings)
	assert.Nil(t, got)
	assert.Equal(t, "", os)

	// Absent preferred OS, absent settings, and an OS the SDK does not define
	// all resolve to nothing rather than guessing at one of the two.
	got, _ = runtimeSettingsForPreferredOs(nil, settings)
	assert.Nil(t, got)
	got, _ = runtimeSettingsForPreferredOs(webOsPtr(web.StackPreferredOsLinux), nil)
	assert.Nil(t, got)
	got, _ = runtimeSettingsForPreferredOs(webOsPtr(web.StackPreferredOs("Solaris")), settings)
	assert.Nil(t, got)

	// A stack that only publishes settings for the other OS yields nil, not the
	// wrong OS's settings.
	linuxOnly := &web.WebAppRuntimes{LinuxRuntimeSettings: linux}
	got, _ = runtimeSettingsForPreferredOs(webOsPtr(web.StackPreferredOsWindows), linuxOnly)
	assert.Nil(t, got)
}

// TestRuntimeStackDescriptorIDIsTheRuntimeVersion pins what the descriptor's ID
// is compared against.
//
// computeWebAppStack matches an app's runtime identifier -- its LinuxFxVersion
// ("NODE|18-lts") or "<STACK>|<version>" -- against descriptor.ID. The ID used
// to be built as "<subscriptionId>/<stackName>", which can never equal either
// shape, so the comparison was dead and matching rested entirely on name plus
// minor version.
//
// Note what this test does and does not buy: it pins the ID as unconditionally
// the runtime version, and fails on any edit that derives it from something
// else. It would NOT have caught the original bug, whose wrong branch was
// reachable only when a live Azure connection supplied a subscription id. What
// closes that gap is the fix itself -- the function no longer reads the
// connection, so there is no longer a branch a test cannot reach.
func TestRuntimeStackDescriptorIDIsTheRuntimeVersion(t *testing.T) {
	stack := &mqlAzureSubscriptionWebServiceAppRuntimeStack{
		Name:           setString("node"),
		MinorVersion:   setString("18-lts"),
		RuntimeVersion: setString("NODE|18-lts"),
		AutoUpdate:     setBool(true),
		Deprecated:     setBool(false),
	}

	got := runtimeStackDescriptorFromResource(stack)
	assert.Equal(t, "NODE|18-lts", got.ID,
		"the ID has to be comparable to an app's LinuxFxVersion")
	assert.Equal(t, "node", got.Name)
	assert.Equal(t, "18-lts", got.MinorVersion)
	assert.True(t, got.AutoUpdate)
	assert.False(t, got.IsDeprecated)

	// Name and minor version are lowercased for the case-insensitive match; the
	// ID is not, because it is compared with EqualFold anyway and the wire form
	// is what a reader expects to see.
	upper := &mqlAzureSubscriptionWebServiceAppRuntimeStack{
		Name:           setString("DOTNET"),
		MinorVersion:   setString("V4.8"),
		RuntimeVersion: setString("ASPNET|v4.8"),
	}
	got = runtimeStackDescriptorFromResource(upper)
	assert.Equal(t, "dotnet", got.Name)
	assert.Equal(t, "v4.8", got.MinorVersion)
	assert.Equal(t, "ASPNET|v4.8", got.ID)

	// A stack with no runtime version leaves the ID empty, which the match loop
	// requires so that an empty ID never counts as a match.
	got = runtimeStackDescriptorFromResource(&mqlAzureSubscriptionWebServiceAppRuntimeStack{
		Name: setString("node"),
	})
	assert.Equal(t, "", got.ID)

	assert.NotNil(t, runtimeStackDescriptorFromResource(nil))
}

//go:fix inline
func webOsPtr(v web.StackPreferredOs) *web.StackPreferredOs { return new(v) }

func setString(v string) plugin.TValue[string] {
	return plugin.TValue[string]{Data: v, State: plugin.StateIsSet}
}

func setBool(v bool) plugin.TValue[bool] {
	return plugin.TValue[bool]{Data: v, State: plugin.StateIsSet}
}
