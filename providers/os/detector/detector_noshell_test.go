// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// localNoShell is a local connection on an image that ships no shell: every
// command fails to start, as `exec: "sh": executable file not found` does.
type localNoShell struct {
	*mock.Connection
}

func (c *localNoShell) Type() shared.ConnectionType { return shared.Type_Local }

func (c *localNoShell) RunCommand(command string) (*shared.Command, error) {
	return nil, errors.New(`exec: "sh": executable file not found in $PATH`)
}

func detectLocalNoShell(t *testing.T, path string) *inventory.Platform {
	t.Helper()
	m, err := mock.New(0, &inventory.Asset{}, mock.WithPath(path))
	require.NoError(t, err)
	pf, ok := OperatingSystems.Resolve(&localNoShell{Connection: m})
	require.True(t, ok)
	return pf
}

func TestDetectLocalWithoutShell(t *testing.T) {
	goos, goarch := localGOOS, localGOARCH
	t.Cleanup(func() { localGOOS, localGOARCH = goos, goarch })
	localGOOS, localGOARCH = "linux", "arm64"
	const want = "aarch64"

	// The arch was "", and the purl lost it.
	t.Run("distroless", func(t *testing.T) {
		pf := detectLocalNoShell(t, "./testdata/detect-distroless-static-noshell.toml")
		assert.Equal(t, "debian", pf.Name)
		assert.Equal(t, want, pf.Arch)
	})

	// The platform was "" with family [os], and every resource reported
	// "unsupported".
	t.Run("scratch", func(t *testing.T) {
		pf := detectLocalNoShell(t, "./testdata/detect-scratch-noshell.toml")
		assert.Equal(t, "generic-linux", pf.Name)
		assert.Contains(t, pf.Family, "linux")
		assert.Equal(t, want, pf.Arch)
	})
}

// The fallback is only for a local scan: over a mock (or SSH, or a mounted
// filesystem) the scanner's own build says nothing about the target.
func TestDetectRemoteWithoutShellKeepsNoArch(t *testing.T) {
	pf, _ := detectPlatformFromMock("./testdata/detect-distroless-static-noshell.toml")
	assert.Equal(t, "debian", pf.Name)
	assert.Equal(t, "", pf.Arch)
}

func TestUnameMachine(t *testing.T) {
	assert.Equal(t, "x86_64", unameMachine("amd64"))
	assert.Equal(t, "aarch64", unameMachine("arm64"))
	assert.Equal(t, "ppc64le", unameMachine("ppc64le"))
	assert.Equal(t, "", unameMachine("arm"), "uname names the arm ISA revision, GOARCH does not")
}
