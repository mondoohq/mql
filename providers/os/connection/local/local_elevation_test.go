// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package local

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

func probeOutput(stdout string) func(string) (*shared.Command, error) {
	return func(string) (*shared.Command, error) {
		return &shared.Command{Stdout: bytes.NewBufferString(stdout), Stderr: &bytes.Buffer{}}, nil
	}
}

func TestLocalResolveElevation(t *testing.T) {
	t.Run("doas only", func(t *testing.T) {
		// Alpine 3.24
		p := &LocalConnection{Sudo: &inventory.Sudo{Active: true}}
		require.NoError(t, p.resolveElevation(probeOutput("/usr/bin/doas\nmql-elevation-probe-done\n")))
		assert.Equal(t, "doas", p.Sudo.Executable)
	})

	t.Run("neither installed is reported", func(t *testing.T) {
		// Alpine 3.21, probe run with PATH=/nonexistent
		p := &LocalConnection{Sudo: &inventory.Sudo{Active: true}}
		err := p.resolveElevation(probeOutput("mql-elevation-probe-done\n"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "neither sudo nor doas")
		assert.Equal(t, "", p.Sudo.Executable)
	})

	t.Run("elevation not requested", func(t *testing.T) {
		p := &LocalConnection{}
		require.NoError(t, p.resolveElevation(func(string) (*shared.Command, error) {
			t.Fatal("probe must not run without elevation")
			return nil, nil
		}))
	})
}
