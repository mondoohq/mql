// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
)

var (
	withStructuredErrors    = []byte(mql.Features{byte(mql.ResourceContext), byte(mql.StructuredErrors)})
	withoutStructuredErrors = []byte(mql.Features{byte(mql.ResourceContext)})
)

// resetStructuredErrors puts the process-wide flag back to off when the test
// ends, so no other test in the package inherits it.
func resetStructuredErrors(t *testing.T) {
	t.Cleanup(func() { structuredErrors.Store(false) })
}

func TestReadFeatures(t *testing.T) {
	resetStructuredErrors(t)
	require.False(t, StructuredErrors(), "off until a client asks for it")

	ReadFeatures(withStructuredErrors)
	assert.True(t, StructuredErrors())

	// Delayed discovery connects without features. That must not switch a
	// provider back to v13 behavior halfway through a scan.
	ReadFeatures(nil)
	assert.True(t, StructuredErrors(), "a request without features leaves the flag alone")

	// A long-running process sees the flag turned off again.
	ReadFeatures(withoutStructuredErrors)
	assert.False(t, StructuredErrors(), "a feature set without the flag turns it off")
}

func TestGRPCServerReadsFeaturesOnConnect(t *testing.T) {
	for name, connect := range map[string]func(*GRPCServer, *ConnectReq) error{
		"Connect": func(m *GRPCServer, req *ConnectReq) error {
			_, err := m.Connect(t.Context(), req)
			return err
		},
		"MockConnect": func(m *GRPCServer, req *ConnectReq) error {
			_, err := m.MockConnect(t.Context(), req)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			resetStructuredErrors(t)

			// Without a broker the callback dial panics and the request fails.
			// The features must already have been read by then: a provider's
			// own Connect runs after the dial and may consult the flag.
			err := connect(&GRPCServer{}, &ConnectReq{Features: withStructuredErrors})
			require.Error(t, err)
			assert.True(t, StructuredErrors())
		})
	}
}
