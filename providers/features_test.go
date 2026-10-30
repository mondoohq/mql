// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// flagProbePlugin records what plugin.StructuredErrors said when its Connect
// ran. Everything else is left to the embedded nil interface: the test only
// connects.
type flagProbePlugin struct {
	plugin.ProviderPlugin
	sawStructuredErrors bool
}

func (p *flagProbePlugin) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	p.sawStructuredErrors = plugin.StructuredErrors()
	return &plugin.ConnectRes{}, nil
}

// An in-process provider never goes through the SDK's gRPC server, which is
// where a provider in its own process reads the features. The runtime has to
// read them before the provider's Connect runs (ADR 046 §9).
func TestRuntime_InProcessProviderSeesStructuredErrors(t *testing.T) {
	t.Cleanup(func() { plugin.ReadFeatures([]byte(mql.Features{byte(mql.ResourceContext)})) })

	probe := &flagProbePlugin{}
	rt := &Runtime{providers: map[string]*ConnectedProvider{}}
	err := rt.UseInProcessProvider(
		plugin.Provider{Name: "probe", ID: "go.mondoo.com/mql/providers/probe"},
		nil,
		probe,
		[]byte(mql.Features{byte(mql.ResourceContext), byte(mql.StructuredErrors)}),
	)
	require.NoError(t, err)
	assert.True(t, probe.sawStructuredErrors)
}
