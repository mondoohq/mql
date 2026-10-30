// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ParseCLI must not panic on an empty argument list (it used to index
// req.Args[0] unconditionally).
func TestParseCLI_NoArgs(t *testing.T) {
	srv := &Service{Service: plugin.NewService()}
	_, err := srv.ParseCLI(&plugin.ParseCLIReq{Connector: "terraform"})
	require.Error(t, err)
}

// A state file with `values` present but no `root_module` (e.g. outputs-only)
// must not panic dereferencing a nil RootModule; modules/resources resolve to
// empty and rootModule to null.
func TestResource_TfstateNoRootModule(t *testing.T) {
	srv, connRes := newTestService(StateConnectionType, "./testdata/tfstate/state_no_root_module.json")
	require.NotEmpty(t, srv)

	dataResp, err := srv.GetData(&plugin.DataReq{
		Connection: connRes.Id,
		Resource:   "terraform.state",
	})
	require.NoError(t, err)
	resourceId := string(dataResp.Data.Value)

	for _, field := range []string{"modules", "resources"} {
		resp, err := srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "terraform.state",
			ResourceId: resourceId,
			Field:      field,
		})
		require.NoError(t, err, "field %q must not error", field)
		assert.Equal(t, 0, len(resp.Data.Array), "field %q must be empty", field)
	}
}
