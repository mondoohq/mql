// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestResource_Tfstate(t *testing.T) {
	t.Run("tf state outputs", func(t *testing.T) {
		srv, connRes := newTestService(StateConnectionType, "./testdata/tfstate/state_simple.json")
		require.NotEmpty(t, srv)
		// simulate terraform.state.outputs.length

		// create terraform state
		dataResp, err := srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "terraform.state",
		})
		require.NoError(t, err)
		resourceId := string(dataResp.Data.Value)

		// fetch outputs
		dataResp, err = srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "terraform.state",
			ResourceId: resourceId,
			Field:      "outputs",
		})
		require.NoError(t, err)
		assert.Equal(t, 0, len(dataResp.Data.Array))
	})

	t.Run("tf state recursive modules", func(t *testing.T) {
		srv, connRes := newTestService(StateConnectionType, "./testdata/tfstate/state_simple.json")
		require.NotEmpty(t, srv)
		// simulate "terraform.state.modules.length"

		// create terraform state
		dataResp, err := srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "terraform.state",
		})
		require.NoError(t, err)
		resourceId := string(dataResp.Data.Value)

		// fetch modules
		dataResp, err = srv.GetData(&plugin.DataReq{
			Connection: connRes.Id,
			Resource:   "terraform.state",
			ResourceId: resourceId,
			Field:      "modules",
		})
		require.NoError(t, err)
		assert.Equal(t, 1, len(dataResp.Data.Array))
	})

	// FIXME: reimplement, when we can use MQL directly
	/*
		t.Run("tf state direct init", func(t *testing.T) {
			// NOTE tfstate root modules have no name
			res := testTerraformStateQuery(t, `terraform.state.module("").resources[0].address`)
			require.NotEmpty(t, res)
			assert.Empty(t, res[0].Result().Error)
			assert.Equal(t, "aws_instance.app_server", res[0].Data.Value)
		})
	*/
}
