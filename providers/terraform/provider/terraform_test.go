// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func newTestService(connType string, path string) (*Service, *plugin.ConnectRes) {
	srv := &Service{
		Service: plugin.NewService(),
	}

	if path == "" {
		switch connType {
		case "plan":
			path = "./testdata/tfplan/plan_gcp_simple.json"
		case "state":
			path = "./testdata/tfstate/state_aws_simple.json"
		}
	}

	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:    connType,
					Options: map[string]string{"path": path},
				},
			},
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return srv, resp
}
