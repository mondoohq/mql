// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build debugtest
// +build debugtest

package provider

import (
	"fmt"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestOciProvider(t *testing.T) {
	srv := &Service{
		runtimes:         map[uint32]*plugin.Runtime{},
		lastConnectionID: 0,
	}

	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type: "oci",
				},
			},
		},
	}, nil)
	if err != nil {
		panic(err)
	}

	// create oci resource
	dataResp, err := srv.GetData(&plugin.DataReq{
		Connection: resp.Id,
		Resource:   "oci",
	})
	if err != nil {
		panic(err)
	}
	resourceId := string(dataResp.Data.Value)
	fmt.Println(resourceId)

	// create resource
	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: resp.Id,
		Resource:   "oci.compute",
	})
	if err != nil {
		panic(err)
	}
	resourceId = string(dataResp.Data.Value)

	// fetch images
	dataResp, err = srv.GetData(&plugin.DataReq{
		Connection: resp.Id,
		Resource:   "oci.compute",
		ResourceId: resourceId,
		Field:      "images",
	})
	if err != nil {
		panic(err)
	}
	resourceId = string(dataResp.Data.Value)
}
