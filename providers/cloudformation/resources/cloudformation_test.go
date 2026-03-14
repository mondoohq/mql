// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/cloudformation/connection"
	"go.mondoo.com/mql/v13/utils/syncx"
)

func loadTemplate(path string) (*mqlCloudformationTemplate, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	conn, err := connection.NewCloudformationConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					"path": path,
				},
			},
		},
	}, nil)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	obj, err := NewResource(
		runtime,
		"cloudformation.template",
		map[string]*llx.RawData{},
	)
	if err != nil {
		return nil, err
	}

	tpl, ok := obj.(*mqlCloudformationTemplate)
	if !ok {
		return nil, errors.New("unexpected type")
	}
	return tpl, nil
}

func TestCloudformationResources(t *testing.T) {
	t.Run("cloudformation json template", func(t *testing.T) {
		path := "../testdata/cloudformation.json"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		assert.Equal(t, "2010-09-09", tpl.Version.Data)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 3, len(res.Data))

		params := tpl.GetParameters()
		require.NoError(t, params.Error)
		assert.Equal(t, 1, len(params.Data))
	})

	t.Run("cloudformation yaml template", func(t *testing.T) {
		path := "../testdata/cloudformation.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		assert.Equal(t, "2010-09-09", tpl.Version.Data)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 3, len(res.Data))

		params := tpl.GetParameters()
		require.NoError(t, params.Error)
		assert.Equal(t, 1, len(params.Data))
	})

	t.Run("cloudformation conditions", func(t *testing.T) {
		path := "../testdata/conditions.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetConditions()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["CreateProdResources"]
		assert.NotNil(t, val)
	})

	t.Run("sam globals", func(t *testing.T) {
		path := "../testdata/globals.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetGlobals()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["Function"]
		assert.NotNil(t, val)

		entries := val.(map[string]any)
		assert.Equal(t, "nodejs12.x", entries["Runtime"])
	})

	t.Run("cloudformation mappings", func(t *testing.T) {
		path := "../testdata/mappings.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetMappings()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["RegionMap"]
		assert.NotNil(t, val)

		entries := val.(map[string]any)
		entry := entries["us-east-1"].(map[string]any)
		assert.Equal(t, "ami-0ff8a91507f77f867", entry["HVM64"])
	})

	t.Run("cloudformation outputs", func(t *testing.T) {
		path := "../testdata/outputs.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetOutputs()
		require.NoError(t, res.Error)
		assert.Equal(t, 2, len(res.Data))

		found := false
		for i := range res.Data {
			assert.NotNil(t, res.Data[i])
			output := res.Data[i].(*mqlCloudformationOutput)
			if output.Name.Data == "BackupLoadBalancerDNSName" {
				props := output.Properties
				assert.Equal(t, "The DNSName of the backup load balancer", props.Data["Description"])
				found = true
			}
		}
		assert.Equal(t, true, found)
	})

	t.Run("cloudformation parameters", func(t *testing.T) {
		path := "../testdata/parameters.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetParameters()
		require.NoError(t, res.Error)
		assert.Equal(t, 2, len(res.Data))
	})

	t.Run("cloudformation resources", func(t *testing.T) {
		path := "../testdata/resources.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 3, len(res.Data))

		count := 0
		for i := range res.Data {
			assert.NotNil(t, res.Data[i])
			resource := res.Data[i].(*mqlCloudformationResource)
			if resource.Name.Data == "MyInstance" {
				props := resource.Properties
				assert.Equal(t, "ami-0ff8a91507f77f867", props.Data["ImageId"])
				count++
			}

			if resource.Name.Data == "HTTPlistener" {
				props := resource.Properties
				assert.Equal(t, float64(80), props.Data["Port"])
				count++
			}
		}
		assert.Equal(t, 2, count)
	})

	t.Run("cloudformation resources-custom", func(t *testing.T) {
		path := "../testdata/resources-custom.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
	})

	t.Run("cloudformation dependsOn", func(t *testing.T) {
		path := "../testdata/dependson.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetResources()
		require.NoError(t, res.Error)
		assert.Equal(t, 4, len(res.Data))

		for i := range res.Data {
			resource := res.Data[i].(*mqlCloudformationResource)
			switch resource.Name.Data {
			case "MySubnet":
				// single string DependsOn
				assert.Equal(t, []any{"MyVPC"}, resource.DependsOn.Data)
			case "MyInstance":
				// list DependsOn
				assert.Equal(t, []any{"MyVPC", "MySubnet"}, resource.DependsOn.Data)
			case "MyVPC", "MyQueue":
				// no DependsOn
				assert.Empty(t, resource.DependsOn.Data)
			}
		}
	})

	t.Run("cloudformation rules", func(t *testing.T) {
		path := "../testdata/rules.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		res := tpl.GetRules()
		require.NoError(t, res.Error)
		assert.Equal(t, 1, len(res.Data))
		val := res.Data["ProdInstanceType"]
		assert.NotNil(t, val)
	})

	t.Run("cloudformation transform", func(t *testing.T) {
		path := "../testdata/transform.yaml"
		tpl, err := loadTemplate(path)
		require.NoError(t, err)

		assert.Equal(t, []any{"MyMacro", "AWS::Serverless"}, tpl.Transform.Data)
	})
}
