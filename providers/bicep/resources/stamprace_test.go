// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/bicep/connection"
)

// syncResources is a concurrency-safe resource cache, so a `-race` report from
// the test below is attributable to the provider's Internal-field stamps and
// not to the test harness's own map.
type syncResources struct {
	mu sync.Mutex
	m  map[string]plugin.Resource
}

func (r *syncResources) Get(key string) (plugin.Resource, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.m[key]
	return v, ok
}

func (r *syncResources) Set(key string, value plugin.Resource) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[key] = value
}

const raceFixture = `import { sku } from './shared.bicep'

@description('Where to deploy')
param location string = 'eastus'

var storageName = 'st${uniqueString(location)}'

type policy = {
  name: string
  enabled: bool
}

resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageName
  location: location
  tags: {
    env: 'prod'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }

  resource blobSvc 'blobServices@2023-01-01' = {
    name: 'default'
    properties: {
      deleteRetentionPolicy: {
        enabled: true
      }
    }
  }
}

module net './shared.bicep' = {
  name: 'net'
  params: {
    location: location
  }
}

output saId string = sa.id
`

const raceShared = `@export()
type sku = 'Standard_LRS'

@export()
func buildName(prefix string) string => '${prefix}-x'

param location string = 'eastus'
`

// F5: the generated CreateResource RETURNS THE CACHED INSTANCE when the __id
// already exists, and every creator then writes its Internal fields into that
// shared instance unconditionally. The same __id is reached concurrently from
// bicep.resources, bicep.files.resources, and the symbol resolver, so the
// stamps race with readers of the same fields.
//
// This test only fails under `-race`; it is the reproducer for the 39 reports
// the audit recorded.
func TestConcurrentMaterializationIsRaceFree(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.bicep"), []byte(raceFixture), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "shared.bicep"), []byte(raceShared), 0o644))

	asset := &inventory.Asset{
		Connections: []*inventory.Config{
			{Type: "bicep", Options: map[string]string{"path": dir}},
		},
	}
	conn, err := connection.NewBicepConnection(0, asset, asset.Connections[0])
	require.NoError(t, err)
	runtime := &plugin.Runtime{
		Connection: conn,
		Resources:  &syncResources{m: map[string]plugin.Resource{}},
	}

	root, err := CreateResource(runtime, "bicep", map[string]*llx.RawData{})
	require.NoError(t, err)
	bicepRes := root.(*mqlBicep)

	// Every worker walks the same declarations, so each __id is created once
	// and then re-fetched from the cache by the others while they stamp it.
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers*8)
	for range workers {
		wg.Go(func() {

			flat, err := bicepRes.resources()
			if err != nil {
				errs <- err
				return
			}
			for _, r := range flat {
				res := r.(*mqlBicepResource)
				if _, err := res.resources(); err != nil {
					errs <- err
				}
				if _, err := res.propertyExpressions(); err != nil {
					errs <- err
				}
				if _, err := res.nameTree(); err != nil {
					errs <- err
				}
			}

			files, err := bicepRes.files()
			if err != nil {
				errs <- err
				return
			}
			for _, f := range files {
				mqlF := f.(*mqlBicepFile)
				if _, err := mqlF.resources(); err != nil {
					errs <- err
				}
				if _, err := mqlF.parameters(); err != nil {
					errs <- err
				}
				if _, err := mqlF.variables(); err != nil {
					errs <- err
				}
				if _, err := mqlF.types(); err != nil {
					errs <- err
				}
				imps, err := mqlF.imports()
				if err != nil {
					errs <- err
					continue
				}
				for _, imp := range imps {
					// targetFile() reads the import's stamped owningFilePath.
					// resolvedTypes() is deliberately NOT called here: it goes
					// through the generated GetTargetFile getter, and
					// plugin.GetOrCompute writes the shared TValue field
					// unsynchronized. That is SDK-wide behavior in every
					// provider's generated getters, not an Internal-field
					// stamp, and the executor computes a given field on a
					// given resource once rather than from several goroutines.
					if _, err := imp.(*mqlBicepImport).targetFile(); err != nil {
						errs <- err
					}
				}
				mods, err := mqlF.modules()
				if err != nil {
					errs <- err
					continue
				}
				for _, m := range mods {
					if _, err := m.(*mqlBicepModule).paramExpressions(); err != nil {
						errs <- err
					}
				}
				outs, err := mqlF.outputs()
				if err != nil {
					errs <- err
					continue
				}
				for _, o := range outs {
					if _, err := o.(*mqlBicepOutput).expressionTree(); err != nil {
						errs <- err
					}
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
}
