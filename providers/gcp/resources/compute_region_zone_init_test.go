// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/compute/v1"
)

func regionZoneScopes() []string {
	return []string{cloudresourcemanager.CloudPlatformReadOnlyScope, compute.ComputeReadonlyScope}
}

// TestRegionInitDoesNotLeakProjectIdIntoArgs pins the two ways a region or zone
// lookup can end.
//
// projectId scopes the lookup but is not a field on either resource. The init
// used to write it into args and then, on any path that returned without a
// resource, hand those args to SetAllData -- which rejects an unknown field. A
// bare `gcp.project.computeService.region` therefore failed with
//
//	[gcp] cannot set 'projectId' in resource
//	'gcp.project.computeService.region', field not found
//
// which names an internal mechanism rather than the missing argument. Dropping
// projectId from args without also reporting the missing name only traded that
// for an empty husk whose every field is unset, which surfaces as "encountered
// a primitive with no type information" with nothing naming the cause. Both
// were verified against a live project.
func TestRegionInitDoesNotLeakProjectIdIntoArgs(t *testing.T) {
	t.Run("region without a name says so", func(t *testing.T) {
		env := setupTestEnv(t, regionZoneScopes())
		_, err := NewResource(env.Runtime, "gcp.project.computeService.region", map[string]*llx.RawData{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `requires a "name" argument`)
		assert.NotContains(t, err.Error(), "field not found",
			"the caller should learn which argument is missing, not that an internal setter rejected a key")
	})

	t.Run("zone without a name says so", func(t *testing.T) {
		env := setupTestEnv(t, regionZoneScopes())
		_, err := NewResource(env.Runtime, "gcp.project.computeService.zone", map[string]*llx.RawData{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `requires a "name" argument`)
		assert.NotContains(t, err.Error(), "field not found")
	})

	t.Run("region with a name and a projectId resolves", func(t *testing.T) {
		env := setupTestEnv(t, regionZoneScopes())
		env.Mux.HandleFunc("/compute/v1/projects/"+testProjectId+"/regions/us-central1",
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"id": "1000", "name": "us-central1", "status": "UP", "description": "us-central1"}`)
			})

		res, err := NewResource(env.Runtime, "gcp.project.computeService.region", map[string]*llx.RawData{
			"name":      llx.StringData("us-central1"),
			"projectId": llx.StringData(testProjectId),
		})
		require.NoError(t, err)
		region := res.(*mqlGcpProjectComputeServiceRegion)
		assert.Equal(t, "us-central1", region.Name.Data)
		assert.Equal(t, "UP", region.Status.Data)
	})

	t.Run("zone with a name and a projectId resolves", func(t *testing.T) {
		env := setupTestEnv(t, regionZoneScopes())
		env.Mux.HandleFunc("/compute/v1/projects/"+testProjectId+"/zones/us-central1-a",
			func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, `{"id": "2000", "name": "us-central1-a", "status": "UP", "description": "us-central1-a"}`)
			})

		res, err := NewResource(env.Runtime, "gcp.project.computeService.zone", map[string]*llx.RawData{
			"name":      llx.StringData("us-central1-a"),
			"projectId": llx.StringData(testProjectId),
		})
		require.NoError(t, err)
		zone := res.(*mqlGcpProjectComputeServiceZone)
		assert.Equal(t, "us-central1-a", zone.Name.Data)
		assert.Equal(t, "UP", zone.Status.Data)
	})
}

// huskProneInits are the per-object inits that resolve one named object, each
// with the argument that selects it. Keeping them in one table is what stops
// the guard from being fixed in the files someone happened to look at: the
// resourcePath-selected resources below were missed exactly that way.
//
// The *Service inits are deliberately absent. A bare gcp.project.<svc> is a
// legitimate empty state whose fields come from the connection rather than a
// lookup, so returning args there is correct.
var huskProneInits = map[string]string{
	"gcp.project.vertexaiService.customJob":                           "name",
	"gcp.project.vertexaiService.endpoint":                            "name",
	"gcp.project.vertexaiService.pipelineJob":                         "name",
	"gcp.project.vertexaiService.notebookRuntimeTemplate":             "name",
	"gcp.project.vertexaiService.schedule":                            "name",
	"gcp.project.memorystoreService.instance":                         "name",
	"gcp.project.memorystoreService.backupCollection":                 "name",
	"gcp.project.memcacheService.instance":                            "name",
	"gcp.project.modelArmorService.template":                          "name",
	"gcp.project.spannerService.instanceConfig":                       "name",
	"gcp.project.datastreamService.connectionProfile":                 "name",
	"gcp.project.datastreamService.privateConnection":                 "name",
	"gcp.project.storageService.bucket":                               "name",
	"gcp.project.pubsubService.schema":                                "name",
	"gcp.service":                                                     "name",
	"gcp.project.certificateManagerService.certificate":               "resourcePath",
	"gcp.project.certificateManagerService.dnsAuthorization":          "resourcePath",
	"gcp.project.certificateManagerService.certificateIssuanceConfig": "resourcePath",
	"gcp.project.kmsService.keyring.cryptokey":                        "resourcePath",
	"gcp.project.documentaiService.processor.version":                 "name",
}

// TestInitsSurviveANullSelectorArgument pins the arg-reading guards.
//
// An init that reads args["name"].Value.(string) without the comma-ok form
// panics when the value is null rather than a string, and a panic in a provider
// takes down the whole scan rather than one field. A null selector must be
// reported, not resolved to a husk.
func TestInitsSurviveANullSelectorArgument(t *testing.T) {
	for resource, selector := range huskProneInits {
		t.Run(resource, func(t *testing.T) {
			env := setupTestEnv(t, regionZoneScopes(), projectScopes())
			var err error
			assert.NotPanics(t, func() {
				_, err = NewResource(env.Runtime, resource, map[string]*llx.RawData{
					selector: {Type: types.String},
				})
			})
			assert.Error(t, err, "a null %s must be reported, not resolved to a husk", selector)
		})
	}
}

// TestInitsRejectAnUnusableSelector pins the same contract for the two other
// ways a selector can be unusable: absent entirely, and present but empty.
//
// Both used to return (args, nil, nil), which the runtime turns into a resource
// with every field UNSET -- not null, unset. Reading one then surfaces
// client-side as
//
//	provider returned no data and no error for a field; the field was never
//	set on the resource (provider bug)
//	llx: encountered a primitive with no type information, coercing to null
//
// with nothing naming the cause, and the husk carries an empty __id so every
// such resource also aliases in the runtime cache. Reproduced live against a
// real project before the change for vertexai customJob, memorystore instance,
// storage bucket, datastream connectionProfile, spanner instanceConfig and
// gcp.service.
//
// Every internal caller of these resources already guards its selector against
// "" before resolving, so erroring here changes nothing for them; it only makes
// a direct query say what is missing.
func TestInitsRejectAnUnusableSelector(t *testing.T) {
	for resource, selector := range huskProneInits {
		for _, tc := range []struct {
			title string
			args  map[string]*llx.RawData
		}{
			{"no selector argument", map[string]*llx.RawData{"projectId": llx.StringData(testProjectId)}},
			{"empty selector argument", map[string]*llx.RawData{selector: llx.StringData("")}},
			{"nil selector argument", map[string]*llx.RawData{selector: nil}},
			{"wrong-typed selector argument", map[string]*llx.RawData{selector: llx.IntData(7)}},
		} {
			t.Run(resource+"/"+tc.title, func(t *testing.T) {
				env := setupTestEnv(t, regionZoneScopes(), projectScopes())
				_, err := NewResource(env.Runtime, resource, tc.args)
				require.Error(t, err)
				assert.Contains(t, err.Error(), selector,
					"the error should name the argument that is missing")
			})
		}
	}
}

// TestGcpServiceRejectsAnUnusableProjectId covers the one argument in this set
// that selects nothing but is still dereferenced.
//
// gcp.service reads args["projectId"] on its own, outside the selector table
// above, and only guarded it against being absent. A caller that supplies the
// key with a null or non-string value got past that guard and into a bare type
// assertion, which panics the provider and takes the whole scan with it. Two
// arguments also stay under the init's len(args) > 2 fast path, so this is
// reachable from a plain query rather than only from an internal caller.
func TestGcpServiceRejectsAnUnusableProjectId(t *testing.T) {
	for _, tc := range []struct {
		title     string
		projectId *llx.RawData
	}{
		{"null projectId", &llx.RawData{Type: types.String}},
		{"wrong-typed projectId", llx.IntData(7)},
		{"empty projectId", llx.StringData("")},
	} {
		t.Run(tc.title, func(t *testing.T) {
			env := setupTestEnv(t, regionZoneScopes(), projectScopes())
			var err error
			assert.NotPanics(t, func() {
				_, err = NewResource(env.Runtime, "gcp.service", map[string]*llx.RawData{
					"name":      llx.StringData("compute.googleapis.com"),
					"projectId": tc.projectId,
				})
			})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "projectId")
		})
	}
}
