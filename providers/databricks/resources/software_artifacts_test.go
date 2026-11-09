// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	sdktime "github.com/databricks/databricks-sdk-go/common/types/time"
	"github.com/databricks/databricks-sdk-go/service/softwareartifacts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic throughout: no workspace available to this change had a software
// artifact registered. Names follow the resource-name forms the SDK documents.

func TestSoftwareArtifactFields(t *testing.T) {
	created := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)

	t.Run("a populated artifact maps every field", func(t *testing.T) {
		got := plainValues(softwareArtifactFields(softwareartifacts.SoftwareArtifact{
			Name:       "software-artifacts/main.apps.agent",
			Owner:      "platform-admins",
			CreatedBy:  "alice@example.com",
			CreateTime: sdktime.New(created),
			UpdatedBy:  "ci-sp",
		}))

		assert.Equal(t, "databricks.softwareArtifact/software-artifacts/main.apps.agent", got["__id"])
		assert.Equal(t, "software-artifacts/main.apps.agent", got["name"])
		assert.Equal(t, "main.apps.agent", got["fullName"])
		assert.Equal(t, "platform-admins", got["owner"])
		assert.Equal(t, "alice@example.com", got["createdBy"])
		assert.Equal(t, "ci-sp", got["updatedBy"])
		gotCreated, ok := got["createTime"].(*time.Time)
		require.True(t, ok)
		assert.True(t, created.Equal(*gotCreated))
		assert.Nil(t, got["updateTime"], "an absent timestamp is null, not the year 1")
	})

	t.Run("full name is null when the name lacks the documented prefix", func(t *testing.T) {
		assert.Nil(t, plainValues(softwareArtifactFields(softwareartifacts.SoftwareArtifact{Name: "main.apps.agent"}))["fullName"])
		assert.Nil(t, plainValues(softwareArtifactFields(softwareartifacts.SoftwareArtifact{Name: "software-artifacts/"}))["fullName"])
		assert.Nil(t, plainValues(softwareArtifactFields(softwareartifacts.SoftwareArtifact{
			Name: "software-artifacts/main.apps.agent/versions/1",
		}))["fullName"], "a version name is not an artifact name")
	})
}

func TestSoftwareArtifactVersionFields(t *testing.T) {
	t.Run("a populated version maps every field", func(t *testing.T) {
		got := plainValues(softwareArtifactVersionFields(softwareartifacts.SoftwareArtifactVersion{
			Name:                     "software-artifacts/main.apps.agent/versions/3",
			Digest:                   "sha256:0f1e",
			Tags:                     []string{"latest", "v1.2.3"},
			ImageAccelerationDetails: &softwareartifacts.ImageAccelerationDetail{Status: softwareartifacts.ImageAccelerationDetailStatusSuccess},
			CreatedBy:                "ci-sp",
		}))

		assert.Equal(t, "databricks.softwareArtifact.version/software-artifacts/main.apps.agent/versions/3", got["__id"])
		assert.Equal(t, "3", got["version"])
		assert.Equal(t, "sha256:0f1e", got["digest"])
		assert.Equal(t, []any{"latest", "v1.2.3"}, got["tags"])
		assert.Equal(t, "SUCCESS", got["imageAccelerationStatus"])
		assert.Equal(t, "ci-sp", got["createdBy"])
		assert.Nil(t, got["createTime"])
	})

	t.Run("absent acceleration details and tags", func(t *testing.T) {
		got := plainValues(softwareArtifactVersionFields(softwareartifacts.SoftwareArtifactVersion{
			Name: "software-artifacts/main.apps.agent/versions/1",
		}))
		assert.Nil(t, got["imageAccelerationStatus"])
		assert.Equal(t, []any{}, got["tags"])

		empty := plainValues(softwareArtifactVersionFields(softwareartifacts.SoftwareArtifactVersion{
			Name:                     "software-artifacts/main.apps.agent/versions/2",
			ImageAccelerationDetails: &softwareartifacts.ImageAccelerationDetail{},
		}))
		assert.Nil(t, empty["imageAccelerationStatus"], "an empty status is null, not an empty string")
	})

	t.Run("the same version name under two artifacts keeps distinct ids", func(t *testing.T) {
		a := plainValues(softwareArtifactVersionFields(softwareartifacts.SoftwareArtifactVersion{Name: "software-artifacts/main.apps.agent/versions/1"}))
		b := plainValues(softwareArtifactVersionFields(softwareartifacts.SoftwareArtifactVersion{Name: "software-artifacts/main.apps.worker/versions/1"}))
		assert.NotEqual(t, a["__id"], b["__id"])
		assert.Equal(t, a["version"], b["version"])
	})

	t.Run("version is null when the name carries no version segment", func(t *testing.T) {
		assert.Nil(t, plainValues(softwareArtifactVersionFields(softwareartifacts.SoftwareArtifactVersion{Name: "software-artifacts/main.apps.agent"}))["version"])
		assert.Nil(t, plainValues(softwareArtifactVersionFields(softwareartifacts.SoftwareArtifactVersion{Name: "software-artifacts/main.apps.agent/versions/"}))["version"])
	})
}

func TestSoftwareArtifactSchemaParent(t *testing.T) {
	assert.Equal(t, "schemas/main.apps", softwareArtifactSchemaParent("main", "apps", "main.apps"))
	assert.Equal(t, "schemas/main.apps", softwareArtifactSchemaParent("main", "apps", ""))
}

const softwareArtifactsPath = "/api/2.1/unity-catalog/software-artifacts"

func listArtifacts(t *testing.T, handler http.HandlerFunc) ([]softwareartifacts.SoftwareArtifact, error) {
	t.Helper()
	ws := testWorkspaceClient(t, softwareArtifactsPath, handler)
	ctx := context.Background()
	it := ws.SoftwareArtifacts.ListSoftwareArtifacts(ctx, softwareartifacts.ListSoftwareArtifactsRequest{Parent: "schemas/main.apps"})
	return collectUniqueByName(ctx, it, func(a softwareartifacts.SoftwareArtifact) string { return a.Name }, "software artifact")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestCollectUniqueByName(t *testing.T) {
	t.Run("walks every page, including an empty one, and stops when the token is absent", func(t *testing.T) {
		var calls int
		got, err := listArtifacts(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			if p := r.URL.Query().Get("parent"); p != "schemas/main.apps" {
				t.Errorf("parent = %q, want schemas/main.apps", p)
			}
			resp := softwareartifacts.ListSoftwareArtifactsResponse{}
			switch tok := r.URL.Query().Get("page_token"); tok {
			case "":
				resp.SoftwareArtifacts = []softwareartifacts.SoftwareArtifact{{Name: "software-artifacts/main.apps.a"}}
				resp.NextPageToken = "p2"
			case "p2":
				// An empty page that still carries a token is not the end.
				resp.NextPageToken = "p3"
			case "p3":
				resp.SoftwareArtifacts = []softwareartifacts.SoftwareArtifact{{Name: "software-artifacts/main.apps.b"}}
			default:
				t.Errorf("unexpected page token %q", tok)
			}
			writeJSON(w, resp)
		})
		require.NoError(t, err)
		assert.Equal(t, 3, calls)
		require.Len(t, got, 2)
		assert.Equal(t, "software-artifacts/main.apps.a", got[0].Name)
		assert.Equal(t, "software-artifacts/main.apps.b", got[1].Name)
	})

	t.Run("a cursor that never advances is reported after one repeated page", func(t *testing.T) {
		var calls int
		_, err := listArtifacts(t, func(w http.ResponseWriter, r *http.Request) {
			calls++
			writeJSON(w, softwareartifacts.ListSoftwareArtifactsResponse{
				SoftwareArtifacts: []softwareartifacts.SoftwareArtifact{{Name: "software-artifacts/main.apps.a"}},
				NextPageToken:     "always-the-same",
			})
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not advancing")
		assert.Equal(t, 2, calls)
	})

	t.Run("an empty schema is an empty list", func(t *testing.T) {
		got, err := listArtifacts(t, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, softwareartifacts.ListSoftwareArtifactsResponse{})
		})
		require.NoError(t, err)
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("a refusal surfaces as an api error the classifiers recognize", func(t *testing.T) {
		_, err := listArtifacts(t, func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, `{"error_code":"PERMISSION_DENIED","message":"no USE SCHEMA"}`, http.StatusForbidden)
		})
		require.Error(t, err)
		assert.True(t, isDatabricksUnreadable(err))
	})

	t.Run("versions are listed under the artifact's resource name", func(t *testing.T) {
		const versionsPath = softwareArtifactsPath + "/main.apps.agent/versions"
		ws := testWorkspaceClient(t, versionsPath, func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, softwareartifacts.ListSoftwareArtifactVersionsResponse{
				SoftwareArtifactVersions: []softwareartifacts.SoftwareArtifactVersion{
					{Name: "software-artifacts/main.apps.agent/versions/1", Digest: "sha256:aa"},
				},
			})
		})
		ctx := context.Background()
		it := ws.SoftwareArtifacts.ListSoftwareArtifactVersions(ctx, softwareartifacts.ListSoftwareArtifactVersionsRequest{
			Parent: "software-artifacts/main.apps.agent",
		})
		got, err := collectUniqueByName(ctx, it, func(v softwareartifacts.SoftwareArtifactVersion) string { return v.Name }, "software artifact version")
		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.True(t, strings.HasSuffix(got[0].Name, "/versions/1"))
		assert.Equal(t, "sha256:aa", got[0].Digest)
	})
}
