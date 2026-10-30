// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func contextConfigTestRepo() *mqlGithubRepository {
	return &mqlGithubRepository{
		Name:              plugin.TValue[string]{Data: "infra", State: plugin.StateIsSet},
		DefaultBranchName: plugin.TValue[string]{Data: "main", State: plugin.StateIsSet},
		CloneUrl:          plugin.TValue[string]{Data: "https://github.com/acme/infra.git", State: plugin.StateIsSet},
	}
}

func TestRepoContextConfig(t *testing.T) {
	config := `
private_key: should-not-travel
exceptions:
  - checks: [mondoo-terraform-aws-security-s3-bucket-logging]
    action: risk-accepted
    justification: central logging
`
	contents := func(fileType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/v3/repos/acme/infra/contents/mondoo.yml" || r.URL.Query().Get("ref") != "main" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"type":     fileType,
				"encoding": "base64",
				"size":     len(config),
				"content":  base64.StdEncoding.EncodeToString([]byte(config)),
				"path":     "mondoo.yml",
			})
		}
	}

	t.Run("file at root", func(t *testing.T) {
		srv := httptest.NewServer(contents("file"))
		defer srv.Close()

		cfg := repoContextConfig(context.Background(), newTestGithubClient(t, srv), "acme", contextConfigTestRepo())
		require.NotNil(t, cfg)
		assert.Equal(t, "github", cfg.Origin.Provider)
		assert.Equal(t, "github.com/acme/infra", cfg.Origin.Repository)
		assert.Equal(t, "main", cfg.Origin.Ref)
		assert.Equal(t, "mondoo.yml", cfg.Origin.Path)
		assert.Equal(t, "", cfg.AssetPath)
		assert.Contains(t, string(cfg.Content), "central logging")
		assert.NotContains(t, string(cfg.Content), "should-not-travel")

		child := withAssetPath(cfg, ".")
		assert.Equal(t, ".", child.AssetPath)
		assert.Equal(t, "", cfg.AssetPath, "the repository asset's config is not changed")
	})

	t.Run("symlink is not followed", func(t *testing.T) {
		srv := httptest.NewServer(contents("symlink"))
		defer srv.Close()
		assert.Nil(t, repoContextConfig(context.Background(), newTestGithubClient(t, srv), "acme", contextConfigTestRepo()))
	})

	t.Run("no file", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		defer srv.Close()
		assert.Nil(t, repoContextConfig(context.Background(), newTestGithubClient(t, srv), "acme", contextConfigTestRepo()))
	})
}
