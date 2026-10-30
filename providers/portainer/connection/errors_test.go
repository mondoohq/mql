// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/go-openapi/runtime"
	"github.com/portainer/client-api-go/v2/pkg/client/edge_jobs"
	"github.com/portainer/client-api-go/v2/pkg/client/users"
	"github.com/stretchr/testify/assert"
)

func TestStatusCode(t *testing.T) {
	t.Run("reads the code off a generated response error", func(t *testing.T) {
		code, ok := StatusCode(&edge_jobs.EdgeJobListServiceUnavailable{})
		assert.True(t, ok)
		assert.Equal(t, 503, code)
	})

	t.Run("reads through a wrapped error", func(t *testing.T) {
		wrapped := fmt.Errorf("listing Edge jobs: %w", &edge_jobs.EdgeJobListServiceUnavailable{})
		code, ok := StatusCode(wrapped)
		assert.True(t, ok)
		assert.Equal(t, 503, code)
	})

	t.Run("reads an undeclared response reported as a runtime error", func(t *testing.T) {
		// Most 403s on this API are not declared by the operation, so the
		// generated client reports them as a runtime.APIError instead of a
		// typed response. Missing this shape makes a refusal look like an
		// unclassifiable failure.
		code, ok := StatusCode(runtime.NewAPIError("RegistryList", nil, 403))
		assert.True(t, ok)
		assert.Equal(t, 403, code)
	})

	t.Run("a transport error carries no code", func(t *testing.T) {
		// A network failure must not be classified, or a blip would degrade a
		// field to null and let an audit pass on data that was never read.
		_, ok := StatusCode(&net.OpError{Op: "dial", Err: errors.New("connection refused")})
		assert.False(t, ok)

		_, ok = StatusCode(errors.New("unexpected EOF"))
		assert.False(t, ok)
	})

	t.Run("nil", func(t *testing.T) {
		_, ok := StatusCode(nil)
		assert.False(t, ok)
	})
}

func TestIsFeatureDisabled(t *testing.T) {
	// Portainer answers 503 on the Edge endpoints when Edge Compute is off.
	assert.True(t, IsFeatureDisabled(&edge_jobs.EdgeJobListServiceUnavailable{}))

	// Anything else is a real failure and must be reported as one.
	assert.False(t, IsFeatureDisabled(&edge_jobs.EdgeJobListInternalServerError{}))
	assert.False(t, IsFeatureDisabled(&edge_jobs.EdgeJobListBadRequest{}))
	assert.False(t, IsFeatureDisabled(&net.OpError{Op: "dial", Err: errors.New("connection refused")}))
	assert.False(t, IsFeatureDisabled(errors.New("i/o timeout")))
	assert.True(t, IsFeatureDisabled(runtime.NewAPIError("EdgeJobList", nil, 503)))
	assert.False(t, IsFeatureDisabled(nil))
}

func TestIsForbidden(t *testing.T) {
	assert.True(t, IsForbidden(&users.UserGetAPIKeysForbidden{}))
	assert.True(t, IsForbidden(fmt.Errorf("listing keys: %w", &users.UserGetAPIKeysForbidden{})))
	assert.True(t, IsForbidden(runtime.NewAPIError("RegistryList", nil, 403)))
	assert.True(t, IsForbidden(runtime.NewAPIError("RoleList", nil, 401)))

	assert.False(t, IsForbidden(runtime.NewAPIError("RegistryList", nil, 500)))
	assert.False(t, IsForbidden(&users.UserGetAPIKeysNotFound{}))
	assert.False(t, IsForbidden(&users.UserGetAPIKeysInternalServerError{}))
	assert.False(t, IsForbidden(&net.OpError{Op: "dial", Err: errors.New("connection refused")}))
	assert.False(t, IsForbidden(nil))
}

func TestRegistryType(t *testing.T) {
	for code, want := range map[int64]string{
		1: "quay", 2: "azure", 3: "custom", 4: "gitlab",
		5: "proget", 6: "dockerhub", 7: "ecr",
		0: "unknown", 8: "unknown", 99: "unknown",
	} {
		assert.Equal(t, want, RegistryType(code), code)
	}
}

func TestStackType(t *testing.T) {
	for code, want := range map[int64]string{
		1: "swarm", 2: "compose", 3: "kubernetes", 0: "unknown", 4: "unknown",
	} {
		assert.Equal(t, want, StackType(code), code)
	}
}

func TestStackStatus(t *testing.T) {
	for code, want := range map[int64]string{
		1: "active", 2: "inactive", 0: "unknown", 3: "unknown",
	} {
		assert.Equal(t, want, StackStatus(code), code)
	}
}

func TestWebhookType(t *testing.T) {
	for code, want := range map[int64]string{
		1: "service", 2: "container", 0: "unknown", 3: "unknown",
	} {
		assert.Equal(t, want, WebhookType(code), code)
	}
}
