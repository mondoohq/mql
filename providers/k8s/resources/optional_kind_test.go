// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/connection/shared/distro"
	sharedres "go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	"go.mondoo.com/mql/utils/syncx"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/version"
)

// stubConnection answers every Resources call with a fixed error, so the tests
// below can drive the "the cluster does not serve this kind" branch without a
// cluster.
type stubConnection struct {
	err error
}

func (c *stubConnection) ID() uint32       { return 0 }
func (c *stubConnection) ParentID() uint32 { return 0 }
func (c *stubConnection) Name() string     { return "stub" }
func (c *stubConnection) Runtime() string  { return "k8s-cluster" }
func (c *stubConnection) Resources(kind, name, namespace string) (*shared.ResourceResult, error) {
	return nil, c.err
}
func (c *stubConnection) ServerVersion() *version.Info { return &version.Info{} }
func (c *stubConnection) Distro() *distro.Result       { return &distro.Result{Name: distro.Unknown} }
func (c *stubConnection) SupportedResourceTypes() (*sharedres.ApiResourceIndex, error) {
	return sharedres.NewApiResourceIndex(), nil
}
func (c *stubConnection) Platform() *inventory.Platform { return &inventory.Platform{} }
func (c *stubConnection) Asset() *inventory.Asset       { return &inventory.Asset{} }
func (c *stubConnection) AssetId() (string, error)      { return "stub", nil }
func (c *stubConnection) BasePlatformId() (string, error) {
	return "stub", nil
}
func (c *stubConnection) AdmissionReviews() ([]admissionv1.AdmissionReview, error) {
	return nil, nil
}
func (c *stubConnection) Namespace(name string) (*corev1.Namespace, error) { return nil, nil }
func (c *stubConnection) Namespaces() ([]corev1.Namespace, error)          { return nil, nil }
func (c *stubConnection) InventoryConfig() *inventory.Config               { return &inventory.Config{} }

func stubRuntime(err error) *plugin.Runtime {
	rt := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	rt.Connection = &stubConnection{err: err}
	return rt
}

// A kind the cluster never installed (Gateway API and the other CRD-backed
// APIs are the common case) is a cluster with none of those objects, not a
// failed scan. Returning an error here fails every policy that touches the
// resource on the majority of clusters.
func TestOptionalKindDegradesToEmpty(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "the CRD was never installed",
			err:  errors.New(`could not find api kind "gateways.v1.gateway.networking.k8s.io"`),
		},
		{
			name: "RBAC hides the kind",
			err: apierrors.NewForbidden(
				schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"},
				"", errors.New("denied")),
		},
		{
			name: "the object itself is reported missing",
			err: apierrors.NewNotFound(
				schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gateways"}, ""),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := k8sOptionalResourceToMql(stubRuntime(test.err), "gateways.v1.gateway.networking.k8s.io", nil)
			require.NoError(t, err)
			assert.Equal(t, []any{}, out)
		})
	}
}

// Anything else is a real failure and has to keep propagating. Swallowing a
// throttled or half-finished list would report "no such objects" for a cluster
// that has them.
func TestOptionalKindPropagatesRealErrors(t *testing.T) {
	wanted := errors.New("etcdserver: request timed out")
	_, err := k8sOptionalResourceToMql(stubRuntime(wanted), "gateways.v1.gateway.networking.k8s.io", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, wanted)
}
