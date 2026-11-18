// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/edr"
	"go.mondoo.com/mql/providers/os/resources/rmm"
	"go.mondoo.com/mql/utils/syncx"
)

func newTestRmm(t *testing.T, platform *inventory.Platform, data *mock.TomlData) *mqlRmm {
	t.Helper()
	if data == nil {
		data = &mock.TomlData{}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: platform}, mock.WithData(data))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}
	raw, err := CreateResource(runtime, "rmm", nil)
	require.NoError(t, err)
	return raw.(*mqlRmm)
}

func TestRmmOnAPlatformWithNoCatalog(t *testing.T) {
	// Synthetic: FreeBSD has no catalog entries, so nothing is read and
	// nothing is reported.
	r := newTestRmm(t, &inventory.Platform{Name: "freebsd", Family: []string{"bsd", "unix", "os"}}, nil)

	products, err := r.products()
	require.NoError(t, err)
	assert.Empty(t, products)

	installed, err := r.installed()
	require.NoError(t, err)
	assert.False(t, installed)

	healthy, err := r.healthy()
	require.NoError(t, err)
	assert.False(t, healthy, "an asset with no agent must not read as healthy")
}

func TestRmmRecognizesAnAgentByItsInstallPath(t *testing.T) {
	// Synthetic: the opsi Linux agent's install directory with no service
	// manager answering, which is what a filesystem-only scan sees. Packages,
	// services and processes all fail to read on this mock, and the path
	// alone still proves the agent is installed.
	r := newTestRmm(t, &inventory.Platform{Name: "ubuntu", Family: []string{"debian", "linux", "unix", "os"}}, &mock.TomlData{
		Files: map[string]*mock.MockFileData{
			"/usr/lib/opsi-client-agent": {
				Path:     "/usr/lib/opsi-client-agent",
				StatData: mock.FileInfo{Mode: os.ModeDir | 0o755, IsDir: true},
			},
		},
	})

	products, err := r.products()
	require.NoError(t, err)
	require.Len(t, products, 1)

	p := products[0].(*mqlRmmProduct)
	assert.Equal(t, "opsi", p.Id.Data)
	assert.Equal(t, "clientManagement", p.Category.Data)
	assert.True(t, p.Installed.Data)
	assert.Equal(t, []any{"path"}, p.DetectedBy.Data)
	assert.False(t, p.Running.Data, "no service could be read, so running cannot be proven")
	assert.False(t, p.Healthy.Data)
	assert.True(t, p.Version.IsNull(), "no package reported a version")

	services, err := p.services()
	require.NoError(t, err)
	assert.Empty(t, services)

	installed, err := r.installed()
	require.NoError(t, err)
	assert.True(t, installed)

	healthy, err := r.healthy()
	require.NoError(t, err)
	assert.False(t, healthy)
}

func TestRmmProductFieldsStayNullWhenNothingReportsThem(t *testing.T) {
	r := newTestRmm(t, &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}, nil)

	// Synthetic: a macOS agent recognized by its path and launchd label.
	// launchd reports no boot-start setting and nothing reported a version.
	p, err := r.newProduct(edr.Detection{
		Product:    edr.Product{ID: "automox", Name: "Automox Agent", Vendor: "Automox", Category: rmm.CategoryPatchManagement},
		DetectedBy: []string{edr.SignalPath, edr.SignalService},
		Running:    true,
		Healthy:    true,
	})
	require.NoError(t, err)
	assert.True(t, p.Enabled.IsNull(), "enabled is null where boot start is not reported")
	assert.True(t, p.Version.IsNull(), "version is null rather than an empty string")
	assert.True(t, p.Running.Data)
	assert.True(t, p.Healthy.Data)

	// Synthetic: a Windows agent whose service is set not to start at boot.
	p, err = r.newProduct(edr.Detection{
		Product:         edr.Product{ID: "atera", Name: "Atera Agent", Vendor: "Atera", Category: rmm.CategoryRMM},
		DetectedBy:      []string{edr.SignalPackage, edr.SignalService},
		Version:         "2.5.19.0",
		Running:         true,
		EnabledReported: true,
		Enabled:         false,
	})
	require.NoError(t, err)
	assert.False(t, p.Enabled.IsNull())
	assert.False(t, p.Enabled.Data)
	assert.Equal(t, "2.5.19.0", p.Version.Data)
}
