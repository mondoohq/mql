// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/mvd"
)

// fakeEolScanner answers IsEol the way the platform does for a product it has
// no lifecycle data for: an empty PlatformEolInfo, no date.
type fakeEolScanner struct {
	mvd.AdvisoryScanner
	eolDate string
	asked   []*mvd.Platform
}

func (f *fakeEolScanner) IsEol(_ context.Context, p *mvd.Platform) (*mvd.PlatformEolInfo, error) {
	f.asked = append(f.asked, p)
	return &mvd.PlatformEolInfo{EolDate: f.eolDate}, nil
}

func newMondooEol(t *testing.T, scanner *fakeEolScanner, product, version string) *mqlMondooEol {
	srv := httptest.NewServer(mvd.NewAdvisoryScannerServer(scanner))
	t.Cleanup(srv.Close)
	return &mqlMondooEol{
		MqlRuntime: &plugin.Runtime{Upstream: &upstream.UpstreamClient{
			UpstreamConfig: upstream.UpstreamConfig{ApiEndpoint: srv.URL},
			HttpClient:     srv.Client(),
		}},
		Product: plugin.TValue[string]{Data: product, State: plugin.StateIsSet},
		Version: plugin.TValue[string]{Data: version, State: plugin.StateIsSet},
	}
}

func TestMondooEolDate(t *testing.T) {
	t.Run("empty product is an error, not Never", func(t *testing.T) {
		scanner := &fakeEolScanner{}
		_, err := newMondooEol(t, scanner, "", "").date()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "product")
		assert.Empty(t, scanner.asked, "an unnamed product must not be looked up")
	})

	t.Run("empty version is an error, not Never", func(t *testing.T) {
		scanner := &fakeEolScanner{}
		_, err := newMondooEol(t, scanner, "debian", "").date()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version")
		assert.Empty(t, scanner.asked)
	})

	t.Run("product without an EOL date is Never", func(t *testing.T) {
		scanner := &fakeEolScanner{}
		d, err := newMondooEol(t, scanner, "debian", "13").date()
		require.NoError(t, err)
		require.NotNil(t, d)
		assert.True(t, d.Equal(llx.NeverFutureTime))
		require.Len(t, scanner.asked, 1)
		assert.Equal(t, "debian", scanner.asked[0].Name)
		assert.Equal(t, "13", scanner.asked[0].Release)
	})

	t.Run("product with an EOL date", func(t *testing.T) {
		scanner := &fakeEolScanner{eolDate: "2022-06-30T00:00:00Z"}
		d, err := newMondooEol(t, scanner, "debian", "9").date()
		require.NoError(t, err)
		require.NotNil(t, d)
		assert.True(t, d.Equal(time.Date(2022, 6, 30, 0, 0, 0, 0, time.UTC)))
	})
}
