// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilterZones(t *testing.T) {
	all := []v3.Zone{{Name: "ch-gva-2"}, {Name: "de-fra-1"}, {Name: "at-vie-1"}}

	got, err := filterZones(all, nil)
	require.NoError(t, err)
	assert.Equal(t, all, got)

	got, err = filterZones(all, []string{"at-vie-1", "ch-gva-2"})
	require.NoError(t, err)
	assert.Equal(t, []v3.Zone{{Name: "at-vie-1"}, {Name: "ch-gva-2"}}, got)

	// A typo must fail loudly instead of scanning nothing.
	_, err = filterZones(all, []string{"ch-gva-3"})
	assert.ErrorContains(t, err, `unknown Exoscale zone "ch-gva-3"`)
}
