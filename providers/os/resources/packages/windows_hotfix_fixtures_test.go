// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWindowsHotfixFixtures parses real Get-HotFix output from Windows Server
// 2016, 2019, 2022 and 2025.
//
// The InstalledOn property is what makes this worth pinning per release: the
// cmdlet wraps a DateTime in a {"value": "/Date(ms)/", "DateTime": "..."}
// object rather than emitting a plain string, and a release that changed that
// wrapping would leave every hotfix reporting no install date while still
// parsing cleanly.
func TestWindowsHotfixFixtures(t *testing.T) {
	for _, rel := range []string{"2016", "2019", "2022", "2025"} {
		t.Run(rel, func(t *testing.T) {
			f, err := os.Open("./testdata/windows-hotfix-" + rel + ".json")
			require.NoError(t, err)
			defer f.Close()

			hotfixes, err := ParseWindowsHotfixes(f)
			require.NoError(t, err)
			require.NotEmpty(t, hotfixes)

			var dated int
			for _, h := range hotfixes {
				assert.Regexp(t, `^KB\d+$`, h.HotFixId)
				assert.NotEmpty(t, h.Description)
				if h.InstalledOnTime() != nil {
					dated++
					assert.Greater(t, h.InstalledOnTime().Year(), 2000,
						"%s: a decoded install date must be a real one", h.HotFixId)
				}
			}
			assert.Equal(t, len(hotfixes), dated,
				"every hotfix in these fixtures carries an install date; a release that changed the wrapping would show up as a zero here")

			// Security updates are the ones a patch policy keys on, so the
			// classification has to survive the parse.
			var security int
			for _, h := range hotfixes {
				if h.Description == "Security Update" {
					security++
				}
			}
			assert.NotZero(t, security, "the fixture must carry a security update")
		})
	}
}
