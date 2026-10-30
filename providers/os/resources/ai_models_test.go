// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/aimodel"
)

// Models whose detected names coincide must still get distinct ids, or the
// resource cache hands back the first one for the second.
func TestAiModelID_DistinctForSameStrippedName(t *testing.T) {
	fs := afero.NewMemMapFs()
	home := "/home/u"
	for _, p := range []string{
		// torchvision's ResNet-50 V1 and V2 weights
		".cache/torch/hub/checkpoints/resnet50-0676ba61.pth",
		".cache/torch/hub/checkpoints/resnet50-11ad3fa6.pth",
		".keras/models/mymodel.h5",
		".keras/models/mymodel.keras",
	} {
		require.NoError(t, afero.WriteFile(fs, home+"/"+p, []byte("x"), 0o644))
	}

	models := aimodel.DetectAll(&afero.Afero{Fs: fs}, []string{home}, "linux", nil)
	require.Len(t, models, 4)

	ids := map[string]string{}
	for _, m := range models {
		id := aiModelID(m)
		if prev, ok := ids[id]; ok {
			t.Errorf("%s and %s share id %q", prev, m.Path, id)
		}
		ids[id] = m.Path
	}
	assert.Len(t, ids, 4)
}
