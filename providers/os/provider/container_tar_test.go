// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/tar"
)

// `docker tar <file>` and `container tar <file>` scan the file. They were
// mapped to the snapshot connection, which exports a container by id and
// never read the path, so every such scan was an empty filesystem.
func TestTarSubcommandScansThePath(t *testing.T) {
	conf := &inventory.Config{}
	parseContainerSubcommand("tar", "/tmp/export.tar", conf)
	assert.Equal(t, shared.Type_Tar.String(), conf.Type)
	assert.Equal(t, "/tmp/export.tar", conf.Options[tar.OPTION_FILE])
}
