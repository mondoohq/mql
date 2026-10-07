// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func TestDisplayUsedConfig_MissingFile(t *testing.T) {
	prevLogger, prevPath, prevLoaded := log.Logger, UserProvidedPath, LoadedConfig
	t.Cleanup(func() { log.Logger, UserProvidedPath, LoadedConfig = prevLogger, prevPath, prevLoaded })
	var buf bytes.Buffer
	log.Logger = zerolog.New(&buf).Level(zerolog.InfoLevel)
	UserProvidedPath = "/tmp/does-not-exist/mondoo.yml"
	LoadedConfig = false

	DisplayUsedConfigForLogin()
	assert.Empty(t, buf.String(), "login creates the file, so a missing one is not worth a warning")

	DisplayUsedConfig()
	assert.Contains(t, buf.String(), `"level":"warn"`)
	assert.Contains(t, buf.String(), "could not load configuration file /tmp/does-not-exist/mondoo.yml")
}
