// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package yarnlock

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePackagename(t *testing.T) {
	var name string
	var version string
	var err error

	name, version, err = parseYarnPackageName("source-map-support@~0.5.10")
	assert.Nil(t, err)
	assert.Equal(t, "source-map-support", name)
	assert.Equal(t, "~0.5.10", version)

	name, version, err = parseYarnPackageName("@types/node@*")
	assert.Nil(t, err)
	assert.Equal(t, "@types/node", name)
	assert.Equal(t, "*", version)

	name, version, err = parseYarnPackageName("@babel/code-frame@^7.0.0-beta.47")
	assert.Nil(t, err)
	assert.Equal(t, "@babel/code-frame", name)
	assert.Equal(t, "^7.0.0-beta.47", version)

	name, version, err = parseYarnPackageName("has@^1.0.1, has@^1.0.3, has@~1.0.3")
	assert.Nil(t, err)
	assert.Equal(t, "has", name)
	assert.Equal(t, "^1.0.1", version)

	// yarn berry keys carry a protocol, which can itself contain "@"
	name, version, err = parseYarnPackageName("@types/node@npm:20.11.5")
	assert.Nil(t, err)
	assert.Equal(t, "@types/node", name)
	assert.Equal(t, "npm:20.11.5", version)

	name, version, err = parseYarnPackageName("typescript@patch:typescript@npm%3A^5.4.5#optional!builtin<compat/typescript>")
	assert.Nil(t, err)
	assert.Equal(t, "typescript", name)
	assert.Equal(t, "patch:typescript@npm%3A^5.4.5#optional!builtin<compat/typescript>", version)

	// Non-package keys like __metadata in yarn berry lockfiles must not panic.
	_, _, err = parseYarnPackageName("__metadata")
	assert.NotNil(t, err)

	_, _, err = parseYarnPackageName("no-at-sign")
	assert.NotNil(t, err)

	_, _, err = parseYarnPackageName("")
	assert.NotNil(t, err)
}
