// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestIsZonecfgUsageError(t *testing.T) {
	// what Oracle Solaris 11.4 zonecfg prints for an option it does not know
	assert.True(t, isZonecfgUsageError("-q: illegal option -- q\nusage:\ninfo [-a] [<resource-type> <identifier>]"))
	assert.False(t, isZonecfgUsageError("nosuch: No such zone exists"))
	assert.False(t, isZonecfgUsageError("exit status 1"))
}

func TestClassifyZonecfgError(t *testing.T) {
	err := classifyZonecfgError("web1", "zonecfg: Permission denied")
	assert.True(t, errors.Is(err, llx.ErrForbidden))

	// what Oracle Solaris 11.4 zonecfg prints inside a non-global zone
	err = classifyZonecfgError("web1", "zonecfg can only be run from the global zone.")
	assert.True(t, errors.Is(err, llx.ErrNotApplicable))
	assert.False(t, errors.Is(err, llx.ErrForbidden))

	err = classifyZonecfgError("web1", "web1: No such zone exists")
	assert.False(t, errors.Is(err, llx.ErrForbidden))
	assert.False(t, errors.Is(err, llx.ErrNotApplicable))
	assert.Contains(t, err.Error(), "No such zone exists")
}

func TestValidZoneName(t *testing.T) {
	for _, n := range []string{"global", "web1", "zone_a.b-c"} {
		assert.True(t, validZoneName.MatchString(n), n)
	}
	for _, n := range []string{"", "-z", "a b", "a;id", "$(id)"} {
		assert.False(t, validZoneName.MatchString(n), n)
	}
}
