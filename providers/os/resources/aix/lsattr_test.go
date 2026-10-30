// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lsattr -El sys0 -F "attribute value" on AIX 7.3 TL4 SP2 after
// chdev -l sys0 -a fullcore=true.
func TestParseLsattr(t *testing.T) {
	out, err := os.ReadFile("testdata/lsattr_sys0_aix73.txt")
	require.NoError(t, err)
	attrs := ParseLsattr(string(out))
	assert.Equal(t, "true", attrs["fullcore"])
	assert.Equal(t, "128", attrs["maxuproc"])
	assert.Equal(t, "disk", attrs["boottype"])
}

func TestParseLsattrEmptyValue(t *testing.T) {
	attrs := ParseLsattr("frequency      \nfullcore       false\n")
	assert.Equal(t, map[string]string{"frequency": "", "fullcore": "false"}, attrs)
}
