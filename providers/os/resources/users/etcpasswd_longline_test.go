// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users_test

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/users"
)

// glibc reads /etc/passwd with no line limit, so a user after a very long
// line (a 70 KB GECOS field) still exists. Stopping at the long line hides
// every later account, including a second uid 0.
func TestParseEtcPasswdKeepsUsersAfterLongLine(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\n" +
		"longgecos:x:1001:1001:" + strings.Repeat("g", 70*1024) + ":/home/longgecos:/bin/bash\n" +
		"toor:x:0:0:hidden root:/root:/bin/sh\n"

	m, err := users.ParseEtcPasswd(strings.NewReader(passwd))
	require.NoError(t, err)
	require.Len(t, m, 3)
	assert.Equal(t, "longgecos", m[1].Name)
	assert.Len(t, m[1].Description, 70*1024)
	assert.Equal(t, "toor", m[2].Name)
	assert.Equal(t, int64(0), m[2].Uid)
}

// A read error must fail the parse rather than return the users read so far
// as if they were the whole file.
func TestParseEtcPasswdReturnsReadError(t *testing.T) {
	r := io.MultiReader(strings.NewReader("root:x:0:0:root:/root:/bin/bash\n"), iotest.ErrReader(errors.New("read failed")))
	_, err := users.ParseEtcPasswd(r)
	require.Error(t, err)
}
