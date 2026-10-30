// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseFile(t *testing.T, path string) *Stanzas {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer f.Close()
	st, err := ParseStanzas(f)
	require.NoError(t, err)
	return st
}

// testdata/security_user_aix73.txt is /etc/security/user of AIX 7.3 TL4
// SP2 with a user, mqluser1, that sets maxage, minlen and loginretries.
func TestParseStanzasSecurityUser(t *testing.T) {
	st := parseFile(t, "testdata/security_user_aix73.txt")

	// root sets minlen with an extra leading space
	v, ok := st.Effective("root", "minlen")
	assert.True(t, ok)
	assert.Equal(t, "15", v)

	// uucp sets no minlen and inherits the default stanza's
	v, ok = st.Effective("uucp", "minlen")
	assert.True(t, ok)
	assert.Equal(t, "10", v)

	// a user without any stanza inherits everything
	v, ok = st.Effective("nosuchuser", "maxage")
	assert.True(t, ok)
	assert.Equal(t, "13", v)

	// quotes are stripped
	v, _ = st.Effective("root", "SYSTEM")
	assert.Equal(t, "compat", v)

	_, ok = st.Effective("root", "notanattribute")
	assert.False(t, ok)

	eff := st.EffectiveAttrs("mqluser1")
	assert.Equal(t, "12", eff["minlen"])
	assert.Equal(t, "5", eff["loginretries"])
	assert.Equal(t, "true", eff["rlogin"], "inherited")
}

func TestParseStanzasComments(t *testing.T) {
	in := "* comment\n" +
		"default:\n" +
		"\tminlen = 8\n" +
		"*\tminlen = 0\n" +
		"user1:\n" +
		"\t* minlen = 1\n" +
		"\tmaxage = 4\n"
	st, err := ParseStanzas(strings.NewReader(in))
	require.NoError(t, err)
	v, _ := st.Effective("user1", "minlen")
	assert.Equal(t, "8", v, "a commented-out minlen in either stanza does not count")
	assert.Equal(t, []string{"maxage"}, st.Get("user1").Keys)
}

func TestParseStanzasMergesRepeatedStanza(t *testing.T) {
	in := "user1:\n\tminlen = 8\n\tmaxage = 4\nuser1:\n\tminlen = 12\n"
	st, err := ParseStanzas(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, st.List, 1)
	assert.Equal(t, map[string]string{"minlen": "12", "maxage": "4"}, st.Get("user1").Attrs)
}

func TestParseStanzasFilesystems(t *testing.T) {
	st := parseFile(t, "testdata/filesystems_aix73.txt")
	tmp := st.Get("/tmp")
	require.NotNil(t, tmp)
	assert.Equal(t, "/dev/hd3", tmp.Attrs["dev"])
	assert.Equal(t, "automatic", tmp.Attrs["mount"])
	assert.NotNil(t, st.Get("/var/adm/ras/livedump"))
}

func TestSplitList(t *testing.T) {
	assert.Equal(t, []string{"ALL", "!staff"}, SplitList(" ALL, !staff ,"))
	assert.Equal(t, []string{}, SplitList(""))
}
