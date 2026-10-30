// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package pwquality

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApply(t *testing.T) {
	s := Settings{}
	err := s.Apply("pwquality.conf", strings.NewReader(`# Configuration for systemwide password quality limits
# minlen = 9
minlen = 14
  dcredit=-1   # trailing comment
UCREDIT -1
lcredit= -1
ocredit =-1
enforce_for_root
dictpath = /usr/share/cracklib/pw_dict
badwords = foo bar
`))
	require.NoError(t, err)
	assert.Equal(t, Settings{
		"minlen":           "14",
		"dcredit":          "-1",
		"ucredit":          "-1",
		"lcredit":          "-1",
		"ocredit":          "-1",
		"enforce_for_root": "",
		"dictpath":         "/usr/share/cracklib/pw_dict",
		"badwords":         "foo bar",
	}, s)
}

func TestApplyStopsAtAnInvalidLine(t *testing.T) {
	s := Settings{}
	err := s.Apply("x.conf", strings.NewReader("minlen = 14\nminlenn = 15\nminclass = 4\n"))
	var perr *Error
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, 2, perr.Line)
	assert.Equal(t, "minlenn", perr.Name)
	assert.Equal(t, Settings{"minlen": "14"}, s, "the lines before the error apply, the ones after it do not")

	s = Settings{}
	err = s.Apply("x.conf", strings.NewReader("minlen = 14 chars\n"))
	require.ErrorAs(t, err, &perr)
	assert.Equal(t, "not an integer", perr.Err)
}

func TestInt(t *testing.T) {
	s := Settings{"minlen": "4", "minclass": "9", "enforce_for_root": ""}
	assert.Equal(t, int64(6), s.Int("minlen", false), "libpwquality raises minlen to 6")
	assert.Equal(t, int64(4), s.Int("minclass", false), "and caps minclass at 4")
	assert.Equal(t, int64(1), s.Int("enforce_for_root", false))
	assert.Equal(t, int64(0), s.Int("local_users_only", false))
	assert.Equal(t, int64(1), s.Int("difok", false), "default")
	assert.Equal(t, int64(1), s.Int("dictcheck", false), "default")

	// libpwquality 1.2.3 on Amazon Linux 2 reported minlen 9, dcredit 1 and
	// ucredit 1 for a file that set none of them
	empty := Settings{}
	assert.Equal(t, int64(9), empty.Int("minlen", true))
	assert.Equal(t, int64(5), empty.Int("difok", true))
	assert.Equal(t, int64(1), empty.Int("dcredit", true))
	assert.Equal(t, int64(0), empty.Int("maxrepeat", true))
	assert.Equal(t, int64(14), Settings{"minlen": "14"}.Int("minlen", true))
}

func TestApplyOption(t *testing.T) {
	s := Settings{"minlen": "14"}
	assert.True(t, s.ApplyOption("minlen=8"))
	assert.True(t, s.ApplyOption("enforce_for_root"))
	assert.False(t, s.ApplyOption("use_authtok"))
	assert.Equal(t, Settings{"minlen": "8", "enforce_for_root": ""}, s)
}

func TestFiles(t *testing.T) {
	t.Run("drop-ins in name order, then the main file", func(t *testing.T) {
		assert.Equal(t, []string{
			"/etc/security/pwquality.conf.d/10-a.conf",
			"/etc/security/pwquality.conf.d/50-cis.conf",
			"/etc/security/pwquality.conf",
		}, Files(DefaultFile, true, []string{"50-cis.conf", "10-a.conf", "README", "x.conf.rpmsave", "a.conf.conf"}, nil, true))
	})

	t.Run("the base file replaces a missing main file, /etc drop-ins hide base ones", func(t *testing.T) {
		assert.Equal(t, []string{
			"/usr/lib/security/pwquality.conf.d/10-vendor.conf",
			"/etc/security/pwquality.conf.d/20-x.conf",
			"/usr/lib/security/pwquality.conf",
		}, Files(DefaultFile, false, []string{"20-x.conf"}, []string{"10-vendor.conf", "20-x.conf"}, true))
	})

	t.Run("a conf= file reads its own drop-ins only", func(t *testing.T) {
		assert.Equal(t, []string{"/etc/pwq.conf.d/a.conf", "/etc/pwq.conf"},
			Files("/etc/pwq.conf", true, []string{"a.conf"}, []string{"b.conf"}, true))
	})

	t.Run("libpwquality before 1.3 reads the main file alone", func(t *testing.T) {
		assert.Equal(t, []string{"/etc/security/pwquality.conf"}, Files(DefaultFile, true, []string{"50-cis.conf"}, nil, false))
	})
}

func TestIsLegacy(t *testing.T) {
	assert.True(t, IsLegacy("1.2.3-5.el7"))
	assert.True(t, IsLegacy("1.2.3-5.amzn2"))
	assert.False(t, IsLegacy("1.4.4-8.el9"))
	assert.False(t, IsLegacy("1.4.5-3build1"))
	assert.False(t, IsLegacy("1:1.3.0"))
	assert.False(t, IsLegacy(""))
}
