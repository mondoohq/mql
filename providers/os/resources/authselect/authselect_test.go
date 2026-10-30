// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package authselect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	t.Run("profile and features", func(t *testing.T) {
		cfg, ok := ParseConfig("custom/hardened\nwith-faillock\nwithout-nullok\nwith-pwhistory\n")
		require.True(t, ok)
		assert.Equal(t, "custom/hardened", cfg.ProfileID)
		assert.Equal(t, []string{"with-faillock", "without-nullok", "with-pwhistory"}, cfg.Features)
	})

	t.Run("trims, skips comments and empty lines, drops duplicates", func(t *testing.T) {
		cfg, ok := ParseConfig("# selected by hand\n\n  sssd  \n with-faillock\n\n# note\nwith-mkhomedir\nwith-faillock\n")
		require.True(t, ok)
		assert.Equal(t, "sssd", cfg.ProfileID)
		assert.Equal(t, []string{"with-faillock", "with-mkhomedir"}, cfg.Features)
	})

	t.Run("profile without features", func(t *testing.T) {
		cfg, ok := ParseConfig("local\n")
		require.True(t, ok)
		assert.Equal(t, "local", cfg.ProfileID)
		assert.Empty(t, cfg.Features)
		assert.NotNil(t, cfg.Features)
	})

	t.Run("no profile is no configuration", func(t *testing.T) {
		for _, content := range []string{"", "\n\n", "# only a comment\n"} {
			_, ok := ParseConfig(content)
			assert.False(t, ok, "%q", content)
		}
	})
}

func TestIsCustom(t *testing.T) {
	assert.True(t, IsCustom("custom/hardened"))
	assert.False(t, IsCustom("sssd"))
	assert.False(t, IsCustom("vendor/custom"))
	assert.False(t, IsCustom("customized"))
}

func TestEvaluate(t *testing.T) {
	enabled := map[string]bool{"a": true, "c": true}
	tests := []struct {
		expr string
		want bool
	}{
		{`"a"`, true},
		{`"b"`, false},
		{`not "a"`, false},
		{`not not "a"`, true},
		{`"a" and "c"`, true},
		{`"a" AND "b"`, false},
		{`"b" or "c"`, true},
		{`"b" Or "x"`, false},
		// and and or have the same precedence, applied from left to right:
		// ("a" or "b") and "x", not "a" or ("b" and "x")
		{`"a" or "b" and "x"`, false},
		{`"a" or ("b" and "x")`, true},
		{`not ("a" and "b")`, true},
		{`("a" or "b") and not "x"`, true},
		{"\t\"a\"  and\t\"c\" ", true},
		// a character that starts no token ends the expression
		{`"a" - "b"`, true},
	}
	for _, tt := range tests {
		got, err := Evaluate(tt.expr, enabled)
		require.NoError(t, err, tt.expr)
		assert.Equal(t, tt.want, got, tt.expr)
	}

	for _, expr := range []string{
		``,
		`not`,
		`"a" and`,
		`"a" "c"`,
		`"a" not "c"`,
		`("a"`,
		`"a")`,
		`()`,
		`"a`,
		`maybe "a"`,
	} {
		_, err := Evaluate(expr, enabled)
		assert.Error(t, err, "%q", expr)
	}
}

// The templates in testdata/profile and the files in testdata/generated
// come from `authselect test custom/fixture <features>`, with authselect
// 1.2.6 (Rocky Linux 9) and 1.5.0 (Fedora 41) printing the same output.
func TestGenerateMatchesAuthselect(t *testing.T) {
	featureSets := [][]string{
		{},
		{"with-lock"},
		{"with-strict"},
		{"with-lock", "without-fail", "without-fprint", "without-nullok", "with-md5"},
		{"a", "c"},
		{"b", "c"},
		{"a"},
		{"b"},
		{"with-x", "with-a", "with-b"},
		{"with-strict", "with-b"},
		{"with-more"},
		{"with-more", "with-early-stop"},
		{"with-early-stop"},
	}
	for _, name := range []string{"system-auth", "postlogin"} {
		template := readTestdata(t, "profile", name)
		for i, features := range featureSets {
			t.Run(fmt.Sprintf("%s %v", name, features), func(t *testing.T) {
				want := readTestdata(t, "generated", fmt.Sprintf("%02d.%s", i, name))
				lines, err := Generate(template, features)
				require.NoError(t, err)
				assert.Equal(t, strings.TrimRight(want, "\n"), strings.TrimRight(Text(lines), "\n"))
				assert.True(t, SameContent(want, Text(lines)))
			})
		}
	}
}

func TestGenerateSourceLines(t *testing.T) {
	template := "auth required pam_env.so\n" +
		"auth required pam_faillock.so preauth {include if \"with-faillock\"}\n" +
		"{imply \"with-faillock\" if \"with-strict\"}\n" +
		"auth required pam_faillock.so authfail {include if \"with-faillock\"}\n" +
		"auth sufficient pam_unix.so {if not \"without-nullok\":nullok}\n"

	lines, err := Generate(template, []string{"with-strict", "without-nullok"})
	require.NoError(t, err)
	// the implied feature applies to the lines after the imply line only, as
	// `authselect test` 1.2.6 prints for this template
	assert.Equal(t, []Line{
		{Source: 0, Text: "auth required pam_env.so"},
		{Source: 3, Text: "auth required pam_faillock.so authfail"},
		{Source: 4, Text: "auth sufficient pam_unix.so"},
		{Source: 5, Text: ""},
	}, lines)
}

func TestGenerateInvalidExpression(t *testing.T) {
	_, err := Generate("auth required pam_env.so\nauth required pam_deny.so {include if \"a\" and}\n", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 2")
}

func TestGenerateEmptyTemplate(t *testing.T) {
	lines, err := Generate("", []string{"with-faillock"})
	require.NoError(t, err)
	assert.Equal(t, "", Text(lines))
}

func TestSameContent(t *testing.T) {
	expected := "auth required pam_env.so\n\nauth required pam_deny.so"

	assert.True(t, SameContent("# Generated by authselect\n# Do not modify this file manually.\n\n"+
		"  auth required pam_env.so  \n\n\nauth required pam_deny.so\n", expected))
	assert.False(t, SameContent("auth required pam_env.so\nauth required pam_deny.so\nauth sufficient pam_permit.so\n", expected))
	assert.False(t, SameContent("auth required pam_deny.so\nauth required pam_env.so\n", expected))
	assert.False(t, SameContent("auth   required pam_env.so\nauth required pam_deny.so\n", expected))
	assert.False(t, SameContent("", expected))
	assert.True(t, SameContent("# Generated by authselect\n", ""))
}

// testdata/generated/nsswitch.* is what `authselect test custom/fixture
// <feature> -n` prints with authselect 1.2.6 (Rocky Linux 9) and
// testdata/user-nsswitch.conf in place, without the comment block
// authselect puts first.
func TestMergeUserNsswitch(t *testing.T) {
	template := readTestdata(t, "profile", "nsswitch.conf")
	user := readTestdata(t, "user-nsswitch.conf")
	for _, feature := range []string{"with-sss", "with-netgroup"} {
		t.Run(feature, func(t *testing.T) {
			lines, err := Generate(template, []string{feature})
			require.NoError(t, err)
			want := readTestdata(t, "generated", "nsswitch."+feature)
			assert.Equal(t, strings.TrimRight(want, "\n"), strings.TrimRight(MergeUserNsswitch(Text(lines), user), "\n"))
		})
	}

	t.Run("nothing left of the user file", func(t *testing.T) {
		assert.Equal(t, "passwd: files\n", MergeUserNsswitch("passwd: files\n", "passwd: files sss\n"))
		assert.Equal(t, "passwd: files\n", MergeUserNsswitch("passwd: files\n", ""))
	})
}

func TestMergesUserNsswitch(t *testing.T) {
	// the comment authselect 1.2.6 writes, as it is stored in libauthselect.so.3
	lib := []byte("\x00passwd\x00# If you want to make changes to nsswitch.conf please modify\n" +
		"# /etc/authselect/user-nsswitch.conf and run 'authselect apply-changes'.\n#\n\x00")
	assert.True(t, MergesUserNsswitch(lib))
	assert.False(t, MergesUserNsswitch([]byte("\x00/etc/authselect/user-nsswitch.conf\x00nsswitch.conf\x00")))
}

func readTestdata(t *testing.T, elem ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, elem...)...))
	require.NoError(t, err)
	return string(data)
}
