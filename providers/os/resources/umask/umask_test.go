// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package umask

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		in       string
		bits     uint32
		relative bool
	}{
		{"027", 0o027, false},
		{"0027", 0o027, false},
		{"77", 0o077, false},
		{"7", 0o007, false},
		{"0", 0, false},
		{"0777", 0o777, false},
		// symbolic modes name the permissions new files keep
		{"u=rwx,g=rx,o=", 0o027, false},
		{"u=rwx,g=,o=", 0o077, false},
		{"u=rw,g=r,o=r", 0o133, false},
		{"a=rx", 0o222, false},
		{"a=", 0o777, false},
		{"ugo=rwx", 0, false},
		{"=rx", 0o222, false},
		{"u=rwx,go=", 0o077, false},
		{"o=,g=rx,u=rwx", 0o027, false},
		// relative: unnamed classes keep the previous umask, so only the bits
		// the mode is known to remove count
		{"g=rx,o=", 0o027, true},
		{"o=", 0o007, true},
		{"o-rwx", 0o007, true},
		{"g-w,o-rwx", 0o027, true},
		{"o+r", 0, true},
		{"u=rwx,g=rx,o=,o+r", 0o023, false},
		{"u=rwx,g=rwx-w,o=", 0o027, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			m, err := Parse(tt.in)
			require.NoError(t, err)
			assert.Equal(t, tt.bits, m.Bits, "bits %04o", m.Bits)
			assert.Equal(t, tt.relative, m.Relative)
		})
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "08", "1000", "07777", "u=rwq", "u", "z=rwx", "u*rwx", "$UMASK", "u=rwx,,o="} {
		t.Run(in, func(t *testing.T) {
			_, err := Parse(in)
			assert.Error(t, err)
		})
	}
}

func TestParseOctal(t *testing.T) {
	m, err := ParseOctal("0077")
	require.NoError(t, err)
	assert.Equal(t, uint32(0o077), m.Bits)

	_, err = ParseOctal("u=rwx,g=rx,o=")
	assert.Error(t, err, "pam_umask and login.defs take octal only")
}

func TestMaskString(t *testing.T) {
	assert.Equal(t, "0027", Mask{Bits: 0o027}.String())
	assert.Equal(t, "0000", Mask{}.String())
	assert.Equal(t, "0777", Mask{Bits: 0o777}.String())
}

func parseShell(t *testing.T, content string) []Statement {
	t.Helper()
	return ParseShell(strings.NewReader(content))
}

func TestParseShell(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Statement
	}{
		{"plain", "umask 027\n", []Statement{{Line: 1, Value: "027"}}},
		{"indented with comment", "\n  umask 0077   # strict\n", []Statement{{Line: 2, Value: "0077"}}},
		{"symbolic", "umask u=rwx,g=rx,o=\n", []Statement{{Line: 1, Value: "u=rwx,g=rx,o="}}},
		{"quoted", "umask '027'\n", []Statement{{Line: 1, Value: "027"}}},
		{"option -S", "umask -S u=rwx,g=,o=\n", []Statement{{Line: 1, Value: "u=rwx,g=,o="}}},
		{"after semicolon", "export X=1; umask 027\n", []Statement{{Line: 1, Value: "027"}}},
		{"builtin prefix", "builtin umask 027\n", []Statement{{Line: 1, Value: "027"}}},
		{"variable", "umask $UMASK\n", []Statement{{Line: 1, Value: "$UMASK"}}},
		{"bare umask prints", "umask\numask -S\n", nil},
		{"commented out", "#umask 022\n# umask 022\n", nil},
		{"word, not a command", "echo umask 022\nmyumask 022\n", nil},
		{"command substitution", "x=`umask`\ny=$(umask)\n[ `umask` -eq 0 ]\n", nil},
		{"after &&", "[ `umask` -eq 0 ] && umask 022\n", []Statement{{Line: 1, Value: "022", Conditional: true}}},
		{"after ||", "test -n \"$X\" || umask 077\n", []Statement{{Line: 1, Value: "077", Conditional: true}}},
		{"&& does not reach past ;", "true && echo x; umask 027\n", []Statement{{Line: 1, Value: "027"}}},
		{
			"if else",
			"if [ $UID -gt 199 ]; then\n    umask 002\nelse\n    umask 022\nfi\numask 027\n",
			[]Statement{{Line: 2, Value: "002", Conditional: true}, {Line: 4, Value: "022", Conditional: true}, {Line: 6, Value: "027"}},
		},
		{"if on one line", "if true; then umask 077; fi; umask 027\n", []Statement{{Line: 1, Value: "077", Conditional: true}, {Line: 1, Value: "027"}}},
		{
			"case",
			"case $USER in\n  root) umask 077 ;;\n  *)\n    umask 027\n    ;;\nesac\numask 022\n",
			[]Statement{{Line: 2, Value: "077", Conditional: true}, {Line: 4, Value: "027", Conditional: true}, {Line: 7, Value: "022"}},
		},
		{
			"loop",
			"for i in 1; do\n  umask 027\ndone\n",
			[]Statement{{Line: 2, Value: "027", Conditional: true}},
		},
		{
			"function",
			"setmask() {\n  umask 077\n}\numask 027\n",
			[]Statement{{Line: 2, Value: "077", Conditional: true}, {Line: 4, Value: "027"}},
		},
		{
			"function keyword",
			"function setmask {\n  umask 077\n}\n",
			[]Statement{{Line: 2, Value: "077", Conditional: true}},
		},
		{
			"function body on the next line",
			"setmask()\n{\n  umask 077\n}\numask 027\n",
			[]Statement{{Line: 3, Value: "077", Conditional: true}, {Line: 5, Value: "027"}},
		},
		{
			"group runs unconditionally",
			"{\n  umask 027\n}\n",
			[]Statement{{Line: 2, Value: "027"}},
		},
		{"subshell", "(umask 077; touch x)\numask 027\n", []Statement{{Line: 1, Value: "077", Conditional: true}, {Line: 2, Value: "027"}}},
		{"continuation", "umask \\\n  027\n", []Statement{{Line: 1, Value: "027"}}},
		{"quoted # is not a comment", "echo '#'; umask 027\n", []Statement{{Line: 1, Value: "027"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseShell(t, tt.in))
		})
	}
}

// The startup files below are the defaults of the distributions they are
// named after, copied from their container images.
func TestParseShellDistributionDefaults(t *testing.T) {
	tests := []struct {
		file string
		want []Statement
	}{
		// RHEL 9 and its rebuilds set the umask in a non-login shell only when
		// it is 0
		{"rocky9-bashrc", []Statement{{Line: 69, Value: "022", Conditional: true}}},
		// RHEL 8: 002 for users whose group is their own, 022 for the rest
		{"ol8-profile", []Statement{{Line: 60, Value: "002", Conditional: true}, {Line: 62, Value: "022", Conditional: true}}},
		{"ol8-bashrc", []Statement{{Line: 73, Value: "002", Conditional: true}, {Line: 75, Value: "022", Conditional: true}}},
		{"al2023-bashrc", []Statement{{Line: 75, Value: "002", Conditional: true}, {Line: 77, Value: "022", Conditional: true}}},
		{"alpine-profile", []Statement{{Line: 4, Value: "022"}}},
		// commented out: the umask comes from login.defs through pam_umask
		{"leap16-profile", nil},
		{"debian13-profile", nil},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			f, err := os.Open("testdata/" + tt.file)
			require.NoError(t, err)
			defer f.Close()
			assert.Equal(t, tt.want, ParseShell(f))
		})
	}
}

func TestParseKey(t *testing.T) {
	content := "# UMASK=000\nUMASK=022\nUMASKX=077\n  UMASK 027 # login.defs style\nUMASK=\"0077\"\numask=0\nUMASK=\n"
	assert.Equal(t, []Assignment{
		{Line: 2, Value: "022"},
		{Line: 4, Value: "027"},
		{Line: 5, Value: "0077"},
	}, ParseKey(strings.NewReader(content), "UMASK"))
}
