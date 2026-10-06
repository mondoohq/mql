// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package loginconf_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/loginconf"
)

func parseFixture(t *testing.T, fixture string) *loginconf.Database {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/"+fixture))
	require.NoError(t, err)
	f, err := conn.FileSystem().Open("/etc/login.conf")
	require.NoError(t, err)
	defer f.Close()
	db, err := loginconf.Parse(f)
	require.NoError(t, err)
	return db
}

func names(db *loginconf.Database) []string {
	res := []string{}
	for _, r := range db.Records {
		res = append(res, r.Name())
	}
	return res
}

func effective(t *testing.T, db *loginconf.Database, class string) map[string]any {
	t.Helper()
	r := db.Lookup(class)
	require.NotNil(t, r, class)
	caps, err := db.Effective(r)
	require.NoError(t, err)
	return caps
}

func TestFreeBSD14(t *testing.T) {
	db := parseFixture(t, "freebsd14.toml")
	assert.Equal(t, []string{"default", "standard", "xuser", "staff", "daemon", "news", "dialer", "root", "russian"}, names(db))

	def := db.Lookup("default")
	require.NotNil(t, def)
	own := def.Own()
	assert.Equal(t, "sha512", own["passwd_format"])
	assert.Equal(t, "022", own["umask"])
	assert.Equal(t, "BLOCKSIZE=K", own["setenv"])
	assert.Equal(t, "/sbin /bin /usr/sbin /usr/bin /usr/local/sbin /usr/local/bin ~/bin", own["path"])
	assert.NotContains(t, own, "ignoretime", "ignoretime@ cancels it")
	assert.Empty(t, def.Inherits())

	// standard is only tc=default: nothing of its own, everything inherited.
	std := db.Lookup("standard")
	require.NotNil(t, std)
	assert.Empty(t, std.Own())
	assert.Equal(t, []string{"default"}, std.Inherits())
	assert.Equal(t, effective(t, db, "default"), effective(t, db, "standard"))

	// daemon cancels mail before tc=default, so default's mail stays hidden,
	// and its own path and memorylocked win over default's.
	daemon := effective(t, db, "daemon")
	assert.NotContains(t, daemon, "mail")
	assert.Equal(t, "128M", daemon["memorylocked"])
	assert.Equal(t, "/sbin /bin /usr/sbin /usr/bin /usr/local/sbin /usr/local/bin", daemon["path"])
	assert.Equal(t, "sha512", daemon["passwd_format"])
	assert.NotContains(t, daemon, "tc")

	root := effective(t, db, "root")
	assert.Equal(t, true, root["ignorenologin"])
	assert.Equal(t, "unlimited", root["memorylocked"])

	// The last header name is a description, and lookups match it as well.
	ru := db.Lookup("Russian Users Accounts")
	require.NotNil(t, ru)
	assert.Equal(t, "russian", ru.Name())
	assert.Equal(t, []string{"Russian Users Accounts"}, ru.Aliases())
	assert.Equal(t, "ru_RU.UTF-8", effective(t, db, "russian")["lang"])
}

func TestOpenBSD7(t *testing.T) {
	db := parseFixture(t, "openbsd7.toml")
	assert.Contains(t, names(db), "auth-defaults")
	assert.Contains(t, names(db), "bgpd")

	// bgpd -> daemon -> default -> auth-defaults, auth-ftp-defaults
	bgpd := effective(t, db, "bgpd")
	assert.Equal(t, "16384M", bgpd["datasize"])
	assert.Equal(t, "512", bgpd["openfiles"])
	assert.Equal(t, "128", bgpd["openfiles-cur"], "daemon's value wins over default's")
	assert.Equal(t, "022", bgpd["umask"])
	assert.Equal(t, "passwd,skey", bgpd["auth"])
	assert.Equal(t, "passwd", bgpd["auth-ftp"])
	assert.Equal(t, "blowfish,a", bgpd["localcipher"])

	staff := db.Lookup("staff")
	require.NotNil(t, staff)
	assert.Equal(t, []string{"default"}, staff.Inherits())
	assert.NotContains(t, effective(t, db, "staff"), "requirehome")

	def := db.Lookup("default")
	require.NotNil(t, def)
	assert.Equal(t, []string{"auth-defaults", "auth-ftp-defaults"}, def.Inherits())
}

func TestNetBSD10AllCommented(t *testing.T) {
	db := parseFixture(t, "netbsd10.toml")
	assert.Empty(t, db.Records)
	assert.Nil(t, db.Lookup("default"))
}

func TestEdgeCases(t *testing.T) {
	db := parseFixture(t, "edgecases.toml")
	assert.Equal(t, []string{"default", "middle", "chain", "override", "loopa", "loopb", "dangling", "default"}, names(db),
		"#commented ends in a backslash and swallows the next line, as in getcap")

	def := db.Lookup("default")
	require.NotNil(t, def)
	assert.Same(t, db.Records[0], def, "the first of two records with the same name wins")
	assert.Equal(t, []string{"Default Class"}, def.Aliases())
	assert.Equal(t, map[string]any{
		"passwordtime":   "90d",
		"minpasswordlen": "12",
		"requirehome":    true,
		"umask":          "022",
		"mail":           "/var/mail/$",
	}, def.Own())

	chain := effective(t, db, "chain")
	assert.Equal(t, "7d", chain["warnpassword"])
	assert.Equal(t, "027", chain["umask"], "middle's umask wins over default's")
	assert.Equal(t, "90d", chain["passwordtime"])
	assert.Equal(t, "12", chain["minpasswordlen"])
	assert.NotContains(t, chain, "ignoretime")

	override := effective(t, db, "override")
	assert.Equal(t, "30d", override["passwordtime"])
	assert.NotContains(t, override, "requirehome", "cancelled before tc=")
	assert.Equal(t, "022", override["umask"], "default's umask comes before the one written after tc=")

	loop := db.Lookup("loopa")
	require.NotNil(t, loop)
	_, err := db.Effective(loop)
	require.Error(t, err)
	assert.True(t, errors.Is(err, loginconf.ErrTcLoop))
	assert.Contains(t, err.Error(), "loopa -> loopb -> loopa")

	dangling := db.Lookup("dangling")
	require.NotNil(t, dangling)
	_, err = db.Effective(dangling)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tc=nosuchclass")
	assert.Equal(t, map[string]any{"umask": "022"}, dangling.Own())
}

func TestDiamondIsNotALoop(t *testing.T) {
	db, err := loginconf.Parse(strings.NewReader("base:umask=022:\na:tc=base:\nb:tc=base:\ntop:tc=a:tc=b:\n"))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"umask": "022"}, effective(t, db, "top"))
}

func TestDepthLimit(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < loginconf.MaxTcDepth+2; i++ {
		sb.WriteString("c")
		sb.WriteString(strings.Repeat("x", i))
		sb.WriteString(":tc=c")
		sb.WriteString(strings.Repeat("x", i+1))
		sb.WriteString(":\n")
	}
	sb.WriteString("c" + strings.Repeat("x", loginconf.MaxTcDepth+2) + ":umask=022:\n")
	db, err := loginconf.Parse(strings.NewReader(sb.String()))
	require.NoError(t, err)
	_, err = db.Effective(db.Lookup("c"))
	assert.ErrorIs(t, err, loginconf.ErrTcLoop)

	// Within the limit resolves.
	_, err = db.Effective(db.Lookup("c" + strings.Repeat("x", 4)))
	assert.NoError(t, err)
}

func TestNoTrailingNewline(t *testing.T) {
	db, err := loginconf.Parse(strings.NewReader("default:\\\n\t:umask=022:"))
	require.NoError(t, err)
	require.Len(t, db.Records, 1)
	assert.Equal(t, map[string]any{"umask": "022"}, db.Records[0].Own())
}
