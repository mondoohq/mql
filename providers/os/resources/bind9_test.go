// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/bind9"
)

func TestBind9ResolveZonePath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		directory  string
		declaredIn string
		expected   string
	}{
		{
			// The Debian default: a directory option plus relative zone files.
			name:       "relative path resolves against the directory option",
			path:       "db.example.com",
			directory:  "/var/cache/bind",
			declaredIn: "/etc/bind/named.conf.local",
			expected:   "/var/cache/bind/db.example.com",
		},
		{
			// Without a directory option, named uses its working directory.
			// Reading the file next to the declaration is the only answer
			// available from the configuration alone, and is where these files
			// sit in practice.
			name:       "relative path falls back to the declaring file",
			path:       "db.local",
			directory:  "",
			declaredIn: "/etc/bind/named.conf.default-zones",
			expected:   "/etc/bind/db.local",
		},
		{
			name:       "an absolute path is left alone",
			path:       "/usr/share/dns/root.hints",
			directory:  "/var/cache/bind",
			declaredIn: "/etc/bind/named.conf.default-zones",
			expected:   "/usr/share/dns/root.hints",
		},
		{
			// A forward or stub zone declares no file at all.
			name:     "no file yields no path",
			path:     "",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, bind9ResolveZonePath(test.path, test.directory, test.declaredIn))
		})
	}
}

func TestBind9IsYes(t *testing.T) {
	for _, v := range []string{"yes", "YES", "Yes", "true", "1", " yes "} {
		assert.True(t, bind9IsYes(v), "%q", v)
	}
	for _, v := range []string{"no", "NO", "false", "0", "", "auto", "maybe"} {
		assert.False(t, bind9IsYes(v), "%q", v)
	}
}

func TestBind9EachZone(t *testing.T) {
	// Zones live at the top level and inside views. A reader that only looks at
	// the top level reports a split-horizon server as serving nothing.
	stmts, err := bind9.Parse(`
zone "." { type hint; file "/usr/share/dns/root.hints"; };
view "internal" {
	match-clients { 10.0.0.0/8; };
	zone "corp.example" { type master; file "db.corp"; };
	zone "0.10.in-addr.arpa" { type master; file "db.10"; };
};
view "external" {
	zone "example.com" { type master; file "db.example.com"; };
};
`)
	require.NoError(t, err)

	type seen struct{ view, zone string }
	var got []seen
	bind9EachZone(stmts, func(view string, z bind9.Statement) {
		got = append(got, seen{view, z.Arg(0)})
	})

	assert.Equal(t, []seen{
		{"", "."},
		{"internal", "corp.example"},
		{"internal", "0.10.in-addr.arpa"},
		{"external", "example.com"},
	}, got)
}

func TestBind9EachZoneIgnoresNonZoneStatements(t *testing.T) {
	// A view carries more than zones, and a top-level acl or key is not one.
	stmts, err := bind9.Parse(`
acl "trusted" { 10.0.0.0/8; };
key "rndc-key" { algorithm hmac-sha256; secret "abc"; };
view "internal" {
	match-clients { any; };
	zone "corp.example" { type master; };
};
`)
	require.NoError(t, err)

	count := 0
	bind9EachZone(stmts, func(view string, z bind9.Statement) { count++ })
	assert.Equal(t, 1, count)
}

// A key statement is legal inside a view, and two views may declare different
// keys under the same name. The view is therefore part of what identifies a
// key: an id built from the name alone makes the second key resolve to the
// cached first one, which reports the wrong algorithm — and reports it as the
// stronger of the two when the weaker one is in the internet-facing view.
func TestBind9KeyIdentityIncludesTheView(t *testing.T) {
	stmts, err := bind9.Parse(`
key "top-level" { algorithm hmac-sha512; secret "a"; };
view "internal" {
	key "shared-name" { algorithm hmac-sha256; secret "b"; };
};
view "external" {
	key "shared-name" { algorithm hmac-md5; secret "c"; };
};
`)
	require.NoError(t, err)

	// the ids the resource builds, in the order it builds them
	var ids []string
	var algorithms []string
	collect := func(block []bind9.Statement, view string) {
		for _, k := range bind9.Find(block, "key") {
			ids = append(ids, "/etc/bind/named.conf/key/"+view+"/"+k.Arg(0))
			algorithms = append(algorithms, bind9.Value(k.Block, "algorithm"))
		}
	}
	collect(stmts, "")
	for _, v := range bind9.Find(stmts, "view") {
		collect(v.Block, v.Arg(0))
	}

	assert.Equal(t, []string{
		"/etc/bind/named.conf/key//top-level",
		"/etc/bind/named.conf/key/internal/shared-name",
		"/etc/bind/named.conf/key/external/shared-name",
	}, ids)
	assert.Equal(t, []string{"hmac-sha512", "hmac-sha256", "hmac-md5"}, algorithms)

	seen := map[string]bool{}
	for _, id := range ids {
		require.False(t, seen[id], "two keys share the id %q, so one shadows the other in the resource cache", id)
		seen[id] = true
	}
}

// [Service] section of bind9.service on Debian 9 and 10.
const debian9Bind9Service = `[Service]
EnvironmentFile=/etc/default/bind9
ExecStart=/usr/sbin/named -f $OPTIONS
ExecReload=/usr/sbin/rndc reload
ExecStop=/usr/sbin/rndc stop
`

// [Service] section of named.service on Debian 13 (Debian 11 and 12 differ
// only in Type=notify).
const debian13NamedService = `[Service]
Type=notify
EnvironmentFile=-/etc/default/named
ExecStart=/usr/sbin/named -f $OPTIONS
ExecReload=/usr/sbin/rndc reload
ExecStop=/usr/sbin/rndc stop
Restart=on-failure
`

// [Service] section of named.service in the Fedora and RHEL bind package.
const rhelNamedService = `[Service]
Type=forking
Environment=NAMEDCONF=/etc/named.conf
EnvironmentFile=-/etc/sysconfig/named
Environment=KRB5_KTNAME=/etc/named.keytab
PIDFile=/run/named/named.pid
ExecStartPre=/bin/bash -c 'if [ ! "$DISABLE_ZONE_CHECKING" == "yes" ]; then /usr/sbin/named-checkconf -z "$NAMEDCONF"; else echo "Checking of zone files is disabled"; fi'
ExecStart=/usr/sbin/named -u named -c ${NAMEDCONF} $OPTIONS
`

// [Service] section of named.service in the SLES 15 SP7 / 16.0 and openSUSE
// Leap 15.6 / 16.0 bind package.
const suseNamedService = `[Service]
Type=forking
KillMode=control-group
EnvironmentFile=/etc/sysconfig/named
ExecStartPre=+/usr/lib/bind/named.prep
ExecStart=/usr/sbin/named -u named $NAMED_ARGS
ExecReload=/usr/bin/kill -HUP $MAINPID
`

func TestBind9LaunchConfig(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			// The sweep's repro: OPTIONS points named at another file, and
			// the running named was started with it.
			name: "running named with -c from OPTIONS (debian 12)",
			files: map[string]string{
				"/lib/systemd/system/named.service": debian13NamedService,
				"/etc/default/named":                "RESOLVCONF=no\nOPTIONS=\"-u bind -c /etc/bind/named-alt.conf\"\n",
				"/run/named/named.pid":              "29169\n",
				"/proc/29169/cmdline":               "/usr/sbin/named\x00-f\x00-u\x00bind\x00-c\x00/etc/bind/named-alt.conf\x00",
			},
			want: "/etc/bind/named-alt.conf",
		},
		{
			// The running process wins over a defaults file edited since
			// named started.
			name: "running named without -c ignores a later OPTIONS edit",
			files: map[string]string{
				"/lib/systemd/system/named.service": debian13NamedService,
				"/etc/default/named":                "OPTIONS=\"-u bind -c /etc/bind/named-alt.conf\"\n",
				"/run/named/named.pid":              "29169\n",
				"/proc/29169/cmdline":               "/usr/sbin/named\x00-f\x00-u\x00bind\x00",
			},
			want: "",
		},
		{
			name: "stopped named: debian 9 bind9.service and /etc/default/bind9",
			files: map[string]string{
				"/lib/systemd/system/bind9.service": debian9Bind9Service,
				"/etc/default/bind9":                "RESOLVCONF=no\n\n# startup options for the server\nOPTIONS=\"-u bind -c /etc/bind/named-alt.conf\"\n",
			},
			want: "/etc/bind/named-alt.conf",
		},
		{
			name: "stopped named: debian 13 stock options",
			files: map[string]string{
				"/usr/lib/systemd/system/named.service": debian13NamedService,
				"/etc/default/named":                    "RESOLVCONF=no\nOPTIONS=\"-u bind\"\n",
			},
			want: "",
		},
		{
			name: "stale pid file falls back to the unit",
			files: map[string]string{
				"/lib/systemd/system/named.service": debian13NamedService,
				"/etc/default/named":                "OPTIONS=\"-u bind -c /etc/bind/named-alt.conf\"\n",
				"/run/named/named.pid":              "4242\n",
				"/proc/4242/cmdline":                "/usr/sbin/sshd\x00-D\x00",
			},
			want: "/etc/bind/named-alt.conf",
		},
		{
			name: "rhel: NAMEDCONF from /etc/sysconfig/named",
			files: map[string]string{
				"/usr/lib/systemd/system/named.service": rhelNamedService,
				"/etc/sysconfig/named":                  "# OPTIONS=\"whatever\"\nNAMEDCONF=/etc/named-alt.conf\n",
			},
			want: "/etc/named-alt.conf",
		},
		{
			name: "rhel: a later -c in OPTIONS overrides NAMEDCONF",
			files: map[string]string{
				"/usr/lib/systemd/system/named.service": rhelNamedService,
				"/etc/sysconfig/named":                  "OPTIONS=\"-c /etc/named-alt.conf\"\n",
			},
			want: "/etc/named-alt.conf",
		},
		{
			name: "suse: NAMED_ARGS from /etc/sysconfig/named",
			files: map[string]string{
				"/usr/lib/systemd/system/named.service": suseNamedService,
				"/etc/sysconfig/named":                  "NAMED_INITIALIZE_SCRIPTS=\"\"\nNAMED_ARGS=\"-c /etc/named-alt.conf\"\nRNDC_KEYSIZE=512\n",
			},
			want: "/etc/named-alt.conf",
		},
		{
			name: "suse: running named started with NAMED_ARGS",
			files: map[string]string{
				"/usr/lib/systemd/system/named.service": suseNamedService,
				"/etc/sysconfig/named":                  "NAMED_ARGS=\"\"\n",
				"/run/named/named.pid":                  "30303\n",
				"/proc/30303/cmdline":                   "/usr/sbin/named\x00-u\x00named\x00-c\x00/etc/named-alt.conf\x00",
			},
			want: "/etc/named-alt.conf",
		},
		{
			name: "suse: empty NAMED_ARGS reads the default",
			files: map[string]string{
				"/usr/lib/systemd/system/named.service": suseNamedService,
				"/etc/sysconfig/named":                  "NAMED_ARGS=\"\"\n",
			},
			want: "",
		},
		{
			name: "relative -c resolves against /",
			files: map[string]string{
				"/run/named/named.pid": "7\n",
				"/proc/7/cmdline":      "/usr/sbin/named-pkcs11\x00-u\x00named\x00-c\x00etc/named.conf\x00",
			},
			want: "/etc/named.conf",
		},
		{
			name:  "no process and no unit",
			files: nil,
			want:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			afs := &afero.Afero{Fs: afero.NewMemMapFs()}
			for p, c := range tt.files {
				require.NoError(t, afs.WriteFile(p, []byte(c), 0o644))
			}
			assert.Equal(t, tt.want, bind9LaunchConfig(afs))
		})
	}
}

// version reads "" both when the statement is absent (named reports its real
// version) and for `version "";` (named answers with an empty string). The
// params map is what tells them apart, as the field documents.
func TestBind9VersionAbsentVersusEmpty(t *testing.T) {
	absent, err := bind9.Parse(`options { directory "/var/cache/bind"; };`)
	require.NoError(t, err)
	opts := bind9.First(absent, "options").Block
	assert.Equal(t, "", bind9.Value(opts, "version"))
	_, ok := bind9.Params(opts)["version"]
	assert.False(t, ok)

	hidden, err := bind9.Parse(`options { directory "/var/cache/bind"; version ""; };`)
	require.NoError(t, err)
	opts = bind9.First(hidden, "options").Block
	assert.Equal(t, "", bind9.Value(opts, "version"))
	v, ok := bind9.Params(opts)["version"]
	assert.True(t, ok)
	assert.Equal(t, "", v)
}

// A zone can keep its keys in its own key-directory. On SLES 15 SP7 the
// RSASHA256 key of p.example.test lived only in /var/lib/named/keys, so
// bind9.dnssecKeys.all(algorithm >= 13) passed without ever seeing it.
func TestBind9DnssecKeyDirs(t *testing.T) {
	stmts, err := bind9.Parse(`
options {
	directory "/var/lib/named";
	key-directory "okeys";
};
zone "p.example.test" {
	type primary;
	file "/var/lib/named/master/db.p.example.test";
	key-directory "/var/lib/named/keys";
};
zone "example.test" { type master; file "master/db.example.test"; };
view "internal" {
	key-directory "/srv/view-keys";
	zone "v.example.test" { type primary; file "v.db"; key-directory "vkeys"; };
};
`)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"/var/lib/named/okeys",
		"/var/lib/named",
		"/srv/view-keys",
		"/var/lib/named/keys",
		"",
		"/var/lib/named/vkeys",
	}, bind9DnssecKeyDirs(stmts))
}
