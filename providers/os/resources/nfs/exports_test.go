// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nfs

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseExports_UnsupportedPlatform(t *testing.T) {
	_, err := ParseExports(strings.NewReader(""), "windows")
	if err == nil {
		t.Fatalf("expected error for unsupported platform")
	}
}

func TestParseLinuxExports(t *testing.T) {
	input := `# /etc/exports — Linux nfs-utils format
# comments and blank lines are ignored

/srv/data       192.168.1.0/24(rw,sync,no_root_squash) backup.example.com(ro,sync)
/srv/public     *(ro,all_squash,insecure)
/srv/krb        client.example.com(rw,sec=krb5p) # trailing comment
/srv/bare       hostonly
/srv/anon       (rw,sync)
`
	got, err := ParseExports(strings.NewReader(input), PlatformLinux)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ExportEntry{
		{Path: "/srv/data", Client: "192.168.1.0/24", Options: []string{"rw", "sync", "no_root_squash"}, ReadOnly: false, NoRootSquash: true},
		{Path: "/srv/data", Client: "backup.example.com", Options: []string{"ro", "sync"}, ReadOnly: true, NoRootSquash: false},
		{Path: "/srv/public", Client: "*", Options: []string{"ro", "all_squash", "insecure"}, ReadOnly: true, NoRootSquash: false},
		{Path: "/srv/krb", Client: "client.example.com", Options: []string{"rw", "sec=krb5p"}, ReadOnly: false, NoRootSquash: false},
		{Path: "/srv/bare", Client: "hostonly", Options: nil, ReadOnly: true, NoRootSquash: false},
		{Path: "/srv/anon", Client: "*", Options: []string{"rw", "sync"}, ReadOnly: false, NoRootSquash: false},
	}
	assertEntries(t, got, want)
}

func TestParseLinuxExports_EdgeCases(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []ExportEntry
	}{
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "only comments",
			input: "# foo\n# bar\n\n",
			want:  nil,
		},
		{
			name:  "non-absolute first token is skipped",
			input: "relative/path client(rw)\n",
			want:  nil,
		},
		{
			name:  "multiple clients on one line",
			input: "/share a(ro) b(rw) c\n",
			want: []ExportEntry{
				{Path: "/share", Client: "a", Options: []string{"ro"}, ReadOnly: true},
				{Path: "/share", Client: "b", Options: []string{"rw"}},
				{Path: "/share", Client: "c", Options: nil, ReadOnly: true},
			},
		},
		{
			name:  "tabs and extra spaces",
			input: "/share\t\t a(ro)   b(rw)\n",
			want: []ExportEntry{
				{Path: "/share", Client: "a", Options: []string{"ro"}, ReadOnly: true},
				{Path: "/share", Client: "b", Options: []string{"rw"}},
			},
		},
		{
			name:  "no_root_squash without rw still flagged",
			input: "/share host(ro,no_root_squash)\n",
			want: []ExportEntry{
				{Path: "/share", Client: "host", Options: []string{"ro", "no_root_squash"}, ReadOnly: true, NoRootSquash: true},
			},
		},
		{
			name:  "line continuation joins physical lines",
			input: "/share \\\n  host1(rw) \\\n  host2(ro)\n",
			want: []ExportEntry{
				{Path: "/share", Client: "host1", Options: []string{"rw"}},
				{Path: "/share", Client: "host2", Options: []string{"ro"}, ReadOnly: true},
			},
		},
		{
			name:  "neither ro nor rw exports read-only",
			input: "/share host(sync)\n",
			want: []ExportEntry{
				{Path: "/share", Client: "host", Options: []string{"sync"}, ReadOnly: true},
			},
		},
		{
			name:  "last of conflicting options wins",
			input: "/share a(ro,rw,root_squash,no_root_squash) b(rw,ro,no_root_squash,root_squash)\n",
			want: []ExportEntry{
				{Path: "/share", Client: "a", Options: []string{"ro", "rw", "root_squash", "no_root_squash"}, NoRootSquash: true},
				{Path: "/share", Client: "b", Options: []string{"rw", "ro", "no_root_squash", "root_squash"}, ReadOnly: true},
			},
		},
		{
			name:  "leading dash token sets defaults for every client",
			input: "/share -rw,no_root_squash a b(ro) c(root_squash)\n",
			want: []ExportEntry{
				{Path: "/share", Client: "a", Options: []string{"rw", "no_root_squash"}, NoRootSquash: true},
				{Path: "/share", Client: "b", Options: []string{"rw", "no_root_squash", "ro"}, ReadOnly: true, NoRootSquash: true},
				{Path: "/share", Client: "c", Options: []string{"rw", "no_root_squash", "root_squash"}},
			},
		},
		{
			name:  "netgroup client preserved",
			input: "/share @trusted(rw,no_root_squash)\n",
			want: []ExportEntry{
				{Path: "/share", Client: "@trusted", Options: []string{"rw", "no_root_squash"}, NoRootSquash: true},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseExports(strings.NewReader(c.input), PlatformLinux)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertEntries(t, got, c.want)
		})
	}
}

func TestParseFreeBSDExports(t *testing.T) {
	input := `# FreeBSD exports(5)
/usr/home  -alldirs -maproot=root  192.168.1.10 192.168.1.11
/usr/src /usr/obj  -ro  192.168.1.20
/data      -network=192.168.2.0 -mask=255.255.255.0
/secure    -sec=krb5p host1
V4: /
`
	got, err := ParseExports(strings.NewReader(input), PlatformFreeBSD)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ExportEntry{
		{Path: "/usr/home", Client: "192.168.1.10", Options: []string{"-alldirs", "-maproot=root"}, NoRootSquash: true},
		{Path: "/usr/home", Client: "192.168.1.11", Options: []string{"-alldirs", "-maproot=root"}, NoRootSquash: true},
		{Path: "/usr/src", Client: "192.168.1.20", Options: []string{"-ro"}, ReadOnly: true},
		{Path: "/usr/obj", Client: "192.168.1.20", Options: []string{"-ro"}, ReadOnly: true},
		{Path: "/data", Client: "*", Options: []string{"-network=192.168.2.0", "-mask=255.255.255.0"}},
		{Path: "/secure", Client: "host1", Options: []string{"-sec=krb5p"}},
	}
	assertEntries(t, got, want)
}

func TestParseMacOSExports(t *testing.T) {
	// macOS accepts both `-flag=value` and `-flag value` styles.
	input := `# macOS exports(5)
/Volumes/Share  -ro -mapall=nobody  host1 host2
/Volumes/Net    -network 192.168.1.0 -mask 255.255.255.0
/Volumes/Root   -maproot=0:0 host3
/Volumes/RootName -maproot=root:wheel host4
`
	got, err := ParseExports(strings.NewReader(input), PlatformDarwin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ExportEntry{
		{Path: "/Volumes/Share", Client: "host1", Options: []string{"-ro", "-mapall=nobody"}, ReadOnly: true},
		{Path: "/Volumes/Share", Client: "host2", Options: []string{"-ro", "-mapall=nobody"}, ReadOnly: true},
		{Path: "/Volumes/Net", Client: "*", Options: []string{"-network=192.168.1.0", "-mask=255.255.255.0"}},
		{Path: "/Volumes/Root", Client: "host3", Options: []string{"-maproot=0:0"}, NoRootSquash: true},
		{Path: "/Volumes/RootName", Client: "host4", Options: []string{"-maproot=root:wheel"}, NoRootSquash: true},
	}
	assertEntries(t, got, want)
}

func TestParseAIXExports(t *testing.T) {
	input := `# AIX /etc/exports
/home/data    -ro,root=clientA:clientB
/var/share    -rw=client1:client2,ro=client3,root=client1,sec=sys
/all/world
/restrict     -access=onlyme:onlyhim,sec=krb5
/global/ro    -ro,access=anyone
`
	got, err := ParseExports(strings.NewReader(input), PlatformAIX)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ExportEntry{
		// /home/data: -ro applies globally; root=clientA:clientB grants no_root_squash to both;
		// the implicit `*` row inherits the global -ro.
		{Path: "/home/data", Client: "clientA", Options: []string{"ro", "root=clientA:clientB"}, ReadOnly: true, NoRootSquash: true},
		{Path: "/home/data", Client: "clientB", Options: []string{"ro", "root=clientA:clientB"}, ReadOnly: true, NoRootSquash: true},
		{Path: "/home/data", Client: "*", Options: []string{"ro", "root=clientA:clientB"}, ReadOnly: true, NoRootSquash: false},
		// /var/share: rw=client1:client2 → rw; ro=client3 → ro; root=client1 → no_root_squash;
		// implicit `*` row is ro because rw= names specific hosts (rest get ro per AIX docs).
		{Path: "/var/share", Client: "client1", Options: []string{"rw=client1:client2", "ro=client3", "root=client1", "sec=sys"}, ReadOnly: false, NoRootSquash: true},
		{Path: "/var/share", Client: "client2", Options: []string{"rw=client1:client2", "ro=client3", "root=client1", "sec=sys"}, ReadOnly: false, NoRootSquash: false},
		{Path: "/var/share", Client: "client3", Options: []string{"rw=client1:client2", "ro=client3", "root=client1", "sec=sys"}, ReadOnly: true, NoRootSquash: false},
		{Path: "/var/share", Client: "*", Options: []string{"rw=client1:client2", "ro=client3", "root=client1", "sec=sys"}, ReadOnly: true, NoRootSquash: false},
		// /all/world: no options → only the implicit `*` row, defaults to rw.
		{Path: "/all/world", Client: "*", Options: nil},
		// /restrict: access= list gates the share; no implicit `*` row.
		{Path: "/restrict", Client: "onlyme", Options: []string{"access=onlyme:onlyhim", "sec=krb5"}},
		{Path: "/restrict", Client: "onlyhim", Options: []string{"access=onlyme:onlyhim", "sec=krb5"}},
		// /global/ro: access= still gates; -ro applies inside the gate.
		{Path: "/global/ro", Client: "anyone", Options: []string{"ro", "access=anyone"}, ReadOnly: true},
	}
	assertEntries(t, got, want)
}

func TestParseAIXExports_ImplicitRest(t *testing.T) {
	// AIX exports(5): when no `access=` gate is given, named hosts get
	// their explicit per-host permission and everyone else can still
	// mount with the default permission for the line. These cases pin
	// down the "rest" semantics under each combination of rw=/ro=/root=
	// and the bare -ro / -rw flags.
	cases := []struct {
		name  string
		input string
		want  []ExportEntry
	}{
		{
			name:  "rw= alone leaves rest read-only",
			input: "/data -rw=trusted\n",
			want: []ExportEntry{
				{Path: "/data", Client: "trusted", Options: []string{"rw=trusted"}, ReadOnly: false},
				{Path: "/data", Client: "*", Options: []string{"rw=trusted"}, ReadOnly: true},
			},
		},
		{
			name:  "ro= alone leaves rest read-write",
			input: "/data -ro=audit\n",
			want: []ExportEntry{
				{Path: "/data", Client: "audit", Options: []string{"ro=audit"}, ReadOnly: true},
				{Path: "/data", Client: "*", Options: []string{"ro=audit"}, ReadOnly: false},
			},
		},
		{
			name:  "root= alone does not change rest access (still rw)",
			input: "/data -root=admin\n",
			want: []ExportEntry{
				{Path: "/data", Client: "admin", Options: []string{"root=admin"}, ReadOnly: false, NoRootSquash: true},
				{Path: "/data", Client: "*", Options: []string{"root=admin"}, ReadOnly: false, NoRootSquash: false},
			},
		},
		{
			name:  "bare -ro with rw= override: rest stays ro",
			input: "/data -ro,rw=trusted\n",
			want: []ExportEntry{
				{Path: "/data", Client: "trusted", Options: []string{"ro", "rw=trusted"}, ReadOnly: false},
				{Path: "/data", Client: "*", Options: []string{"ro", "rw=trusted"}, ReadOnly: true},
			},
		},
		{
			name:  "access= suppresses implicit rest",
			input: "/data -rw=trusted,access=trusted:audit\n",
			want: []ExportEntry{
				{Path: "/data", Client: "trusted", Options: []string{"rw=trusted", "access=trusted:audit"}, ReadOnly: false},
				{Path: "/data", Client: "audit", Options: []string{"rw=trusted", "access=trusted:audit"}, ReadOnly: true},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseExports(strings.NewReader(c.input), PlatformAIX)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertEntries(t, got, c.want)
		})
	}
}

func TestStripComment(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"foo bar", "foo bar"},
		{"foo # comment", "foo "},
		{"# whole line", ""},
		{`foo \# escaped`, `foo \# escaped`},
		{`foo \\ # real`, `foo \\ `},
		{"", ""},
	}
	for _, c := range cases {
		if got := stripComment(c.in); got != c.want {
			t.Errorf("stripComment(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func assertEntries(t *testing.T, got, want []ExportEntry) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("entry count mismatch: got %d, want %d\ngot:  %#v\nwant: %#v", len(got), len(want), got, want)
	}
	for i := range got {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("entry %d mismatch:\n got:  %#v\n want: %#v", i, got[i], want[i])
		}
	}
}

// exportfs reads an export path in double quotes, and decodes octal escapes
// in it, so "/srv/nfs/sp ace" and /srv/nfs/sp\040ace both export the
// directory `exportfs -v` lists as /srv/nfs/sp ace.
func TestParseLinuxExports_QuotedAndEscapedPaths(t *testing.T) {
	input := `"/srv/nfs/sp ace" 192.0.2.33(rw,no_root_squash)
/srv/nfs/sp\040ace2 192.0.2.34(ro)
"/srv/nfs/q" 192.0.2.35(rw)
`
	got, err := ParseExports(strings.NewReader(input), PlatformLinux)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []ExportEntry{
		{Path: "/srv/nfs/sp ace", Client: "192.0.2.33", Options: []string{"rw", "no_root_squash"}, ReadOnly: false, NoRootSquash: true},
		{Path: "/srv/nfs/sp ace2", Client: "192.0.2.34", Options: []string{"ro"}, ReadOnly: true, NoRootSquash: false},
		{Path: "/srv/nfs/q", Client: "192.0.2.35", Options: []string{"rw"}, ReadOnly: false, NoRootSquash: false},
	}
	assertEntries(t, got, want)
}
