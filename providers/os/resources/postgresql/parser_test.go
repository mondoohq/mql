// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package postgresql

import (
	"errors"
	"io/fs"
	"reflect"
	"sort"
	"testing"
)

// ---------------------------------------------------------------------------
// postgresql.conf
// ---------------------------------------------------------------------------

func TestParseConf_Basic(t *testing.T) {
	reader := func(path string) (string, error) {
		if path != "/etc/postgresql/16/main/postgresql.conf" {
			t.Fatalf("unexpected read of %q", path)
		}
		return `# comment
listen_addresses = 'localhost,10.0.0.5'
port = 5432
ssl = on
ssl_cert_file = '/etc/ssl/server.crt'   # inline comment
shared_buffers = 128MB
log_line_prefix = '%m [%p] '
`, nil
	}
	cfg, err := ParseConf("/etc/postgresql/16/main/postgresql.conf", reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"listen_addresses": "localhost,10.0.0.5",
		"port":             "5432",
		"ssl":              "on",
		"ssl_cert_file":    "/etc/ssl/server.crt",
		"shared_buffers":   "128MB",
		"log_line_prefix":  "%m [%p] ",
	}
	if !reflect.DeepEqual(cfg.Params, want) {
		t.Fatalf("Params = %v, want %v", cfg.Params, want)
	}
	if len(cfg.Files) != 1 || cfg.Files[0] != "/etc/postgresql/16/main/postgresql.conf" {
		t.Errorf("Files = %v", cfg.Files)
	}
}

// TestParseConf_Syntax exercises the per-line grammar: the optional `=`, tab
// separators, case-insensitive keys, values that themselves contain `=`,
// GUC-style enum values, and comment/quote interactions.
func TestParseConf_Syntax(t *testing.T) {
	reader := func(string) (string, error) {
		return "" +
			"port 5432\n" + // no '=' separator
			"max_connections\t=\t100\n" + // tab around '='
			"Work_Mem = 4MB\n" + // mixed-case key normalises to lower
			"log_line_prefix = '%m [%p] user=%u db=%d'\n" + // value contains '='
			"archive_command = 'test ! -f /mnt/%f'\n" + // value contains '!' and spaces
			"password_encryption = scram-sha-256\n" + // bare (unquoted) enum value
			"custom.setting = 'has # hash inside'\n" + // '#' inside quotes is literal
			"empty_value = ''\n" + // explicitly empty quoted value
			"   \t   \n" + // whitespace-only line
			"# a full comment line\n" +
			"", nil
	}
	cfg, err := ParseConf("/x.conf", reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"port":                "5432",
		"max_connections":     "100",
		"work_mem":            "4MB",
		"log_line_prefix":     "%m [%p] user=%u db=%d",
		"archive_command":     "test ! -f /mnt/%f",
		"password_encryption": "scram-sha-256",
		"custom.setting":      "has # hash inside",
		"empty_value":         "",
	}
	if !reflect.DeepEqual(cfg.Params, want) {
		t.Fatalf("Params = %#v\nwant     %#v", cfg.Params, want)
	}
}

func TestParseConf_QuotedAndEscaped(t *testing.T) {
	reader := func(path string) (string, error) {
		return `application_name = 'it''s working'
search_path = '"$user", public'
weird = 'trailing quote missing
`, nil
	}
	cfg, err := ParseConf("/etc/main.conf", reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Params["application_name"] != "it's working" {
		t.Errorf("application_name = %q", cfg.Params["application_name"])
	}
	if cfg.Params["search_path"] != `"$user", public` {
		t.Errorf("search_path = %q", cfg.Params["search_path"])
	}
	// An unterminated quote returns the best-effort remainder.
	if cfg.Params["weird"] != "trailing quote missing" {
		t.Errorf("weird = %q", cfg.Params["weird"])
	}
}

func TestParseConf_CRLF(t *testing.T) {
	reader := func(string) (string, error) {
		return "port = 5432\r\nssl = on\r\n", nil
	}
	cfg, err := ParseConf("/x.conf", reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Params["port"] != "5432" || cfg.Params["ssl"] != "on" {
		t.Fatalf("CRLF not handled: %#v", cfg.Params)
	}
}

func TestParseConf_Includes(t *testing.T) {
	files := map[string]string{
		"/main.conf": `port = 5432
include 'tuning.conf'
include_if_exists 'missing.conf'
include_dir 'conf.d'
log_statement = 'ddl'
`,
		"/tuning.conf": `shared_buffers = 256MB
log_statement = 'all'
`,
		"/conf.d/01-replication.conf": `wal_level = replica
`,
		"/conf.d/README":            `not parsed`,
		"/conf.d/99-overrides.conf": `port = 6543`,
	}
	reader := func(path string) (string, error) {
		v, ok := files[path]
		if !ok {
			return "", &notFoundError{path}
		}
		return v, nil
	}
	dirLister := directoryLister(files)

	cfg, err := ParseConf("/main.conf", reader, dirLister)
	if err != nil {
		t.Fatal(err)
	}

	// log_statement = 'ddl' in main.conf is assigned AFTER the include of
	// tuning.conf (which set 'all'), so last-write-wins keeps 'ddl'.
	if cfg.Params["log_statement"] != "ddl" {
		t.Errorf("log_statement = %q, want ddl", cfg.Params["log_statement"])
	}
	if cfg.Params["shared_buffers"] != "256MB" {
		t.Errorf("shared_buffers = %q, want 256MB", cfg.Params["shared_buffers"])
	}
	if cfg.Params["wal_level"] != "replica" {
		t.Errorf("wal_level = %q, want replica", cfg.Params["wal_level"])
	}
	if cfg.Params["port"] != "6543" {
		t.Errorf("port = %q, want 6543 (override from 99-overrides.conf)", cfg.Params["port"])
	}
	// README without a .conf suffix must be skipped.
	if _, present := cfg.Params["not"]; present {
		t.Errorf("non-.conf file in include_dir was parsed")
	}
}

// TestParseConf_IncludeDirNilLister confirms include_dir is a no-op (rather
// than an error) when the caller can't enumerate directories.
func TestParseConf_IncludeDirNilLister(t *testing.T) {
	reader := func(path string) (string, error) {
		if path == "/main.conf" {
			return "port = 5432\ninclude_dir 'conf.d'\n", nil
		}
		return "", &notFoundError{path}
	}
	cfg, err := ParseConf("/main.conf", reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Params["port"] != "5432" {
		t.Fatalf("params = %#v", cfg.Params)
	}
}

// TestParseConf_IncludeCycle makes sure a self- or mutually-referential include
// chain terminates instead of recursing forever.
func TestParseConf_IncludeCycle(t *testing.T) {
	files := map[string]string{
		"/a.conf": "shared_buffers = 128MB\ninclude 'b.conf'\n",
		"/b.conf": "work_mem = 8MB\ninclude './a.conf'\n", // points back at a via a different spelling
	}
	reader := func(path string) (string, error) {
		v, ok := files[path]
		if !ok {
			return "", &notFoundError{path}
		}
		return v, nil
	}
	cfg, err := ParseConf("/a.conf", reader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Params["shared_buffers"] != "128MB" || cfg.Params["work_mem"] != "8MB" {
		t.Fatalf("params = %#v", cfg.Params)
	}
}

// TestParseConf_IncludeReadErrorPropagates ensures a hard read error on a
// mandatory `include` is surfaced (only `include_if_exists` swallows it).
func TestParseConf_IncludeReadErrorPropagates(t *testing.T) {
	reader := func(path string) (string, error) {
		if path == "/main.conf" {
			return "include 'broken.conf'\n", nil
		}
		return "", &notFoundError{path}
	}
	if _, err := ParseConf("/main.conf", reader, nil); err == nil {
		t.Fatal("expected error from a missing mandatory include, got nil")
	}
}

// include_dir loads only `*.conf` files whose name does not start with a dot
// (PostgreSQL's ParseConfigDirectory). The Ubuntu sweep host carried
// conf.d/.hidden.conf, which `postgres -C log_min_duration_statement`
// confirmed the server ignores, and conf.d/30-backup.conf~.
// Fails if includeDirFiles stops skipping dotfiles.
func TestParseConf_IncludeDirSkipsDotfiles(t *testing.T) {
	files := map[string]string{
		"/etc/postgresql/16/main/postgresql.conf":        "include_dir = 'conf.d'\n",
		"/etc/postgresql/16/main/conf.d/10-sweep.conf":   "port = 5433\n",
		"/etc/postgresql/16/main/conf.d/.hidden.conf":    "log_min_duration_statement = 0\n",
		"/etc/postgresql/16/main/conf.d/30-backup.conf~": "port = 7777\n",
	}
	cfg, err := ParseConf("/etc/postgresql/16/main/postgresql.conf", mapReader(files), directoryLister(files))
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := cfg.Params["log_min_duration_statement"]; ok {
		t.Errorf("log_min_duration_statement = %q from a dotfile, want unset", v)
	}
	if cfg.Params["port"] != "5433" {
		t.Errorf("port = %q, want 5433", cfg.Params["port"])
	}
	want := []string{"/etc/postgresql/16/main/postgresql.conf", "/etc/postgresql/16/main/conf.d/10-sweep.conf"}
	if !reflect.DeepEqual(cfg.Files, want) {
		t.Errorf("Files = %v, want %v", cfg.Files, want)
	}
}

// A missing include_if_exists target contributed nothing, so it must not be
// listed as a configuration file. Fails if parseConfRec appends to Files
// before the read succeeds.
func TestParseConf_MissingIncludeIfExistsNotListed(t *testing.T) {
	files := map[string]string{
		"/main.conf": "port = 5434\ninclude_if_exists 'missing.conf'\n",
	}
	cfg, err := ParseConf("/main.conf", mapReader(files), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.Files, []string{"/main.conf"}) {
		t.Errorf("Files = %v, want only /main.conf", cfg.Files)
	}
}

// include_if_exists only forgives a missing file. A fragment the scan may not
// read can hold the very setting under audit, so the refusal must surface.
// Fails if the include_if_exists branch swallows every error again.
func TestParseConf_IncludeIfExistsRefusalPropagates(t *testing.T) {
	files := map[string]string{
		"/main.conf":   "include_if_exists 'secret.conf'\n",
		"/secret.conf": "ssl = off\n",
	}
	_, err := ParseConf("/main.conf", mapReader(files, "/secret.conf"), nil)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want a permission error", err)
	}
}

// A plain include of a missing file inside an include_if_exists target is
// an error for the server, and must not be swallowed as if the optional
// target itself were missing.
func TestParseConf_MissingIncludeNestedInIncludeIfExists(t *testing.T) {
	files := map[string]string{
		"/main.conf":   "include_if_exists 'exists.conf'\n",
		"/exists.conf": "include 'gone.conf'\n",
	}
	_, err := ParseConf("/main.conf", mapReader(files), nil)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want the nested include's not-found error", err)
	}
}

func TestSplitListParam(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"localhost", []string{"localhost"}},
		{"localhost, 10.0.0.5", []string{"localhost", "10.0.0.5"}},
		{`"localhost",10.0.0.5`, []string{"localhost", "10.0.0.5"}},
		{"pg_stat_statements,auto_explain", []string{"pg_stat_statements", "auto_explain"}},
		{"  pg_stat_statements   auto_explain  ", []string{"pg_stat_statements", "auto_explain"}},
		{"*", []string{"*"}},
	}
	for _, tc := range tests {
		got := SplitListParam(tc.in)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("SplitListParam(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestIsTruthy(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"on", true}, {"On", true}, {"ON", true},
		{"true", true}, {"yes", true}, {"1", true},
		{"off", false}, {"false", false}, {"no", false}, {"0", false},
		{"", false}, {"  on  ", true}, {"enabled", false},
		// PostgreSQL accepts any unique prefix (parse_bool). The sweep wrote
		// `log_connections = t` and `postgres -C log_connections` answered on.
		{"t", true}, {"tr", true}, {"T", true}, {"y", true}, {"ye", true},
		{"f", false}, {"n", false}, {"of", false},
		// `o` is ambiguous between on and off; `01` and `trueish` are not booleans.
		{"o", false}, {"01", false}, {"trueish", false}, {"onoff", false},
	} {
		if got := IsTruthy(tc.in); got != tc.want {
			t.Errorf("IsTruthy(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseBoolRejectsNonBooleans(t *testing.T) {
	for _, in := range []string{"", "o", "01", "enabled", "all", "receipt"} {
		if _, ok := ParseBool(in); ok {
			t.Errorf("ParseBool(%q) accepted a value PostgreSQL rejects", in)
		}
	}
	for _, in := range []string{"of", "OFF", "no", "f", "0"} {
		if v, ok := ParseBool(in); !ok || v {
			t.Errorf("ParseBool(%q) = %v, %v, want false, true", in, v, ok)
		}
	}
}

// PostgreSQL 18 turned log_connections into a list. `on` still works and
// stands for receipt,authentication,authorization.
func TestLogConnectionsEnabled(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"on", true}, {"t", true}, {"off", false}, {"", false},
		{"all", true}, {"ALL", true},
		{"receipt,authentication,authorization", true},
		{"authorization, receipt, authentication, setup_durations", true},
		{"receipt", false},
		{"receipt,authentication", false},
		{"setup_durations", false},
	} {
		if got := LogConnectionsEnabled(tc.in); got != tc.want {
			t.Errorf("LogConnectionsEnabled(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// pg_hba.conf
// ---------------------------------------------------------------------------

func TestParseHba_AllConnectionTypes(t *testing.T) {
	content := `# TYPE  DATABASE        USER            ADDRESS                 METHOD
local        all             postgres                                peer
local        all             all                                     scram-sha-256
host         all             all             127.0.0.1/32            md5
hostssl      all             all             0.0.0.0/0               scram-sha-256
hostnossl    all             all             10.0.0.0/8              reject
host         all             all             ::1/128                 trust
hostgssenc   all             all             192.168.0.0/16          gss
hostnogssenc replication     repl            samenet                 scram-sha-256
`
	rules := ParseHba(content)
	if len(rules) != 8 {
		t.Fatalf("got %d rules, want 8: %+v", len(rules), rules)
	}

	want := []HbaRule{
		{Type: "local", Database: "all", User: "postgres", Address: "", AuthMethod: "peer"},
		{Type: "local", Database: "all", User: "all", Address: "", AuthMethod: "scram-sha-256"},
		{Type: "host", Database: "all", User: "all", Address: "127.0.0.1/32", AuthMethod: "md5"},
		{Type: "hostssl", Database: "all", User: "all", Address: "0.0.0.0/0", AuthMethod: "scram-sha-256"},
		{Type: "hostnossl", Database: "all", User: "all", Address: "10.0.0.0/8", AuthMethod: "reject"},
		{Type: "host", Database: "all", User: "all", Address: "::1/128", AuthMethod: "trust"},
		{Type: "hostgssenc", Database: "all", User: "all", Address: "192.168.0.0/16", AuthMethod: "gss"},
		{Type: "hostnogssenc", Database: "replication", User: "repl", Address: "samenet", AuthMethod: "scram-sha-256"},
	}
	for i, w := range want {
		g := rules[i]
		if g.Type != w.Type || g.Database != w.Database || g.User != w.User || g.Address != w.Address || g.AuthMethod != w.AuthMethod {
			t.Errorf("rule %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestParseHba_NetmaskForm(t *testing.T) {
	content := `host  all  all  192.168.1.0  255.255.255.0  md5
host  all  all  10.0.0.0     255.0.0.0      trust  clientcert=verify-ca
`
	rules := ParseHba(content)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Address != "192.168.1.0 255.255.255.0" || rules[0].AuthMethod != "md5" {
		t.Errorf("rule 0 = %+v", rules[0])
	}
	if rules[1].Address != "10.0.0.0 255.0.0.0" || rules[1].AuthMethod != "trust" {
		t.Errorf("rule 1 = %+v", rules[1])
	}
	if rules[1].Options["clientcert"] != "verify-ca" {
		t.Errorf("rule 1 options = %v", rules[1].Options)
	}
}

func TestParseHba_OptionsAndQuoting(t *testing.T) {
	content := `hostssl replication repuser 10.0.0.0/8 cert clientcert=verify-full
host    db1,db2     "user one"  192.168.1.0/24  ldap  ldapserver="ldap.example.com"  ldapport=389
host    all         +admins     ::1/128         md5   map=omicron
`
	rules := ParseHba(content)
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3: %+v", len(rules), rules)
	}
	if rules[0].Options["clientcert"] != "verify-full" {
		t.Errorf("rule 0 options = %v", rules[0].Options)
	}
	// Quoted user token with an embedded space survives tokenization.
	if rules[1].User != "user one" {
		t.Errorf("rule 1 user = %q", rules[1].User)
	}
	if rules[1].Database != "db1,db2" {
		t.Errorf("rule 1 database = %q", rules[1].Database)
	}
	if rules[1].Options["ldapserver"] != "ldap.example.com" || rules[1].Options["ldapport"] != "389" {
		t.Errorf("rule 1 options = %v", rules[1].Options)
	}
	if rules[2].User != "+admins" || rules[2].Options["map"] != "omicron" {
		t.Errorf("rule 2 = %+v", rules[2])
	}
}

// TestParseHba_InlineComments verifies that an unquoted `#` truncates the rule
// (so its text does not leak into the auth-method options) while a `#` inside a
// quoted token stays literal.
func TestParseHba_InlineComments(t *testing.T) {
	content := `local all all peer          # allow local unix-socket logins
host  all all 127.0.0.1/32 md5  # ipv4 loopback
host  all "od#d"  ::1/128    trust
`
	rules := ParseHba(content)
	if len(rules) != 3 {
		t.Fatalf("got %d rules, want 3: %+v", len(rules), rules)
	}
	if len(rules[0].Options) != 0 {
		t.Errorf("rule 0 leaked comment into options: %v", rules[0].Options)
	}
	if rules[1].AuthMethod != "md5" || len(rules[1].Options) != 0 {
		t.Errorf("rule 1 = %+v (comment should be stripped)", rules[1])
	}
	if rules[2].User != "od#d" {
		t.Errorf("rule 2 user = %q, want od#d (# inside quotes is literal)", rules[2].User)
	}
}

// TestParseHba_LineContinuation checks that a trailing backslash joins physical
// lines into one record and that the record's LineNumber is the first physical
// line.
func TestParseHba_LineContinuation(t *testing.T) {
	content := `# header
host    all             all \
        127.0.0.1/32 \
        md5 clientcert=verify-full
local   all             all             peer
`
	rules := ParseHba(content)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2: %+v", len(rules), rules)
	}
	r := rules[0]
	if r.Type != "host" || r.Database != "all" || r.User != "all" || r.Address != "127.0.0.1/32" || r.AuthMethod != "md5" {
		t.Errorf("continued rule = %+v", r)
	}
	if r.Options["clientcert"] != "verify-full" {
		t.Errorf("continued rule options = %v", r.Options)
	}
	// The continued record begins on physical line 2 (line 1 is the comment).
	if r.LineNumber != 2 {
		t.Errorf("continued rule LineNumber = %d, want 2", r.LineNumber)
	}
	if rules[1].LineNumber != 5 {
		t.Errorf("second rule LineNumber = %d, want 5", rules[1].LineNumber)
	}
}

func TestParseHba_LineNumbers(t *testing.T) {
	content := `# comment line 1

local all all peer
# another comment
host all all 127.0.0.1/32 md5
`
	rules := ParseHba(content)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].LineNumber != 3 {
		t.Errorf("rule 0 LineNumber = %d, want 3", rules[0].LineNumber)
	}
	if rules[1].LineNumber != 5 {
		t.Errorf("rule 1 LineNumber = %d, want 5", rules[1].LineNumber)
	}
}

func TestParseHba_SkipsMalformedAndIncludes(t *testing.T) {
	content := `local
host all all
not_a_real_type all all 127.0.0.1/32 md5
include "extra_hba.conf"
include_dir "hba.d"
`
	rules := ParseHba(content)
	if len(rules) != 0 {
		t.Errorf("malformed/include lines produced %d rules: %+v", len(rules), rules)
	}
}

// The PostgreSQL 16 sweep fixture: pg_hba.conf ends with an
// include_if_exists whose target holds a trust rule. pg_hba_file_rules listed
// it as file_name=/etc/postgresql/16/main/sweep_hba_extra.conf, line 1, and
// `postgresql.hba.rules.none(authMethod == "trust")` passed because the
// include was dropped. Fails if walkAuthFile stops following includes.
func TestParseHbaFile_FollowsIncludes(t *testing.T) {
	const dir = "/etc/postgresql/16/main"
	files := map[string]string{
		dir + "/pg_hba.conf": `local   all             postgres                                peer
host    all          all        198.51.100.0/24 \
        md5
include_if_exists sweep_hba_extra.conf
include_if_exists absent.conf
include /etc/postgresql/shared_hba.conf
include_dir hba.d
local   all             all                                     reject
`,
		dir + "/sweep_hba_extra.conf":     "host all all 203.0.113.0/24 trust\n",
		"/etc/postgresql/shared_hba.conf": "hostssl all all 10.0.0.0/8 cert\n",
		dir + "/hba.d/20-b.conf":          "host all all 192.0.2.2/32 md5\n",
		dir + "/hba.d/10-a.conf":          "\nhost all all 192.0.2.1/32 md5\n",
		dir + "/hba.d/.10-hidden.conf":    "host all all 0.0.0.0/0 trust\n",
		dir + "/hba.d/README":             "host all all 0.0.0.0/0 trust\n",
	}
	rules, err := ParseHbaFile(dir+"/pg_hba.conf", mapReader(files), directoryLister(files))
	if err != nil {
		t.Fatal(err)
	}
	type got struct {
		file    string
		line    int
		address string
		method  string
	}
	var out []got
	for _, r := range rules {
		out = append(out, got{r.File, r.LineNumber, r.Address, r.AuthMethod})
	}
	want := []got{
		{dir + "/pg_hba.conf", 1, "", "peer"},
		{dir + "/pg_hba.conf", 2, "198.51.100.0/24", "md5"},
		{dir + "/sweep_hba_extra.conf", 1, "203.0.113.0/24", "trust"},
		{"/etc/postgresql/shared_hba.conf", 1, "10.0.0.0/8", "cert"},
		{dir + "/hba.d/10-a.conf", 2, "192.0.2.1/32", "md5"},
		{dir + "/hba.d/20-b.conf", 1, "192.0.2.2/32", "md5"},
		{dir + "/pg_hba.conf", 8, "", "reject"},
	}
	if !reflect.DeepEqual(out, want) {
		t.Errorf("rules =\n%v\nwant\n%v", out, want)
	}
}

func TestParseHbaFile_IncludeErrors(t *testing.T) {
	t.Run("missing mandatory include", func(t *testing.T) {
		files := map[string]string{"/pg_hba.conf": "include gone.conf\n"}
		if _, err := ParseHbaFile("/pg_hba.conf", mapReader(files), nil); err == nil {
			t.Fatal("want an error for a missing include target")
		}
	})
	t.Run("unreadable include_if_exists", func(t *testing.T) {
		files := map[string]string{
			"/pg_hba.conf": "include_if_exists extra.conf\n",
			"/extra.conf":  "host all all 0.0.0.0/0 trust\n",
		}
		_, err := ParseHbaFile("/pg_hba.conf", mapReader(files, "/extra.conf"), nil)
		if !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v, want a permission error", err)
		}
	})
	// Only the include_if_exists target itself may be missing. A plain
	// include inside it that names a missing file is still an error.
	t.Run("missing include nested in include_if_exists", func(t *testing.T) {
		files := map[string]string{
			"/pg_hba.conf": "include_if_exists exists.conf\n",
			"/exists.conf": "include gone.conf\n",
		}
		_, err := ParseHbaFile("/pg_hba.conf", mapReader(files), nil)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("err = %v, want the nested include's not-found error", err)
		}
	})
	t.Run("include cycle terminates", func(t *testing.T) {
		files := map[string]string{
			"/a.conf": "include b.conf\nlocal all all peer\n",
			"/b.conf": "include ./a.conf\nlocal all all trust\n",
		}
		rules, err := ParseHbaFile("/a.conf", mapReader(files), nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 2 {
			t.Fatalf("got %d rules, want 2: %+v", len(rules), rules)
		}
	})
}

// A three-token line starting with `include` is not a directive (PostgreSQL
// requires exactly two fields), and must not be followed.
func TestParseHbaFile_IncludeNeedsExactlyTwoTokens(t *testing.T) {
	files := map[string]string{
		"/pg_hba.conf": "include extra.conf extra\n",
		"/extra.conf":  "host all all 0.0.0.0/0 trust\n",
	}
	rules, err := ParseHbaFile("/pg_hba.conf", mapReader(files), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Fatalf("got %+v, want no rules", rules)
	}
}

func TestParseHba_Empty(t *testing.T) {
	for _, in := range []string{"", "\n\n\n", "# only comments\n#\n"} {
		if rules := ParseHba(in); len(rules) != 0 {
			t.Errorf("ParseHba(%q) = %+v, want empty", in, rules)
		}
	}
}

// ---------------------------------------------------------------------------
// pg_ident.conf
// ---------------------------------------------------------------------------

func TestParseIdent(t *testing.T) {
	content := `# MAPNAME  SYSTEM-USERNAME       PG-USERNAME
mymap       /^(.*)@example\.com$      \1
mymap       alice                     postgres
peer        "/^(.*)$"                 \1
`
	maps := ParseIdent(content)
	if len(maps) != 3 {
		t.Fatalf("got %d, want 3: %+v", len(maps), maps)
	}
	if maps[0].MapName != "mymap" || maps[0].SystemUsername != `/^(.*)@example\.com$` || maps[0].PgUsername != `\1` {
		t.Errorf("entry 0 = %+v", maps[0])
	}
	if maps[1].SystemUsername != "alice" || maps[1].PgUsername != "postgres" {
		t.Errorf("entry 1 = %+v", maps[1])
	}
	// A quoted regex pattern keeps its content (quotes removed by tokenizer).
	if maps[2].SystemUsername != "/^(.*)$" || maps[2].PgUsername != `\1` {
		t.Errorf("entry 2 = %+v", maps[2])
	}
	if maps[0].LineNumber != 2 || maps[2].LineNumber != 4 {
		t.Errorf("line numbers wrong: %d, %d", maps[0].LineNumber, maps[2].LineNumber)
	}
}

func TestParseIdent_InlineCommentAndContinuation(t *testing.T) {
	content := `mymap  bob  postgres   # bob is a superuser
krb    /^(.*)@EXAMPLE\.COM$ \
       \1
`
	maps := ParseIdent(content)
	if len(maps) != 2 {
		t.Fatalf("got %d, want 2: %+v", len(maps), maps)
	}
	if maps[0].MapName != "mymap" || maps[0].SystemUsername != "bob" || maps[0].PgUsername != "postgres" {
		t.Errorf("entry 0 = %+v", maps[0])
	}
	if maps[1].MapName != "krb" || maps[1].SystemUsername != `/^(.*)@EXAMPLE\.COM$` || maps[1].PgUsername != `\1` {
		t.Errorf("entry 1 = %+v", maps[1])
	}
	if maps[1].LineNumber != 2 {
		t.Errorf("continued mapping LineNumber = %d, want 2", maps[1].LineNumber)
	}
}

func TestParseIdent_SkipsMalformed(t *testing.T) {
	content := `mymap alice
onlyonetoken
mymap bob postgres
`
	maps := ParseIdent(content)
	if len(maps) != 1 {
		t.Fatalf("got %d, want 1: %+v", len(maps), maps)
	}
	if maps[0].SystemUsername != "bob" {
		t.Errorf("entry = %+v", maps[0])
	}
}

// ---------------------------------------------------------------------------
// preprocessing helpers
// ---------------------------------------------------------------------------

// pg_ident.conf accepts the same inclusion directives as pg_hba.conf from
// PostgreSQL 16 on. Fails if ParseIdentFile stops following includes.
func TestParseIdentFile_FollowsIncludes(t *testing.T) {
	files := map[string]string{
		"/etc/pg/pg_ident.conf":  "sweepmap ubuntu postgres\ninclude_dir ident.d\nothermap root admin\n",
		"/etc/pg/ident.d/a.conf": "# extra\nsweepmap deploy app\n",
	}
	maps, err := ParseIdentFile("/etc/pg/pg_ident.conf", mapReader(files), directoryLister(files))
	if err != nil {
		t.Fatal(err)
	}
	want := []IdentMapping{
		{File: "/etc/pg/pg_ident.conf", LineNumber: 1, MapName: "sweepmap", SystemUsername: "ubuntu", PgUsername: "postgres"},
		{File: "/etc/pg/ident.d/a.conf", LineNumber: 2, MapName: "sweepmap", SystemUsername: "deploy", PgUsername: "app"},
		{File: "/etc/pg/pg_ident.conf", LineNumber: 3, MapName: "othermap", SystemUsername: "root", PgUsername: "admin"},
	}
	if !reflect.DeepEqual(maps, want) {
		t.Errorf("mappings =\n%+v\nwant\n%+v", maps, want)
	}
}

func TestStripCommentAndContinuation(t *testing.T) {
	tests := []struct {
		in       string
		wantBody string
		wantCont bool
	}{
		{"host all all 127.0.0.1/32 md5", "host all all 127.0.0.1/32 md5", false},
		{"host all all peer   # comment", "host all all peer", false},
		{"# whole line comment", "", false},
		{`host all "a#b" ::1/128 trust`, `host all "a#b" ::1/128 trust`, false},
		{`host all all \`, "host all all ", true},
		{`host all all 127.0.0.1/32 \  `, "host all all 127.0.0.1/32 ", true}, // trailing spaces after backslash
		{`host all all peer \ # not a continuation because comment wins`, "host all all peer \\", false},
		{`"unterminated \`, `"unterminated \`, false}, // backslash inside an open quote is not a continuation
	}
	for _, tc := range tests {
		body, cont := stripCommentAndContinuation(tc.in)
		if body != tc.wantBody || cont != tc.wantCont {
			t.Errorf("stripCommentAndContinuation(%q) = (%q, %v), want (%q, %v)", tc.in, body, cont, tc.wantBody, tc.wantCont)
		}
	}
}

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

type notFoundError struct{ path string }

func (e *notFoundError) Error() string { return "not found: " + e.path }

// Unwrap lets the parser tell a missing file from a refused one, the way the
// os provider's reader reports a missing file.
func (e *notFoundError) Unwrap() error { return fs.ErrNotExist }

// mapReader serves files from an in-memory map. Paths in denied fail with a
// permission error instead, the way a fragment readable only by the
// postgres user fails for a non-root scan.
func mapReader(files map[string]string, denied ...string) FileReader {
	return func(path string) (string, error) {
		for _, d := range denied {
			if d == path {
				return "", fs.ErrPermission
			}
		}
		v, ok := files[path]
		if !ok {
			return "", &notFoundError{path}
		}
		return v, nil
	}
}

// directoryLister builds a dirLister over an in-memory file map that returns
// the immediate children of a directory in sorted order, mirroring the
// C-locale ordering PostgreSQL applies to include_dir.
func directoryLister(files map[string]string) func(string) ([]string, error) {
	return func(dir string) ([]string, error) {
		var out []string
		prefix := dir + "/"
		for p := range files {
			if len(p) > len(prefix) && p[:len(prefix)] == prefix && !contains(p[len(prefix):], "/") {
				out = append(out, p)
			}
		}
		sort.Strings(out)
		return out, nil
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestConfOverlay(t *testing.T) {
	c := &Conf{Params: map[string]string{"ssl": "on", "port": "5443"}, Files: []string{"/etc/postgresql/18/main/postgresql.conf"}}
	c.Overlay(&Conf{Params: map[string]string{"ssl": "off"}, Files: []string{"/var/lib/postgresql/18/main/postgresql.auto.conf"}})
	if want := map[string]string{"ssl": "off", "port": "5443"}; !reflect.DeepEqual(c.Params, want) {
		t.Errorf("params = %v, want %v", c.Params, want)
	}
	if want := []string{"/etc/postgresql/18/main/postgresql.conf", "/var/lib/postgresql/18/main/postgresql.auto.conf"}; !reflect.DeepEqual(c.Files, want) {
		t.Errorf("files = %v, want %v", c.Files, want)
	}
}
