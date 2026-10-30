// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestIsYes(t *testing.T) {
	for _, s := range []string{"YES", "Y", "ON", "1"} {
		if !isYes(s) {
			t.Errorf("isYes(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"NO", "N", "OFF", "0", ""} {
		if isYes(s) {
			t.Errorf("isYes(%q) = true, want false", s)
		}
	}
}

func TestGrantee(t *testing.T) {
	if got := grantee("appuser", "%"); got != "'appuser'@'%'" {
		t.Errorf("grantee = %q", got)
	}
	if got := grantee("", "localhost"); got != "''@'localhost'" {
		t.Errorf("anonymous grantee = %q", got)
	}
}

func TestIdentifierBuilders(t *testing.T) {
	if got := userResourceID("SRV", "root", "localhost"); got != "SRV/user/root@localhost" {
		t.Errorf("userResourceID = %q", got)
	}
	if got := schemaResourceID("SRV", "appdb"); got != "SRV/schema/appdb" {
		t.Errorf("schemaResourceID = %q", got)
	}
	// composite privilege id must vary by grantee, scope, object, and type
	a := privilegeResourceID("p", "'app'@'%'", "GLOBAL", "", "", "SUPER")
	b := privilegeResourceID("p", "'app'@'%'", "SCHEMA", "appdb", "", "SELECT")
	c := privilegeResourceID("p", "'app'@'%'", "TABLE", "appdb", "t1", "SELECT")
	if a == b || b == c || a == c {
		t.Errorf("privilegeResourceID collides: %q %q %q", a, b, c)
	}
}

// schema.privileges and table.privileges list every grantee under one parent,
// so two accounts holding the same privilege on the same object must get
// distinct ids. Captured on MySQL 8.4: 'mqlapp'@'10.0.0.1' and 'mql_ro'@'%'
// both hold SELECT on the mqlapp schema, and mysql.user is readable by both
// 'mysql.session'@'localhost' and 'mqlmid'@'%'.
func TestPrivilegeResourceIDIncludesGrantee(t *testing.T) {
	cases := []struct {
		scope, schema, table, priv string
		grantees                   []string
	}{
		{"SCHEMA", "mqlapp", "", "SELECT", []string{"'mqlapp'@'10.0.0.1'", "'mql_ro'@'%'"}},
		{"TABLE", "mysql", "user", "SELECT", []string{"'mysql.session'@'localhost'", "'mqlmid'@'%'"}},
		// a MariaDB role has an empty host
		{"SCHEMA", "mqlapp", "", "SELECT", []string{"'mql_ro'@''", "'mql_ro'@'%'"}},
	}
	for _, tc := range cases {
		a := privilegeResourceID("srv/schema/"+tc.schema, tc.grantees[0], tc.scope, tc.schema, tc.table, tc.priv)
		b := privilegeResourceID("srv/schema/"+tc.schema, tc.grantees[1], tc.scope, tc.schema, tc.table, tc.priv)
		if a == b {
			t.Errorf("grantees %v share privilege id %q", tc.grantees, a)
		}
	}
}

// MariaDB 10.10+ registers uuid twice in information_schema.PLUGINS, once as
// DATA TYPE and once as FUNCTION; both rows must survive.
func TestPluginResourceIDIncludesType(t *testing.T) {
	a := pluginResourceID("srv", "uuid", "DATA TYPE")
	b := pluginResourceID("srv", "uuid", "FUNCTION")
	if a == b {
		t.Errorf("plugin rows of different type share id %q", a)
	}
}

// The hasPassword field must be derived from a server-side emptiness test, so
// that mysql.user.authentication_string (the credential) never crosses the
// connection. These tests pin both halves of that: the SQL projection and the
// mapping of its result.

func TestHasPasswordExprDoesNotSelectTheCredential(t *testing.T) {
	for _, alias := range []string{"", "u."} {
		expr := hasPasswordExpr(alias)
		want := "LENGTH(COALESCE(" + alias + "authentication_string, '')) > 0"
		if expr != want {
			t.Errorf("hasPasswordExpr(%q) = %q, want %q", alias, expr, want)
		}
		// the column may only appear inside LENGTH(), never as a bare
		// projection that would transfer the hash itself
		if !strings.Contains(expr, "LENGTH(") {
			t.Errorf("hasPasswordExpr(%q) = %q, must project through LENGTH", alias, expr)
		}
	}
}

// stripLengthCalls removes every LENGTH(...) call, balancing parentheses, so
// what remains is what the server would project as data.
func stripLengthCalls(s string) string {
	for {
		i := strings.Index(s, "LENGTH(")
		if i < 0 {
			return s
		}
		depth, j := 0, i+len("LENGTH")
		for ; j < len(s); j++ {
			if s[j] == '(' {
				depth++
			} else if s[j] == ')' {
				depth--
				if depth == 0 {
					break
				}
			}
		}
		s = s[:i] + s[j+1:]
	}
}

var allUserSchemas = map[string]userSchema{
	"mysql":                  userSchemaMySQL,
	"mariadb":                userSchemaMariaDB,
	"mariadb no global_priv": userSchemaMariaDBNoGlobalPriv,
	"mariadb before 10.4":    userSchemaMariaDBLegacy,
}

func TestUserColumnsNeverProjectsTheCredential(t *testing.T) {
	for name, schema := range allUserSchemas {
		for _, alias := range []string{"", "u."} {
			cols := userColumns(alias, schema)
			// the credential columns may only be read inside LENGTH(), never
			// projected, or the hash would cross the connection
			rest := stripLengthCalls(cols)
			for _, credential := range []string{"authentication_string", "Password"} {
				if strings.Contains(rest, credential) {
					t.Errorf("%s/%q projects %s outside LENGTH(): %s", name, alias, credential, cols)
				}
			}
			if !strings.Contains(cols, "LENGTH(") {
				t.Errorf("%s/%q has no hasPassword projection: %s", name, alias, cols)
			}
		}
	}
}

// countSelectColumns counts comma-separated projections at parenthesis depth
// zero, so commas inside COALESCE() and LENGTH() do not inflate the count.
func countSelectColumns(list string) int {
	depth, n := 0, 1
	for _, r := range list {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				n++
			}
		}
	}
	return n
}

func TestUserColumnsCountMatchesScan(t *testing.T) {
	// the scan targets in scanMysqldbUser are positional
	want := map[userSchema]int{
		userSchemaMySQL:               11,
		userSchemaMariaDB:             12,
		userSchemaMariaDBNoGlobalPriv: 12,
		userSchemaMariaDBLegacy:       9,
	}
	for name, schema := range allUserSchemas {
		for _, alias := range []string{"", "u."} {
			if got := countSelectColumns(userColumns(alias, schema)); got != want[schema] {
				t.Errorf("%s/%q userColumns has %d columns, want %d", name, alias, got, want[schema])
			}
		}
	}
}

func TestLegacyMariaDBReadsThePasswordColumn(t *testing.T) {
	// MariaDB 10.1 and 10.3 keep the hash in Password with plugin and
	// authentication_string empty
	expr := legacyHasPasswordExpr("u.")
	if !strings.Contains(expr, "u.Password") || !strings.Contains(expr, "u.authentication_string") {
		t.Errorf("legacyHasPasswordExpr does not consider both credential columns: %s", expr)
	}
	if !strings.Contains(userColumns("u.", userSchemaMariaDBLegacy), "mysql_native_password") {
		t.Error("legacy layout does not name the built-in plugin for an empty plugin column")
	}
}

func TestMariadbUserSchema(t *testing.T) {
	cases := map[string]userSchema{
		"10.1.48-MariaDB-0ubuntu0.18.04.1":  userSchemaMariaDBLegacy,
		"10.3.39-MariaDB-0ubuntu0.20.04.2":  userSchemaMariaDBLegacy,
		"10.4.0-MariaDB":                    userSchemaMariaDB,
		"10.6.28-MariaDB-ubu2204":           userSchemaMariaDB,
		"10.11.14-MariaDB-0ubuntu0.24.04.1": userSchemaMariaDB,
		"11.8.6-MariaDB-5ubuntu0.1":         userSchemaMariaDB,
		"13.0.2-MariaDB":                    userSchemaMariaDB,
	}
	for v, want := range cases {
		if got := mariadbUserSchema(v); got != want {
			t.Errorf("mariadbUserSchema(%q) = %v, want %v", v, got, want)
		}
	}
}

// Values as JSON_VALUE returns them from mysql.global_priv on MariaDB 10.6.
func TestMariadbGlobalPriv(t *testing.T) {
	str := func(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
	null := sql.NullString{}

	// mqllocked: "account_locked":true, which JSON_VALUE returns as 1
	locked, life, changed := mariadbGlobalPriv(str("1"), null, str("1790993093"))
	if locked == nil || !*locked {
		t.Errorf("account_locked true read as %v", locked)
	}
	if life.Valid {
		t.Errorf("absent password_lifetime read as %v", life)
	}
	if changed == nil || changed.Unix() != 1790993093 {
		t.Errorf("password_last_changed = %v", changed)
	}

	// an ordinary account has no account_locked key: unlocked, not unknown
	locked, _, _ = mariadbGlobalPriv(null, null, str("1790993093"))
	if locked == nil || *locked {
		t.Errorf("absent account_locked read as %v, want false", locked)
	}

	// mqllife: INTERVAL 30 DAY; mqlnever: NEVER
	if _, life, _ = mariadbGlobalPriv(null, str("30"), null); !life.Valid || life.Int64 != 30 {
		t.Errorf("password_lifetime 30 read as %v", life)
	}
	if _, life, _ = mariadbGlobalPriv(null, str("0"), null); !life.Valid || life.Int64 != 0 {
		t.Errorf("password_lifetime 0 (never) read as %v", life)
	}
	// mqlexpired: PASSWORD EXPIRE writes password_last_changed 0 and
	// password_lifetime -1 (server default)
	_, life, changed = mariadbGlobalPriv(null, str("-1"), str("0"))
	if life.Valid {
		t.Errorf("password_lifetime -1 read as %v, want the default", life)
	}
	if changed != nil {
		t.Errorf("password_last_changed 0 read as %v, want null", changed)
	}
}

// Values from SHOW ALL SLAVES STATUS on MariaDB 10.6 with a named connection
// to a source that does not use TLS.
func TestMariadbChannelFromStatus(t *testing.T) {
	ch := mariadbChannelFromStatus(map[string]string{
		"Connection_name":               "mqlchan",
		"Slave_IO_State":                "",
		"Master_Host":                   "192.0.2.10",
		"Master_User":                   "r",
		"Master_Port":                   "3306",
		"Master_SSL_Allowed":            "No",
		"Master_SSL_Verify_Server_Cert": "No",
	})
	if ch.channel != "mqlchan" || ch.host != "192.0.2.10" {
		t.Errorf("channel = %+v", ch)
	}
	if ch.sslAllowed || ch.sslVerifyServerCert {
		t.Errorf("No read as true: %+v", ch)
	}
	ch = mariadbChannelFromStatus(map[string]string{
		"Connection_name":               "",
		"Master_Host":                   "192.0.2.11",
		"Master_SSL_Allowed":            "Yes",
		"Master_SSL_Verify_Server_Cert": "Yes",
	})
	if ch.channel != "" || !ch.sslAllowed || !ch.sslVerifyServerCert {
		t.Errorf("default connection with TLS = %+v", ch)
	}
}

func TestCreateOptionsEncrypted(t *testing.T) {
	cases := map[string]bool{
		"`ENCRYPTED`='YES'":                 true, // MariaDB 10.6, ENCRYPTED=YES
		"ENCRYPTION='Y'":                    true, // MySQL 8
		"row_format=DYNAMIC ENCRYPTION='Y'": true,
		"`ENCRYPTED`='NO'":                  false,
		"ENCRYPTION='N'":                    false,
		"row_format=COMPACT":                false,
		"":                                  false,
	}
	for in, want := range cases {
		if got := createOptionsEncrypted(in); got != want {
			t.Errorf("createOptionsEncrypted(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestHasPasswordValue(t *testing.T) {
	cases := []struct {
		name string
		in   sql.NullInt64
		want bool
	}{
		// a hashing plugin with a credential set: caching_sha2_password,
		// mysql_native_password, ed25519 -> non-empty -> 1
		{"password set", sql.NullInt64{Int64: 1, Valid: true}, true},
		// CREATE USER with no IDENTIFIED BY, and the socket plugins
		// (auth_socket / unix_socket), both store an empty string -> 0
		{"no password", sql.NullInt64{Int64: 0, Valid: true}, false},
		// COALESCE rules this out, but a NULL must read as "no password"
		// rather than erroring or reporting a credential
		{"null", sql.NullInt64{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasPasswordValue(tc.in); got != tc.want {
				t.Errorf("hasPasswordValue(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsSyntaxError(t *testing.T) {
	// MariaDB 10.3 on SHOW ALL REPLICAS STATUS
	if !isSyntaxError(&mysqldriver.MySQLError{Number: 1064, Message: "You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near 'REPLICAS STATUS' at line 1"}) {
		t.Error("1064 is a syntax error")
	}
	if isSyntaxError(&mysqldriver.MySQLError{Number: 1227}) || isSyntaxError(nil) || isSyntaxError(errors.New("i/o timeout")) {
		t.Error("only 1064 is a syntax error")
	}
}

func setStructuredErrors(t *testing.T, on bool) {
	t.Helper()
	if on {
		plugin.ReadFeatures(mql.Features{byte(mql.StructuredErrors)})
	} else {
		// a non-empty feature set without the flag turns it off
		plugin.ReadFeatures(mql.Features{byte(mql.MassQueries)})
	}
	t.Cleanup(func() { plugin.ReadFeatures(mql.Features{byte(mql.MassQueries)}) })
}

// The error a USAGE-only account gets for SELECT ... FROM mysql.user.
var errTableDenied = &mysqldriver.MySQLError{
	Number:  1142,
	Message: "SELECT command denied to user 'mqlnone'@'127.0.0.1' for table 'user'",
}

func TestRefusedListV13KeepsEmptyList(t *testing.T) {
	setStructuredErrors(t, false)
	list, err := refusedList(errTableDenied, "SELECT ON mysql.user")
	if err != nil {
		t.Fatalf("refusedList returned %v with StructuredErrors off", err)
	}
	if list == nil || len(list) != 0 {
		t.Errorf("refusedList = %#v, want an empty non-nil list", list)
	}
}

func TestRefusedListIsForbidden(t *testing.T) {
	setStructuredErrors(t, true)
	list, err := refusedList(errTableDenied, "SELECT ON mysql.user")
	if list != nil {
		t.Errorf("refusedList returned a list %#v alongside the refusal", list)
	}
	if !errors.Is(err, llx.ErrForbidden) {
		t.Fatalf("refusedList error kind = %v, want forbidden", llx.KindOf(err))
	}
	var e *llx.Error
	if !errors.As(err, &e) || len(e.Permissions) != 1 || e.Permissions[0] != "SELECT ON mysql.user" {
		t.Errorf("permissions = %+v", e)
	}
	// the server's own message must survive the classification
	var myErr *mysqldriver.MySQLError
	if !errors.As(err, &myErr) || myErr.Number != 1142 {
		t.Errorf("wrapped MySQL error lost: %v", err)
	}
}

func TestIsAccessDeniedDoesNotMatchTransportErrors(t *testing.T) {
	if isAccessDenied(errors.New("dial tcp 192.0.2.1:3306: i/o timeout")) {
		t.Error("a transport error is not a refusal")
	}
	if isAccessDenied(&mysqldriver.MySQLError{Number: 1146, Message: "Table 'mysql.role_edges' doesn't exist"}) {
		t.Error("a missing table is not a refusal")
	}
	if !isAccessDenied(errTableDenied) {
		t.Error("1142 is a refusal")
	}
}
