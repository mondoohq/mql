// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"strings"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// The connection string the README advertises, with a replica-set member
// reached directly: the form that put the password into the asset name and
// platform id.
// A generated stand-in, spliced in so the source holds no literal credential.
var testPassword = strings.Repeat("x", 12)

var uriWithPassword = "mongodb://db3admin:" + testPassword + "@127.0.0.1:28002/?authSource=admin&directConnection=true"

func eq[T comparable](t *testing.T, want, got T, msg ...string) {
	t.Helper()
	if want != got {
		t.Errorf("want %v, got %v %v", want, got, msg)
	}
}

func notContains(t *testing.T, s, sub string, msg ...string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Errorf("%q must not contain %q %v", s, sub, msg)
	}
}

func newConnFromHost(t *testing.T, host string, creds ...*vault.Credential) (*MongoConnection, *inventory.Config) {
	t.Helper()
	conf := &inventory.Config{Type: "mongo", Host: host, Credentials: creds}
	asset := &inventory.Asset{Connections: []*inventory.Config{conf}}
	conn, err := NewMongoConnection(1, asset, conf)
	if err != nil {
		t.Fatal(err)
	}
	return conn, conf
}

func TestServerIDAndNameOmitUserinfo(t *testing.T) {
	conn, conf := newConnFromHost(t, uriWithPassword)

	eq(t, "127.0.0.1:28002", conn.ServerID())
	eq(t, "127.0.0.1:28002", conn.DisplayName())
	eq(t, "//platformid.api.mondoo.app/runtime/mongo/server/127.0.0.1:28002", NewMongoServerIdentifier(conn.ServerID()))
	notContains(t, conf.Host, testPassword, "the inventory host must not keep the password")
	notContains(t, conf.Host, "db3admin@", "the inventory host must not keep the user info")
}

func TestServerIDSameForURIAndHostFlag(t *testing.T) {
	uriConn, _ := newConnFromHost(t, "mongodb://db.example.com/")
	flagConn := newTestConn(t, map[string]string{OptionHost: "db.example.com"})
	eq(t, flagConn.ServerID(), uriConn.ServerID())
}

func TestServerIDForms(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"mongodb://u:p@a.example.com,b.example.com:27018/app?replicaSet=rs0", "a.example.com:27017,b.example.com:27018"},
		{"mongodb://[::1]:27117/?directConnection=true", "[::1]:27117"},
		{"mongodb://[::1]/", "[::1]:27017"},
		{"mongodb+srv://u:p@cluster0.example.net/?retryWrites=true", "mongodb+srv://cluster0.example.net"},
		// An unescaped @ in the password is invalid, but no part of the
		// password may reach the id.
		{"mongodb://u:p@ss@db.example.com:27017/", "db.example.com:27017"},
		{"mongodb://u:p%40ss@db.example.com", "db.example.com:27017"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			conn, _ := newConnFromHost(t, tt.host)
			got := conn.ServerID()
			eq(t, tt.want, got)
			notContains(t, got, "ss@")
		})
	}
}

func TestMoveURICredentials(t *testing.T) {
	conf := &inventory.Config{Host: "mongodb://audit%40corp:p%40ss%3Aword@db.example.com:27017/admin?tls=true"}
	MoveURICredentials(conf)
	eq(t, "mongodb://db.example.com:27017/admin?tls=true", conf.Host)
	if len(conf.Credentials) != 1 {
		t.Fatalf("want 1 credentials, got %d", len(conf.Credentials))
	}
	eq(t, vault.CredentialType_password, conf.Credentials[0].Type)
	eq(t, "audit@corp", conf.Credentials[0].User)
	eq(t, "p@ss:word", string(conf.Credentials[0].Secret))
}

func TestMoveURICredentialsFlagsWin(t *testing.T) {
	// --ask-pass with the user in the connection string: the prompted
	// password stays, the user comes from the host.
	conf := &inventory.Config{
		Host:        "mongodb://admin@db.example.com:27017",
		Credentials: []*vault.Credential{vault.NewPasswordCredential("", "prompted")},
	}
	MoveURICredentials(conf)
	if len(conf.Credentials) != 1 {
		t.Fatalf("want 1 credentials, got %d", len(conf.Credentials))
	}
	eq(t, "admin", conf.Credentials[0].User)
	eq(t, "prompted", string(conf.Credentials[0].Secret))
	eq(t, "mongodb://db.example.com:27017", conf.Host)

	// --user and --password both set: the host's user info is dropped.
	conf = &inventory.Config{
		Host:        "mongodb://old:" + testPassword + "@db.example.com",
		Credentials: []*vault.Credential{vault.NewPasswordCredential("new", "newpw")},
	}
	MoveURICredentials(conf)
	eq(t, "new", conf.Credentials[0].User)
	eq(t, "newpw", string(conf.Credentials[0].Secret))
	eq(t, "mongodb://db.example.com", conf.Host)
}

func TestMoveURICredentialsLeavesPlainHosts(t *testing.T) {
	conf := &inventory.Config{Host: "db.example.com"}
	MoveURICredentials(conf)
	eq(t, "db.example.com", conf.Host)
	eq(t, 0, len(conf.Credentials))
}

func TestURIRestoresCredentialsForConnectionString(t *testing.T) {
	conn, _ := newConnFromHost(t, uriWithPassword)
	eq(t, uriWithPassword, conn.uri())

	// A password given with --ask-pass reaches the driver for a connection
	// string that names only the user.
	conn, _ = newConnFromHost(t, "mongodb://admin@db.example.com:27017/?authSource=admin",
		vault.NewPasswordCredential("", "s3cr:t/@"))
	got := conn.uri()
	if !strings.HasPrefix(got, "mongodb://admin:s3cr%3At%2F%40@db.example.com:27017/") {
		t.Errorf("unexpected uri %q", got)
	}

	// No credentials: the connection string is used as given.
	conn, _ = newConnFromHost(t, "mongodb://db.example.com:27017/?replicaSet=rs0")
	eq(t, "mongodb://db.example.com:27017/?replicaSet=rs0", conn.uri())
}
