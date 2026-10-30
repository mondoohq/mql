// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"
)

func TestParseHBA(t *testing.T) {
	conf := "# allow the app subnet\n" +
		"host all root all cert\n" +
		"hostssl \"shop\",defaultdb app,ops 10.0.0.0/8 cert-scram-sha-256 # app\n" +
		"host all all 192.168.0.1 255.255.255.0 ldap ldapserver=ldap.example.com \"ldapsearchattribute=uid\"\n" +
		"\n" +
		"host all all 0.0.0.0/0 reject\n" +
		"local all all password\n"

	got := parseHBA(conf)
	want := []hbaRule{
		{position: 1, connectionType: "host", databases: []string{"all"}, users: []string{"root"}, address: "all", method: "cert", options: map[string]string{}, line: "host all root all cert"},
		{position: 2, connectionType: "hostssl", databases: []string{"shop", "defaultdb"}, users: []string{"app", "ops"}, address: "10.0.0.0/8", method: "cert-scram-sha-256", options: map[string]string{}, line: "hostssl \"shop\",defaultdb app,ops 10.0.0.0/8 cert-scram-sha-256"},
		{position: 3, connectionType: "host", databases: []string{"all"}, users: []string{"all"}, address: "192.168.0.1 255.255.255.0", method: "ldap", options: map[string]string{"ldapserver": "ldap.example.com", "ldapsearchattribute": "uid"}, line: "host all all 192.168.0.1 255.255.255.0 ldap ldapserver=ldap.example.com \"ldapsearchattribute=uid\""},
		{position: 4, connectionType: "host", databases: []string{"all"}, users: []string{"all"}, address: "0.0.0.0/0", method: "reject", options: map[string]string{}, line: "host all all 0.0.0.0/0 reject"},
		{position: 5, connectionType: "local", databases: []string{"all"}, users: []string{"all"}, method: "password", options: map[string]string{}, line: "local all all password"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseHBA:\n got %+v\nwant %+v", got, want)
	}
}

func TestParseHBAEmpty(t *testing.T) {
	if got := parseHBA(""); len(got) != 0 {
		t.Errorf("parseHBA(\"\") = %+v, want no rules", got)
	}
	if got := parseHBA("# only a comment\n   \n"); len(got) != 0 {
		t.Errorf("parseHBA(comments) = %+v, want no rules", got)
	}
}

func TestHBATokensKeepsQuotedHash(t *testing.T) {
	got := hbaTokens("host all \"we#ird\" all cert # comment")
	want := []string{"host", "all", "we#ird", "all", "cert"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hbaTokens = %q, want %q", got, want)
	}
}
