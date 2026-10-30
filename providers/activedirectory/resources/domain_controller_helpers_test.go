// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

func TestLDAPPortForConnection(t *testing.T) {
	conn := &connection.ActiveDirectoryConnection{Conf: &inventory.Config{Options: map[string]string{}}}
	if got := ldapPortForConnection(conn); got != 636 {
		t.Fatalf("default port = %d", got)
	}

	conn.Conf.Options = map[string]string{connection.OptionStartTLS: "true"}
	if got := ldapPortForConnection(conn); got != 389 {
		t.Fatalf("starttls port = %d", got)
	}

	conn.Conf.Options = map[string]string{connection.OptionPlainLDAP: "true"}
	if got := ldapPortForConnection(conn); got != 389 {
		t.Fatalf("plain ldap port = %d", got)
	}

	conn.Conf.Options = map[string]string{connection.OptionPort: "1389"}
	if got := ldapPortForConnection(conn); got != 1389 {
		t.Fatalf("explicit port = %d", got)
	}
}
