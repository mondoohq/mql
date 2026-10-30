// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

const ntdsSettingsGCBit = 0x1

type currentGCState struct {
	host  string
	ready bool
}

func ldapPortForConnection(conn *connection.ActiveDirectoryConnection) int {
	return conn.LDAPPort()
}

func queryNTDSSettingsGC(conn *connection.ActiveDirectoryConnection, serverRef string) (bool, error) {
	if serverRef == "" {
		return false, nil
	}

	req := ldap.NewSearchRequest(
		"CN=NTDS Settings,"+serverRef,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"options"},
		nil,
	)
	resp, err := conn.LDAPConn().Search(req)
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			return false, nil
		}
		return false, fmt.Errorf("querying NTDS Settings for %s: %w", serverRef, err)
	}
	if len(resp.Entries) == 0 {
		return false, nil
	}

	options := parseInt64Attr(connection.GetStringAttr(resp.Entries[0], "options"))
	return options&ntdsSettingsGCBit != 0, nil
}

func currentConnectionGCState(conn *connection.ActiveDirectoryConnection) (*currentGCState, error) {
	raw, err := conn.CachedFetch("currentConnectionGCState", func() (any, error) {
		resp, err := conn.LDAPConn().Search(ldap.NewSearchRequest(
			"",
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{"dnsHostName", "isGlobalCatalogReady"},
			nil,
		))
		if err != nil {
			return nil, err
		}
		if len(resp.Entries) == 0 {
			return &currentGCState{}, nil
		}

		entry := resp.Entries[0]
		return &currentGCState{
			host:  strings.ToLower(connection.GetStringAttr(entry, "dnsHostName")),
			ready: strings.EqualFold(connection.GetStringAttr(entry, "isGlobalCatalogReady"), "TRUE"),
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return raw.(*currentGCState), nil
}

func queryRootDSEGC(conn *connection.ActiveDirectoryConnection, host string) (bool, error) {
	if host == "" {
		return false, nil
	}

	port := ldapPortForConnection(conn)
	ldapConn, err := conn.DialLDAPHost(host, port, 5*time.Second)
	if err != nil {
		return false, err
	}
	defer ldapConn.Close()

	resp, err := ldapConn.Search(ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"isGlobalCatalogReady"},
		nil,
	))
	if err != nil {
		return false, err
	}
	if len(resp.Entries) == 0 {
		return false, nil
	}

	return strings.EqualFold(connection.GetStringAttr(resp.Entries[0], "isGlobalCatalogReady"), "TRUE"), nil
}

func isGlobalCatalogServer(conn *connection.ActiveDirectoryConnection, host, serverRef string) (bool, error) {
	byOptions, err := queryNTDSSettingsGC(conn, serverRef)
	if err == nil && byOptions {
		return true, nil
	}

	currentState, currentErr := currentConnectionGCState(conn)
	if currentErr == nil && strings.EqualFold(currentState.host, host) {
		return currentState.ready, nil
	}

	byRootDSE, rootErr := queryRootDSEGC(conn, host)
	if rootErr == nil {
		return byRootDSE, nil
	}
	if err != nil {
		return false, err
	}
	if currentErr != nil {
		return false, currentErr
	}
	return false, nil
}
