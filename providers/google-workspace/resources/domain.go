// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	directory "google.golang.org/api/admin/directory/v1"
)

func GetPrimaryDomain(conn *connection.GoogleWorkspaceConnection) (string, error) {
	directoryService, err := directoryService(conn, directory.AdminDirectoryDomainReadonlyScope)
	if err != nil {
		return "", err
	}

	domains, err := directoryService.Domains.List(conn.CustomerID()).Do()
	if err != nil {
		return "", err
	}

	for _, domain := range domains.Domains {
		if domain.IsPrimary {
			return domain.DomainName, nil
		}
	}

	return "", errors.New("no primary domain found")
}

func (g *mqlGoogleworkspace) domains() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	directoryService, err := directoryService(conn, directory.AdminDirectoryDomainReadonlyScope)
	if err != nil {
		return nil, err
	}

	domains, err := directoryService.Domains.List(conn.CustomerID()).Do()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range domains.Domains {
		r, err := newMqlGoogleWorkspaceDomain(g.MqlRuntime, domains.Domains[i])
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func newMqlGoogleWorkspaceDomain(runtime *plugin.Runtime, entry *directory.Domains) (any, error) {
	unixTimeUTC := time.UnixMilli(entry.CreationTime)
	return CreateResource(runtime, "googleworkspace.domain", map[string]*llx.RawData{
		"domainName":   llx.StringData(entry.DomainName),
		"isPrimary":    llx.BoolData(entry.IsPrimary),
		"verified":     llx.BoolData(entry.Verified),
		"creationTime": llx.TimeData(unixTimeUTC),
	})
}

func (g *mqlGoogleworkspaceDomain) id() (string, error) {
	return "googleworkspace.domain/" + g.DomainName.Data, g.DomainName.Error
}
