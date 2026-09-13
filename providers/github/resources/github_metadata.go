// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/github/connection"
)

// initGithubMetadata reports where the account under scan is hosted. It needs
// no organization access, which is the point of keeping it separate from
// github.organization: a scan running with a read-only token can still tell a
// self-hosted installation from GitHub.com, and so tell whether an empty
// Enterprise-only collection means the account is clean or simply unlicensed.
func initGithubMetadata(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Singleton with no lookup key, so the only reason to skip the fetch is a
	// caller that already handed us the full field set. The threshold allows
	// for the implicit __id arg.
	if len(args) > 2 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GithubConnection)
	version := conn.EnterpriseVersion()

	args["enterpriseServer"] = llx.BoolData(conn.IsEnterpriseServer())
	// GitHub.com and GitHub Enterprise Cloud run a release nobody can name, so
	// the absence of a version reads as null rather than as a version of "".
	args["version"] = llx.NilData
	if version != "" {
		args["version"] = llx.StringData(version)
	}

	return args, nil, nil
}

func (m *mqlGithubMetadata) id() (string, error) {
	return "github.metadata", nil
}
