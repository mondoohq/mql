// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/v13/llx"
)

// systemCredentialsDomain is the default (global) credentials domain scoped
// to the Jenkins controller itself, as opposed to a folder-scoped store.
const systemCredentialsDomain = "_"

// credentialGlobalScope is the scope reported for every credential read from
// the system-scoped store: it is available to jobs across the controller.
const credentialGlobalScope = "GLOBAL"

// credentials lists stored credential metadata from the system-scoped
// Credentials plugin store, in a single deep fetch. Only identifying fields
// (id, typeName, description) are requested; secret material (passwords,
// private keys, tokens) is never part of this response and is never
// fetched by this provider.
func (r *mqlJenkins) credentials() ([]any, error) {
	conn := r.conn()

	var resp struct {
		Credentials []struct {
			Id          string `json:"id"`
			TypeName    string `json:"typeName"`
			Description string `json:"description"`
		} `json:"credentials"`
	}
	_, err := conn.Client().Requester.GetJSON(context.Background(),
		"/credentials/store/system/domain/"+systemCredentialsDomain, &resp, map[string]string{
			"tree": "credentials[id,typeName,description]",
		})
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(resp.Credentials))
	for _, c := range resp.Credentials {
		res, err := CreateResource(r.MqlRuntime, "jenkins.credential", map[string]*llx.RawData{
			"__id":        llx.StringData(conn.BaseUrl() + "/credential/" + systemCredentialsDomain + "/" + c.Id),
			"id":          llx.StringData(c.Id),
			"typeName":    llx.StringData(c.TypeName),
			"scope":       llx.StringData(credentialGlobalScope),
			"description": llx.StringData(c.Description),
			"domain":      llx.StringData(systemCredentialsDomain),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}
