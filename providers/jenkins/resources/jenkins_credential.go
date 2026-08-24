// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/jenkins/connection"
)

// systemCredentialsDomain is the default (global) credentials domain, present
// in every credentials store (the controller's system store and each folder
// store) under the reserved name "_".
const systemCredentialsDomain = "_"

// jenkinsCredentialData is the identifying metadata fetched for a stored
// credential. Secret material (passwords, private keys, tokens) is never part
// of this response and is never fetched by this provider.
type jenkinsCredentialData struct {
	Id          string `json:"id"`
	TypeName    string `json:"typeName"`
	Description string `json:"description"`
}

// credentials lists stored credential metadata across the controller's system
// store (all of its domains) and every folder-scoped credential store. Only
// identifying fields (id, typeName, description) are requested; secret
// material is never fetched by this provider.
func (r *mqlJenkins) credentials() ([]any, error) {
	conn := r.conn()
	all := []any{}

	const systemStore = "/credentials/store/system"
	systemIDBase := conn.BaseUrl() + "/credentials/system"

	// Default global domain of the controller's system store. A failure here is
	// surfaced (it typically signals an auth or connectivity problem) rather
	// than swallowed.
	sysDefault, err := r.credentialsFromStoreDomain(conn, systemStore, systemCredentialsDomain, systemIDBase)
	if err != nil {
		return nil, err
	}
	all = append(all, sysDefault...)

	// Additional, non-default domains configured in the system store.
	for _, domain := range fetchCredentialDomains(conn, systemStore) {
		if domain == systemCredentialsDomain {
			continue
		}
		creds, err := r.credentialsFromStoreDomain(conn, systemStore, domain, systemIDBase)
		if err != nil {
			log.Debug().Err(err).Str("domain", domain).Msg("jenkins> unable to read system credential domain")
			continue
		}
		all = append(all, creds...)
	}

	// Folder-scoped credential stores, one per folder job (all their domains).
	folders, err := fetchFolders(conn)
	if err != nil {
		log.Warn().Err(err).Msg("jenkins> unable to enumerate folders for folder-scoped credentials; credential coverage may be incomplete")
		return all, nil
	}
	for _, f := range folders {
		folderPath := "/job/" + strings.ReplaceAll(f.FullName, "/", "/job/")
		storeBase := folderPath + "/credentials/store/folder"
		idBase := conn.BaseUrl() + folderPath + "/credentials/folder"
		for _, domain := range fetchCredentialDomains(conn, storeBase) {
			creds, err := r.credentialsFromStoreDomain(conn, storeBase, domain, idBase)
			if err != nil {
				log.Debug().Err(err).Str("folder", f.FullName).Str("domain", domain).
					Msg("jenkins> unable to read folder credential store domain")
				continue
			}
			all = append(all, creds...)
		}
	}
	return all, nil
}

// fetchCredentialDomains lists the domain names configured in a credentials
// store. It is best effort: a store that does not exist (e.g. a folder without
// a folder credential store) returns an error, which yields an empty list so
// the caller simply skips it.
func fetchCredentialDomains(conn *connection.JenkinsConnection, storeBase string) []string {
	var resp struct {
		Domains map[string]json.RawMessage `json:"domains"`
	}
	_, err := conn.Client().Requester.GetJSON(context.Background(), storeBase, &resp, map[string]string{
		"tree": "domains[urlName]",
	})
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(resp.Domains))
	for name := range resp.Domains {
		out = append(out, name)
	}
	return out
}

// credentialsFromStoreDomain fetches credential metadata for a single store and
// domain and maps each entry to a jenkins.credential resource. idBase seeds the
// cache key; domain and store together make it unique across stores.
func (r *mqlJenkins) credentialsFromStoreDomain(conn *connection.JenkinsConnection, storeBase, domain, idBase string) ([]any, error) {
	var resp struct {
		Credentials []jenkinsCredentialData `json:"credentials"`
	}
	_, err := conn.Client().Requester.GetJSON(context.Background(), storeBase+"/domain/"+domain, &resp, map[string]string{
		"tree": "credentials[id,typeName,description]",
	})
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(resp.Credentials))
	for _, c := range resp.Credentials {
		res, err := CreateResource(r.MqlRuntime, "jenkins.credential", map[string]*llx.RawData{
			"__id":        llx.StringData(idBase + "/" + domain + "/" + c.Id),
			"id":          llx.StringData(c.Id),
			"typeName":    llx.StringData(c.TypeName),
			"description": llx.StringData(c.Description),
			"domain":      llx.StringData(domain),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
