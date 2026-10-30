// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/artifactory/connection"
)

// httpsScheme marks a replication URL whose transport is encrypted.
const httpsScheme = "https://"

// replicationRecord is one configured copy between this instance and another.
//
// The instance also returns the stored password here. It is deliberately not
// decoded, so it cannot reach a field, a log line, or a recording. Whether a
// credential exists at all is reported from the user name instead.
type replicationRecord struct {
	ReplicationKey           string `json:"replicationKey"`
	RepoKey                  string `json:"repoKey"`
	URL                      string `json:"url"`
	Username                 string `json:"username"`
	Enabled                  *bool  `json:"enabled"`
	CronExp                  string `json:"cronExp"`
	EnableEventReplication   *bool  `json:"enableEventReplication"`
	SyncDeletes              *bool  `json:"syncDeletes"`
	SyncProperties           *bool  `json:"syncProperties"`
	SyncStatistics           *bool  `json:"syncStatistics"`
	IncludePathPrefixPattern string `json:"includePathPrefixPattern"`
	ExcludePathPrefixPattern string `json:"excludePathPrefixPattern"`
	SocketTimeoutMillis      *int64 `json:"socketTimeoutMillis"`
}

type mqlArtifactoryReplicationInternal struct {
	repositoryKey string
}

// replications reads the replications of the repository.
//
// The instance serves them per repository only, so this is one call for each
// repository it is asked about. A repository that replicates nothing answers
// 404, which is an empty list rather than an error: not replicating is a
// normal state, unlike a denied read.
func (r *mqlArtifactoryRepository) replications() ([]any, error) {
	conn := artifactoryConn(r.MqlRuntime)
	key := r.Key.Data
	requestURL := conn.ArtifactoryURL("/api/replications/" + url.PathEscape(key))

	body, err := conn.GetRaw(context.Background(), requestURL)
	if err != nil {
		if connection.IsNotFound(err) {
			return []any{}, nil
		}
		return nil, err
	}

	records, err := decodeReplications(body)
	if err != nil {
		return nil, fmt.Errorf("artifactory API %s: %w", requestURL, err)
	}

	res := make([]any, 0, len(records))
	for i := range records {
		replication, err := newArtifactoryReplication(r.MqlRuntime, key, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, replication)
	}
	return res, nil
}

// decodeReplications reads both shapes the endpoint answers with. A repository
// with one replication answers with the object itself, and a repository with
// several answers with an array of them.
func decodeReplications(body []byte) ([]replicationRecord, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, nil
	}

	if trimmed[0] == '[' {
		var list []replicationRecord
		if err := json.Unmarshal(body, &list); err != nil {
			return nil, fmt.Errorf("decode response: %w", err)
		}
		return list, nil
	}

	var single replicationRecord
	if err := json.Unmarshal(body, &single); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return []replicationRecord{single}, nil
}

func newArtifactoryReplication(runtime *plugin.Runtime, repositoryKey string, rec *replicationRecord) (*mqlArtifactoryReplication, error) {
	key := rec.RepoKey
	if key == "" {
		key = repositoryKey
	}

	created, err := CreateResource(runtime, "artifactory.replication", map[string]*llx.RawData{
		"key":                      optionalString(rec.ReplicationKey),
		"repositoryKey":            llx.StringData(key),
		"url":                      llx.StringData(rec.URL),
		"usesEncryptedTransport":   llx.BoolData(usesEncryptedReplicationTransport(rec.URL)),
		"enabled":                  llx.BoolData(boolValue(rec.Enabled)),
		"cronExpression":           optionalString(rec.CronExp),
		"enableEventReplication":   llx.BoolData(boolValue(rec.EnableEventReplication)),
		"syncDeletes":              llx.BoolData(boolValue(rec.SyncDeletes)),
		"syncProperties":           llx.BoolData(boolValue(rec.SyncProperties)),
		"syncStatistics":           llx.BoolData(boolValue(rec.SyncStatistics)),
		"hasCredential":            llx.BoolData(strings.TrimSpace(rec.Username) != ""),
		"includePathPrefixPattern": optionalString(rec.IncludePathPrefixPattern),
		"excludePathPrefixPattern": optionalString(rec.ExcludePathPrefixPattern),
		"socketTimeoutMillis":      optionalInt(rec.SocketTimeoutMillis),
	})
	if err != nil {
		return nil, err
	}

	replication := created.(*mqlArtifactoryReplication)
	replication.repositoryKey = key
	return replication, nil
}

// usesEncryptedReplicationTransport reports whether the other end is reached
// over TLS. A plain HTTP URL sends both the artifacts and the stored credential
// in the clear.
func usesEncryptedReplicationTransport(replicationURL string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(replicationURL)), httpsScheme)
}

func (r *mqlArtifactoryReplication) id() (string, error) {
	// The identifier is built from the replication key and, when the instance
	// does not name one, from the other end it copies to. The error of each
	// field that is read is reported, so a failure cannot be dropped.
	if r.Key.Error != nil {
		return "", r.Key.Error
	}

	name := r.Key.Data
	if name == "" {
		if r.Url.Error != nil {
			return "", r.Url.Error
		}
		// A replication the instance does not name is still identified by the
		// repository it belongs to and the other end it copies to.
		name = r.Url.Data
	}
	return "artifactory.replication/" + r.repositoryKey + "/" + name, nil
}

func (r *mqlArtifactoryReplication) repository() (*mqlArtifactoryRepository, error) {
	repositories, err := resolveRepositories(r.MqlRuntime, []string{r.repositoryKey})
	if err != nil {
		return nil, err
	}
	if len(repositories) == 0 {
		r.Repository.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return repositories[0].(*mqlArtifactoryRepository), nil
}
