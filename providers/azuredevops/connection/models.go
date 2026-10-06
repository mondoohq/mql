// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/url"
	"strings"
	"time"
)

// ConnectionData is the part of GET /_apis/connectionData the provider reads.
// The response also describes the signed-in identity; none of that is decoded.
type ConnectionData struct {
	// InstanceID is the organization GUID.
	InstanceID string `json:"instanceId"`
	// DeploymentType is "hosted" for Azure DevOps Services. Azure DevOps Server
	// answers "onPremises" and is out of scope.
	DeploymentType string `json:"deploymentType"`
}

// Project is one entry of GET /_apis/projects.
type Project struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	URL            string     `json:"url"`
	State          string     `json:"state"`
	Revision       int64      `json:"revision"`
	Visibility     string     `json:"visibility"`
	LastUpdateTime *time.Time `json:"lastUpdateTime"`
}

// ProjectRef is the project summary embedded in a repository.
type ProjectRef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	State      string `json:"state"`
	Visibility string `json:"visibility"`
}

// Repository is one entry of GET /{project}/_apis/git/repositories.
type Repository struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	URL     string     `json:"url"`
	Project ProjectRef `json:"project"`
	// DefaultBranch is a full ref such as refs/heads/main. It is absent on a
	// repository with no commits.
	DefaultBranch string `json:"defaultBranch"`
	Size          int64  `json:"size"`
	// RemoteURL embeds the user name of the caller, so it is never used as is.
	RemoteURL  string `json:"remoteUrl"`
	SSHURL     string `json:"sshUrl"`
	WebURL     string `json:"webUrl"`
	IsDisabled bool   `json:"isDisabled"`
	IsFork     bool   `json:"isFork"`
}

// IsEmpty reports a repository with no default branch, which has no commits to
// clone or to walk.
func (r Repository) IsEmpty() bool {
	return r.DefaultBranch == ""
}

// HTTPURL is the clone URL without the user name that Azure DevOps embeds in
// remoteUrl. The credential travels separately, so the URL never holds a secret
// or a person's name. It is empty when the API gave no remote URL.
func (r Repository) HTTPURL() string {
	if r.RemoteURL == "" {
		return ""
	}
	u, err := url.Parse(r.RemoteURL)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

// Item is one entry of the repository tree from the Items API.
type Item struct {
	ObjectID      string `json:"objectId"`
	GitObjectType string `json:"gitObjectType"`
	CommitID      string `json:"commitId"`
	Path          string `json:"path"`
	IsFolder      bool   `json:"isFolder"`
	URL           string `json:"url"`
}

// IsBlob reports a file entry.
func (i Item) IsBlob() bool {
	return !i.IsFolder && strings.EqualFold(i.GitObjectType, "blob")
}
