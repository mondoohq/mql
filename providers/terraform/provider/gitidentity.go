// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/transport"
)

// gitIdentity is the repository a scanned path belongs to, read from the
// checkout the path sits in: the origin remote, and where inside the
// repository the path is.
type gitIdentity struct {
	Domain string
	Org    string
	Repo   string
	// RelPath is the scanned path relative to the repository root, with
	// forward slashes. Empty for the root itself.
	RelPath string
}

// platformID is the repository identity the git-integration path already
// derives for a whole checkout (the ssh-url branch of detect), with the
// scanned sub-folder appended so that two roots of one repository, or its
// prod/ and dev/ folders, stay two assets. The id is an opaque key: nothing
// parses the path back out of it, so RelPath is spliced in as it is, and a
// folder that is itself called "path" is as unambiguous as any other key.
func (g gitIdentity) platformID() string {
	id := "//platformid.api.mondoo.app/runtime/terraform/domain/" + g.Domain + "/org/" + g.Org + "/repo/" + g.Repo
	if g.RelPath != "" {
		id += "/path/" + g.RelPath
	}
	return id
}

// name is the asset name's variable part: org/repo, plus the sub-folder.
func (g gitIdentity) name() string {
	n := g.Org + "/" + g.Repo
	if g.RelPath != "" {
		n += "/" + g.RelPath
	}
	return n
}

// detectGitIdentity finds the git checkout absPath lies in and reads its
// origin remote (or the first remote when there is no origin). It reports
// false when the path is outside any checkout, the checkout has no remote, the
// remote URL names no repository, or the repository is bare: the caller then
// keeps the path hash it used before.
func detectGitIdentity(absPath string) (gitIdentity, bool) {
	repo, err := git.PlainOpenWithOptions(absPath, &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if err != nil {
		return gitIdentity{}, false
	}

	remote, err := repo.Remote(git.DefaultRemoteName)
	if err != nil {
		remotes, err := repo.Remotes()
		if err != nil || len(remotes) == 0 {
			return gitIdentity{}, false
		}
		remote = remotes[0]
	}
	urls := remote.Config().URLs
	if len(urls) == 0 {
		return gitIdentity{}, false
	}
	domain, org, name, err := parseGitRemote(urls[0])
	if err != nil {
		return gitIdentity{}, false
	}

	wt, err := repo.Worktree()
	if err != nil {
		return gitIdentity{}, false
	}
	rel, err := filepath.Rel(wt.Filesystem.Root(), absPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return gitIdentity{}, false
	}
	if rel == "." {
		rel = ""
	}
	return gitIdentity{Domain: domain, Org: org, Repo: name, RelPath: filepath.ToSlash(rel)}, true
}

var errMalformedGitRemote = errors.New("malformed git remote URL")

// parseGitRemote reads domain, org and repo out of a git remote URL. go-git's
// endpoint parser accepts every spelling git does (https://, ssh://, git://
// and the scp-like git@host:path) and keeps credentials embedded in the URL
// (a CI token) out of Host and Path; a local path comes back without a host
// and is not a repository identity here.
//
// Org and repo are the first and the last path segment, the cut
// urlx.ParseGitSshUrl makes for the ssh-url branch of detect, so a
// repository has one identity whichever way it was scanned, a checkout on
// disk or the git integration's clone. Segments in between (GitLab
// subgroups, an Azure DevOps project) are not part of the identity, at the
// price the ssh-url branch already pays: two repositories that differ only
// in a middle segment share an id.
func parseGitRemote(raw string) (domain, org, repo string, err error) {
	ep, err := transport.NewEndpoint(strings.TrimSpace(raw))
	if err != nil || ep.Host == "" {
		return "", "", "", errMalformedGitRemote
	}
	path := strings.Trim(ep.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	segments := strings.Split(path, "/")
	if len(segments) < 2 {
		return "", "", "", errMalformedGitRemote
	}
	org = segments[0]
	repo = segments[len(segments)-1]
	if org == "" || repo == "" {
		return "", "", "", errMalformedGitRemote
	}
	return ep.Host, org, repo, nil
}
