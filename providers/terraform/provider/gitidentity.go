// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"go.mondoo.com/mql/utils/urlx"
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

// parseGitRemote reads domain, org and repo out of a git remote URL in the
// spellings git accepts: https://host/org/repo.git, ssh://git@host/org/repo,
// git://host/org/repo and the scp-like git@host:org/repo.git. Credentials in
// the URL (a CI token in https://user:token@host/...) are dropped.
//
// The three parts are cut the way urlx.ParseGitSshUrl cuts them for the
// ssh-url branch of detect: the first path segment is the org, the last is
// the repo, and segments in between (GitLab subgroups, an Azure DevOps
// project) are not part of the identity. That keeps one identity per
// repository whichever way it was scanned, a checkout on disk or the git
// integration's clone, at the price the ssh-url branch already pays: two
// repositories that differ only in a middle segment share an id.
func parseGitRemote(raw string) (domain, org, repo string, err error) {
	raw = strings.TrimSpace(raw)
	if !strings.Contains(raw, "://") {
		// scp-like: [user@]host:path. ParseGitSshUrl also accepts a path
		// with a single segment and then names the org after the repo; a
		// remote that names no org is not a repository identity here.
		domain, org, repo, err = urlx.ParseGitSshUrl(raw)
		if err != nil {
			return "", "", "", err
		}
		if _, path, _ := strings.Cut(raw, ":"); len(strings.Split(strings.Trim(path, "/"), "/")) < 2 {
			return "", "", "", errMalformedGitRemote
		}
		return domain, org, repo, nil
	}
	u, perr := url.Parse(raw)
	if perr != nil || u.Host == "" {
		return "", "", "", errMalformedGitRemote
	}
	path := strings.TrimSuffix(strings.Trim(u.Path, "/"), ".git")
	segments := strings.Split(path, "/")
	if u.Hostname() == "" || len(segments) < 2 || segments[0] == "" || segments[len(segments)-1] == "" {
		return "", "", "", errMalformedGitRemote
	}
	return u.Hostname(), segments[0], segments[len(segments)-1], nil
}
