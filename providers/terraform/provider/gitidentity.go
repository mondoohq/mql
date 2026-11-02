// Copyright Mondoo, Inc. 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"errors"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
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
// prod/ and dev/ folders, stay two assets.
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
// the URL (a CI token in https://user:token@host/...) are dropped. The org
// keeps every path segment above the repository, so GitLab subgroups stay
// distinct; Azure DevOps' "_git" segment is not part of the identity.
func parseGitRemote(raw string) (domain, org, repo string, err error) {
	raw = strings.TrimSpace(raw)
	var host, path string
	if strings.Contains(raw, "://") {
		u, perr := url.Parse(raw)
		if perr != nil || u.Host == "" {
			return "", "", "", errMalformedGitRemote
		}
		host, path = u.Hostname(), u.Path
	} else {
		// scp-like: [user@]host:path
		hostPart, pathPart, ok := strings.Cut(raw, ":")
		if !ok {
			return "", "", "", errMalformedGitRemote
		}
		if _, h, found := strings.Cut(hostPart, "@"); found {
			hostPart = h
		}
		host, path = hostPart, pathPart
	}

	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	segments := make([]string, 0, 4)
	for _, s := range strings.Split(path, "/") {
		if s == "" || s == "_git" {
			continue
		}
		segments = append(segments, s)
	}
	if host == "" || len(segments) < 2 {
		return "", "", "", errMalformedGitRemote
	}
	return host, strings.Join(segments[:len(segments)-1], "/"), segments[len(segments)-1], nil
}
