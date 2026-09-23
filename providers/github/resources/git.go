// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/google/go-github/v92/github"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (g *mqlGitGpgSignature) id() (string, error) {
	return "git.gpgSignature/" + g.Sha.Data, nil
}

func newMqlGitGpgSignature(runtime *plugin.Runtime, sha string, a *github.SignatureVerification) (any, error) {
	return CreateResource(runtime, "git.gpgSignature", map[string]*llx.RawData{
		"sha":       llx.StringData(sha),
		"reason":    llx.StringData(a.GetReason()),
		"verified":  llx.BoolData(a.GetVerified()),
		"payload":   llx.StringData(a.GetPayload()),
		"signature": llx.StringData(a.GetSignature()),
	})
}

func (g *mqlGitCommitAuthor) id() (string, error) {
	return "git.commitAuthor/" + g.Sha.Data, nil
}

// commitAuthorID keys a commit identity by both the commit sha and the role it
// plays on that commit. A commit carries two identities (author and committer)
// which frequently differ; keying on the sha alone made the second one collide
// with the first in the resource cache, so every committer resolved to the
// commit's author.
func commitAuthorID(sha, role string) string {
	return "git.commitAuthor/" + sha + "/" + role
}

func newMqlGitAuthor(runtime *plugin.Runtime, sha string, role string, a *github.CommitAuthor) (any, error) {
	date := a.GetDate()
	return CreateResource(runtime, "git.commitAuthor", map[string]*llx.RawData{
		"__id":  llx.StringData(commitAuthorID(sha, role)),
		"sha":   llx.StringData(sha),
		"name":  llx.StringData(a.GetName()),
		"email": llx.StringData(a.GetEmail()),
		"date":  llx.TimeData(date.Time),
	})
}

func (g *mqlGitCommit) id() (string, error) {
	return "git.commit/" + g.Sha.Data, nil
}

func newMqlGitCommit(runtime *plugin.Runtime, sha string, c *github.Commit) (any, error) {
	// we have to pass-in the sha because the sha is often not set c.GetSHA()
	author, err := newMqlGitAuthor(runtime, sha, "author", c.GetAuthor())
	if err != nil {
		return nil, err
	}

	committer, err := newMqlGitAuthor(runtime, sha, "committer", c.GetCommitter())
	if err != nil {
		return nil, err
	}

	signatureVerification, err := newMqlGitGpgSignature(runtime, sha, c.GetVerification())
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "git.commit", map[string]*llx.RawData{
		"sha":                   llx.StringData(sha),
		"message":               llx.StringData(c.GetMessage()),
		"author":                llx.AnyData(author),
		"committer":             llx.AnyData(committer),
		"signatureVerification": llx.AnyData(signatureVerification),
	})
}
