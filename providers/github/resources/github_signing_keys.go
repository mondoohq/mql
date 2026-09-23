// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/github/connection"
	"go.mondoo.com/mql/types"
)

// A rule requiring signed commits only bites for accounts that hold a signing
// key. GitHub registers signing keys in two places that are separate from the
// authentication keys github.publicKey reports: GPG keys, and SSH keys
// registered specifically for signing. Only public key material is read here.

type mqlGithubGpgKeyInternal struct {
	cacheUserLogin string
}

type mqlGithubSshSigningKeyInternal struct {
	cacheUserLogin string
}

func (g *mqlGithubGpgKey) id() (string, error) {
	return g.__id, nil
}

func (g *mqlGithubSshSigningKey) id() (string, error) {
	return g.__id, nil
}

// gpgKeyExpired reports whether the key's expiry has passed. A key with no
// expiry never expires, which is a real answer rather than an unread one, so it
// is false and not null.
func gpgKeyExpired(expiresAt *github.Timestamp, now time.Time) bool {
	t := githubTime(expiresAt)
	if t == nil {
		return false
	}
	return t.Before(now)
}

// gpgKeyCanSignCommits reports whether the key or any of its subkeys carries
// the signing capability. A key generated with GnuPG's defaults has a primary
// key that certifies and a subkey that signs, so reading can_sign on the
// primary key alone reports a perfectly usable signing key as unusable.
func gpgKeyCanSignCommits(key *github.GPGKey) bool {
	if key == nil {
		return false
	}
	if key.GetCanSign() {
		return true
	}
	for _, sub := range key.Subkeys {
		if gpgKeyCanSignCommits(sub) {
			return true
		}
	}
	return false
}

// gpgKeyEmails maps each address attached to the key to whether GitHub verified
// it. Git only accepts a signature as belonging to the account when the
// committer address is one of the verified ones.
func gpgKeyEmails(key *github.GPGKey) map[string]any {
	emails := map[string]any{}
	for _, e := range key.Emails {
		if e == nil || e.GetEmail() == "" {
			continue
		}
		emails[e.GetEmail()] = e.GetVerified()
	}
	return emails
}

// gpgKeys returns the public GPG keys registered on the account.
func (g *mqlGithubUser) gpgKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	userLogin := g.Login.Data

	allKeys, err := collectPages(func(opts *github.ListOptions) ([]*github.GPGKey, *github.Response, error) {
		return conn.Client().Users.ListGPGKeys(conn.Context(), userLogin, opts)
	})
	if err != nil {
		if githubForbidden(err) {
			log.Warn().Err(err).Str("login", userLogin).
				Msg("permission denied reading GPG keys; reporting them as unknown")
		} else if githubNotAvailable(err) {
			// A bot account or a deleted user has no key endpoint at all,
			// which is not the same as an account that registered none.
			log.Debug().Err(err).Str("login", userLogin).
				Msg("GPG keys are not available for this account")
		} else {
			return nil, err
		}
		g.GpgKeys.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	now := time.Now()
	res := make([]any, 0, len(allKeys))
	for _, k := range allKeys {
		r, err := CreateResource(g.MqlRuntime, "github.gpgKey", map[string]*llx.RawData{
			"__id":           llx.StringData("github.gpgKey/" + userLogin + "/" + strconv.FormatInt(k.GetID(), 10)),
			"id":             llx.IntDataPtr(k.ID),
			"keyId":          llx.StringDataPtr(k.KeyID),
			"publicKey":      llx.StringDataPtr(k.PublicKey),
			"emails":         llx.MapData(gpgKeyEmails(k), types.Bool),
			"canSign":        llx.BoolDataPtr(k.CanSign),
			"canSignCommits": llx.BoolData(gpgKeyCanSignCommits(k)),
			"createdAt":      llx.TimeDataPtr(githubTime(k.CreatedAt)),
			"expiresAt":      llx.TimeDataPtr(githubTime(k.ExpiresAt)),
			"expired":        llx.BoolData(gpgKeyExpired(k.ExpiresAt, now)),
			"ageInDays":      llx.IntData(keyAgeInDays(k.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlGithubGpgKey).cacheUserLogin = userLogin
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubGpgKey) user() (*mqlGithubUser, error) {
	return signingKeyUser(g.MqlRuntime, g.cacheUserLogin, &g.User)
}

// sshSigningKeys returns the SSH keys registered for signing commits and tags.
// Registering a key for authentication does not register it for signing, so
// this is a different set from publicKeys even where the key material matches.
func (g *mqlGithubUser) sshSigningKeys() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GithubConnection)
	if g.Login.Error != nil {
		return nil, g.Login.Error
	}
	userLogin := g.Login.Data

	allKeys, err := collectPages(func(opts *github.ListOptions) ([]*github.SSHSigningKey, *github.Response, error) {
		return conn.Client().Users.ListSSHSigningKeys(conn.Context(), userLogin, opts)
	})
	if err != nil {
		if githubForbidden(err) {
			log.Warn().Err(err).Str("login", userLogin).
				Msg("permission denied reading SSH signing keys; reporting them as unknown")
		} else if githubNotAvailable(err) {
			log.Debug().Err(err).Str("login", userLogin).
				Msg("SSH signing keys are not available for this account")
		} else {
			return nil, err
		}
		g.SshSigningKeys.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res := make([]any, 0, len(allKeys))
	for _, k := range allKeys {
		r, err := CreateResource(g.MqlRuntime, "github.sshSigningKey", map[string]*llx.RawData{
			"__id":      llx.StringData("github.sshSigningKey/" + userLogin + "/" + strconv.FormatInt(k.GetID(), 10)),
			"id":        llx.IntDataPtr(k.ID),
			"title":     llx.StringDataPtr(k.Title),
			"key":       llx.StringDataPtr(k.Key),
			"createdAt": llx.TimeDataPtr(githubTime(k.CreatedAt)),
			"ageInDays": llx.IntData(keyAgeInDays(k.CreatedAt)),
		})
		if err != nil {
			return nil, err
		}
		r.(*mqlGithubSshSigningKey).cacheUserLogin = userLogin
		res = append(res, r)
	}
	return res, nil
}

func (g *mqlGithubSshSigningKey) user() (*mqlGithubUser, error) {
	return signingKeyUser(g.MqlRuntime, g.cacheUserLogin, &g.User)
}

// signingKeyUser resolves the account a key belongs to, marking the field null
// when the key was built without a login to resolve from.
func signingKeyUser(runtime *plugin.Runtime, login string, field *plugin.TValue[*mqlGithubUser]) (*mqlGithubUser, error) {
	if login == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	u, err := NewResource(runtime, "github.user", map[string]*llx.RawData{
		"login": llx.StringData(login),
	})
	if err != nil {
		return nil, err
	}
	return u.(*mqlGithubUser), nil
}
