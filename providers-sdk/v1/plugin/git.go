// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const GitUrlOptionKey = "git-http-url" // used for tracking the link to the git repo for later reference

func NewGitClone(asset *inventory.Asset) (string, func(), error) {
	cc := asset.Connections[0]

	if len(cc.Options) == 0 {
		return "", nil, errors.New("missing URLs in options for HCL over Git connection")
	}

	user := ""
	token := ""
	for i := range cc.Credentials {
		cred := cc.Credentials[i]
		if cred.Type == vault.CredentialType_password {
			user = cred.User
			token = string(cred.Secret)
			if token == "" && cred.Password != "" {
				token = string(cred.Password)
			}
		}
	}

	gitUrl := ""

	// If a token is provided, it will be used to clone the repo
	// gitlab: git clone https://oauth2:ACCESS_TOKEN@somegitlab.com/vendor/package.git
	// if sshUrl := cc.Options["ssh-url"]; sshUrl != "" { ... not doing ssh url right now
	if httpUrl := cc.Options["http-url"]; httpUrl != "" {
		cc.Options[GitUrlOptionKey] = httpUrl // stick this on the asset connection options so we can reference it later
		u, err := url.Parse(httpUrl)
		if err != nil {
			return "", nil, errors.New("failed to parse url for git repo: " + httpUrl)
		}

		if user != "" && token != "" {
			u.User = url.UserPassword(user, token)
		} else if token != "" {
			u.User = url.User(token)
		}

		gitUrl = u.String()
	}

	if gitUrl == "" {
		return "", nil, errors.New("missing url for git repo " + asset.Name)
	}

	path, closer, err := gitClone(gitUrl)
	if err != nil {
		return "", nil, err
	}
	return path, closer, nil
}

func gitClone(gitUrl string) (string, func(), error) {
	cloneDir, err := os.MkdirTemp(os.TempDir(), "mql-git-clone")
	if err != nil {
		return "", nil, errors.Wrap(err, "failed to create temporary dir for git processing")
	}

	closer := func() {
		log.Info().Str("path", cloneDir).Msg("cleaning up git clone")
		if rmErr := os.RemoveAll(cloneDir); rmErr != nil {
			log.Error().Err(rmErr).Msg("failed to remove temporary dir for git processing")
		}
	}

	// Note: DO NOT leak credentials into logs!!
	var infoUrl string
	if u, err := url.Parse(gitUrl); err == nil {
		if u.User != nil {
			u.User = url.User("_obfuscated_")
		}
		infoUrl = u.String()
	}
	secrets := urlSecrets(gitUrl)

	log.Info().Str("url", infoUrl).Str("path", cloneDir).Msg("git clone")
	repo, err := git.PlainClone(cloneDir, false, &git.CloneOptions{
		URL:               gitUrl,
		Progress:          os.Stderr,
		Depth:             1,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})
	if err != nil {
		closer()
		return "", nil, errors.Wrap(redactSecrets(err, secrets), "failed to clone git repo "+infoUrl)
	}

	ref, err := repo.Head()
	if err != nil {
		closer()
		return "", nil, errors.Wrap(redactSecrets(err, secrets), "failed to get head of git repo "+infoUrl)
	}

	log.Info().Str("url", infoUrl).Str("path", cloneDir).Str("head", ref.Hash().String()).Msg("finished git clone")

	return cloneDir, closer, nil
}

// redactedError reports its cause's text with secrets replaced, and keeps the
// cause reachable through errors.Is and errors.As.
type redactedError struct {
	cause   error
	secrets []string
}

func (e *redactedError) Error() string {
	text := e.cause.Error()
	for _, secret := range e.secrets {
		text = strings.ReplaceAll(text, secret, "_obfuscated_")
	}
	return text
}

func (e *redactedError) Unwrap() error { return e.cause }

// redactSecrets returns err unchanged when there is nothing to hide.
func redactSecrets(err error, secrets []string) error {
	if err == nil || len(secrets) == 0 {
		return err
	}
	return &redactedError{cause: err, secrets: secrets}
}

// urlSecrets lists the strings that carry the credential in rawURL's userinfo:
// the password when there is one, otherwise the username, which NewGitClone
// fills with the token when no user is configured. go-git copies the request
// URL into its HTTP errors and redacts a password, but leaves a username-only
// credential in place. The raw and URL-escaped spellings are both listed
// because go-git prints the escaped one.
func urlSecrets(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return nil
	}
	secret, hasPassword := u.User.Password()
	if !hasPassword {
		secret = u.User.Username()
	}
	if secret == "" {
		return nil
	}
	secrets := []string{secret}
	for _, escaped := range []string{url.PathEscape(secret), url.User(secret).String()} {
		if !slices.Contains(secrets, escaped) {
			secrets = append(secrets, escaped)
		}
	}
	return secrets
}
