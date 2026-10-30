// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"cmp"
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

// GitServerOptionKey is the connection option that names the git server
// implementation behind http-url when the clone has to adapt its request to
// it. The provider that discovered the repository sets it, because it knows
// what it talked to; nothing here guesses from the host name. Without it the
// clone sends go-git's default request, which GitHub and GitLab accept.
const GitServerOptionKey = "git-server"

// GitServerAzureDevOps is the GitServerOptionKey value for Azure DevOps, which
// rejects go-git's default upload-pack request (see git_transport.go).
const GitServerAzureDevOps = "azure-devops"

func NewGitClone(asset *inventory.Asset) (string, func(), error) {
	cc := asset.Connections[0]

	if len(cc.Options) == 0 {
		return "", nil, errors.New("missing URLs in options for HCL over Git connection")
	}

	server, err := gitServerOption(cc.Options)
	if err != nil {
		return "", nil, errors.Wrap(err, "git repo "+asset.Name)
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

	path, closer, err := gitClone(gitUrl, withGitServer(server))
	if err != nil {
		return "", nil, err
	}
	return path, closer, nil
}

// gitServerOption reads GitServerOptionKey. A value this package does not know
// is an error rather than a silent default: a misspelt value would otherwise
// send go-git's default request to a server that rejects it.
func gitServerOption(opts map[string]string) (string, error) {
	switch server := opts[GitServerOptionKey]; server {
	case "", GitServerAzureDevOps:
		return server, nil
	default:
		return "", errors.Errorf("unknown %s %q", GitServerOptionKey, server)
	}
}

// gitCloneOption adjusts one clone. Without options a clone does exactly what
// it did before options existed.
type gitCloneOption func(*gitCloneConfig)

type gitCloneConfig struct {
	// server is the GitServerOptionKey value; "" sends go-git's default request.
	server string
}

// withGitServer names the git server behind the URL, a GitServerOptionKey
// value, so that the transport can adjust the request to it. "" is the default.
func withGitServer(server string) gitCloneOption {
	return func(c *gitCloneConfig) { c.server = server }
}

// gitClone clones gitUrl shallowly into a fresh temporary directory.
func gitClone(gitUrl string, opts ...gitCloneOption) (string, func(), error) {
	installGitTransport()
	var cfg gitCloneConfig
	for _, opt := range opts {
		opt(&cfg)
	}

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
	secrets, userinfoNames := urlSecrets(gitUrl)

	log.Info().Str("url", infoUrl).Str("path", cloneDir).Msg("git clone")
	repo, err := git.PlainClone(cloneDir, false, &git.CloneOptions{
		URL:               gitUrl,
		Auth:              gitServerAuthFor(cfg.server),
		Progress:          os.Stderr,
		Depth:             1,
		RecurseSubmodules: git.DefaultSubmoduleRecursionDepth,
	})
	if err != nil {
		closer()
		return "", nil, errors.Wrap(redactSecrets(err, secrets, userinfoNames), "failed to clone git repo "+infoUrl)
	}

	ref, err := repo.Head()
	if err != nil {
		closer()
		return "", nil, errors.Wrap(redactSecrets(err, secrets, userinfoNames), "failed to get head of git repo "+infoUrl)
	}

	log.Info().Str("url", infoUrl).Str("path", cloneDir).Str("head", ref.Hash().String()).Msg("finished git clone")

	return cloneDir, closer, nil
}

// redactedError reports its cause's text with secrets replaced, and keeps the
// cause reachable through errors.Is and errors.As.
type redactedError struct {
	cause      error
	redactions []redaction
}

// A redaction replaces every occurrence of old in an error's text with new.
type redaction struct{ old, new string }

func (e *redactedError) Error() string {
	text := e.cause.Error()
	for _, r := range e.redactions {
		text = strings.ReplaceAll(text, r.old, r.new)
	}
	return text
}

func (e *redactedError) Unwrap() error { return e.cause }

// redactSecrets returns err unchanged when there is nothing to hide. Each
// secret is replaced wherever it appears. Each user name is replaced only where
// it opens a URL's userinfo ("//name:" or "//name@"), so a short name such as
// "ci" is left alone elsewhere in the text. A spelling can be a substring of
// another ("tok%" inside "tok%25"), so the longest is replaced first; the
// caller's slices are left as given.
func redactSecrets(err error, secrets, userinfoNames []string) error {
	if err == nil || len(secrets)+len(userinfoNames) == 0 {
		return err
	}
	redactions := make([]redaction, 0, len(secrets)+2*len(userinfoNames))
	for _, secret := range secrets {
		redactions = append(redactions, redaction{old: secret, new: "_obfuscated_"})
	}
	for _, name := range userinfoNames {
		for _, next := range []string{":", "@"} {
			redactions = append(redactions, redaction{old: "//" + name + next, new: "//_obfuscated_" + next})
		}
	}
	slices.SortStableFunc(redactions, func(a, b redaction) int { return cmp.Compare(len(b.old), len(a.old)) })
	return &redactedError{cause: err, redactions: redactions}
}

// urlSecrets lists the spellings of the credential in rawURL's userinfo. go-git
// copies the request URL into its HTTP errors and redacts a password, but
// leaves the user name in place.
//
// secrets holds the password when there is a non-empty one, otherwise the user
// name, which NewGitClone fills with the token when no user is configured. An
// empty password ("https://tok:@host") still sends the user name as the
// credential.
//
// userinfoNames holds the user name when it sits next to a non-empty password,
// because either one can be the token: "https://ci:TOKEN@host", or a
// placeholder password as in "https://TOKEN:x-oauth-basic@host".
//
// The raw and URL-escaped spellings are all listed, because go-git prints the
// escaped ones.
func urlSecrets(rawURL string) (secrets, userinfoNames []string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.User == nil {
		return nil, nil
	}
	name := u.User.Username()
	password, hasPassword := u.User.Password()
	if !hasPassword || password == "" {
		return spellings(name), nil
	}
	return spellings(password), spellings(name)
}

// spellings lists s as written and as url.PathEscape and url.User escape it,
// without repeats. An empty s has none.
func spellings(s string) []string {
	if s == "" {
		return nil
	}
	out := []string{s}
	for _, escaped := range []string{url.PathEscape(s), url.User(s).String()} {
		if !slices.Contains(out, escaped) {
			out = append(out, escaped)
		}
	}
	return out
}

// GitHeadRef names what is checked out in the clone at dir: the branch name
// when HEAD is a branch, otherwise the commit hash. It returns "" when dir is
// not a git repository.
func GitHeadRef(dir string) string {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return ""
	}
	head, err := repo.Head()
	if err != nil {
		return ""
	}
	if head.Name().IsBranch() {
		return head.Name().Short()
	}
	return head.Hash().String()
}
