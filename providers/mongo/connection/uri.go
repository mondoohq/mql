// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

const (
	schemeMongoDB    = "mongodb://"
	schemeMongoDBSRV = "mongodb+srv://"
	defaultMongoPort = 27017
)

// connStringParts is a connection string split the way the MongoDB driver
// splits it: the user info ends at the first "@", the host list ends at the
// first "/" or "?" after it. The parts keep their original (escaped) spelling.
type connStringParts struct {
	scheme   string
	userinfo string
	hasUser  bool
	hosts    string
	rest     string // "/db?query", or empty
}

func splitConnString(s string) (connStringParts, bool) {
	var p connStringParts
	switch {
	case strings.HasPrefix(s, schemeMongoDBSRV):
		p.scheme = schemeMongoDBSRV
	case strings.HasPrefix(s, schemeMongoDB):
		p.scheme = schemeMongoDB
	default:
		return p, false
	}
	s = s[len(p.scheme):]

	if at := strings.Index(s, "@"); at != -1 {
		p.hasUser = true
		p.userinfo = s[:at]
		s = s[at+1:]
		// An unescaped "@" in the password is invalid, and the driver refuses
		// it, but it must still never end up in the host list: consume every
		// "@" that comes before the end of the host list.
		for {
			idx := strings.IndexAny(s, "/?@")
			if idx == -1 || s[idx] != '@' {
				break
			}
			p.userinfo += "@" + s[:idx]
			s = s[idx+1:]
		}
	}

	p.hosts = s
	if idx := strings.IndexAny(s, "/?"); idx != -1 {
		p.hosts = s[:idx]
		p.rest = s[idx:]
	}
	return p, true
}

// String reassembles the connection string, without user info.
func (p connStringParts) withoutUserinfo() string {
	return p.scheme + p.hosts + p.rest
}

// credentials returns the unescaped user and password from the user info.
func (p connStringParts) credentials() (user string, password string) {
	if !p.hasUser {
		return "", ""
	}
	u, pw, _ := strings.Cut(p.userinfo, ":")
	if v, err := url.PathUnescape(u); err == nil {
		u = v
	}
	if v, err := url.PathUnescape(pw); err == nil {
		pw = v
	}
	return u, pw
}

// serverID identifies the server(s) a connection string points at by its host
// list alone. User info and options never take part: the id is shown as the
// asset's platform id, and it must not change when a password rotates. A host
// without a port gets the default port, so mongodb://db and --host db share an
// id.
func (p connStringParts) serverID() string {
	if p.scheme == schemeMongoDBSRV {
		// An SRV name is resolved to hosts through DNS; the name itself is the
		// stable identity.
		return p.scheme + p.hosts
	}
	hosts := strings.Split(p.hosts, ",")
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(h); err != nil {
			h = net.JoinHostPort(strings.Trim(h, "[]"), strconv.Itoa(defaultMongoPort))
		}
		out = append(out, h)
	}
	return strings.Join(out, ",")
}

// withCredentials returns the connection string with the given user and
// password as its user info, replacing any user info it had.
func (p connStringParts) withCredentials(user, password string) string {
	if user == "" && password == "" {
		return p.withoutUserinfo()
	}
	return p.scheme + url.UserPassword(user, password).String() + "@" + p.hosts + p.rest
}

// MoveURICredentials takes the user info out of a mongodb:// host in conf and
// keeps it as a password credential instead, so the secret lives in the
// credential store and never in conf.Host, which is shown and persisted with
// the asset. A user or password already given as a credential (--user,
// --password, --ask-pass) wins over the one in the connection string.
func MoveURICredentials(conf *inventory.Config) {
	if conf == nil {
		return
	}
	user, password, found := "", "", false
	if conf.Options != nil {
		if h, ok := conf.Options[OptionHost]; ok {
			if p, ok := splitConnString(h); ok && p.hasUser {
				user, password = p.credentials()
				found = true
				conf.Options[OptionHost] = p.withoutUserinfo()
			}
		}
	}
	// conf.Host is redacted too, but when both carry user info the one in
	// Options wins, as Options[OptionHost] is also the host that gets dialed.
	if p, ok := splitConnString(conf.Host); ok && p.hasUser {
		if !found {
			user, password = p.credentials()
			found = true
		}
		conf.Host = p.withoutUserinfo()
	}
	if !found {
		return
	}

	for _, cred := range conf.Credentials {
		if cred == nil || cred.Type != vault.CredentialType_password {
			continue
		}
		if cred.User == "" {
			cred.User = user
		}
		if len(cred.Secret) == 0 {
			cred.Secret = []byte(password)
		}
		return
	}
	conf.Credentials = append(conf.Credentials, vault.NewPasswordCredential(user, password))
}
