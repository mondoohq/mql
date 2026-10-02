// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/shadow"
)

// a good description of this file is available at:
// https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/
func ParseEtcPasswd(input io.Reader) ([]*User, error) {
	var users []*User
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := scanner.Text()

		// check if line starts with #
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		m := strings.Split(line, ":")

		if len(m) >= 7 {
			// parse uid
			uid, err := strconv.ParseInt(m[2], 10, 0)
			if err != nil {
				// Skip the entry rather than fall through with uid 0: a
				// malformed line must not surface as a phantom root account.
				log.Error().Err(err).Str("user", m[0]).Msg("could not parse uid, skipping user")
				continue
			}
			gid, err := strconv.ParseInt(m[3], 10, 0)
			if err != nil {
				log.Error().Err(err).Str("user", m[0]).Msg("could not parse gid, skipping user")
				continue
			}

			// bin:x:1:1:bin:/bin:/sbin/nologin
			users = append(users, &User{
				ID:          m[2],
				Name:        m[0],
				Uid:         uid,
				Gid:         gid,
				Description: m[4],
				Home:        m[5],
				Shell:       m[6],
			})
		}
	}

	return users, nil
}

type UnixUserManager struct {
	conn shared.Connection
}

func (s *UnixUserManager) Name() string {
	return "Unix User Manager"
}

func (s *UnixUserManager) User(id string) (*User, error) {
	users, err := s.List()
	if err != nil {
		return nil, err
	}

	return findUser(users, id)
}

func (s *UnixUserManager) List() ([]*User, error) {
	users, err := s.listGetentPasswd()
	if err != nil || len(users) == 0 {
		// fallback to /etc/passwd
		users, err = s.listEtcPasswd()
		if err != nil {
			return nil, err
		}
	}
	s.setEnabledFromShadow(users, time.Now())
	return users, nil
}

const etcShadowPath = "/etc/shadow"

// setEnabledFromShadow derives each user's Enabled state from /etc/shadow.
// When the file cannot be read (non-root scan, no /etc/shadow on this
// platform) or has no entry for a user (directory-service accounts), the
// state is unknown rather than false.
func (s *UnixUserManager) setEnabledFromShadow(users []*User, now time.Time) {
	entries, err := s.readShadow()
	if err != nil {
		log.Debug().Err(err).Msg("cannot read /etc/shadow, user enabled state is unknown")
	}
	ApplyShadowEnabled(users, entries, now)
}

func (s *UnixUserManager) readShadow() ([]shadow.ShadowEntry, error) {
	f, err := s.conn.FileSystem().Open(etcShadowPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return shadow.ParseShadow(f)
}

// ApplyShadowEnabled sets Enabled on every user that has a shadow entry and
// marks every other user's state as unknown. A nil entries slice (shadow not
// readable) marks all users unknown.
func ApplyShadowEnabled(users []*User, entries []shadow.ShadowEntry, now time.Time) {
	byName := make(map[string]shadow.ShadowEntry, len(entries))
	for _, e := range entries {
		if _, ok := byName[e.User]; !ok {
			byName[e.User] = e
		}
	}
	for _, u := range users {
		e, ok := byName[u.Name]
		if !ok {
			u.Enabled = false
			u.EnabledUnknown = true
			continue
		}
		u.Enabled = ShadowAccountEnabled(e, now)
		u.EnabledUnknown = false
	}
}

// ShadowAccountEnabled reports whether a shadow entry describes an account
// that is neither locked nor expired, matching `passwd -S` and shadow-utils:
// a password field starting with '!' or '*' is locked (status L), and an
// account whose expiry date (days since 1970-01-01) is set, positive, and on
// or before today has expired.
func ShadowAccountEnabled(e shadow.ShadowEntry, now time.Time) bool {
	if strings.HasPrefix(e.Password, "!") || strings.HasPrefix(e.Password, "*") {
		return false
	}
	if e.ExpiryDates != "" {
		expire, err := strconv.ParseInt(e.ExpiryDates, 10, 64)
		if err == nil && expire > 0 {
			today := now.UTC().Unix() / 86400
			if today >= expire {
				return false
			}
		}
	}
	return true
}

func (s *UnixUserManager) listEtcPasswd() ([]*User, error) {
	f, err := s.conn.FileSystem().Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseEtcPasswd(f)
}

// https://man7.org/linux/man-pages/man1/getent.1.html
func (s *UnixUserManager) listGetentPasswd() ([]*User, error) {
	getent, err := s.conn.RunCommand("getent passwd")
	if err != nil {
		return nil, err
	}

	return ParseEtcPasswd(getent.Stdout)
}
