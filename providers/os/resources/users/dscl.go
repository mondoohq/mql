// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users

import (
	"io"
	"regexp"
	"strconv"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

var USER_OSX_DSCL_REGEX = regexp.MustCompile(`(?m)^(\S*)\s*(.*)$`)

func ParseDsclListResult(input io.Reader) (map[string]string, error) {
	content, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}

	userMap := make(map[string]string)
	m := USER_OSX_DSCL_REGEX.FindAllStringSubmatch(string(content), -1)
	for i := range m {
		key := m[i][1]
		value := m[i][2]

		if len(key) > 0 {
			userMap[key] = value
		}
	}
	return userMap, nil
}

type OSXUserManager struct {
	conn shared.Connection
}

func (s *OSXUserManager) Name() string {
	return "macOS User Manager"
}

func (s *OSXUserManager) User(id string) (*User, error) {
	users, err := s.List()
	if err != nil {
		return nil, err
	}

	return findUser(users, id)
}

// To retrieve all user information, we have two options:
//
//  1. fetch all users via `dscl . list /Users`
//  2. iterate over each user and fetch the data via
//     dscl -q . -read /Users/nobody NFSHomeDirectory PrimaryGroupID RecordName UniqueID UserShell
//
// This approach is not very effective since it requires O(n), there we use the option to fetch one
// value per list, which requires us to do 5 calls to fetch all information:
// dscl . -list /Users UserShell
// dscl . -list /Users UniqueID
// dscl . -list /Users NFSHomeDirectory
// dscl . -list /Users RecordName
// dscl . -list /Users RealName
func (s *OSXUserManager) List() ([]*User, error) {
	users := make(map[string]*User)

	// fetch all uids first
	f, err := s.conn.RunCommand("dscl . -list /Users UniqueID")
	if err != nil {
		return nil, err
	}

	m, err := ParseDsclListResult(f.Stdout)
	if err != nil {
		return nil, err
	}
	for k := range m {
		uid, err := strconv.ParseInt(m[k], 10, 0)
		if err != nil {
			log.Error().Err(err).Str("user", k).Msg("could not parse uid")
		}

		// dscl does not report whether an account is disabled
		users[k] = &User{
			ID:             m[k],
			Name:           k,
			Uid:            uid,
			EnabledUnknown: true,
		}
	}

	// fetch shells
	f, err = s.conn.RunCommand("dscl . -list /Users UserShell")
	if err != nil {
		return nil, err
	}

	m, err = ParseDsclListResult(f.Stdout)
	if err != nil {
		return nil, err
	}
	for k := range m {
		if u, ok := users[k]; ok {
			u.Shell = m[k]
		}
	}

	// fetch home
	f, err = s.conn.RunCommand("dscl . -list /Users NFSHomeDirectory")
	if err != nil {
		return nil, err
	}

	m, err = ParseDsclListResult(f.Stdout)
	if err != nil {
		return nil, err
	}
	for k := range m {
		if u, ok := users[k]; ok {
			u.Home = m[k]
		}
	}

	// fetch usernames
	f, err = s.conn.RunCommand("dscl . -list /Users RealName")
	if err != nil {
		return nil, err
	}

	m, err = ParseDsclListResult(f.Stdout)
	if err != nil {
		return nil, err
	}
	for k := range m {
		if u, ok := users[k]; ok {
			u.Description = m[k]
		}
	}

	// fetch gid
	f, err = s.conn.RunCommand("dscl . -list /Users PrimaryGroupID")
	if err != nil {
		return nil, err
	}

	m, err = ParseDsclListResult(f.Stdout)
	if err != nil {
		return nil, err
	}
	for k := range m {
		u, ok := users[k]
		if !ok {
			continue
		}
		gid, err := strconv.ParseInt(m[k], 10, 0)
		if err != nil {
			log.Error().Err(err).Str("user", k).Msg("could not parse gid")
		}
		u.Gid = gid
	}

	// convert map to slice
	res := make([]*User, len(users))

	i := 0
	for k := range users {
		res[i] = users[k]
		i++
	}

	return res, nil
}
