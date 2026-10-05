// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// maxLineBytes bounds a single /etc/passwd line, the same 16 MiB cap the
// authorized_keys parser uses.
const maxLineBytes = 16 << 20

// a good description of this file is available at:
// https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/
func ParseEtcPasswd(input io.Reader) ([]*User, error) {
	var users []*User
	scanner := bufio.NewScanner(input)
	// glibc has no line limit for /etc/passwd; read lines up to maxLineBytes so
	// a long entry does not end the scan early. The bound only keeps a
	// pathological file from exhausting memory; a longer line fails the
	// parse through scanner.Err below instead of truncating the list.
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
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
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read passwd entries: %w", err)
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
	if err == nil && len(users) != 0 {
		return users, nil
	}
	// fallback to /etc/passwd
	return s.listEtcPasswd()
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
