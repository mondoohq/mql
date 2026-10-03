// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"slices"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/users"
	"go.mondoo.com/mql/utils/multierr"
)

// a good description of this file is available at:
// https://www.cyberciti.biz/faq/understanding-etcgroup-file/
func ParseEtcGroup(input io.Reader) ([]*Group, error) {
	var groups []*Group
	scanner := bufio.NewScanner(input)
	// glibc has no line limit for /etc/group; read whole lines so a group
	// with thousands of members does not end the scan early.
	scanner.Buffer(make([]byte, 0, 64*1024), math.MaxInt)
	for scanner.Scan() {
		line := scanner.Text()

		// check if line starts with #
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		m := strings.Split(line, ":")
		if len(m) >= 4 {
			// parse gid
			gid, err := strconv.ParseInt(m[2], 10, 0)
			if err != nil {
				// glibc skips the line; reporting it with gid 0 would invent
				// a second root group.
				log.Error().Err(err).Str("group", m[0]).Msg("could not parse gid, skipping group")
				continue
			}

			// extract usernames
			members := []string{}
			if len(m[3]) > 0 {
				members = strings.Split(m[3], ",")
			}

			// vagrant:x:1000:vagrant
			groups = append(groups, &Group{
				ID:      m[2],
				Gid:     gid,
				Name:    m[0],
				Members: members,
			})
		} else {
			log.Warn().Str("line", line).Msg("cannot parse etc group entry")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("cannot read group entries: %w", err)
	}

	return groups, nil
}

type UnixGroupManager struct {
	conn shared.Connection
}

func (s *UnixGroupManager) Name() string {
	return "Unix Group Manager"
}

func (s *UnixGroupManager) Group(id string) (*Group, error) {
	groups, err := s.List()
	if err != nil {
		return nil, err
	}

	return findGroup(groups, id)
}

func (s *UnixGroupManager) List() ([]*Group, error) {
	f, err := s.conn.FileSystem().Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	groups, err := ParseEtcGroup(f)
	if err != nil {
		return nil, multierr.Wrap(err, "could not parse /etc/group")
	}

	um, err := users.ResolveManager(s.conn)
	if err != nil {
		return nil, multierr.Wrap(err, "cannot resolve users manager")
	}
	if um == nil {
		return nil, errors.New("cannot find users manager")
	}

	groupsByGid := map[int64]*Group{}
	for i := range groups {
		g := groups[i]
		groupsByGid[g.Gid] = g
	}

	users, err := um.List()
	if err != nil {
		return nil, multierr.Wrap(err, "could not retrieve users list")
	}

	for _, u := range users {
		if g, ok := groupsByGid[u.Gid]; ok {
			if slices.Contains(g.Members, u.Name) {
				continue
			}
			g.Members = append(g.Members, u.Name)
		}
	}

	return groups, nil
}
