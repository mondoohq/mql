// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"bufio"
	"errors"
	"io"
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
				log.Error().Err(err).Str("group", m[0]).Msg("could not parse gid")
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

// listGroups enumerates the groups the system actually resolves, not just the
// ones written in /etc/group.
//
// getent asks NSS, so it also returns groups served by sssd, systemd-userdb,
// LDAP or a distribution specific module. Reading /etc/group alone under
// reports on any such host: on Flatcar, whose groups live in
// /usr/share/flatcar/etc/group behind the usrfiles NSS module, getent lists 56
// groups and /etc/group holds 6. A group that is missing from the list cannot
// fail a check, so the gap is silent and points the wrong way.
//
// This mirrors UnixUserManager.List, which has always preferred getent passwd
// and fallen back to /etc/passwd. The two managers disagreeing is why the same
// host reported 37 users but 6 groups.
func (s *UnixGroupManager) listGroups() ([]*Group, error) {
	groups, err := s.listGetentGroup()
	if err == nil && len(groups) != 0 {
		return groups, nil
	}
	// getent is missing on busybox style images and fails when NSS is
	// misconfigured. Record why we dropped to /etc/group, otherwise a host that
	// should have resolved through NSS looks indistinguishable from one that
	// never had getent at all.
	log.Debug().Err(err).Int("groups", len(groups)).Msg("getent group did not return groups, falling back to /etc/group")
	return s.listEtcGroup()
}

func (s *UnixGroupManager) listEtcGroup() ([]*Group, error) {
	f, err := s.conn.FileSystem().Open("/etc/group")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	groups, err := ParseEtcGroup(f)
	if err != nil {
		return nil, multierr.Wrap(err, "could not parse /etc/group")
	}
	return groups, nil
}

// https://man7.org/linux/man-pages/man1/getent.1.html
//
// getent group emits the same colon separated format as /etc/group, so the
// existing parser handles it unchanged.
func (s *UnixGroupManager) listGetentGroup() ([]*Group, error) {
	getent, err := s.conn.RunCommand("getent group")
	if err != nil {
		return nil, err
	}

	return ParseEtcGroup(getent.Stdout)
}

func (s *UnixGroupManager) List() ([]*Group, error) {
	groups, err := s.listGroups()
	if err != nil {
		return nil, err
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
