// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/utils/iox"
)

var GROUP_OSX_DSCACHEUTIL_REGEX = regexp.MustCompile(`^(\S+):\s(.*?)$`)

func ParseDscacheutilResult(input io.Reader) ([]*Group, error) {
	groups := map[string]*Group{}

	add := func(group Group) {
		// a group must have a username, otherwise it is not valid
		// this will happen at least for the last item, where we got an empty row
		// we also need to eliminate duplicates, it happens on macos with dscacheutil -q group
		if len(group.ID) != 0 {
			groups[group.ID] = &group
		}
	}

	scanner := iox.NewLineScanner(input)
	group := Group{Members: []string{}}

	var key string
	for scanner.Scan() {
		line := scanner.Text()

		// reset group definition once we reach an empty line
		if len(line) == 0 {
			add(group)
			group = Group{Members: []string{}}
		}

		m := GROUP_OSX_DSCACHEUTIL_REGEX.FindStringSubmatch(line)
		key = ""
		if m != nil {
			key = m[1]
		}

		// Parse the group content
		switch key {
		case "name":
			group.Name = strings.TrimSpace(m[2])
		case "password":
			// we ignore the password for now
		case "gid":
			gid, err := strconv.ParseInt(m[2], 10, 0)
			if err != nil {
				// m[0] is the whole matched line, not the group name; log the
				// group's name and the offending value instead. Skip recording
				// a bogus ID/gid so the malformed entry is dropped by add().
				log.Error().Err(err).Str("group", group.Name).Str("value", m[2]).Msg("could not parse gid")
				continue
			}
			group.ID = m[2]
			group.Gid = gid
		case "users":
			content := strings.TrimSpace(m[2])
			if len(content) > 0 {
				group.Members = strings.Split(content, " ")
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// if the last line is not an empty line we have things in flight, lets check it
	add(group)

	res := []*Group{}
	for k := range groups {
		res = append(res, groups[k])
	}

	return res, nil
}

type OSXGroupManager struct {
	conn shared.Connection
}

func (s *OSXGroupManager) Name() string {
	return "macOS Group Manager"
}

func (s *OSXGroupManager) Group(id string) (*Group, error) {
	groups, err := s.List()
	if err != nil {
		return nil, err
	}

	return findGroup(groups, id)
}

func (s *OSXGroupManager) List() ([]*Group, error) {
	c, err := s.conn.RunCommand("dscacheutil -q group")
	if err != nil {
		return nil, err
	}
	return ParseDscacheutilResult(c.Stdout)
}
