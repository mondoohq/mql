// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package groups

import (
	"errors"
)

type Group struct {
	ID      string // is the string representation of gid on linux/unix and sid on windows
	Gid     int64
	Sid     string
	Name    string
	Members []string
	// MemberSids is parallel to Members on Windows: the SID of each member, so
	// a member resolves to its user by SID, which survives a renamed account.
	// Empty where a member's SID could not be read, and on other platforms.
	MemberSids []string
	// MembersUnknown is set when the members could not be read (for example
	// access denied). Members is then empty, but that is not a statement that
	// the group has none.
	MembersUnknown bool
}

type OSGroupManager interface {
	Name() string
	Group(id string) (*Group, error)
	List() ([]*Group, error)
}

func findGroup(groups []*Group, id string) (*Group, error) {
	// search for id
	for i := range groups {
		group := groups[i]
		if group.ID == id {
			return group, nil
		}
	}

	return nil, errors.New("group> " + id + " does not exist")
}
