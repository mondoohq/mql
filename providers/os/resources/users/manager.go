// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users

import (
	"errors"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

type User struct {
	ID          string
	Uid         int64
	Gid         int64
	Sid         string
	Name        string
	Description string
	Shell       string
	Home        string
	Enabled     bool
	// EnabledUnknown is set when the account state could not be read, for
	// example /etc/shadow is not readable by a non-root user. Enabled is then
	// meaningless and the user's enabled field is reported as null.
	EnabledUnknown bool
}

type OSUserManager interface {
	Name() string
	User(id string) (*User, error)
	List() ([]*User, error)
}

func ResolveManager(conn shared.Connection) (OSUserManager, error) {
	var um OSUserManager

	asset := conn.Asset()
	if osFamilyConn, ok := conn.(shared.ConnectionWithOSFamily); ok {
		osFamily := osFamilyConn.OSFamily()
		switch osFamily {
		case shared.OSFamily_Windows:
			um = &WindowsUserManager{conn: conn}
		case shared.OSFamily_Unix:
			um = &UnixUserManager{conn: conn}
		case shared.OSFamily_Darwin:
			um = &OSXUserManager{conn: conn}
		default:
			return nil, errors.New("could not detect suitable group manager for platform: " + string(osFamily))
		}
	} else {
		if asset == nil || asset.Platform == nil {
			return nil, errors.New("cannot find OS information for users detection")
		}

		// check darwin before unix since darwin is also a unix
		if asset.Platform.IsFamily("darwin") {
			um = &OSXUserManager{conn: conn}
		} else if asset.Platform.IsFamily("unix") {
			um = &UnixUserManager{conn: conn}
		} else if asset.Platform.IsFamily("windows") {
			um = &WindowsUserManager{conn: conn}
		}
	}

	if um == nil {
		return nil, errors.New("could not detect suitable group manager for platform: " + asset.Platform.Name)
	}

	return um, nil
}

func findUser(users []*User, id string) (*User, error) {
	// search for id
	for i := range users {
		user := users[i]
		if user.ID == id {
			return user, nil
		}
	}

	return nil, errors.New("user> " + id + " does not exist")
}
