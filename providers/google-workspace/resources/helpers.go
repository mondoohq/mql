// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

// filterUsers returns the subset of the customer's users for which keep
// reports true. It reuses the cached `users` field so every aggregate
// accessor shares a single Users.List instead of re-fetching. It resolves
// that field via GetUsers() so the aggregate works even when the caller
// never touched googleworkspace.users directly.
func filterUsers(g *mqlGoogleworkspace, keep func(*mqlGoogleworkspaceUser) (bool, error)) ([]any, error) {
	users := g.GetUsers()
	if users.Error != nil {
		return nil, users.Error
	}
	res := []any{}
	for _, u := range users.Data {
		user := u.(*mqlGoogleworkspaceUser)
		ok, err := keep(user)
		if err != nil {
			return nil, err
		}
		if ok {
			res = append(res, user)
		}
	}
	return res, nil
}

func (g *mqlGoogleworkspace) superAdmins() ([]any, error) {
	return filterUsers(g, func(u *mqlGoogleworkspaceUser) (bool, error) {
		if u.IsAdmin.Error != nil {
			return false, u.IsAdmin.Error
		}
		return u.IsAdmin.Data, nil
	})
}

func (g *mqlGoogleworkspace) suspendedUsers() ([]any, error) {
	return filterUsers(g, func(u *mqlGoogleworkspaceUser) (bool, error) {
		if u.Suspended.Error != nil {
			return false, u.Suspended.Error
		}
		return u.Suspended.Data, nil
	})
}

func (g *mqlGoogleworkspace) usersWithout2sv() ([]any, error) {
	return filterUsers(g, func(u *mqlGoogleworkspaceUser) (bool, error) {
		if u.Suspended.Error != nil {
			return false, u.Suspended.Error
		}
		if u.Archived.Error != nil {
			return false, u.Archived.Error
		}
		if u.IsEnrolledIn2Sv.Error != nil {
			return false, u.IsEnrolledIn2Sv.Error
		}
		// Only count active accounts — suspended / archived users cannot sign
		// in, so their 2SV enrollment is irrelevant to MFA-coverage audits.
		active := !u.Suspended.Data && !u.Archived.Data
		return active && !u.IsEnrolledIn2Sv.Data, nil
	})
}

// hasRecovery reports whether either account-recovery channel is configured.
func hasRecovery(recoveryEmail, recoveryPhone string) bool {
	return recoveryEmail != "" || recoveryPhone != ""
}

func (g *mqlGoogleworkspaceUser) hasRecoveryConfigured() (bool, error) {
	if g.RecoveryEmail.Error != nil {
		return false, g.RecoveryEmail.Error
	}
	if g.RecoveryPhone.Error != nil {
		return false, g.RecoveryPhone.Error
	}
	return hasRecovery(g.RecoveryEmail.Data, g.RecoveryPhone.Data), nil
}

func (g *mqlGoogleworkspaceUser) hasSshKeys() (bool, error) {
	if g.SshPublicKeys.Error != nil {
		return false, g.SshPublicKeys.Error
	}
	return len(g.SshPublicKeys.Data) > 0, nil
}
