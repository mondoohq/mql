// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"io"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/providers/os/resources/windows"
)

func (r *mqlWindowsLogonSession) id() (string, error) {
	// The LSA assigns each session a locally unique identifier, which is
	// unique for the life of the boot.
	//
	// Both guards exist because an empty id is silently destructive here
	// rather than merely wrong: every session missing one would share a cache
	// key, and CreateResource returns the cached first instance for a repeated
	// id, so the second session would report the first one's values. Failing
	// loudly is the only outcome that does not invent data.
	if r.LogonId.Error != nil {
		return "", r.LogonId.Error
	}
	if r.LogonId.Data == "" {
		return "", errors.New("windows.logonSession has no logonId")
	}
	return "windows.logonSession/" + r.LogonId.Data, nil
}

func (w *mqlWindows) logonSessions() ([]any, error) {
	conn := w.MqlRuntime.Connection.(shared.Connection)

	executedCmd, err := conn.RunCommand(powershell.Encode(windows.LogonSessionsScript))
	if err != nil {
		return nil, err
	}
	if executedCmd.ExitStatus != 0 {
		stderr, err := io.ReadAll(executedCmd.Stderr)
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to retrieve logon sessions: " + string(stderr))
	}

	sessions, err := windows.ParseLogonSessions(executedCmd.Stdout)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(sessions))
	for _, s := range sessions {
		res, err := CreateResource(w.MqlRuntime, "windows.logonSession", map[string]*llx.RawData{
			"logonId":               llx.StringData(s.LogonId),
			"logonType":             llx.IntData(s.LogonType),
			"logonTypeName":         llx.StringData(windows.LogonTypeName(s.LogonType)),
			"authenticationPackage": llx.StringData(s.AuthenticationPackage),
			// TimeDataPtr preserves a missing start time as null. A zero
			// time.Time would report the session as having started in year 1.
			"startTime":     llx.TimeDataPtr(s.StartTime),
			"accountName":   llx.StringData(s.AccountName),
			"accountDomain": llx.StringData(s.AccountDomain),
			"sid":           llx.StringData(s.Sid),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// user resolves the session's account to a local user.
//
// Matched on SID only. An account name is not unique across a machine and the
// domains it trusts, so matching on it would confidently return the wrong
// user for a domain account that shares a name with a local one.
//
// Resolution goes through the cached users collection rather than a lookup per
// session: `user` declares no init, and a per-session lookup would turn one
// enumeration into one per session.
func (r *mqlWindowsLogonSession) user() (*mqlUser, error) {
	if r.Sid.Error != nil {
		return nil, r.Sid.Error
	}

	sid := r.Sid.Data
	if sid == "" {
		// No SID to match on, which is the domain-unreachable case.
		r.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(r.MqlRuntime, "users", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	users := obj.(*mqlUsers)

	list := users.GetList()
	if list.Error != nil {
		return nil, list.Error
	}

	for _, entry := range list.Data {
		usr, ok := entry.(*mqlUser)
		if !ok {
			continue
		}
		if usr.Sid.Data == sid {
			return usr, nil
		}
	}

	// A domain account, or one of the accounts the system creates, is not a
	// local user. The state has to be set explicitly, or the runtime does not
	// know the field resolved and may re-fetch it.
	r.User.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
