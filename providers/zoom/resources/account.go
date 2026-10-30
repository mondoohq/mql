// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/zoom/connection"
)

// lazyFetch holds the result of a single API read so that every field backed
// by that read costs one call no matter how many of them are queried, and so
// that concurrent field access does not issue the call twice. A failed read is
// not retained, which leaves a later query free to retry it.
type lazyFetch[T any] struct {
	lock    sync.Mutex
	fetched bool
	value   T
}

func (l *lazyFetch[T]) get(fetch func() (T, error)) (T, error) {
	l.lock.Lock()
	defer l.lock.Unlock()
	if l.fetched {
		return l.value, nil
	}
	v, err := fetch()
	if err != nil {
		var zero T
		return zero, err
	}
	l.value = v
	l.fetched = true
	return l.value, nil
}

// orNull reports the value v points at, or marks field null when the API did
// not report the key at all. Absent is not false: leaving an unreported
// setting at its zero value would report the permissive reading as fact, and
// an assertion over it would pass on an account where nothing was read.
func orNull[T any](field *plugin.TValue[T], v *T) (T, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		var zero T
		return zero, nil
	}
	return *v, nil
}

// mqlZoomAccountInternal holds the account reads this resource's fields are
// backed by. Zoom splits them across five responses: the un-optioned settings
// endpoint carries the schedule-meeting, recording, and security sections,
// while the meeting-security and meeting-authentication views of that same
// endpoint are returned only for their own `option` query value, and the lock
// settings endpoint repeats the same split. Each is fetched at most once, so
// querying any subset of the fields backed by a view costs exactly one call
// for it and querying none costs nothing.
type mqlZoomAccountInternal struct {
	settings            lazyFetch[*connection.AccountSettings]
	meetingSecurity     lazyFetch[*connection.MeetingSecuritySettings]
	meetingAuth         lazyFetch[*connection.MeetingAuthenticationSettings]
	lockSettings        lazyFetch[*connection.AccountLockSettings]
	meetingSecurityLock lazyFetch[*connection.MeetingSecurityLockSettings]
}

// initZoomAccount populates the account singleton on construction. It is an
// init rather than a zoom accessor because zoom.account is a
// directly-addressable resource: a field of the same dotted name on the parent
// would collide with the resource and leave its fields unset when queried as
// `zoom.account`. It reads the account's identity eagerly and defers the
// settings, lock settings, and domain reads to lazy field accessors.
func initZoomAccount(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a populated resource
	if len(args) > 1 {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.ZoomConnection)
	info, err := conn.Client().GetAccount(context.Background(), conn.AccountID())
	if err != nil {
		return nil, nil, err
	}

	args["__id"] = llx.StringData(conn.AccountID())
	args["id"] = llx.StringData(conn.AccountID())
	args["accountName"] = llx.StringDataPtr(&info.AccountName)
	args["ownerEmail"] = llx.StringDataPtr(&info.OwnerEmail)
	return args, nil, nil
}

// conn returns the Zoom connection backing this resource.
func (a *mqlZoomAccount) conn() *connection.ZoomConnection {
	return a.MqlRuntime.Connection.(*connection.ZoomConnection)
}

// fetchSettings performs the single un-optioned account-settings GET the
// schedule-meeting, recording, and security fields all read from.
func (a *mqlZoomAccount) fetchSettings() (*connection.AccountSettings, error) {
	return a.settings.get(func() (*connection.AccountSettings, error) {
		conn := a.conn()
		return conn.Client().GetAccountSettings(context.Background(), conn.AccountID())
	})
}

// fetchMeetingSecurity performs the `?option=meeting_security` account-settings
// GET the meeting* fields read from. The meeting_security object is absent from
// the un-optioned response, so it needs its own call rather than a second read
// of fetchSettings.
func (a *mqlZoomAccount) fetchMeetingSecurity() (*connection.MeetingSecuritySettings, error) {
	return a.meetingSecurity.get(func() (*connection.MeetingSecuritySettings, error) {
		conn := a.conn()
		return conn.Client().GetAccountMeetingSecurity(context.Background(), conn.AccountID())
	})
}

// fetchMeetingAuthentication performs the `?option=meeting_authentication`
// account-settings GET. Zoom reports the meeting-authentication requirement as
// a top-level boolean of that view, not as a member of meeting_security, so it
// needs its own call.
func (a *mqlZoomAccount) fetchMeetingAuthentication() (*connection.MeetingAuthenticationSettings, error) {
	return a.meetingAuth.get(func() (*connection.MeetingAuthenticationSettings, error) {
		conn := a.conn()
		return conn.Client().GetAccountMeetingAuthentication(context.Background(), conn.AccountID())
	})
}

// fetchLockSettings performs the un-optioned lock-settings GET the
// schedule-meeting and recording *Locked fields read from.
func (a *mqlZoomAccount) fetchLockSettings() (*connection.AccountLockSettings, error) {
	return a.lockSettings.get(func() (*connection.AccountLockSettings, error) {
		conn := a.conn()
		return conn.Client().GetAccountLockSettings(context.Background(), conn.AccountID())
	})
}

// fetchMeetingSecurityLock performs the `?option=meeting_security`
// lock-settings GET, which is the only view carrying the locks on the
// meeting-security defaults.
func (a *mqlZoomAccount) fetchMeetingSecurityLock() (*connection.MeetingSecurityLockSettings, error) {
	return a.meetingSecurityLock.get(func() (*connection.MeetingSecurityLockSettings, error) {
		conn := a.conn()
		return conn.Client().GetAccountMeetingSecurityLock(context.Background(), conn.AccountID())
	})
}

// ---- identity ----

// owner resolves the account owner from the owner's email address, so the
// owner's own status, sign-in methods, and role can be read alongside the
// account settings.
func (a *mqlZoomAccount) owner() (*mqlZoomUser, error) {
	email := a.OwnerEmail.Data
	if email == "" {
		a.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Zoom's Get a user endpoint accepts an email address wherever it accepts
	// a user ID, so the owner costs one lookup rather than a walk of the
	// account roster.
	res, err := NewResource(a.MqlRuntime, "zoom.user", map[string]*llx.RawData{
		"id": llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlZoomUser), nil
}

// ---- meeting security ----

func (a *mqlZoomAccount) meetingWaitingRoomEnabled() (bool, error) {
	s, err := a.fetchMeetingSecurity()
	if err != nil {
		return false, err
	}
	return s.WaitingRoom, nil
}

func (a *mqlZoomAccount) meetingPasscodeRequired() (bool, error) {
	s, err := a.fetchMeetingSecurity()
	if err != nil {
		return false, err
	}
	return s.MeetingPasswordRequirement, nil
}

func (a *mqlZoomAccount) meetingPmiPasscodeRequired() (bool, error) {
	s, err := a.fetchMeetingSecurity()
	if err != nil {
		return false, err
	}
	return s.PmiPasswordRequirement, nil
}

func (a *mqlZoomAccount) meetingEncryptionType() (string, error) {
	s, err := a.fetchMeetingSecurity()
	if err != nil {
		return "", err
	}
	return s.EncryptionType, nil
}

func (a *mqlZoomAccount) meetingE2eeAvailable() (bool, error) {
	s, err := a.fetchMeetingSecurity()
	if err != nil {
		return false, err
	}
	return s.E2eeAvailable, nil
}

func (a *mqlZoomAccount) meetingAuthenticationRequired() (bool, error) {
	s, err := a.fetchMeetingAuthentication()
	if err != nil {
		return false, err
	}
	return s.MeetingAuthentication, nil
}

func (a *mqlZoomAccount) meetingSignedInUsersOnly() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.ScheduleMeeting.EnforceLogin, nil
}

func (a *mqlZoomAccount) joinBeforeHostEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.JoinBeforeHostEnabled, s.ScheduleMeeting.JoinBeforeHost)
}

// ---- sign-in security ----

func (a *mqlZoomAccount) signInSessionTimeoutWebMinutes() (int64, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return 0, err
	}
	return s.Security.SignAgainPeriodForInactivityOnWeb, nil
}

func (a *mqlZoomAccount) signInSessionTimeoutClientMinutes() (int64, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return 0, err
	}
	return s.Security.SignAgainPeriodForInactivityOnClient, nil
}

func (a *mqlZoomAccount) twoFactorAuthMode() (string, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return "", err
	}
	return orNull(&a.TwoFactorAuthMode, s.Security.SignInWithTwoFactorAuth)
}

// twoFactorAuthGroups resolves the group IDs Zoom reports for the `group`
// two-factor mode. Zoom returns the list only in that mode, so every other
// mode yields an empty list rather than a null.
func (a *mqlZoomAccount) twoFactorAuthGroups() ([]any, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return nil, err
	}
	return resolveZoomGroups(a.MqlRuntime, a.conn(), s.Security.SignInWithTwoFactorAuthGroups)
}

// twoFactorAuthRoles resolves the role IDs Zoom reports for the `role`
// two-factor mode. Zoom returns the list only in that mode, so every other
// mode yields an empty list rather than a null.
func (a *mqlZoomAccount) twoFactorAuthRoles() ([]any, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return nil, err
	}
	return resolveZoomRoles(a.MqlRuntime, a.conn(), s.Security.SignInWithTwoFactorAuthRoles)
}

func (a *mqlZoomAccount) passwordMinimumLength() (int64, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return 0, err
	}
	return orNull(&a.PasswordMinimumLength, s.Security.PasswordRequirement.MinimumPasswordLength)
}

func (a *mqlZoomAccount) passwordSpecialCharacterRequired() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.PasswordSpecialCharacterRequired, s.Security.PasswordRequirement.HaveSpecialCharacter)
}

func (a *mqlZoomAccount) passwordMaxConsecutiveCharacters() (int64, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return 0, err
	}
	return orNull(&a.PasswordMaxConsecutiveCharacters, s.Security.PasswordRequirement.ConsecutiveCharactersLength)
}

func (a *mqlZoomAccount) passwordWeakDetectionEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.PasswordWeakDetectionEnabled, s.Security.PasswordRequirement.WeakEnhanceDetection)
}

func (a *mqlZoomAccount) passwordExpiryDays() (int64, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return 0, err
	}
	return orNull(&a.PasswordExpiryDays, s.Security.PasswordRequirement.ExpiredRule)
}

func (a *mqlZoomAccount) passwordHistoryCount() (int64, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return 0, err
	}
	return orNull(&a.PasswordHistoryCount, s.Security.PasswordRequirement.FormerRule)
}

func (a *mqlZoomAccount) passwordChangeRequiredOnFirstSignIn() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.PasswordChangeRequiredOnFirstSignIn, s.Security.PasswordRequirement.FirstLoginRule)
}

// ---- single sign-on ----

func (a *mqlZoomAccount) ssoSignInEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.SsoSignInEnabled, s.Security.SignInWithSso.Enable)
}

func (a *mqlZoomAccount) ssoRequiredForDomains() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.SsoRequiredForDomains, s.Security.SignInWithSso.RequireSsoForDomains)
}

func (a *mqlZoomAccount) ssoRequiredDomains() ([]any, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return nil, err
	}
	return strToAnyList(s.Security.SignInWithSso.Domains), nil
}

// ssoBypassUsers resolves the users exempted from the single sign-on
// requirement. Zoom identifies each by ID and email; the ID is resolved
// through the account roster, which is read at most once per connection, and
// an entry the roster does not carry falls back to a direct lookup.
func (a *mqlZoomAccount) ssoBypassUsers() ([]any, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return nil, err
	}

	bypass := s.Security.SignInWithSso.SsoBypassUsers
	if len(bypass) == 0 {
		return []any{}, nil
	}

	ids := make([]string, 0, len(bypass))
	for _, u := range bypass {
		// Zoom omits the ID for a user who has not completed onboarding, in
		// which case the email address is the only handle on them. Get a user
		// accepts either.
		if u.ID != "" {
			ids = append(ids, u.ID)
			continue
		}
		if u.Email != "" {
			ids = append(ids, u.Email)
		}
	}
	return resolveZoomUsers(a.MqlRuntime, a.conn(), ids)
}

// ---- domains ----

// managedDomains lists the domains the account has claimed, keyed by domain
// name with the verification status as the value. Zoom offers the endpoint to
// paid accounts only; on an account whose plan does not include it nothing was
// read, so the field is null rather than an empty map, which would claim the
// account has claimed no domains.
func (a *mqlZoomAccount) managedDomains() (map[string]any, error) {
	conn := a.conn()
	res, err := conn.Client().GetManagedDomains(context.Background(), conn.AccountID())
	if err != nil {
		if connection.IsPlanRestricted(err) || connection.IsNotFound(err) {
			log.Debug().Err(err).Msg("zoom> managed domains are not available on this account")
			a.ManagedDomains.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	domains := make(map[string]any, len(res.Domains))
	for _, d := range res.Domains {
		if d.Domain == "" {
			continue
		}
		domains[d.Domain] = d.Status
	}
	return domains, nil
}

// trustedDomains lists the domains the account trusts. As with
// managedDomains, an account whose plan does not include the endpoint reports
// null rather than an empty list.
func (a *mqlZoomAccount) trustedDomains() ([]any, error) {
	conn := a.conn()
	res, err := conn.Client().GetTrustedDomains(context.Background(), conn.AccountID())
	if err != nil {
		if connection.IsPlanRestricted(err) || connection.IsNotFound(err) {
			log.Debug().Err(err).Msg("zoom> trusted domains are not available on this account")
			a.TrustedDomains.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return strToAnyList(res.TrustedDomains), nil
}

// ---- cloud recording ----

func (a *mqlZoomAccount) cloudRecordingEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return s.Recording.CloudRecording, nil
}

func (a *mqlZoomAccount) localRecordingEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.LocalRecordingEnabled, s.Recording.LocalRecording)
}

func (a *mqlZoomAccount) autoRecordingMode() (string, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return "", err
	}
	return orNull(&a.AutoRecordingMode, s.Recording.AutoRecording)
}

func (a *mqlZoomAccount) recordingAutoDeleteEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.RecordingAutoDeleteEnabled, s.Recording.AutoDeleteCmr)
}

func (a *mqlZoomAccount) recordingAutoDeleteDays() (int64, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return 0, err
	}
	return orNull(&a.RecordingAutoDeleteDays, s.Recording.AutoDeleteCmrDays)
}

func (a *mqlZoomAccount) recordingExistingPasscodeRequired() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.RecordingExistingPasscodeRequired, s.Recording.RequiredPasswordForExistingCloudRecordings)
}

func (a *mqlZoomAccount) recordingAccountMembersOnly() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.RecordingAccountMembersOnly, s.Recording.AccountUserAccessRecording)
}

func (a *mqlZoomAccount) recordingDownloadEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.RecordingDownloadEnabled, s.Recording.CloudRecordingDownload)
}

func (a *mqlZoomAccount) recordingDisclaimerEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.RecordingDisclaimerEnabled, s.Recording.RecordingDisclaimer)
}

func (a *mqlZoomAccount) recordingIpAccessControlEnabled() (bool, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.RecordingIpAccessControlEnabled, s.Recording.IPAddressAccessControl.Enable)
}

// recordingIpAccessRanges splits the comma-separated address list Zoom reports
// into one entry per address or range. A response that does not carry the key
// leaves the field null, since no allow list was read; a response that carries
// an empty one reports no ranges, which is the state in which the IP access
// control admits everyone.
func (a *mqlZoomAccount) recordingIpAccessRanges() ([]any, error) {
	s, err := a.fetchSettings()
	if err != nil {
		return nil, err
	}
	raw := s.Recording.IPAddressAccessControl.IPAddressesOrRanges
	if raw == nil {
		a.RecordingIpAccessRanges.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return strToAnyList(connection.SplitIPRanges(*raw)), nil
}

// ---- locked settings ----

func (a *mqlZoomAccount) waitingRoomLocked() (bool, error) {
	s, err := a.fetchMeetingSecurityLock()
	if err != nil {
		return false, err
	}
	return orNull(&a.WaitingRoomLocked, s.WaitingRoom)
}

func (a *mqlZoomAccount) meetingPasscodeLocked() (bool, error) {
	s, err := a.fetchMeetingSecurityLock()
	if err != nil {
		return false, err
	}
	return orNull(&a.MeetingPasscodeLocked, s.MeetingPassword)
}

func (a *mqlZoomAccount) pmiPasscodeLocked() (bool, error) {
	s, err := a.fetchMeetingSecurityLock()
	if err != nil {
		return false, err
	}
	return orNull(&a.PmiPasscodeLocked, s.PmiPassword)
}

func (a *mqlZoomAccount) meetingE2eeAvailableLocked() (bool, error) {
	s, err := a.fetchMeetingSecurityLock()
	if err != nil {
		return false, err
	}
	return orNull(&a.MeetingE2eeAvailableLocked, s.E2eeAvailable)
}

func (a *mqlZoomAccount) meetingSignedInUsersOnlyLocked() (bool, error) {
	s, err := a.fetchLockSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.MeetingSignedInUsersOnlyLocked, s.ScheduleMeeting.EnforceLogin)
}

func (a *mqlZoomAccount) meetingAuthenticationRequiredLocked() (bool, error) {
	s, err := a.fetchLockSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.MeetingAuthenticationRequiredLocked, s.ScheduleMeeting.MeetingAuthentication)
}

func (a *mqlZoomAccount) joinBeforeHostLocked() (bool, error) {
	s, err := a.fetchLockSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.JoinBeforeHostLocked, s.ScheduleMeeting.JoinBeforeHost)
}

func (a *mqlZoomAccount) cloudRecordingLocked() (bool, error) {
	s, err := a.fetchLockSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.CloudRecordingLocked, s.Recording.CloudRecording)
}

func (a *mqlZoomAccount) localRecordingLocked() (bool, error) {
	s, err := a.fetchLockSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.LocalRecordingLocked, s.Recording.LocalRecording)
}

func (a *mqlZoomAccount) recordingAutoDeleteLocked() (bool, error) {
	s, err := a.fetchLockSettings()
	if err != nil {
		return false, err
	}
	return orNull(&a.RecordingAutoDeleteLocked, s.Recording.AutoDeleteCmr)
}
