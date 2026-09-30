// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package users

import (
	"io"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

type WindowsSID struct {
	BinaryLength     int
	AccountDomainSid *string
	Value            string
}

// NOTE: there is some overlap with windows groups
type WindowsLocalUser struct {
	// same values as in group
	Name            string
	Description     string
	PrincipalSource int
	SID             WindowsSID
	ObjectClass     string

	// special attributes for user.
	// For profile-only SIDs (domain/AAD users that aren't in Get-LocalUser) Enabled
	// is always true - the script can't read AD/AAD state without LSA, and a profile
	// on disk implies the account logged in at some point. Don't treat Enabled as
	// authoritative for synthesized entries; cross-check against an upstream IDP.
	Enabled                bool
	FullName               string
	PasswordRequired       bool
	UserMayChangePassword  bool
	AccountExpires         *string
	PasswordChangeableDate *string
	PasswordExpires        *string
	PasswordLastSet        *string
	LastLogon              *string

	// On-disk profile path, joined from HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList.
	// Empty for accounts that have never logged in (Guest, DefaultAccount, WDAGUtilityAccount, ...).
	LocalPath string
}

// getLocalUsersScript unions Get-LocalUser with ProfileList registry entries so
// domain/AAD users with profiles on disk show up in users.list. Names for
// profile-only SIDs come from the profile path leaf, upgraded to the UPN from
// the IdentityStore cache for AAD SIDs - never from LSA, so AD reachability
// never gates discovery. Registry I/O uses [Microsoft.Win32.Registry] directly
// (the PSDrive provider adds ~10x overhead per call).
const getLocalUsersScript = `
$svcSids = @{ 'S-1-5-18' = $true; 'S-1-5-19' = $true; 'S-1-5-20' = $true }
$profiles = @{}
$plKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList', $false)
if ($plKey) {
    try {
        foreach ($sid in $plKey.GetSubKeyNames()) {
            if ($svcSids.ContainsKey($sid)) { continue }
            $sub = $plKey.OpenSubKey($sid, $false)
            if ($sub) {
                try {
                    $path = $sub.GetValue('ProfileImagePath')
                    if ($path) { $profiles[$sid] = [string]$path }
                } finally { $sub.Close() }
            }
        }
    } finally { $plKey.Close() }
}
$locals = @{}
foreach ($u in Get-LocalUser) { $locals[$u.SID.Value] = $u }
$machineDomainSid = $null
foreach ($u in $locals.Values) {
    if ($u.SID -and $u.SID.AccountDomainSid) {
        $machineDomainSid = $u.SID.AccountDomainSid.Value
        break
    }
}
$identityStoreRoot = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\IdentityStore\Cache', $false)
function Get-LeafName {
    param([string]$path)
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }
    $leaf = [System.IO.Path]::GetFileName($path.TrimEnd('\','/'))
    if ([string]::IsNullOrWhiteSpace($leaf)) { return $null }
    return $leaf.Trim()
}
function Get-AadCachedName {
    param([string]$sid)
    if (-not ($sid -like 'S-1-12-1-*')) { return $null }
    if (-not $identityStoreRoot) { return $null }
    $cacheKey = $identityStoreRoot.OpenSubKey("$sid\IdentityCache\$sid", $false)
    if (-not $cacheKey) { return $null }
    try {
        $name = $cacheKey.GetValue('UserName')
        if ($name) {
            $n = [string]$name
            if (-not [string]::IsNullOrWhiteSpace($n)) { return $n.Trim() }
        }
    } finally { $cacheKey.Close() }
    return $null
}
$allSids = New-Object 'System.Collections.Generic.HashSet[string]'
foreach ($k in $locals.Keys)   { [void]$allSids.Add($k) }
foreach ($k in $profiles.Keys) { [void]$allSids.Add($k) }
$out = foreach ($sid in $allSids) {
    $u = $locals[$sid]
    if ($u) {
        [PSCustomObject]@{
            Name                   = $u.Name
            Description            = $u.Description
            PrincipalSource        = [int]$u.PrincipalSource
            ObjectClass            = $u.ObjectClass
            Enabled                = [bool]$u.Enabled
            FullName               = $u.FullName
            PasswordRequired       = [bool]$u.PasswordRequired
            UserMayChangePassword  = [bool]$u.UserMayChangePassword
            AccountExpires         = if ($u.AccountExpires) { $u.AccountExpires.ToString('o') } else { $null }
            PasswordChangeableDate = if ($u.PasswordChangeableDate) { $u.PasswordChangeableDate.ToString('o') } else { $null }
            PasswordExpires        = if ($u.PasswordExpires) { $u.PasswordExpires.ToString('o') } else { $null }
            PasswordLastSet        = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('o') } else { $null }
            LastLogon              = if ($u.LastLogon) { $u.LastLogon.ToString('o') } else { $null }
            SID = [PSCustomObject]@{
                BinaryLength     = [int]$u.SID.BinaryLength
                AccountDomainSid = if ($u.SID.AccountDomainSid) { $u.SID.AccountDomainSid.ToString() } else { $null }
                Value            = $u.SID.Value
            }
            LocalPath              = $profiles[$u.SID.Value]
        }
    } else {
        $sidObj = $null
        try { $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid) } catch { }
        $accountDomainSid = $null
        $binaryLength    = 0
        if ($sidObj) {
            try { $binaryLength = [int]$sidObj.BinaryLength } catch { }
            try { if ($sidObj.AccountDomainSid) { $accountDomainSid = $sidObj.AccountDomainSid.ToString() } } catch { }
        }
        $name = Get-AadCachedName -sid $sid
        if (-not $name) { $name = Get-LeafName -path $profiles[$sid] }
        if (-not $name) { $name = $sid }
        $principalSource = 2
        if ($sid -like 'S-1-12-1-*') {
            $principalSource = 3
        } elseif ($accountDomainSid -and $machineDomainSid -and ($accountDomainSid -ieq $machineDomainSid)) {
            $principalSource = 1
        }
        [PSCustomObject]@{
            Name                   = $name
            Description            = ''
            PrincipalSource        = $principalSource
            ObjectClass            = 'User'
            Enabled                = $true
            FullName               = ''
            PasswordRequired       = $false
            UserMayChangePassword  = $false
            AccountExpires         = $null
            PasswordChangeableDate = $null
            PasswordExpires        = $null
            PasswordLastSet        = $null
            LastLogon              = $null
            SID = [PSCustomObject]@{
                BinaryLength     = $binaryLength
                AccountDomainSid = $accountDomainSid
                Value            = $sid
            }
            LocalPath              = $profiles[$sid]
        }
    }
}
if ($identityStoreRoot) { $identityStoreRoot.Close() }
ConvertTo-Json -InputObject @($out) -Depth 3
`

func ParseWindowsLocalUsers(r io.Reader) ([]WindowsLocalUser, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	localUsers, err := powershell.UnmarshalList[WindowsLocalUser](data)
	if err != nil {
		return nil, err
	}

	return localUsers, nil
}

type WindowsUserManager struct {
	conn shared.Connection
}

func (s *WindowsUserManager) Name() string {
	return "Windows User Manager"
}

func (s *WindowsUserManager) User(id string) (*User, error) {
	users, err := s.List()
	if err != nil {
		return nil, err
	}

	return findUser(users, id)
}

func (s *WindowsUserManager) List() ([]*User, error) {
	if shared.WindowsNative(s.conn) {
		native, err := nativeWindowsLocalUsers()
		if err == nil {
			res := []*User{}
			for i := range native {
				res = append(res, winToUser(native[i]))
			}
			return res, nil
		}
		log.Debug().Err(err).Msg("native Windows users failed, falling back to PowerShell")
	}
	// getLocalUsersScript is 5,294 characters, about 14,000 once Encode has
	// widened it to UTF-16 and base64 encoded it, well past MaxCommandLength.
	// Over WinRM the command is routed through cmd.exe and rejected before
	// PowerShell ever runs, so the caller got a non-zero exit with empty stdout
	// and users.list failed with "unexpected end of JSON input". Staging writes
	// the script to the target and runs it with -File, so the command line
	// carries a path rather than the whole program; see powershell.Stage.
	staged, err := powershell.Stage(s.conn, "users", getLocalUsersScript)
	if err != nil {
		return nil, err
	}
	// On the error path too: a scan that dies between the write and the run
	// would otherwise leave the file behind.
	defer staged.Remove()

	c, err := s.conn.RunCommand(staged.Command)
	if err != nil {
		return nil, err
	}
	winUsers, err := ParseWindowsLocalUsers(c.Stdout)
	if err != nil {
		return nil, err
	}

	res := []*User{}
	for i := range winUsers {
		res = append(res, winToUser(winUsers[i]))
	}
	return res, nil
}

func winToUser(g WindowsLocalUser) *User {
	// TODO: consider to store additional attributes in key-value pairs
	return &User{
		ID:      g.SID.Value,
		Sid:     g.SID.Value,
		Uid:     -1, // TODO: not its suboptimal, but lets make sure to avoid runtime conflicts for now
		Gid:     -1,
		Name:    g.Name,
		Home:    g.LocalPath,
		Enabled: g.Enabled,
	}
}
