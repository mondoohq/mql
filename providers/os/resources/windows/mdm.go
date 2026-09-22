// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// PSGetMdmState reads the MDM enrollment state from the registry in one round
// trip: every key under Enrollments with the server address of its matching
// OMADM account, the Autopilot tenant assignment, and the Group Policy
// auto-enrollment setting.
//
// A key that cannot be read is counted in Unreadable rather than failing the
// whole script, so one locked key does not hide an enrollment the others
// prove. The caller decides what an unreadable key means for the answer.
const PSGetMdmState = `
$ErrorActionPreference = 'Stop'
$list = @()
$bad = 0
$root = 'HKLM:\SOFTWARE\Microsoft\Enrollments'
if (Test-Path $root) {
  foreach ($k in Get-ChildItem -Path $root) {
    try {
      $p = Get-ItemProperty -Path $k.PSPath
      $acct = 'HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\' + $k.PSChildName
      $addr = $null
      if (Test-Path $acct) { $addr = (Get-ItemProperty -Path $acct).Addr }
      $list += [PSCustomObject]@{
        Id = $k.PSChildName
        ProviderId = $p.ProviderID
        EnrollmentState = $p.EnrollmentState
        EnrollmentType = $p.EnrollmentType
        DiscoveryUrl = $p.DiscoveryServiceFullURL
        ServerUrl = $addr
      }
    } catch { $bad++ }
  }
}
$ap = $null
$apKey = 'HKLM:\SOFTWARE\Microsoft\Provisioning\Diagnostics\Autopilot'
if (Test-Path $apKey) { $ap = (Get-ItemProperty -Path $apKey).CloudAssignedTenantId }
$gp = $null
$gpKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\MDM'
if (Test-Path $gpKey) { $gp = (Get-ItemProperty -Path $gpKey).AutoEnrollMDM }
[PSCustomObject]@{
  Enrollments = @($list)
  Unreadable = $bad
  AutopilotTenantId = $ap
  AutoEnrollMdm = $gp
} | ConvertTo-Json -Depth 3 -Compress
`

// MdmEnrollment is one key under HKLM\SOFTWARE\Microsoft\Enrollments. Windows
// also keeps bookkeeping keys there (Context, Ownership, Status), which carry
// none of these values and are never active.
type MdmEnrollment struct {
	ID              string `json:"Id"`
	ProviderID      string `json:"ProviderId"`
	EnrollmentState *int64 `json:"EnrollmentState"`
	EnrollmentType  *int64 `json:"EnrollmentType"`
	DiscoveryURL    string `json:"DiscoveryUrl"`
	ServerURL       string `json:"ServerUrl"`
}

// mdmEnrollmentStateEnrolled is the EnrollmentState of a completed enrollment.
const mdmEnrollmentStateEnrolled = 1

// Active reports whether the key is a completed enrollment with a management
// server. Both conditions matter: a failed or removed enrollment leaves its key
// behind with another state, and a bookkeeping key has no server at all.
func (e MdmEnrollment) Active() bool {
	if e.EnrollmentState == nil || *e.EnrollmentState != mdmEnrollmentStateEnrolled {
		return false
	}
	return e.ServerURL != "" || e.DiscoveryURL != ""
}

// URL returns the management server address, falling back to the discovery
// service when the OMADM account carries none.
func (e MdmEnrollment) URL() string {
	if e.ServerURL != "" {
		return e.ServerURL
	}
	return e.DiscoveryURL
}

type mdmEnrollmentList []MdmEnrollment

func (l *mdmEnrollmentList) UnmarshalJSON(data []byte) error {
	raw, err := psUnwrapList(data)
	if err != nil {
		return err
	}
	if raw == nil {
		*l = nil
		return nil
	}
	var items []MdmEnrollment
	if err := json.Unmarshal(raw, &items); err != nil {
		return err
	}
	*l = items
	return nil
}

// MdmState is the parsed result of PSGetMdmState.
type MdmState struct {
	Enrollments       mdmEnrollmentList `json:"Enrollments"`
	Unreadable        int64             `json:"Unreadable"`
	AutopilotTenantID string            `json:"AutopilotTenantId"`
	AutoEnrollMdm     *int64            `json:"AutoEnrollMdm"`
}

// ParseMdmState decodes the JSON emitted by PSGetMdmState. Empty output is an
// error: the script always prints an object, so missing output means it did
// not run.
func ParseMdmState(r io.Reader) (*MdmState, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil, errors.New("MDM enrollment state returned no data")
	}
	var state MdmState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// ActiveEnrollment returns the first active enrollment, or nil when there is
// none. When none is active but some keys could not be read, it returns an
// error, because an unreadable key may be the enrollment and reporting "not
// enrolled" would be a guess.
func (s *MdmState) ActiveEnrollment() (*MdmEnrollment, error) {
	for i := range s.Enrollments {
		if s.Enrollments[i].Active() {
			return &s.Enrollments[i], nil
		}
	}
	if s.Unreadable > 0 {
		return nil, errors.New("could not read every MDM enrollment key")
	}
	return nil, nil
}

// Method reports how the active enrollment was made: automated when the device
// holds an Autopilot tenant assignment, policy when Group Policy turns on
// auto-enrollment, and user otherwise.
func (s *MdmState) Method() string {
	switch {
	case s.AutopilotTenantID != "":
		return "automated"
	case s.AutoEnrollMdm != nil && *s.AutoEnrollMdm == 1:
		return "policy"
	default:
		return "user"
	}
}
