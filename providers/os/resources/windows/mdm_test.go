// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An Intune enrollment beside the bookkeeping keys Windows keeps under
// Enrollments, which carry no state and no server.
const mdmIntuneJSON = `{"Enrollments":[
{"Id":"Context","ProviderId":null,"EnrollmentState":null,"EnrollmentType":null,"DiscoveryUrl":null,"ServerUrl":null},
{"Id":"Ownership","ProviderId":null,"EnrollmentState":null,"EnrollmentType":null,"DiscoveryUrl":null,"ServerUrl":null},
{"Id":"5D1A3B2C-0000-4000-8000-000000000001","ProviderId":"MS DM Server","EnrollmentState":1,"EnrollmentType":6,
 "DiscoveryUrl":"https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc",
 "ServerUrl":"https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx"}
],"Unreadable":0,"AutopilotTenantId":null,"AutoEnrollMdm":null}`

func TestParseMdmState_Intune(t *testing.T) {
	s, err := ParseMdmState(strings.NewReader(mdmIntuneJSON))
	require.NoError(t, err)
	require.Len(t, s.Enrollments, 3)

	e, err := s.ActiveEnrollment()
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "MS DM Server", e.ProviderID)
	assert.Equal(t, int64(6), *e.EnrollmentType)
	assert.Equal(t, "https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx", e.URL())
	assert.Equal(t, "user", s.Method())
}

// An Intune-managed device also keeps an active "Microsoft Device Management"
// enrollment whose key can sort before the OMA-DM one. The OMA-DM enrollment
// must win, or the vendor is not recognized.
func TestParseMdmState_PrefersOMADMEnrollment(t *testing.T) {
	in := `{"Enrollments":[
{"Id":"3A49A6B2-0000-4000-8000-000000000001","ProviderId":"Microsoft Device Management","EnrollmentState":1,"EnrollmentType":26,
 "DiscoveryUrl":"https://discovery.dm.microsoft.com/EnrollmentConfiguration?api-version=1.0","ServerUrl":null},
{"Id":"87BB0C1D-0000-4000-8000-000000000002","ProviderId":"MS DM Server","EnrollmentState":1,"EnrollmentType":6,
 "DiscoveryUrl":"https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc",
 "ServerUrl":"https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx"}
],"Unreadable":0}`
	s, err := ParseMdmState(strings.NewReader(in))
	require.NoError(t, err)
	e, err := s.ActiveEnrollment()
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "MS DM Server", e.ProviderID)
	assert.Equal(t, "https://r.manage.microsoft.com/devicegatewayproxy/cimhandler.ashx", e.URL())
}

// Without an OMA-DM enrollment the first active enrollment is still reported.
func TestParseMdmState_FirstActiveWithoutOMADM(t *testing.T) {
	in := `{"Enrollments":[
{"Id":"A","ProviderId":"Other","EnrollmentState":2,"DiscoveryUrl":"https://a.example.com"},
{"Id":"B","ProviderId":"Microsoft Device Management","EnrollmentState":1,"DiscoveryUrl":"https://discovery.dm.microsoft.com/x"}
],"Unreadable":0}`
	s, err := ParseMdmState(strings.NewReader(in))
	require.NoError(t, err)
	e, err := s.ActiveEnrollment()
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "B", e.ID)
}

// PowerShell wraps a list held in a property as {"value":[...],"Count":n} on
// some hosts. A plain slice tag decodes that to empty and reports an enrolled
// device as not enrolled.
func TestParseMdmState_WrappedList(t *testing.T) {
	in := `{"Enrollments":{"value":[{"Id":"A","ProviderId":"MS DM Server","EnrollmentState":1,"ServerUrl":"https://r.manage.microsoft.com/x"}],"Count":1},"Unreadable":0}`
	s, err := ParseMdmState(strings.NewReader(in))
	require.NoError(t, err)
	e, err := s.ActiveEnrollment()
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Equal(t, "A", e.ID)
}

// A single element can be flattened out of its array.
func TestParseMdmState_FlattenedSingleElement(t *testing.T) {
	in := `{"Enrollments":{"Id":"A","ProviderId":"MS DM Server","EnrollmentState":1,"ServerUrl":"https://r.manage.microsoft.com/x"},"Unreadable":0}`
	s, err := ParseMdmState(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, s.Enrollments, 1)
	assert.Equal(t, "A", s.Enrollments[0].ID)
}

func TestParseMdmState_NotEnrolled(t *testing.T) {
	s, err := ParseMdmState(strings.NewReader(`{"Enrollments":[],"Unreadable":0,"AutopilotTenantId":null,"AutoEnrollMdm":null}`))
	require.NoError(t, err)
	e, err := s.ActiveEnrollment()
	require.NoError(t, err)
	assert.Nil(t, e)
}

func TestParseMdmState_EmptyOutputIsError(t *testing.T) {
	_, err := ParseMdmState(strings.NewReader("  \n"))
	assert.Error(t, err)
}

func TestParseMdmState_MalformedIsError(t *testing.T) {
	_, err := ParseMdmState(strings.NewReader(`{"Enrollments":`))
	assert.Error(t, err)
}

// An enrollment that failed or was removed leaves its key behind in another
// state. It must not count as enrolled.
func TestMdmEnrollment_ActiveRequiresEnrolledState(t *testing.T) {
	two := int64(2)
	one := int64(1)
	assert.False(t, MdmEnrollment{EnrollmentState: &two, ServerURL: "https://x"}.Active())
	assert.False(t, MdmEnrollment{ServerURL: "https://x"}.Active())
	assert.False(t, MdmEnrollment{EnrollmentState: &one}.Active())
	assert.True(t, MdmEnrollment{EnrollmentState: &one, DiscoveryURL: "https://d"}.Active())
}

func TestMdmEnrollment_URLFallsBackToDiscovery(t *testing.T) {
	assert.Equal(t, "https://d", MdmEnrollment{DiscoveryURL: "https://d"}.URL())
	assert.Equal(t, "https://s", MdmEnrollment{ServerURL: "https://s", DiscoveryURL: "https://d"}.URL())
}

// An unreadable key may be the enrollment, so with nothing else active the
// answer is an error rather than "not enrolled".
func TestMdmState_UnreadableWithoutActiveIsError(t *testing.T) {
	s := &MdmState{Unreadable: 1}
	_, err := s.ActiveEnrollment()
	assert.Error(t, err)
}

func TestMdmState_UnreadableWithActiveIsFine(t *testing.T) {
	one := int64(1)
	s := &MdmState{Unreadable: 1, Enrollments: mdmEnrollmentList{{ID: "A", EnrollmentState: &one, ServerURL: "https://x"}}}
	e, err := s.ActiveEnrollment()
	require.NoError(t, err)
	assert.Equal(t, "A", e.ID)
}

func TestMdmState_Method(t *testing.T) {
	one := int64(1)
	zero := int64(0)
	assert.Equal(t, "automated", (&MdmState{AutopilotTenantID: "t", AutoEnrollMdm: &one}).Method())
	assert.Equal(t, "policy", (&MdmState{AutoEnrollMdm: &one}).Method())
	assert.Equal(t, "user", (&MdmState{AutoEnrollMdm: &zero}).Method())
	assert.Equal(t, "user", (&MdmState{}).Method())
}
