// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/gopcua/opcua/ua"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func endpoint(policy string, mode ua.MessageSecurityMode, level uint8, tokens ...ua.UserTokenType) *ua.EndpointDescription {
	ep := &ua.EndpointDescription{
		EndpointURL:       "opc.tcp://server:4840",
		SecurityPolicyURI: policy,
		SecurityMode:      mode,
		SecurityLevel:     level,
	}
	for _, t := range tokens {
		ep.UserIdentityTokens = append(ep.UserIdentityTokens, &ua.UserTokenPolicy{TokenType: t})
	}
	return ep
}

// hardenedServer models a correctly configured server: it offers no None
// endpoint at all, only Basic256Sha256 with Sign and SignAndEncrypt.
func hardenedServer() []*ua.EndpointDescription {
	return []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 0, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeAnonymous),
	}
}

func TestSelectEndpoints_PrefersStrongestSecurity(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIBasic256, ua.MessageSecurityModeSign, 0, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIBasic128Rsa15, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeAnonymous),
	}

	candidates, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	require.Len(t, candidates, 4)

	// strongest policy and mode combination first. Basic128Rsa15 is deprecated,
	// so encrypting with it does not outrank signing with Basic256.
	assert.Equal(t, []string{
		"Basic256Sha256/SignAndEncrypt",
		"Basic256/Sign",
		"Basic128Rsa15/SignAndEncrypt",
		"None/None",
	}, describeAll(candidates))
}

// A server that advertises an endpoint it cannot serve must not take the whole
// asset down: the weaker endpoints stay in the list as fallbacks.
func TestSelectEndpoints_FallbackOrderIncludesWeakerEndpoints(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIAes256Sha256RsaPss, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeAnonymous),
	}

	candidates, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"Aes256_Sha256_RsaPss/SignAndEncrypt",
		"None/None",
	}, describeAll(candidates))
}

// The regression guard for insecure servers: a None-only server still connects.
func TestSelectEndpoints_NoneOnlyServerStillConnects(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, ua.UserTokenTypeAnonymous),
	}

	candidates, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	assert.Equal(t, "None/None", describeEndpoint(candidates[0]))
}

// This is the shape that used to make the provider fail outright: asking for
// None/None on a server that offers neither.
func TestSelectEndpoints_HardenedServerIsReachable(t *testing.T) {
	candidates, err := selectEndpoints(hardenedServer(), "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"Basic256Sha256/SignAndEncrypt",
		"Basic256Sha256/Sign",
	}, describeAll(candidates))
}

func TestSelectEndpoints_ExplicitPolicyAndMode(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSign, 0, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeAnonymous),
	}

	candidates, err := selectEndpoints(endpoints, "Basic256Sha256", "Sign", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	assert.Equal(t, "Basic256Sha256/Sign", describeEndpoint(candidates[0]))

	// pinning only the mode leaves every policy in that mode as a candidate
	candidates, err = selectEndpoints(endpoints, "", "None", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
	assert.Equal(t, "None/None", describeEndpoint(candidates[0]))
}

func TestSelectEndpoints_NoMatchForPinnedSettings(t *testing.T) {
	_, err := selectEndpoints(hardenedServer(), "None", "None", ua.UserTokenTypeAnonymous)
	require.Error(t, err)
	// the error names what the server actually offers
	assert.Contains(t, err.Error(), "Basic256Sha256/SignAndEncrypt")
	assert.Contains(t, err.Error(), "anonymous")
}

// A server that only accepts username authentication has to say so, rather than
// blaming the security settings.
func TestSelectEndpoints_NoMatchForTokenTypeNamesTheAuthentication(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeUserName),
	}

	_, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeAnonymous)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no endpoint supports anonymous authentication")
	assert.Contains(t, err.Error(), "authentication username and password")
}

func TestSelectEndpoints_FiltersByUserTokenType(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeUserName),
		endpoint(ua.SecurityPolicyURIBasic256, ua.MessageSecurityModeSign, 0, ua.UserTokenTypeAnonymous),
	}

	anonymous, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	require.Len(t, anonymous, 1)
	assert.Equal(t, "Basic256/Sign", describeEndpoint(anonymous[0]))

	username, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeUserName)
	require.NoError(t, err)
	require.Len(t, username, 1)
	assert.Equal(t, "Basic256Sha256/SignAndEncrypt", describeEndpoint(username[0]))
}

// Servers that advertise no user identity tokens at all must not be dropped.
func TestSelectEndpoints_EndpointWithoutTokenPoliciesIsKept(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 0),
	}

	candidates, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeUserName)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
}

// The level the server publishes breaks ties, but only after policy and mode.
func TestSelectEndpoints_SecurityLevelBreaksTies(t *testing.T) {
	low := endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 1, ua.UserTokenTypeAnonymous)
	low.EndpointURL = "opc.tcp://low:4840"
	high := endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 9, ua.UserTokenTypeAnonymous)
	high.EndpointURL = "opc.tcp://high:4840"

	candidates, err := selectEndpoints([]*ua.EndpointDescription{low, high}, "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	require.Len(t, candidates, 2)
	assert.Equal(t, "opc.tcp://high:4840", candidates[0].EndpointURL)
}

// An unknown policy cannot be negotiated by this client, so it must never be
// preferred over a policy we can actually speak.
func TestSelectEndpoints_UnknownPolicyRanksLast(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		endpoint(ua.SecurityPolicyURIPrefix+"Future_Policy", ua.MessageSecurityModeSignAndEncrypt, 9, ua.UserTokenTypeAnonymous),
		endpoint(ua.SecurityPolicyURIBasic256Sha256, ua.MessageSecurityModeSignAndEncrypt, 0, ua.UserTokenTypeAnonymous),
	}

	candidates, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	assert.Equal(t, []string{
		"Basic256Sha256/SignAndEncrypt",
		"Future_Policy/SignAndEncrypt",
	}, describeAll(candidates))
}

func TestSelectEndpoints_NoEndpointsAdvertised(t *testing.T) {
	_, err := selectEndpoints(nil, "", "", ua.UserTokenTypeAnonymous)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not advertise any endpoints")
}

func TestSelectEndpoints_NilEndpointsAreSkipped(t *testing.T) {
	endpoints := []*ua.EndpointDescription{
		nil,
		endpoint(ua.SecurityPolicyURINone, ua.MessageSecurityModeNone, 0, ua.UserTokenTypeAnonymous),
	}

	candidates, err := selectEndpoints(endpoints, "", "", ua.UserTokenTypeAnonymous)
	require.NoError(t, err)
	require.Len(t, candidates, 1)
}

func TestParseSecurityPolicy(t *testing.T) {
	tests := []struct {
		policy  string
		want    string
		wantErr bool
	}{
		{policy: "", want: ""},
		{policy: "None", want: ua.SecurityPolicyURINone},
		{policy: "Basic256Sha256", want: ua.SecurityPolicyURIBasic256Sha256},
		{policy: "Aes256Sha256RsaPss", want: ua.SecurityPolicyURIAes256Sha256RsaPss},
		{policy: ua.SecurityPolicyURIBasic256, want: ua.SecurityPolicyURIBasic256},
		// the policy name is case sensitive, a near miss has to be reported
		{policy: "Basic256sha256", wantErr: true},
		{policy: "nonsense", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.policy, func(t *testing.T) {
			got, err := parseSecurityPolicy(test.policy)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func TestParseSecurityMode(t *testing.T) {
	tests := []struct {
		mode    string
		want    ua.MessageSecurityMode
		wantErr bool
	}{
		{mode: "", want: ua.MessageSecurityModeInvalid},
		{mode: "None", want: ua.MessageSecurityModeNone},
		{mode: "Sign", want: ua.MessageSecurityModeSign},
		{mode: "SignAndEncrypt", want: ua.MessageSecurityModeSignAndEncrypt},
		// a typo must be reported, not silently downgraded to "any mode"
		{mode: "signandencrypt", wantErr: true},
		{mode: "Invalid", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.mode, func(t *testing.T) {
			got, err := parseSecurityMode(test.mode)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
}

func describeAll(endpoints []*ua.EndpointDescription) []string {
	res := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		res = append(res, describeEndpoint(ep))
	}
	return res
}
