// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseWinRMListeners(t *testing.T) {
	t.Run("the default HTTP listener of a domain-joined server", func(t *testing.T) {
		input := `[{"Address":"*","Transport":"HTTP","Port":"5985","Hostname":"","Enabled":"true","CertificateThumbprint":""}]`

		list, err := ParseWinRMListeners(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, PSScalar("HTTP"), list[0].Transport)
		assert.Equal(t, int64(5985), list[0].PortNumber())
		assert.Equal(t, PSScalar("*"), list[0].Address)
		assert.True(t, list[0].IsEnabled())
		assert.Equal(t, PSScalar(""), list[0].CertificateThumbprint)
	})

	t.Run("an HTTPS listener reports its certificate and hostname", func(t *testing.T) {
		input := `[{"Address":"IP:10.0.0.4","Transport":"HTTPS","Port":"5986","Hostname":"host.example.com","Enabled":"true","CertificateThumbprint":"9F2B1C3D4E5F60718293A4B5C6D7E8F901234567"}]`

		list, err := ParseWinRMListeners(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, PSScalar("HTTPS"), list[0].Transport)
		assert.Equal(t, int64(5986), list[0].PortNumber())
		assert.Equal(t, PSScalar("host.example.com"), list[0].Hostname)
		assert.Equal(t, PSScalar("9F2B1C3D4E5F60718293A4B5C6D7E8F901234567"), list[0].CertificateThumbprint)
	})

	// A host with no listener is common and is a real answer. It has to decode
	// to an empty list without an error, because the caller turns a decode
	// error into a failed field and an empty list into "nothing is listening",
	// and only one of those is true here.
	t.Run("no listener configured is an empty list, not an error", func(t *testing.T) {
		for _, input := range []string{`[]`, `null`, ``, `   `} {
			list, err := ParseWinRMListeners(strings.NewReader(input))
			require.NoError(t, err, "input %q", input)
			assert.Empty(t, list, "input %q", input)
			assert.NotNil(t, list, "input %q", input)
		}
	})

	// PowerShell serializes the same list two ways. A plain slice tag decodes
	// the Count-wrapped shape to empty and reports "no listeners" on a host
	// that has two.
	t.Run("a Count-wrapped list is not read as empty", func(t *testing.T) {
		input := `{"value":[{"Address":"*","Transport":"HTTP","Port":"5985","Enabled":"true"},{"Address":"*","Transport":"HTTPS","Port":"5986","Enabled":"true"}],"Count":2}`

		list, err := ParseWinRMListeners(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, list, 2)
		assert.Equal(t, PSScalar("HTTP"), list[0].Transport)
		assert.Equal(t, PSScalar("HTTPS"), list[1].Transport)
	})

	t.Run("a Count-wrapped empty list is empty and not an error", func(t *testing.T) {
		list, err := ParseWinRMListeners(strings.NewReader(`{"value":[],"Count":0}`))
		require.NoError(t, err)
		assert.Empty(t, list)
	})

	// A one-element array can reach us as a bare object when PowerShell
	// flattens it away. It must not be confused with the Count wrapper, which
	// is also an object.
	t.Run("a single flattened listener is one listener", func(t *testing.T) {
		input := `{"Address":"*","Transport":"HTTP","Port":"5985","Hostname":"","Enabled":"true","CertificateThumbprint":""}`

		list, err := ParseWinRMListeners(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, PSScalar("HTTP"), list[0].Transport)
		assert.Equal(t, int64(5985), list[0].PortNumber())
	})

	// The WSMan provider reports every setting as a string, but a value that
	// reached ConvertTo-Json as a number or a boolean is rendered unquoted. A
	// plain string tag fails the decode of the whole payload on one of those,
	// which would report a listener host as unreadable.
	t.Run("an unquoted port or enabled flag still decodes", func(t *testing.T) {
		input := `[{"Address":"*","Transport":"HTTP","Port":5985,"Enabled":true,"Hostname":"","CertificateThumbprint":""}]`

		list, err := ParseWinRMListeners(strings.NewReader(input))
		require.NoError(t, err)
		require.Len(t, list, 1)
		assert.Equal(t, int64(5985), list[0].PortNumber())
		assert.True(t, list[0].IsEnabled())
	})

	t.Run("malformed output is an error, not an empty list", func(t *testing.T) {
		_, err := ParseWinRMListeners(strings.NewReader(`not json at all`))
		assert.Error(t, err)
	})
}

func TestWinRMListenerPortNumber(t *testing.T) {
	// 0 rather than a guessed 5985: an unreadable port must stay
	// distinguishable from a listener that really is on the default port.
	assert.Equal(t, int64(0), WinRMListener{Port: ""}.PortNumber())
	assert.Equal(t, int64(0), WinRMListener{Port: "not a port"}.PortNumber())
	assert.Equal(t, int64(5985), WinRMListener{Port: " 5985 "}.PortNumber())
	assert.Equal(t, int64(80), WinRMListener{Port: "80"}.PortNumber())
}

func TestWinRMListenerIsEnabled(t *testing.T) {
	assert.True(t, WinRMListener{Enabled: "true"}.IsEnabled())
	assert.True(t, WinRMListener{Enabled: "True"}.IsEnabled())
	assert.True(t, WinRMListener{Enabled: " true "}.IsEnabled())
	assert.False(t, WinRMListener{Enabled: "false"}.IsEnabled())
	// anything that is not an affirmative reads as disabled rather than
	// defaulting a listener into existence
	assert.False(t, WinRMListener{Enabled: ""}.IsEnabled())
	assert.False(t, WinRMListener{Enabled: "1"}.IsEnabled())
}

// One host carries an HTTP and an HTTPS listener on the same address, and two
// listeners on different addresses with the same transport. Both dimensions
// have to be in the id, or CreateResource returns the cached first instance
// and the second listener reports the first one's port and certificate.
func TestWinRMListenerIDDimensions(t *testing.T) {
	http := WinRMListener{Address: "*", Transport: "HTTP"}
	https := WinRMListener{Address: "*", Transport: "HTTPS"}
	other := WinRMListener{Address: "IP:10.0.0.4", Transport: "HTTP"}

	assert.NotEqual(t, http.ID(), https.ID(), "same address, different transport")
	assert.NotEqual(t, http.ID(), other.ID(), "same transport, different address")
	assert.Equal(t, http.ID(), WinRMListener{Address: "*", Transport: "HTTP"}.ID(), "stable")
}

func TestParseWinRMConfig(t *testing.T) {
	t.Run("a wildcard trusted host is reported verbatim", func(t *testing.T) {
		input := `{"Client":{"TrustedHosts":"*"},"Service":{"IPv4Filter":"*","IPv6Filter":"*"}}`

		config, err := ParseWinRMConfig(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, PSScalar("*"), config.Client.TrustedHosts)
		assert.Equal(t, PSScalar("*"), config.Service.IPv4Filter)
		assert.Equal(t, PSScalar("*"), config.Service.IPv6Filter)
	})

	t.Run("shipped defaults: no trusted host, every address accepted", func(t *testing.T) {
		input := `{"Client":{"TrustedHosts":""},"Service":{"IPv4Filter":"*","IPv6Filter":"*"}}`

		config, err := ParseWinRMConfig(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, PSScalar(""), config.Client.TrustedHosts)
	})

	t.Run("a restricted filter list is reported verbatim", func(t *testing.T) {
		input := `{"Client":{"TrustedHosts":"host1.example.com,*.corp.example.com"},"Service":{"IPv4Filter":"10.0.0.0-10.0.0.255","IPv6Filter":""}}`

		config, err := ParseWinRMConfig(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, PSScalar("host1.example.com,*.corp.example.com"), config.Client.TrustedHosts)
		assert.Equal(t, PSScalar("10.0.0.0-10.0.0.255"), config.Service.IPv4Filter)
		// empty means the service accepts no IPv6 request at all, which is a
		// real setting and not a missing value
		assert.Equal(t, PSScalar(""), config.Service.IPv6Filter)
	})

	// A calculated property yielding nothing serializes as {} rather than as
	// null, which fails the decode of the whole payload against a plain string
	// tag.
	t.Run("an empty object value does not fail the whole decode", func(t *testing.T) {
		input := `{"Client":{"TrustedHosts":{}},"Service":{"IPv4Filter":"*","IPv6Filter":{}}}`

		config, err := ParseWinRMConfig(strings.NewReader(input))
		require.NoError(t, err)
		assert.Equal(t, PSScalar(""), config.Client.TrustedHosts)
		assert.Equal(t, PSScalar("*"), config.Service.IPv4Filter)
		assert.Equal(t, PSScalar(""), config.Service.IPv6Filter)
	})

	t.Run("malformed output is an error", func(t *testing.T) {
		_, err := ParseWinRMConfig(strings.NewReader(`{"Client":`))
		assert.Error(t, err)
	})
}

// The scripts are passed to the target base64 encoded as UTF-16, which roughly
// triples their length against a command line cap that depends on the
// transport. Over the cap the command is rejected before PowerShell runs and
// the non-zero exit reads as "WinRM is not configured".
func TestWinRMScriptsFitCommandLine(t *testing.T) {
	assert.LessOrEqual(t, len(PSGetWinRMListeners), PSMaxScriptLength)
	assert.LessOrEqual(t, len(PSGetWinRMConfig), PSMaxScriptLength)
}

// The WS-Management provider reports every setting as a string, so a boolean
// arrives as "true" or "false". Anything else means the value read was not the
// setting expected, and has to surface as an error: reporting it as false
// would state that the service refuses Basic authentication when nobody
// established that.
func TestPSScalarBool(t *testing.T) {
	for _, tc := range []struct {
		in   PSScalar
		want bool
	}{
		{"true", true},
		{"false", false},
		{"True", true},
		{"FALSE", false},
		{" true ", true},
	} {
		got, err := tc.in.Bool()
		require.NoError(t, err, "input %q", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}

	for _, in := range []PSScalar{"", "yes", "1", "0", "enabled"} {
		_, err := in.Bool()
		require.Error(t, err, "input %q should not decode to a boolean", in)
	}
}

// The payload captured from a stock Windows Server. Every one of these is the
// opposite of, or agrees with, what the policy-key fallback used to report:
// service Basic and unencrypted, and client unencrypted, are all false here
// while the fallback reported them as true.
const stockWinRMConfig = `{"Client":{"TrustedHosts":"","AllowBasic":"true","AllowDigest":"true","AllowUnencrypted":"false"},"Service":{"IPv4Filter":"*","IPv6Filter":"*","AllowBasic":"false","AllowUnencrypted":"false"},"Shell":{"AllowRemoteShellAccess":"true"}}`

func TestParseWinRMConfigStockHost(t *testing.T) {
	config, err := ParseWinRMConfig(strings.NewReader(stockWinRMConfig))
	require.NoError(t, err)

	require.Empty(t, config.Client.TrustedHosts)

	clientBasic, err := config.Client.AllowBasic.Bool()
	require.NoError(t, err)
	require.True(t, clientBasic, "the client offers Basic credentials on a stock host")

	clientDigest, err := config.Client.AllowDigest.Bool()
	require.NoError(t, err)
	require.True(t, clientDigest)

	clientUnenc, err := config.Client.AllowUnencrypted.Bool()
	require.NoError(t, err)
	require.False(t, clientUnenc, "the client refuses unencrypted requests on a stock host")

	serviceBasic, err := config.Service.AllowBasic.Bool()
	require.NoError(t, err)
	require.False(t, serviceBasic, "the service refuses Basic authentication on a stock host")

	serviceUnenc, err := config.Service.AllowUnencrypted.Bool()
	require.NoError(t, err)
	require.False(t, serviceUnenc, "the service refuses unencrypted traffic on a stock host")

	shell, err := config.Shell.AllowRemoteShellAccess.Bool()
	require.NoError(t, err)
	require.True(t, shell)

	require.Equal(t, PSScalar("*"), config.Service.IPv4Filter)
	require.Equal(t, PSScalar("*"), config.Service.IPv6Filter)
}

// A host that has been hardened, to prove the fields move rather than being
// pinned to whatever a stock host happens to report.
func TestParseWinRMConfigHardenedHost(t *testing.T) {
	config, err := ParseWinRMConfig(strings.NewReader(
		`{"Client":{"TrustedHosts":"*.example.com","AllowBasic":"false","AllowDigest":"false","AllowUnencrypted":"false"},` +
			`"Service":{"IPv4Filter":"10.0.0.0-10.0.0.255","IPv6Filter":"","AllowBasic":"false","AllowUnencrypted":"false"},` +
			`"Shell":{"AllowRemoteShellAccess":"false"}}`))
	require.NoError(t, err)

	require.Equal(t, PSScalar("*.example.com"), config.Client.TrustedHosts)
	require.Equal(t, PSScalar("10.0.0.0-10.0.0.255"), config.Service.IPv4Filter)

	for name, v := range map[string]PSScalar{
		"client basic":  config.Client.AllowBasic,
		"client digest": config.Client.AllowDigest,
		"service basic": config.Service.AllowBasic,
		"shell access":  config.Shell.AllowRemoteShellAccess,
	} {
		got, err := v.Bool()
		require.NoError(t, err, name)
		require.False(t, got, name)
	}
}
