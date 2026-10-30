// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// No Exchange server was available to capture output from. The payloads below
// are written by hand in the shape the collection scripts produce (booleans
// and integers as JSON values, collections as string lists, every other value
// as its .NET string form), and the string forms follow Microsoft's
// documentation of each type: ByteQuantifiedSize prints "25 MB (26,214,400
// bytes)", Unlimited<T> prints "Unlimited", TimeSpan and EnhancedTimeSpan
// print [d.]hh:mm:ss, and a flags enum prints its flags joined by ", ".

func TestExchangeScriptsFitCommandLine(t *testing.T) {
	scripts := map[string]string{
		"EXCHANGE_ORGANIZATION": EXCHANGE_ORGANIZATION,
		"EXCHANGE_CLIENTS":      EXCHANGE_CLIENTS,
		"EXCHANGE_TRANSPORT":    EXCHANGE_TRANSPORT,
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			assert.LessOrEqual(t, len(script), PSMaxScriptLength,
				"script is too long to be encoded onto a Windows command line; split it rather than raising the cap")
			assert.Less(t, len(powershell.Encode(script)), 8191)
		})
	}
}

func TestParseExchangeCollection(t *testing.T) {
	// ReceiveConnectors has two records, TransportConfig arrives flattened to
	// a bare object, MailboxDatabases as null, and Get-SenderIdConfig failed
	// because the anti-spam agents are not installed.
	out := `{"Data":{"ReceiveConnectors":[{"Identity":"EX01\\Default EX01","AuthMechanism":"Tls, Integrated, BasicAuth, BasicAuthRequireTLS, ExchangeServer"},{"Identity":"EX01\\Client Frontend EX01","AuthMechanism":"Tls, BasicAuth, BasicAuthRequireTLS"}],"TransportConfig":{"MaxReceiveSize":"25 MB (26,214,400 bytes)"},"MailboxDatabases":null},"Errors":{"SenderIdConfig":"The term 'Get-SenderIdConfig' is not recognized as the name of a cmdlet"}}`

	c, err := ParseExchangeCollection(strings.NewReader(out))
	require.NoError(t, err)

	recv, err := c.Section("ReceiveConnectors")
	require.NoError(t, err)
	require.Len(t, recv, 2)
	id, err := recv[1].String("Identity")
	require.NoError(t, err)
	assert.Equal(t, `EX01\Client Frontend EX01`, *id)

	tc, err := c.Single("TransportConfig")
	require.NoError(t, err)
	size, err := tc.Bytes("MaxReceiveSize")
	require.NoError(t, err)
	assert.Equal(t, int64(26214400), *size)

	dbs, err := c.Section("MailboxDatabases")
	require.NoError(t, err)
	assert.Empty(t, dbs)
	_, err = c.Single("MailboxDatabases")
	assert.Error(t, err, "an organization-wide cmdlet that returned nothing has no settings to report")

	_, err = c.Section("SenderIdConfig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not recognized")

	_, err = c.Section("RemoteDomains")
	assert.Error(t, err, "a section the script never wrote is an error, not an empty list")
}

// testdata/exchange-*-mocked.json are the output of EXCHANGE_TRANSPORT and
// EXCHANGE_CLIENTS run under PowerShell 7 with each Exchange cmdlet replaced
// by a function returning objects of the documented property types: flags
// enums for AuthMechanism and PermissionGroups, TimeSpan for timeouts, string
// lists for bindings, and the string forms of ByteQuantifiedSize and
// Unlimited<T>. They prove the scripts and the parser agree on the shape; they
// say nothing about how a real Exchange server fills the properties in.
func loadExchangeFixture(t *testing.T, name string) *ExchangeCollection {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer f.Close()
	c, err := ParseExchangeCollection(f)
	require.NoError(t, err)
	return c
}

func TestParseExchangeTransportFixture(t *testing.T) {
	c := loadExchangeFixture(t, "exchange-transport-mocked.json")

	recv, err := c.Section("ReceiveConnectors")
	require.NoError(t, err)
	require.Len(t, recv, 2)

	frontend := &ExchangeRecordReader{Record: recv[1]}
	assert.Equal(t, []string{"Tls"}, frontend.Flags("AuthMechanism"))
	assert.Equal(t, []string{"AnonymousUsers", "ExchangeServers", "ExchangeLegacyServers"}, frontend.Flags("PermissionGroups"))
	assert.Equal(t, "220 SMTP Server Ready", *frontend.String("Banner"))
	assert.Equal(t, int64(300), *frontend.Seconds("ConnectionTimeout"))
	assert.Equal(t, int64(26214400), *frontend.Bytes("MaxMessageSize"))
	assert.Equal(t, "Verbose", *frontend.String("ProtocolLoggingLevel"))
	assert.Equal(t, []string{"0.0.0.0:25"}, frontend.Strings("Bindings"))
	assert.False(t, *frontend.Bool("RequireTLS"))
	require.NoError(t, frontend.Err)

	hub := &ExchangeRecordReader{Record: recv[0]}
	assert.Equal(t, []string{"Tls", "Integrated", "BasicAuth", "BasicAuthRequireTLS", "ExchangeServer"}, hub.Flags("AuthMechanism"))
	assert.Nil(t, hub.String("Banner"), "a connector with the default banner has none set")
	require.NoError(t, hub.Err)

	dbs, err := c.Section("MailboxDatabases")
	require.NoError(t, err)
	require.Len(t, dbs, 1)
	db := &ExchangeRecordReader{Record: dbs[0]}
	assert.Equal(t, int64(14*86400), *db.Seconds("DeletedItemRetention"))
	assert.Equal(t, int64(2039480320), *db.Bytes("IssueWarningQuota"))
	assert.Nil(t, db.Bytes("ProhibitSendQuota"), "an Unlimited quota is null, so `<= limit` fails on it")
	require.NoError(t, db.Err)

	send, err := c.Section("SendConnectors")
	require.NoError(t, err)
	require.Len(t, send, 1)
	sc := &ExchangeRecordReader{Record: send[0]}
	assert.Equal(t, int64(600), *sc.Seconds("ConnectionInactivityTimeOut"))
	assert.Equal(t, []string{"SMTP:*;1"}, sc.Strings("AddressSpaces"))
	assert.Empty(t, sc.Strings("SmartHosts"))
	require.NoError(t, sc.Err)
}

func TestParseExchangeClientsFixture(t *testing.T) {
	c := loadExchangeFixture(t, "exchange-clients-mocked.json")

	policies, err := c.Section("MobileDeviceMailboxPolicies")
	require.NoError(t, err)
	require.Len(t, policies, 1)
	p := &ExchangeRecordReader{Record: policies[0]}
	assert.Nil(t, p.Int("MinPasswordLength"), "no minimum set is null, not 0")
	assert.Nil(t, p.Seconds("PasswordExpiration"), "a password that never expires is null, so `<= 365 days` fails on it")
	assert.Equal(t, int64(10), *p.Int("MaxPasswordFailedAttempts"))
	assert.Equal(t, int64(900), *p.Seconds("MaxInactivityTimeLock"))
	assert.Equal(t, int64(3600), *p.Seconds("DevicePolicyRefreshInterval"))
	require.NoError(t, p.Err)

	domains, err := c.Section("RemoteDomains")
	require.NoError(t, err)
	require.Len(t, domains, 2)

	agents, err := c.Section("TransportAgents")
	require.NoError(t, err)
	assert.Empty(t, agents)
}

func TestParseExchangeCollectionWrappedArray(t *testing.T) {
	// Windows PowerShell 5.1 can serialize an array as {"value":[...],"Count":n}.
	out := `{"Data":{"RemoteDomains":{"value":[{"Identity":"Default","AutoForwardEnabled":false},{"Identity":"Partner","AutoForwardEnabled":true}],"Count":2}},"Errors":{}}`
	c, err := ParseExchangeCollection(strings.NewReader(out))
	require.NoError(t, err)
	domains, err := c.Section("RemoteDomains")
	require.NoError(t, err)
	require.Len(t, domains, 2, "the wrapper must not read as one record whose settings are all null")
	b, err := domains[1].Bool("AutoForwardEnabled")
	require.NoError(t, err)
	assert.True(t, *b)
}

func TestParseExchangeCollectionMalformed(t *testing.T) {
	_, err := ParseExchangeCollection(strings.NewReader(""))
	assert.Error(t, err)
	_, err = ParseExchangeCollection(strings.NewReader("WARNING: something\n{"))
	assert.Error(t, err)
}

func TestExchangeRecordBytes(t *testing.T) {
	r := ExchangeRecord{
		"Size":      []byte(`"25 MB (26,214,400 bytes)"`),
		"German":    []byte(`"25 MB (26.214.400 bytes)"`),
		"Swiss":     []byte(`"1.999 GB (2’146’435’072 bytes)"`),
		"Small":     []byte(`"512 B (512 bytes)"`),
		"Unlimited": []byte(`"Unlimited"`),
		"Null":      []byte(`null`),
		"Bad":       []byte(`"twenty megabytes"`),
	}

	cases := map[string]int64{"Size": 26214400, "German": 26214400, "Swiss": 2146435072, "Small": 512}
	for key, want := range cases {
		got, err := r.Bytes(key)
		require.NoError(t, err, key)
		require.NotNil(t, got, key)
		assert.Equal(t, want, *got, key)
	}

	for _, key := range []string{"Unlimited", "Null", "Missing"} {
		got, err := r.Bytes(key)
		require.NoError(t, err, key)
		assert.Nil(t, got, "%s is no size limit, which must not read as 0 bytes", key)
	}

	_, err := r.Bytes("Bad")
	assert.Error(t, err)
}

func TestExchangeRecordSeconds(t *testing.T) {
	r := ExchangeRecord{
		"Timeout":   []byte(`"00:05:00"`),
		"Retention": []byte(`"14.00:00:00"`),
		"Year":      []byte(`"365.00:00:00"`),
		"Fraction":  []byte(`"1.02:03:04.5000000"`),
		"Negative":  []byte(`"-00:00:01"`),
		"Unlimited": []byte(`"Unlimited"`),
		"Hours":     []byte(`"25:00:00"`),
		"Bad":       []byte(`"five minutes"`),
	}

	cases := map[string]int64{"Timeout": 300, "Retention": 1209600, "Year": 31536000, "Fraction": 93784, "Negative": -1}
	for key, want := range cases {
		got, err := r.Seconds(key)
		require.NoError(t, err, key)
		require.NotNil(t, got, key)
		assert.Equal(t, want, *got, key)
	}

	got, err := r.Seconds("Unlimited")
	require.NoError(t, err)
	assert.Nil(t, got)

	_, err = r.Seconds("Hours")
	assert.Error(t, err, "hours past 23 belong in the day part, so this is not a TimeSpan")
	_, err = r.Seconds("Bad")
	assert.Error(t, err)
}

func TestExchangeRecordIntBoolString(t *testing.T) {
	r := ExchangeRecord{
		"Number":     []byte(`10`),
		"NumberStr":  []byte(`"10"`),
		"Unlimited":  []byte(`"Unlimited"`),
		"NotANumber": []byte(`"ten"`),
		"True":       []byte(`true`),
		"TrueStr":    []byte(`"True"`),
		"FalseStr":   []byte(`"False"`),
		"Maybe":      []byte(`"Maybe"`),
		"Empty":      []byte(`""`),
		"Banner":     []byte(`"220 SMTP Server Ready"`),
		"Null":       []byte(`null`),
	}

	for _, key := range []string{"Number", "NumberStr"} {
		n, err := r.Int(key)
		require.NoError(t, err)
		assert.Equal(t, int64(10), *n)
	}
	n, err := r.Int("Unlimited")
	require.NoError(t, err)
	assert.Nil(t, n)
	_, err = r.Int("NotANumber")
	assert.Error(t, err)

	b, err := r.Bool("True")
	require.NoError(t, err)
	assert.True(t, *b)
	b, err = r.Bool("TrueStr")
	require.NoError(t, err)
	assert.True(t, *b)
	b, err = r.Bool("FalseStr")
	require.NoError(t, err)
	assert.False(t, *b)
	b, err = r.Bool("Null")
	require.NoError(t, err)
	assert.Nil(t, b, "an unread boolean is null, not false")
	_, err = r.Bool("Maybe")
	assert.Error(t, err)

	s, err := r.String("Empty")
	require.NoError(t, err)
	assert.Nil(t, s, "an unset banner or mailbox reads as null")
	s, err = r.String("Banner")
	require.NoError(t, err)
	assert.Equal(t, "220 SMTP Server Ready", *s)
	s, err = r.String("Number")
	require.NoError(t, err)
	assert.Equal(t, "10", *s)
}

func TestExchangeRecordFlagsAndStrings(t *testing.T) {
	r := ExchangeRecord{
		"Auth":     []byte(`"Tls, BasicAuth, BasicAuthRequireTLS"`),
		"One":      []byte(`"Tls"`),
		"None":     []byte(`"None"`),
		"List":     []byte(`["*"]`),
		"Wrapped":  []byte(`{"value":["Set-Mailbox","New-Mailbox"],"Count":2}`),
		"Bare":     []byte(`"*"`),
		"EmptyArr": []byte(`[]`),
	}

	f, err := r.Flags("Auth")
	require.NoError(t, err)
	assert.Equal(t, []string{"Tls", "BasicAuth", "BasicAuthRequireTLS"}, f)
	f, err = r.Flags("One")
	require.NoError(t, err)
	assert.Equal(t, []string{"Tls"}, f)
	f, err = r.Flags("None")
	require.NoError(t, err)
	assert.Empty(t, f)
	f, err = r.Flags("Missing")
	require.NoError(t, err)
	assert.Empty(t, f)

	l, err := r.Strings("List")
	require.NoError(t, err)
	assert.Equal(t, []string{"*"}, l)
	l, err = r.Strings("Wrapped")
	require.NoError(t, err)
	assert.Equal(t, []string{"Set-Mailbox", "New-Mailbox"}, l)
	l, err = r.Strings("Bare")
	require.NoError(t, err)
	assert.Equal(t, []string{"*"}, l, "PowerShell can flatten a one-element list to its element")
	l, err = r.Strings("EmptyArr")
	require.NoError(t, err)
	assert.Empty(t, l)
}

func TestExchangeRecordReaderKeepsFirstError(t *testing.T) {
	x := &ExchangeRecordReader{Record: ExchangeRecord{
		"Size":    []byte(`"lots"`),
		"Timeout": []byte(`"soon"`),
		"Enabled": []byte(`true`),
	}}
	assert.Nil(t, x.Bytes("Size"))
	assert.Nil(t, x.Seconds("Timeout"))
	assert.True(t, *x.Bool("Enabled"))
	require.Error(t, x.Err)
	assert.Contains(t, x.Err.Error(), "Size")
}
