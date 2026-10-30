// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func loadIisFixture(t *testing.T, name string) *IisData {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer f.Close()

	data, err := ParseIisData(f)
	require.NoError(t, err)
	return data
}

func TestParseIisDataNotInstalled(t *testing.T) {
	data := loadIisFixture(t, "iis_not_installed.json")

	require.False(t, data.Installed)
	require.Empty(t, data.Version)
	require.Empty(t, data.Sites)
	require.Empty(t, data.AppPools)

	// A host with no IIS must still answer with an empty configuration rather
	// than a nil map, so the typed fields resolve to null instead of erroring.
	config := ParseIisConfiguration(data.Config)
	require.Nil(t, config.DirectoryBrowsingEnabled)
	require.Nil(t, config.SessionStateMode)
	require.Empty(t, config.SslFlags)
	require.Empty(t, config.CustomHeaders)
}

func TestParseIisDataEmptyOutput(t *testing.T) {
	// The command produced nothing at all. That is reported as "not installed",
	// never as an error, so a scan of a host without PowerShell output still
	// answers.
	data, err := ParseIisData(strings.NewReader("   \n"))
	require.NoError(t, err)
	require.False(t, data.Installed)
	require.Empty(t, data.Sites)
	require.Empty(t, data.AppPools)
}

// The captured fixtures.
//
// `iis.json` and `iis_hardened.json` are **captures**: the shipped iis.ps1 run
// verbatim on a Windows Server 2022 host with the IIS role installed, in two
// deliberately different configuration states, and its stdout written here
// unedited. Every value below is one a real IIS 10 produced.
//
// That distinction is load-bearing rather than pedantic. The values these files
// used to carry were written from the Microsoft.Web.Administration
// documentation, and a live run showed several of them were values no server
// sends — enum-valued configuration attributes in particular, which arrive as a
// boxed Int32 and used to be reported as a bare number.
//
// `iis_synthetic.json` is the hand-authored file, kept deliberately and named so
// it cannot be mistaken for a capture. It carries shapes the host these captures
// came from does not have: an HTTPS binding with a bound certificate, a
// `SpecificUser` application pool identity, a periodic restart schedule, a
// virtual directory with credentials, forms credentials written inline, and a
// site whose configuration disagrees with the server's. Those are all real IIS
// shapes and the parser has to handle them, but the assertions about them are
// **unverified against a live host** and should be read that way.
const (
	iisCapture         = "iis.json"
	iisCaptureHardened = "iis_hardened.json"
	iisCaptureDefault  = "iis_default.json"
	iisSynthetic       = "iis_synthetic.json"
)

// TestParseIisDataSitesFromCapture reads the two sites a real server reported.
func TestParseIisDataSitesFromCapture(t *testing.T) {
	data := loadIisFixture(t, iisCapture)

	require.True(t, data.Installed)
	// "10.0", not "Version 10.0". The registry value carries the prefix and the
	// script strips it; unstripped it turns every version comparison into a
	// string match against a word nobody expects.
	require.Equal(t, "10.0", data.Version)
	require.Equal(t, `C:\Windows\system32\inetsrv\config\applicationHost.config`, data.ApplicationHostPath)
	require.Len(t, data.Sites, 2)

	site := data.Sites[0]
	require.Equal(t, "Default Web Site", site.Name)
	require.Equal(t, int64(1), site.ID)
	require.Equal(t, "Started", site.State)
	require.Equal(t, "DefaultAppPool", site.ApplicationPool)
	// "NCSA", not the CLR member name "Ncsa". LogFormat's members are Iis, Ncsa,
	// W3c and Custom, so ToString() disagrees with every place the format is
	// named — IIS Manager, appcmd and the logFile attribute all say NCSA.
	require.Equal(t, "NCSA", site.LogFormat)
	require.Equal(t, "MaxSize", site.LogPeriod)
	require.Equal(t, "File", site.LogTarget)
	require.False(t, site.LogEnabled)
	require.Len(t, site.Bindings, 1)
	require.Equal(t, "http", site.Bindings[0].Protocol)
	require.Equal(t, int64(80), site.Bindings[0].Port)
	require.Len(t, site.Applications, 1)

	second := data.Sites[1]
	require.Equal(t, "fixture-b", second.Name)
	require.Equal(t, int64(2), second.ID)
	require.Equal(t, "fixture-b-pool", second.ApplicationPool)
	require.Equal(t, int64(8080), second.Bindings[0].Port)
	// Two applications: the root, and one nested below it. The nested one is the
	// only scope in this capture that actually overrides its parent — see
	// TestParseIisConfigurationApplicationOverrideFromCapture.
	require.Len(t, second.Applications, 2)
	require.Equal(t, "/", second.Applications[0].Path)
	require.Equal(t, "/app1", second.Applications[1].Path)
}

// TestParseIisDataAppPoolsFromCapture pins what a real pool reports. Both pools
// here are in the non-hardened state, which is why neither looks like a stock
// pool: the identity is LocalSystem and rapid-fail protection is off.
func TestParseIisDataAppPoolsFromCapture(t *testing.T) {
	data := loadIisFixture(t, iisCapture)
	require.Len(t, data.AppPools, 2)

	for _, pool := range data.AppPools {
		require.Equal(t, "Started", pool.State)
		require.Equal(t, "LocalSystem", pool.IdentityType)
		require.Empty(t, pool.UserName)
		// An idle timeout of 0 is a real setting — the timeout is off — not a
		// missing value, and has to survive decoding as 0 rather than as null.
		require.Equal(t, int64(0), pool.IdleTimeout)
		require.Equal(t, int64(0), pool.PeriodicRestartTime)
		require.False(t, pool.RapidFailProtection)
		require.Equal(t, "Time", pool.LogEventOnRecycle)
	}
	require.Equal(t, "DefaultAppPool", data.AppPools[0].Name)
	require.Equal(t, "fixture-b-pool", data.AppPools[1].Name)

	// The same pools after hardening, which is what proves these fields are read
	// rather than defaulted. A single state cannot tell the two apart.
	hardened := loadIisFixture(t, iisCaptureHardened)
	require.Len(t, hardened.AppPools, 2)
	for _, pool := range hardened.AppPools {
		require.Equal(t, "ApplicationPoolIdentity", pool.IdentityType)
		require.Equal(t, int64(1200), pool.IdleTimeout)
		require.Equal(t, int64(104400), pool.PeriodicRestartTime)
		require.True(t, pool.RapidFailProtection)
		require.Equal(t, int64(300), pool.RapidFailProtectionInterval)
	}
}

// TestParseIisDataSitesSyntheticShapes covers the site and pool shapes the
// captured host does not have. Hand-authored, and unverified against a live
// server — see the comment on iisSynthetic.
func TestParseIisDataSitesSyntheticShapes(t *testing.T) {
	data := loadIisFixture(t, iisSynthetic)
	require.Len(t, data.Sites, 2)

	legacy := data.Sites[1]
	require.Equal(t, "legacy", legacy.Name)
	require.Len(t, legacy.Bindings, 2)

	// The HTTPS binding carries the certificate thumbprint, which is a public
	// identifier, and the SNI flag.
	https := legacy.Bindings[1]
	require.Equal(t, "https", https.Protocol)
	require.Equal(t, int64(443), https.Port)
	require.Equal(t, "legacy.example.com", https.HostName)
	require.Equal(t, "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", https.CertificateHash)
	require.Equal(t, "My", https.CertificateStoreName)
	require.Equal(t, int64(1), https.SslFlags)

	require.Len(t, legacy.Applications, 2)
	shop := legacy.Applications[1]
	require.Equal(t, "/shop", shop.Path)
	require.Equal(t, `D:\sites\legacy\shop`, shop.PhysicalPath)
	require.Len(t, shop.VirtualDirectories, 1)
	require.Equal(t, "svc_shop", shop.VirtualDirectories[0].UserName)

	legacyPool := data.AppPools[1]
	require.Equal(t, "SpecificUser", legacyPool.IdentityType)
	require.Equal(t, `CORP\svc_legacy`, legacyPool.UserName)
	require.Equal(t, []int64{10800, 50400}, legacyPool.PeriodicRestartSchedule)
}

// TestParseIisConfigurationServerScopeFromCapture is the test that used to be
// wrong in the most consequential way.
//
// It asserted that the ASP.NET sections read **null** at server scope, on the
// reasoning that they are declared in machine.config and the root web.config
// rather than in applicationHost.config. A live run disproves it: the server
// configuration object resolves the whole inheritance chain, and every
// system.web section comes back with the value a site inherits. The old
// assertion passed only because the hand-authored fixture declared no
// system.web section at all — the test and the fixture agreed with each other
// and with nothing else.
func TestParseIisConfigurationServerScopeFromCapture(t *testing.T) {
	data := loadIisFixture(t, iisCapture)
	config := ParseIisConfiguration(data.Config)

	// Every one of these was null in the old fixture.
	require.NotNil(t, config.AuthenticationMode)
	require.Equal(t, "None", *config.AuthenticationMode)
	require.NotNil(t, config.SessionStateMode)
	require.Equal(t, "StateServer", *config.SessionStateMode)
	require.NotNil(t, config.MachineKeyValidation)
	require.Equal(t, "MD5", *config.MachineKeyValidation)
	require.NotNil(t, config.CompilationDebug)
	require.True(t, *config.CompilationDebug)
	require.NotNil(t, config.TraceEnabled)
	require.True(t, *config.TraceEnabled)
	require.NotNil(t, config.HttpCookiesRequireSsl)
	require.False(t, *config.HttpCookiesRequireSsl)
	require.NotNil(t, config.TrustLevel)
	require.Equal(t, "Full", *config.TrustLevel)

	// Enum-valued attributes, every one of which used to report a bare number.
	// Microsoft.Web.Administration boxes an Int32 in ConfigurationAttribute.Value
	// even for an enum-typed attribute, so the obvious `-is [System.Enum]` test
	// is false and the number fell straight through.
	require.Equal(t, "Off", *config.CustomErrorsMode)
	require.Equal(t, "Detailed", *config.HttpErrorsMode)
	require.Equal(t, "UseUri", *config.SessionStateCookieless)
	require.Equal(t, "UseUri", *config.FormsCookieless)
	require.Equal(t, "None", *config.FormsProtection)

	// A flags attribute, which is the case no lookup can serve: 7 is
	// Read|Write|Execute plus Script, and the value is not a member of its own
	// enum. Comma-space, which is how .NET renders a flags enum.
	require.Equal(t, "Read, Write, Execute, Script", *config.HandlerAccessPolicy)

	require.NotNil(t, config.DirectoryBrowsingEnabled)
	require.True(t, *config.DirectoryBrowsingEnabled)
	require.Equal(t, int64(65534), *config.MaxUrl)
	require.Equal(t, int64(65534), *config.MaxQueryString)
	require.Equal(t, int64(4294967295), *config.MaxAllowedContentLength)
	require.True(t, *config.AllowDoubleEscaping)
	require.True(t, *config.AllowUnlistedFileExtensions)
	require.True(t, *config.NotListedIsapisAllowed)
	require.True(t, *config.NotListedCgisAllowed)
	require.True(t, *config.AnonymousAuthenticationEnabled)
	require.Equal(t, "IUSR", *config.AnonymousAuthenticationUser)

	// sslFlags now arrives as the **name** "None" rather than as the number 0,
	// because the schema lookup resolves it like any other flags attribute.
	// ParseIisSslFlags accepted both forms already, which is the only reason
	// this field did not change behaviour; the test pins that it still does.
	require.Empty(t, config.SslFlags)

	require.Equal(t, "ASP.NET", config.CustomHeaders["X-Powered-By"])
}

// TestParseIisDataApplicationPoolDefaultsFromCapture reads the defaults every
// application pool inherits. `iis_default.json` is a capture of a stock Windows
// Server 2022 with the IIS role installed and nothing changed.
func TestParseIisDataApplicationPoolDefaultsFromCapture(t *testing.T) {
	data := loadIisFixture(t, iisCaptureDefault)

	section, ok := data.Config[IisSectionApplicationPools].(map[string]any)
	require.True(t, ok, "%s is reported at server scope", IisSectionApplicationPools)
	defaults, ok := section["applicationPoolDefaults"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "v4.0", defaults["managedRuntimeVersion"])
	require.Equal(t, "Integrated", defaults["managedPipelineMode"])

	processModel, ok := defaults["processModel"].(map[string]any)
	require.True(t, ok)
	// An enum attribute, resolved to its name like every other one.
	require.Equal(t, "ApplicationPoolIdentity", processModel["identityType"])
	require.Equal(t, false, processModel["loadUserProfile"])
	require.NotContains(t, processModel, "password", "the pool identity's password is redacted")

	// The pools themselves are appPools, not members of the section.
	require.NotContains(t, section, "add")
	require.Len(t, data.AppPools, 1)
	require.Equal(t, "DefaultAppPool", data.AppPools[0].Name)
}

// TestParseIisConfigurationHardenedCapture reads the same server after
// hardening. Its job is not to check hardening but to show that each field
// above is genuinely read: a value identical in both states is
// indistinguishable from a field the resource ignores.
func TestParseIisConfigurationHardenedCapture(t *testing.T) {
	data := loadIisFixture(t, iisCaptureHardened)
	config := ParseIisConfiguration(data.Config)

	require.Equal(t, "Windows", *config.AuthenticationMode)
	require.Equal(t, "InProc", *config.SessionStateMode)
	require.Equal(t, "UseCookies", *config.SessionStateCookieless)
	require.Equal(t, "UseCookies", *config.FormsCookieless)
	require.Equal(t, "All", *config.FormsProtection)
	require.Equal(t, "HMACSHA256", *config.MachineKeyValidation)
	require.Equal(t, "RemoteOnly", *config.CustomErrorsMode)
	require.Equal(t, "DetailedLocalOnly", *config.HttpErrorsMode)
	require.Equal(t, "Medium", *config.TrustLevel)
	// Two bits instead of four, which is the stock value.
	require.Equal(t, "Read, Script", *config.HandlerAccessPolicy)

	require.False(t, *config.DirectoryBrowsingEnabled)
	require.False(t, *config.CompilationDebug)
	require.False(t, *config.TraceEnabled)
	require.True(t, *config.DeploymentRetail)
	require.True(t, *config.HttpCookiesRequireSsl)
	require.True(t, *config.HttpCookiesHttpOnly)
	require.Equal(t, int64(4096), *config.MaxUrl)
	require.False(t, *config.AnonymousAuthenticationEnabled)

	// The header is removed rather than set to empty, so the key is gone.
	require.NotContains(t, config.CustomHeaders, "X-Powered-By")

	// Every enum field has to differ from the non-hardened capture, or it is not
	// being read. This is the assertion the two captures exist for.
	fail := ParseIisConfiguration(loadIisFixture(t, iisCapture).Config)
	for _, pair := range []struct {
		name string
		a, b *string
	}{
		{"authenticationMode", fail.AuthenticationMode, config.AuthenticationMode},
		{"sessionStateMode", fail.SessionStateMode, config.SessionStateMode},
		{"sessionStateCookieless", fail.SessionStateCookieless, config.SessionStateCookieless},
		{"formsCookieless", fail.FormsCookieless, config.FormsCookieless},
		{"formsProtection", fail.FormsProtection, config.FormsProtection},
		{"machineKeyValidation", fail.MachineKeyValidation, config.MachineKeyValidation},
		{"customErrorsMode", fail.CustomErrorsMode, config.CustomErrorsMode},
		{"httpErrorsMode", fail.HttpErrorsMode, config.HttpErrorsMode},
		{"handlerAccessPolicy", fail.HandlerAccessPolicy, config.HandlerAccessPolicy},
		{"trustLevel", fail.TrustLevel, config.TrustLevel},
	} {
		require.NotNil(t, pair.a, pair.name)
		require.NotNil(t, pair.b, pair.name)
		require.NotEqual(t, *pair.a, *pair.b,
			"%s reads the same in both states, so nothing here proves it is read", pair.name)
	}
}

// TestParseIisConfigurationApplicationOverrideFromCapture covers the deeper
// scope with the one override the capture actually contains.
//
// **The capture contains exactly one**, and that is worth stating: the two
// sites in it agree with the server on every single attribute. The site-level
// override — the case the whole resource exists for, since a check reading
// applicationHost.config directly would report the server's value — is
// therefore not exercised by a live capture today and is covered only by the
// synthetic fixture below.
func TestParseIisConfigurationApplicationOverrideFromCapture(t *testing.T) {
	data := loadIisFixture(t, iisCapture)
	site := data.Sites[1]

	siteConfig := ParseIisConfiguration(site.Config)
	require.Equal(t, int64(7200), *siteConfig.SessionStateTimeout)

	nested := ParseIisConfiguration(site.Applications[1].Config)
	require.Equal(t, "/app1", site.Applications[1].Path)
	require.Equal(t, int64(3600), *nested.SessionStateTimeout,
		"the nested application overrides the site and must not report the site's value")

	// The root application resolves at the site's own path, so the script leaves
	// its configuration out and the resource reuses the site's.
	require.Nil(t, site.Applications[0].Config)
}

// TestParseIisConfigurationSiteOverrideSynthetic is the override case, on the
// hand-authored fixture, because no live capture available to this test has a
// site that disagrees with its server. Unverified against a live host.
func TestParseIisConfigurationSiteOverrideSynthetic(t *testing.T) {
	data := loadIisFixture(t, iisSynthetic)

	server := ParseIisConfiguration(data.Config)
	require.False(t, *server.DirectoryBrowsingEnabled)
	require.Equal(t, "DetailedLocalOnly", *server.HttpErrorsMode)
	require.False(t, *server.AllowDoubleEscaping)
	require.Equal(t, int64(4096), *server.MaxUrl)

	compliant := ParseIisConfiguration(data.Sites[0].Config)
	require.False(t, *compliant.DirectoryBrowsingEnabled)
	require.False(t, *compliant.CompilationDebug)
	require.Equal(t, "RemoteOnly", *compliant.CustomErrorsMode)
	require.Equal(t, "UseCookies", *compliant.SessionStateCookieless)
	require.Equal(t, int64(1200), *compliant.SessionStateTimeout)
	require.Equal(t, "HMACSHA256", *compliant.MachineKeyValidation)
	require.True(t, *compliant.HttpCookiesRequireSsl)
	require.True(t, *compliant.HttpCookiesHttpOnly)
	require.Equal(t, "Windows", *compliant.AuthenticationMode)
	require.Equal(t, []string{"Ssl"}, compliant.SslFlags)
	require.Equal(t, "max-age=31536000", compliant.CustomHeaders["Strict-Transport-Security"])

	overridden := ParseIisConfiguration(data.Sites[1].Config)
	require.True(t, *overridden.DirectoryBrowsingEnabled, "the site turns directory browsing back on")
	require.True(t, *overridden.CompilationDebug)
	require.Equal(t, "Off", *overridden.CustomErrorsMode)
	require.Equal(t, "Detailed", *overridden.HttpErrorsMode)
	require.Equal(t, "UseUri", *overridden.SessionStateCookieless)
	require.Equal(t, int64(3600), *overridden.SessionStateTimeout)
	require.Equal(t, "SHA1", *overridden.MachineKeyValidation)
	require.True(t, *overridden.TraceEnabled)
	require.False(t, *overridden.HttpCookiesRequireSsl)
	require.True(t, *overridden.AllowDoubleEscaping, "the site relaxes request filtering")
	require.Equal(t, int64(8192), *overridden.MaxUrl)

	// Forms authentication without SSL, with the ticket in the URL and no
	// protection, plus credentials written into the configuration in the clear.
	// No live host available to this suite declares inline credentials, so
	// formsCredentialsPasswordFormat is covered here and nowhere else.
	require.Equal(t, "Forms", *overridden.AuthenticationMode)
	require.False(t, *overridden.FormsRequireSsl)
	require.Equal(t, "UseUri", *overridden.FormsCookieless)
	require.Equal(t, "None", *overridden.FormsProtection)
	require.Equal(t, int64(1800), *overridden.FormsTimeout)
	require.Equal(t, "Clear", *overridden.FormsCredentialsPasswordFormat)
	require.NotNil(t, overridden.FormsCredentialsDeclared)
	require.True(t, *overridden.FormsCredentialsDeclared)

	require.Equal(t, "ASP.NET", overridden.CustomHeaders["X-Powered-By"])
	require.Empty(t, overridden.SslFlags)

	// The compliant site declares a credentials element with no users in it, so
	// the format is readable while nothing is actually declared.
	require.NotNil(t, compliant.FormsCredentialsDeclared)
	require.False(t, *compliant.FormsCredentialsDeclared)
}

func TestParseIisSslFlags(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected []string
	}{
		{"absent", nil, []string{}},
		{"numeric zero", float64(0), []string{}},
		{"ssl only", float64(8), []string{"Ssl"}},
		{"ssl and 128 bit", float64(8 + 256), []string{"Ssl", "Ssl128"}},
		{"client certificate required", float64(8 + 32 + 64), []string{"Ssl", "SslNegotiateCert", "SslRequireCert"}},
		{"named single", "Ssl", []string{"Ssl"}},
		{"named list", "Ssl, SslNegotiateCert", []string{"Ssl", "SslNegotiateCert"}},
		{"named none", "None", []string{}},
		{"empty string", "", []string{}},
		{"numeric string", "40", []string{"Ssl", "SslNegotiateCert"}},
		{"unexpected type", true, []string{}},
		// SslMapCert (128) is one of the five names the access section
		// documents. It used to be absent from the table, so a server mapping
		// client certificates to accounts reported nothing for it.
		{"map certificate", float64(128), []string{"SslMapCert"}},
		{"map certificate with ssl", float64(8 + 128), []string{"Ssl", "SslMapCert"}},
		{"all five names", float64(8 + 32 + 64 + 128 + 256), []string{"Ssl", "Ssl128", "SslMapCert", "SslNegotiateCert", "SslRequireCert"}},
		// A bit the table does not name survives as its number rather than
		// being dropped: dropping it would report a stricter transport
		// requirement than the one actually configured.
		{"unnamed bit kept as a number", float64(8 + 1), []string{"1", "Ssl"}},
		{"only an unnamed bit", float64(2), []string{"2"}},
		// Disjoint unnamed bits are reported one per entry rather than as the
		// combined remainder, so every element of the list is a single flag and
		// a caller can compare against one directly.
		{"several unnamed bits", float64(2 + 4), []string{"2", "4"}},
		{"unnamed bits beside names", float64(8 + 2 + 16), []string{"16", "2", "Ssl"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, ParseIisSslFlags(test.input))
		})
	}
}

// TestParseIisConfigurationMachineKeyIsNotASecret pins that the key material the
// script strips never reaches the parsed configuration, whatever the section
// happens to carry. The algorithm name is reported; the key is not, so a section
// that still holds one cannot leak it through a typed field.
func TestParseIisConfigurationMachineKeyIsNotASecret(t *testing.T) {
	const key = "DEADBEEFDEADBEEFDEADBEEFDEADBEEF"
	sections := map[string]any{
		IisSectionMachineKey: map[string]any{
			"validation":    "HMACSHA256",
			"decryption":    "Auto",
			"validationKey": key,
			"decryptionKey": key,
		},
	}
	config := ParseIisConfiguration(sections)
	require.Equal(t, "HMACSHA256", *config.MachineKeyValidation)

	encoded, err := json.Marshal(config)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), key)
}

// TestParseIisConfigurationMalformedSections covers a section that is present
// but not shaped the way the parser expects. It must leave the field null rather
// than panic or invent a value.
func TestParseIisConfigurationMalformedSections(t *testing.T) {
	sections := map[string]any{
		IisSectionDirectoryBrowse:  "not an element",
		IisSectionRequestFiltering: map[string]any{"requestLimits": "not an element"},
		IisSectionSessionState:     map[string]any{"timeout": "not a number"},
		IisSectionHttpProtocol:     map[string]any{"customHeaders": map[string]any{"collection": "not a list"}},
	}

	config := ParseIisConfiguration(sections)
	require.Nil(t, config.DirectoryBrowsingEnabled)
	require.Nil(t, config.MaxUrl)
	require.Nil(t, config.SessionStateTimeout)
	require.Empty(t, config.CustomHeaders)
}

// TestParseIisConfigurationStringBooleans covers the form a value takes when IIS
// reports it as text rather than as a typed attribute.
func TestParseIisConfigurationStringBooleans(t *testing.T) {
	sections := map[string]any{
		IisSectionDirectoryBrowse: map[string]any{"enabled": "true"},
		IisSectionSessionState:    map[string]any{"timeout": "1200", "mode": "InProc"},
	}

	config := ParseIisConfiguration(sections)
	require.NotNil(t, config.DirectoryBrowsingEnabled)
	require.True(t, *config.DirectoryBrowsingEnabled)
	require.Equal(t, int64(1200), *config.SessionStateTimeout)
	require.Equal(t, "InProc", *config.SessionStateMode)
}

// TestIisScriptRedactsKeyMaterial reads the shipped script and confirms the
// attributes that carry secrets are on its redaction list. The script is what
// decides what leaves the host, so the guarantee belongs here rather than in a
// comment.
func TestIisScriptRedactsKeyMaterial(t *testing.T) {
	require.NotEmpty(t, IIS_CONFIGURATION)
	for _, attribute := range []string{"validationKey", "decryptionKey", "password"} {
		require.Contains(t, IIS_CONFIGURATION, "'"+attribute+"'", "%s must be redacted by the collection script", attribute)
	}
	// The script has to resolve through the management assembly. Reading the
	// configuration file directly would report what one file declares instead of
	// what IIS applies.
	require.Contains(t, IIS_CONFIGURATION, "GetWebConfiguration")
	require.Contains(t, IIS_CONFIGURATION, "Microsoft.Web.Administration")
}

// TestIisScriptLogic runs the collection script's own conversion functions
// against mock configuration elements. The Go tests above start from JSON that
// is shaped like the script's output; this one exercises the script that
// produces that shape, which is where a wrong property name or a missed
// redaction would otherwise sit unnoticed until it ran on a real host.
//
// Skipped where PowerShell is not installed. It is not skipped on Windows only:
// the functions under test touch no IIS type, so pwsh on any platform runs them.
func TestIisScriptLogic(t *testing.T) {
	shell, err := exec.LookPath("pwsh")
	if err != nil {
		shell, err = exec.LookPath("powershell")
	}
	if err != nil {
		t.Skip("neither pwsh nor powershell is available")
	}

	out, err := exec.Command(shell, "-NoProfile", "-File", "testdata/iis_logic_check.ps1").CombinedOutput()
	require.NoError(t, err, "script logic check failed:\n%s", out)
	require.Contains(t, string(out), "all harness assertions passed")
}

// TestIisScriptParses is the cheap guard against a syntax error shipping in the
// embedded script, which would otherwise surface as a failed command on a
// customer's host rather than as a failed build.
func TestIisScriptParses(t *testing.T) {
	shell, err := exec.LookPath("pwsh")
	if err != nil {
		shell, err = exec.LookPath("powershell")
	}
	if err != nil {
		t.Skip("neither pwsh nor powershell is available")
	}

	const check = `$errors = $null
$tokens = $null
[void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path 'iis.ps1'), [ref]$tokens, [ref]$errors)
if ($errors -and $errors.Count -gt 0) { $errors | ForEach-Object { $_.Message }; exit 1 }
'parsed'`

	out, err := exec.Command(shell, "-NoProfile", "-Command", check).CombinedOutput()
	require.NoError(t, err, "collection script does not parse:\n%s", out)
	require.Contains(t, string(out), "parsed")
}
