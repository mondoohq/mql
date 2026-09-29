// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	detwin "go.mondoo.com/mql/providers/os/detector/windows"
	"go.mondoo.com/mql/utils/syncx"
)

var (
	adLinuxPlatform = &inventory.Platform{Name: "redhat", Family: []string{"redhat", "linux", "unix", "os"}}
	adMacosPlatform = &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}}
)

func windowsWorkstation() *inventory.Platform {
	return &inventory.Platform{
		Name:   "windows",
		Title:  "Windows 11 Enterprise",
		Family: []string{"windows", "os"},
		Labels: map[string]string{"windows.mondoo.com/product-type": "1"},
	}
}

func windowsServer() *inventory.Platform {
	return &inventory.Platform{
		Name:   "windows",
		Title:  "Windows Server 2022 Datacenter",
		Family: []string{"windows", "os"},
		Labels: map[string]string{"windows.mondoo.com/product-type": "3"},
	}
}

// adCommandOutput is a mock answer to the Windows Active Directory query.
func adCommandOutput(stdout string, exit int) *mock.TomlData {
	return &mock.TomlData{Commands: map[string]*mock.Command{
		detwin.ActiveDirectoryInfoCommand(): {Stdout: stdout, ExitStatus: exit},
	}}
}

func newIdpWith(t *testing.T, pf *inventory.Platform, opts ...mock.Option) *mqlIdp {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{Platform: pf}, opts...)
	require.NoError(t, err)
	return &mqlIdp{MqlRuntime: &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}}
}

// A member reports the domain from each platform's own configuration, and
// joined follows from it.
func TestIdpPopulate_ActiveDirectoryMember(t *testing.T) {
	cases := []struct {
		name   string
		pf     *inventory.Platform
		opt    mock.Option
		domain string
		forest string
	}{
		{"Linux joined with SSSD", adLinuxPlatform, mock.WithPath("./testdata/idp_ad_linux_sssd.toml"), "ad.example.com", ""},
		{"Linux joined with winbind", adLinuxPlatform, mock.WithPath("./testdata/idp_ad_linux_winbind.toml"), "ad.example.com", ""},
		{"macOS bound with dsconfigad", adMacosPlatform, mock.WithPath("./testdata/idp_ad_macos.toml"), "corp.example.com", "example.com"},
		{
			"Windows member workstation", windowsWorkstation(),
			mock.WithData(adCommandOutput(`{"DomainRole":1,"Flat":"CORP","Dns":"corp.example.com","Forest":"example.com"}`, 0)),
			"corp.example.com", "example.com",
		},
		{
			"Windows domain controller", windowsServer(),
			mock.WithData(adCommandOutput(`{"DomainRole":5,"Flat":"CORP","Dns":"corp.example.com","Forest":"corp.example.com"}`, 0)),
			"corp.example.com", "corp.example.com",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i := newIdpWith(t, tc.pf, tc.opt)
			require.NoError(t, i.populate())
			assert.Equal(t, plugin.StateIsSet, i.Joined.State)
			assert.True(t, i.Joined.Data)
			require.NotNil(t, i.ActiveDirectory.Data)
			assert.Equal(t, tc.domain, i.ActiveDirectory.Data.Domain.Data)
			if tc.forest == "" {
				assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, i.ActiveDirectory.Data.Forest.State, "forest is null, not empty")
			} else {
				assert.Equal(t, tc.forest, i.ActiveDirectory.Data.Forest.Data)
			}
		})
	}
}

// Detection that ran and found nothing is a measured non-membership; one that
// could not read its source is not.
func TestIdpPopulate_ActiveDirectoryNotMember(t *testing.T) {
	null := plugin.StateIsSet | plugin.StateIsNull

	t.Run("Linux with neither SSSD nor Samba", func(t *testing.T) {
		i := newIdpWith(t, adLinuxPlatform)
		require.NoError(t, i.populate())
		assert.Equal(t, plugin.StateIsSet, i.Joined.State)
		assert.False(t, i.Joined.Data)
		assert.Equal(t, null, i.ActiveDirectory.State)
	})

	t.Run("Linux with SSSD and Samba serving no domain", func(t *testing.T) {
		i := newIdpWith(t, adLinuxPlatform, mock.WithPath("./testdata/idp_ad_linux_none.toml"))
		require.NoError(t, i.populate())
		assert.Equal(t, plugin.StateIsSet, i.Joined.State)
		assert.False(t, i.Joined.Data)
		assert.Equal(t, null, i.ActiveDirectory.State)
	})

	t.Run("an unbound Mac", func(t *testing.T) {
		i := newIdpWith(t, adMacosPlatform)
		require.NoError(t, i.populate())
		assert.Equal(t, plugin.StateIsSet, i.Joined.State)
		assert.False(t, i.Joined.Data)
		assert.Equal(t, null, i.ActiveDirectory.State)
	})

	t.Run("a Windows server in a workgroup", func(t *testing.T) {
		i := newIdpWith(t, windowsServer(), mock.WithData(adCommandOutput(`{"DomainRole":2,"Flat":null,"Dns":null,"Forest":null}`, 0)))
		require.NoError(t, i.populate())
		assert.Equal(t, plugin.StateIsSet, i.Joined.State, "Active Directory was read on the server")
		assert.False(t, i.Joined.Data)
		assert.Equal(t, null, i.ActiveDirectory.State)
		assert.Equal(t, null, i.Entra.State)
	})

	t.Run("a Windows query that fails leaves joined unknown", func(t *testing.T) {
		i := newIdpWith(t, windowsWorkstation(), mock.WithData(adCommandOutput("", 1)))
		require.NoError(t, i.populate())
		assert.Equal(t, null, i.Joined.State, "joined is null, not false")
		assert.Equal(t, null, i.ActiveDirectory.State)
	})

	t.Run("a Windows disk image leaves joined unknown", func(t *testing.T) {
		conn, err := mock.New(0, &inventory.Asset{Platform: windowsWorkstation()})
		require.NoError(t, err)
		i := &mqlIdp{MqlRuntime: &plugin.Runtime{Connection: fileOnlyConn{conn}, Resources: &syncx.Map[plugin.Resource]{}}}
		require.NoError(t, i.populate())
		assert.Equal(t, null, i.Joined.State)
		assert.Equal(t, null, i.ActiveDirectory.State)
	})
}

// fileOnlyConn is a connection that can read files but not run commands, as a
// scan of a disk image.
type fileOnlyConn struct{ *mock.Connection }

func (fileOnlyConn) Capabilities() shared.Capabilities { return shared.Capability_File }

// joined combines every provider's outcome: any membership makes it true,
// Active Directory that could not be read keeps it from being false, and it
// is false only when something was read and nothing was found.
func TestIdpResultSet_Combinations(t *testing.T) {
	null := plugin.StateIsSet | plugin.StateIsNull
	entra := entraMembership{deviceID: "c0ffee00-1234-4abc-8def-0123456789ab", tenantID: "11223344-5566-7788-99aa-bbccddeeff00", joinType: "hybrid"}
	ad := adMember("CORP.example.com", "Example.com")

	newIdp := func() *mqlIdp {
		return &mqlIdp{MqlRuntime: &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}}
	}

	t.Run("hybrid join reports both", func(t *testing.T) {
		i := newIdp()
		require.NoError(t, idpResult{entraRead: true, entra: entra, ad: ad}.set(i))
		assert.True(t, i.Joined.Data)
		require.NotNil(t, i.Entra.Data)
		require.NotNil(t, i.ActiveDirectory.Data)
		assert.Equal(t, "corp.example.com", i.ActiveDirectory.Data.Domain.Data, "names are lower-cased")
		assert.Equal(t, "example.com", i.ActiveDirectory.Data.Forest.Data)
	})

	t.Run("Entra member with unreadable Active Directory is joined", func(t *testing.T) {
		i := newIdp()
		require.NoError(t, idpResult{entraRead: true, entra: entra, ad: adUnreadable}.set(i))
		assert.Equal(t, plugin.StateIsSet, i.Joined.State)
		assert.True(t, i.Joined.Data)
		assert.Equal(t, null, i.ActiveDirectory.State)
	})

	t.Run("no Entra identity and unreadable Active Directory is unknown", func(t *testing.T) {
		i := newIdp()
		require.NoError(t, idpResult{entraRead: true, ad: adUnreadable}.set(i))
		assert.Equal(t, null, i.Joined.State)
	})

	t.Run("Active Directory read alone decides", func(t *testing.T) {
		i := newIdp()
		require.NoError(t, idpResult{ad: adResult{state: membershipRead}}.set(i))
		assert.Equal(t, plugin.StateIsSet, i.Joined.State)
		assert.False(t, i.Joined.Data)
		assert.Equal(t, null, i.Entra.State)
	})

	t.Run("a member on a platform without Entra detection", func(t *testing.T) {
		i := newIdp()
		require.NoError(t, idpResult{ad: ad}.set(i))
		assert.True(t, i.Joined.Data)
		assert.Equal(t, null, i.Entra.State, "Entra was not read")
	})
}

func TestSssdADDomain(t *testing.T) {
	parse := func(s string) confSections { return parseConfSections(s, false) }

	t.Run("ad_domain wins over the SSSD domain name", func(t *testing.T) {
		assert.Equal(t, "ad.example.com", sssdADDomain(parse(`
[sssd]
domains = AD
[domain/AD]
id_provider = ad
ad_domain = ad.example.com
`)))
	})

	t.Run("without ad_domain the SSSD domain name is the domain", func(t *testing.T) {
		assert.Equal(t, "ad.example.com", sssdADDomain(parse(`
[sssd]
domains = ad.example.com
[domain/ad.example.com]
id_provider = ad
`)))
	})

	t.Run("a domain not listed in domains is inactive", func(t *testing.T) {
		assert.Equal(t, "", sssdADDomain(parse(`
[sssd]
domains = local
[domain/local]
id_provider = files
[domain/ad.example.com]
id_provider = ad
`)))
	})

	t.Run("enabled = true activates an unlisted domain", func(t *testing.T) {
		assert.Equal(t, "ad.example.com", sssdADDomain(parse(`
[sssd]
services = nss, pam
[domain/ad.example.com]
id_provider = ad
enabled = true
`)))
	})

	t.Run("an LDAP identity provider is not Active Directory", func(t *testing.T) {
		assert.Equal(t, "", sssdADDomain(parse(`
[sssd]
domains = example.com
[domain/example.com]
id_provider = ldap
auth_provider = krb5
`)))
	})

	t.Run("the first listed Active Directory domain is reported", func(t *testing.T) {
		assert.Equal(t, "two.example.com", sssdADDomain(parse(`
[sssd]
domains = local, two.example.com, one.example.com
[domain/local]
id_provider = files
[domain/one.example.com]
id_provider = ad
[domain/two.example.com]
id_provider = ad
`)))
	})

	t.Run("commented options are ignored", func(t *testing.T) {
		assert.Equal(t, "", sssdADDomain(parse(`
[sssd]
domains = ad.example.com
[domain/ad.example.com]
# id_provider = ad
; id_provider = ad
id_provider = ldap
`)))
	})
}

func TestSambaADDomain(t *testing.T) {
	parse := func(s string) confSections { return parseConfSections(s, true) }

	assert.Equal(t, "AD.EXAMPLE.COM", sambaADDomain(parse("[Global]\n  Security = ads\n  Realm = AD.EXAMPLE.COM\n")),
		"section and option names are case-insensitive")
	assert.Equal(t, "", sambaADDomain(parse("[global]\n  security = user\n  realm = AD.EXAMPLE.COM\n")),
		"a realm without security = ads is not a membership")
	assert.Equal(t, "", sambaADDomain(parse("[share]\n  security = ads\n  realm = AD.EXAMPLE.COM\n")),
		"only the global section counts")
}

// conf.d snippets are merged after sssd.conf in name order, and a later one
// overrides an earlier one.
func TestReadLinuxActiveDirectory_ConfD(t *testing.T) {
	fsys := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fsys, "/etc/sssd/sssd.conf", []byte("[sssd]\ndomains = ad.example.com\n[domain/ad.example.com]\nid_provider = ldap\n"), 0o600))
	require.NoError(t, afero.WriteFile(fsys, "/etc/sssd/conf.d/10-ad.conf", []byte("[domain/ad.example.com]\nid_provider = ad\nad_domain = old.example.com\n"), 0o600))
	require.NoError(t, afero.WriteFile(fsys, "/etc/sssd/conf.d/20-ad.conf", []byte("[domain/ad.example.com]\nad_domain = new.example.com\n"), 0o600))
	require.NoError(t, afero.WriteFile(fsys, "/etc/sssd/conf.d/.30-hidden.conf", []byte("[domain/ad.example.com]\nad_domain = hidden.example.com\n"), 0o600))
	require.NoError(t, afero.WriteFile(fsys, "/etc/sssd/conf.d/40-ad.conf.bak", []byte("[domain/ad.example.com]\nad_domain = backup.example.com\n"), 0o600))

	res := readLinuxActiveDirectory(fsys)
	assert.Equal(t, membershipRead, res.state)
	assert.Equal(t, "new.example.com", res.membership.domain)
}

// A scan without root cannot read sssd.conf. That must not read as "not a
// member", but a membership found elsewhere still stands.
func TestReadLinuxActiveDirectory_Unreadable(t *testing.T) {
	t.Run("unreadable sssd.conf is unknown", func(t *testing.T) {
		fsys := deniedFs{Fs: afero.NewMemMapFs(), denied: sssdConfPath}
		require.NoError(t, afero.WriteFile(fsys.Fs, sssdConfPath, []byte("[sssd]\n"), 0o600))
		assert.Equal(t, adUnreadable, readLinuxActiveDirectory(fsys))
	})

	t.Run("winbind membership stands beside an unreadable sssd.conf", func(t *testing.T) {
		fsys := deniedFs{Fs: afero.NewMemMapFs(), denied: sssdConfPath}
		require.NoError(t, afero.WriteFile(fsys.Fs, sssdConfPath, []byte("[sssd]\n"), 0o600))
		require.NoError(t, afero.WriteFile(fsys.Fs, sambaConfPath, []byte("[global]\nsecurity = ads\nrealm = AD.EXAMPLE.COM\n"), 0o644))
		res := readLinuxActiveDirectory(fsys)
		assert.Equal(t, membershipRead, res.state)
		assert.Equal(t, "ad.example.com", res.membership.domain)
	})
}

func TestReadMacosActiveDirectory(t *testing.T) {
	t.Run("a binding directory without bindings is not a membership", func(t *testing.T) {
		fsys := afero.NewMemMapFs()
		require.NoError(t, fsys.MkdirAll(macosADConfigDir, 0o755))
		assert.Equal(t, adResult{state: membershipRead}, readMacosActiveDirectory(fsys))
	})

	t.Run("an unlistable binding directory is unknown", func(t *testing.T) {
		fsys := deniedFs{Fs: afero.NewMemMapFs(), denied: macosADConfigDir}
		require.NoError(t, fsys.MkdirAll(macosADConfigDir, 0o700))
		assert.Equal(t, adUnreadable, readMacosActiveDirectory(fsys))
	})

	t.Run("a malformed binding is unknown", func(t *testing.T) {
		fsys := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fsys, macosADConfigDir+"/CORP.plist", []byte("not a plist"), 0o600))
		assert.Equal(t, adUnreadable, readMacosActiveDirectory(fsys))
	})

	t.Run("trust domain stands in for a missing domain", func(t *testing.T) {
		domain, forest, err := parseMacosADBinding([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>module options</key><dict><key>ActiveDirectory</key><dict>
<key>trust domain</key><string>corp.example.com</string>
</dict></dict></dict></plist>`))
		require.NoError(t, err)
		assert.Equal(t, "corp.example.com", domain)
		assert.Equal(t, "", forest)
	})
}

// deniedFs refuses to open one path, as a file only root may read does for
// an unprivileged scan.
type deniedFs struct {
	afero.Fs
	denied string
}

func (d deniedFs) Open(name string) (afero.File, error) {
	if strings.TrimSuffix(name, "/") == d.denied {
		return nil, &fs.PathError{Op: "open", Path: name, Err: os.ErrPermission}
	}
	return d.Fs.Open(name)
}
