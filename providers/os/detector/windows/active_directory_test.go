// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// The domain and forest names below are made up.
func TestParseActiveDirectoryInfo(t *testing.T) {
	t.Run("member workstation", func(t *testing.T) {
		info, err := ParseActiveDirectoryInfo(strings.NewReader(`{"DomainRole":1,"Flat":"CORP","Dns":"Corp.Example.com","Forest":"example.com"}`))
		require.NoError(t, err)
		assert.Equal(t, &ActiveDirectoryInfo{Member: true, Domain: "corp.example.com", Forest: "example.com"}, info)
	})

	t.Run("member server without the forest", func(t *testing.T) {
		// The forest is read through a compiled wrapper, which a host may
		// refuse; the domain from WMI still stands.
		info, err := ParseActiveDirectoryInfo(strings.NewReader(`{"DomainRole":3,"Flat":null,"Dns":"corp.example.com","Forest":null}`))
		require.NoError(t, err)
		assert.Equal(t, &ActiveDirectoryInfo{Member: true, Domain: "corp.example.com"}, info)
	})

	t.Run("domain controllers are members", func(t *testing.T) {
		for _, role := range []string{"4", "5"} {
			info, err := ParseActiveDirectoryInfo(strings.NewReader(`{"DomainRole":` + role + `,"Flat":"CORP","Dns":"corp.example.com","Forest":"corp.example.com"}`))
			require.NoError(t, err)
			assert.True(t, info.Member, role)
		}
	})

	t.Run("a domain without a DNS name reports its NetBIOS name", func(t *testing.T) {
		info, err := ParseActiveDirectoryInfo(strings.NewReader(`{"DomainRole":1,"Flat":"LEGACY","Dns":null,"Forest":null}`))
		require.NoError(t, err)
		assert.Equal(t, "legacy", info.Domain)
	})

	t.Run("a workgroup is not a domain", func(t *testing.T) {
		for _, role := range []string{"0", "2"} {
			info, err := ParseActiveDirectoryInfo(strings.NewReader(`{"DomainRole":` + role + `,"Flat":"WORKGROUP","Dns":null,"Forest":null}`))
			require.NoError(t, err)
			assert.Equal(t, &ActiveDirectoryInfo{}, info, role)
		}
	})

	t.Run("no answer is an error, not a non-member", func(t *testing.T) {
		for _, out := range []string{"", "  \n", `{"Dns":"corp.example.com"}`, "not json"} {
			_, err := ParseActiveDirectoryInfo(strings.NewReader(out))
			assert.Error(t, err, out)
		}
	})
}

func TestPowershellGetActiveDirectoryInfo(t *testing.T) {
	run := func(t *testing.T, stdout string, exit int) (*ActiveDirectoryInfo, error) {
		t.Helper()
		conn, err := mock.New(0, &inventory.Asset{}, mock.WithData(&mock.TomlData{Commands: map[string]*mock.Command{
			ActiveDirectoryInfoCommand(): {Stdout: stdout, ExitStatus: exit},
		}}))
		require.NoError(t, err)
		return powershellGetActiveDirectoryInfo(conn)
	}

	t.Run("member", func(t *testing.T) {
		info, err := run(t, `{"DomainRole":1,"Flat":"CORP","Dns":"corp.example.com","Forest":"example.com"}`+"\r\n", 0)
		require.NoError(t, err)
		assert.Equal(t, "corp.example.com", info.Domain)
	})

	t.Run("a failed command is an error", func(t *testing.T) {
		_, err := run(t, "", 1)
		assert.Error(t, err)
	})
}

func TestActiveDirectoryScriptFitsCommandLine(t *testing.T) {
	assert.LessOrEqual(t, len(activeDirectoryScript), powershell.MaxScriptLength)
	assert.True(t, powershell.FitsCommandLine(activeDirectoryScript))
}
