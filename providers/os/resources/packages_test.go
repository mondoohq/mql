// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/utils/syncx"
)

// list() reuses one args map for every package, so fillPackageArgs has to
// leave no trace of the previous one. license is the field that exposes this:
// it is only set when the backend reported one, so without the clear a package
// that has no license inherits whichever license came before it.
func TestFillPackageArgsDoesNotLeakBetweenPackages(t *testing.T) {
	args := make(map[string]*llx.RawData, 15)
	installed := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	withLicense := packages.Package{
		Name: "openssl", Version: "3.0.11", Arch: "x86_64", Format: "rpm",
		License: "Apache-2.0", InstallDate: installed,
	}
	withoutLicense := packages.Package{
		Name: "libfoo", Version: "1.2.3", Arch: "amd64", Format: "deb",
	}

	fillPackageArgs(args, &withLicense, "", nil)
	require.Contains(t, args, "license")
	assert.Equal(t, "Apache-2.0", args["license"].Value)
	require.IsType(t, &time.Time{}, args["installDate"].Value)
	assert.Equal(t, installed, *args["installDate"].Value.(*time.Time))

	fillPackageArgs(args, &withoutLicense, "", nil)
	assert.NotContains(t, args, "license",
		"license leaked from the previous package")
	assert.Equal(t, llx.NilData.Value, args["installDate"].Value,
		"installDate leaked from the previous package")
	assert.Equal(t, "libfoo", args["name"].Value)
	assert.Equal(t, "deb", args["format"].Value)
}

func TestFillPackageArgs(t *testing.T) {
	args := make(map[string]*llx.RawData, 15)

	pkg := packages.Package{
		Name:         "openssl",
		Version:      "3.0.11-1",
		Arch:         "x86_64",
		Status:       "install ok installed",
		Description:  "TLS toolkit",
		Format:       "rpm",
		Origin:       "openssl-src",
		Epoch:        "1",
		PUrl:         "pkg:rpm/redhat/openssl@3.0.11-1?arch=x86_64",
		Vendor:       "Red Hat",
		InstallScope: "user",
		InstallUser:  "S-1-5-21-1-2-3-1001",
	}
	fillPackageArgs(args, &pkg, "3.0.12-1", nil)

	assert.Equal(t, "openssl", args["name"].Value)
	assert.Equal(t, "3.0.11-1", args["version"].Value)
	assert.Equal(t, "3.0.12-1", args["available"].Value)
	assert.Equal(t, "x86_64", args["arch"].Value)
	assert.Equal(t, "install ok installed", args["status"].Value)
	assert.Equal(t, "TLS toolkit", args["description"].Value)
	assert.Equal(t, "rpm", args["format"].Value)
	assert.Equal(t, true, args["installed"].Value)
	assert.Equal(t, "openssl-src", args["origin"].Value)
	assert.Equal(t, "1", args["epoch"].Value)
	assert.Equal(t, "pkg:rpm/redhat/openssl@3.0.11-1?arch=x86_64", args["purl"].Value)
	assert.Equal(t, "Red Hat", args["vendor"].Value)
	assert.Equal(t, "user", args["installScope"].Value)
	// installUser is a lazy user accessor (os.lr), not a settable raw field:
	// fillPackageArgs carries the raw SID as part of args["__id"] instead (see
	// packageID) so two users' identical app version get distinct resources.
	assert.Equal(t, "rpm://openssl/3.0.11-1/x86_64/user/S-1-5-21-1-2-3-1001", args["__id"].Value)

	// An absent install date must stay a real null rather than becoming the Go
	// zero time, which would report 0001-01-01 as a genuine install date.
	assert.Equal(t, llx.NilData.Value, args["installDate"].Value)

	// dpkg reports no license inline; the key must stay absent so the lazy
	// license() accessor still runs.
	assert.NotContains(t, args, "license")
}

// The reuse is only sound because CreateResource copies every value out and
// keeps no reference to the map. If it ever retained one, every package would
// collapse onto the last package's values.
func TestCreateResourceDoesNotRetainArgs(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	args := make(map[string]*llx.RawData, 15)

	pkgs := []packages.Package{
		{Name: "alpha", Version: "1.0", Arch: "amd64", Format: "deb", License: "MIT"},
		{Name: "beta", Version: "2.0", Arch: "amd64", Format: "deb"},
		{Name: "gamma", Version: "3.0", Arch: "amd64", Format: "deb", License: "GPL-2.0"},
	}

	created := make([]*mqlPackage, 0, len(pkgs))
	for i := range pkgs {
		fillPackageArgs(args, &pkgs[i], "", nil)
		res, err := CreateResource(runtime, "package", args)
		require.NoError(t, err)
		created = append(created, res.(*mqlPackage))
	}

	for i, got := range created {
		assert.Equal(t, pkgs[i].Name, got.Name.Data, "package %d name", i)
		assert.Equal(t, pkgs[i].Version, got.Version.Data, "package %d version", i)
	}

	// beta has no license of its own and must not have picked up alpha's.
	assert.Equal(t, "MIT", created[0].License.Data)
	assert.Empty(t, created[1].License.Data, "beta inherited a license")
	assert.Equal(t, "GPL-2.0", created[2].License.Data)
}

// seedUsersCache pre-populates runtime's "users" resource cache with a fixed
// list, so installUser() can resolve against it without a real connection
// (mqlUsers.list() needs one). CreateResource("users", ...) with no args
// caches under __id "" (mqlUsers has no id() method, see createUsers in
// os.lr.go), so seeding that same key is what installUser()'s own
// CreateResource("users", ...) call finds.
func seedUsersCache(t *testing.T, runtime *plugin.Runtime, users ...*mqlUser) {
	t.Helper()
	entries := make([]any, len(users))
	for i, u := range users {
		entries[i] = u
	}
	cached := &mqlUsers{
		MqlRuntime: runtime,
		List:       plugin.TValue[[]any]{Data: entries, State: plugin.StateIsSet},
	}
	runtime.Resources.Set("users\x00", cached)
}

func newTestUser(runtime *plugin.Runtime, name, sid string) *mqlUser {
	return &mqlUser{
		MqlRuntime: runtime,
		Name:       plugin.TValue[string]{Data: name, State: plugin.StateIsSet},
		Sid:        plugin.TValue[string]{Data: sid, State: plugin.StateIsSet},
	}
}

// createTestPackage mirrors what mqlPackages.list() does for one package:
// fillPackageArgs -> CreateResource -> set installUser()'s internal backing
// field (installUserSid). That field is not reachable via args (installUser
// is a lazy accessor, not a settable raw field — see fillPackageArgs), so
// list() sets it directly on the created resource; a test that calls
// CreateResource on its own, bypassing list(), has to do the same or
// installUser() always resolves to null regardless of osPkg.InstallUser.
func createTestPackage(t *testing.T, runtime *plugin.Runtime, args map[string]*llx.RawData, osPkg *packages.Package) *mqlPackage {
	t.Helper()
	fillPackageArgs(args, osPkg, "", nil)
	res, err := CreateResource(runtime, "package", args)
	require.NoError(t, err)
	pkg := res.(*mqlPackage)
	pkg.installUserSid = osPkg.InstallUser
	return pkg
}

// TestPackageInstallScopeAndUserSurface proves installScope/installUser reach
// the mqlPackage resource end to end: fillPackageArgs -> CreateResource -> the
// generated field getters, not just the intermediate args map. installUser is
// a lazy accessor (os.lr: installUser() user) resolved by matching SID
// against the users collection, so this also exercises that resolution.
func TestPackageInstallScopeAndUserSurface(t *testing.T) {
	args := make(map[string]*llx.RawData, 15)

	t.Run("user-scope package resolves installUser to the matching user", func(t *testing.T) {
		runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
		const sid = "S-1-5-21-1-2-3-1001"
		seedUsersCache(t, runtime, newTestUser(runtime, "alice", sid))

		pkg := packages.Package{
			Name: "Cursor", Version: "1.2.3", Arch: "x86_64", Format: "windows/app",
			InstallScope: "user", InstallUser: sid,
		}
		got := createTestPackage(t, runtime, args, &pkg)

		assert.Equal(t, "user", got.InstallScope.Data)
		resolved := got.GetInstallUser()
		require.NoError(t, resolved.Error)
		require.NotNil(t, resolved.Data)
		assert.Equal(t, "alice", resolved.Data.Name.Data)
		assert.Equal(t, sid, resolved.Data.Sid.Data)
	})

	t.Run("SID with no matching user resolves to null (deleted profile)", func(t *testing.T) {
		runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
		seedUsersCache(t, runtime) // no users at all

		pkg := packages.Package{
			Name: "Cursor", Version: "1.2.3", Arch: "x86_64", Format: "windows/app",
			InstallScope: "user", InstallUser: "S-1-5-21-9-9-9-9999",
		}
		got := createTestPackage(t, runtime, args, &pkg)

		resolved := got.GetInstallUser()
		require.NoError(t, resolved.Error)
		assert.Nil(t, resolved.Data)
	})

	t.Run("machine-scope package carries no user", func(t *testing.T) {
		runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
		pkg := packages.Package{
			Name: "7-Zip", Version: "23.01", Arch: "x86_64", Format: "windows/app",
			InstallScope: "machine",
		}
		got := createTestPackage(t, runtime, args, &pkg)

		assert.Equal(t, "machine", got.InstallScope.Data)
		// installUserSid is empty, so installUser() must resolve to null
		// without ever needing a users lookup (no seedUsersCache call here).
		resolved := got.GetInstallUser()
		require.NoError(t, resolved.Error)
		assert.Nil(t, resolved.Data)
	})

	t.Run("backend with no such concept leaves both empty", func(t *testing.T) {
		runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
		pkg := packages.Package{Name: "openssl", Version: "3.0.11", Arch: "amd64", Format: "rpm"}
		got := createTestPackage(t, runtime, args, &pkg)

		assert.Empty(t, got.InstallScope.Data)
		resolved := got.GetInstallUser()
		require.NoError(t, resolved.Error)
		assert.Nil(t, resolved.Data)
	})
}

// TestPackageIDIncludesSIDForUserScope pins the fix for the resource-id
// collision: two users installing the identical app version each get their
// own package.id() (format://name/version/arch/user/<sid>), so the runtime
// resource cache (keyed on __id) does not fold the second user's declaration
// onto the first user's cached resource.
func TestPackageIDIncludesSIDForUserScope(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	args := make(map[string]*llx.RawData, 15)
	seedUsersCache(t, runtime,
		newTestUser(runtime, "alice", "S-1-5-21-1-2-3-1001"),
		newTestUser(runtime, "bob", "S-1-5-21-1-2-3-1002"),
	)

	pkgAlice := packages.Package{
		Name: "Cursor", Version: "1.2.3", Arch: "x86_64", Format: "windows/app",
		InstallScope: "user", InstallUser: "S-1-5-21-1-2-3-1001",
	}
	alice := createTestPackage(t, runtime, args, &pkgAlice)

	pkgBob := packages.Package{
		Name: "Cursor", Version: "1.2.3", Arch: "x86_64", Format: "windows/app",
		InstallScope: "user", InstallUser: "S-1-5-21-1-2-3-1002",
	}
	bob := createTestPackage(t, runtime, args, &pkgBob)

	require.NotSame(t, alice, bob, "the runtime cache must not have returned alice's resource for bob's declaration")
	assert.NotEqual(t, alice.__id, bob.__id, "same app + version for two different users must not collide")
	assert.Equal(t, "windows/app://Cursor/1.2.3/x86_64/user/S-1-5-21-1-2-3-1001", alice.__id)
	assert.Equal(t, "windows/app://Cursor/1.2.3/x86_64/user/S-1-5-21-1-2-3-1002", bob.__id)

	aliceUser := alice.GetInstallUser()
	require.NoError(t, aliceUser.Error)
	require.NotNil(t, aliceUser.Data)
	assert.Equal(t, "alice", aliceUser.Data.Name.Data)

	bobUser := bob.GetInstallUser()
	require.NoError(t, bobUser.Error)
	require.NotNil(t, bobUser.Data)
	assert.Equal(t, "bob", bobUser.Data.Name.Data)
}

// TestPackageIDMachineScopeUnaffected pins that the id change is additive:
// a machine-scope (or non-Windows) package's id is unchanged, since the
// "/user/<sid>" suffix is only appended when installScope is "user".
func TestPackageIDMachineScopeUnaffected(t *testing.T) {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	args := make(map[string]*llx.RawData, 15)

	pkg := packages.Package{Name: "openssl", Version: "3.0.11-1", Arch: "x86_64", Format: "rpm"}
	fillPackageArgs(args, &pkg, "", nil)
	res, err := CreateResource(runtime, "package", args)
	require.NoError(t, err)

	assert.Equal(t, "rpm://openssl/3.0.11-1/x86_64", res.(*mqlPackage).__id)
}
