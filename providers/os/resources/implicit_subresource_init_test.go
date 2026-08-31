// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type subResourceInit func(*plugin.Runtime, map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error)

// subResourceInits are the sub-resources that codegen exposes as an implicit
// singular field, which makes them nameable as a static path. Each entry pairs
// the resource name with its init and with the arguments its parent lister
// supplies.
var subResourceInits = []struct {
	name     string
	init     subResourceInit
	identity map[string]*llx.RawData
	// partial carries only some of the identity fields, which is still not
	// enough to resolve the sub-resource.
	partial map[string]*llx.RawData
}{
	{
		name: "nftables.table",
		init: initNftablesTable,
		identity: map[string]*llx.RawData{
			"family": llx.StringData("inet"),
			"name":   llx.StringData("filter"),
		},
		partial: map[string]*llx.RawData{"family": llx.StringData("inet")},
	},
	{
		name: "nftables.chain",
		init: initNftablesChain,
		identity: map[string]*llx.RawData{
			"family": llx.StringData("inet"),
			"table":  llx.StringData("filter"),
			"name":   llx.StringData("input"),
		},
		partial: map[string]*llx.RawData{
			"family": llx.StringData("inet"),
			"table":  llx.StringData("filter"),
		},
	},
	{
		name: "nftables.rule",
		init: initNftablesRule,
		identity: map[string]*llx.RawData{
			"family": llx.StringData("inet"),
			"table":  llx.StringData("filter"),
			"chain":  llx.StringData("input"),
		},
		partial: map[string]*llx.RawData{"family": llx.StringData("inet")},
	},
	{
		name: "nftables.set",
		init: initNftablesSet,
		identity: map[string]*llx.RawData{
			"family": llx.StringData("inet"),
			"table":  llx.StringData("filter"),
			"name":   llx.StringData("blocklist"),
		},
		partial: map[string]*llx.RawData{"table": llx.StringData("filter")},
	},
	{
		name:     "iptables.table",
		init:     initIptablesTable,
		identity: map[string]*llx.RawData{"name": llx.StringData("filter")},
		partial:  map[string]*llx.RawData{"name": llx.StringData("")},
	},
	{
		name: "iptables.chain",
		init: initIptablesChain,
		identity: map[string]*llx.RawData{
			"table": llx.StringData("filter"),
			"name":  llx.StringData("INPUT"),
		},
		partial: map[string]*llx.RawData{"name": llx.StringData("INPUT")},
	},
	{
		name: "iptables.entry",
		init: initIptablesEntry,
		identity: map[string]*llx.RawData{
			"chain":      llx.StringData("filter/INPUT"),
			"lineNumber": llx.IntData(1),
		},
		partial: map[string]*llx.RawData{"lineNumber": llx.IntData(1)},
	},
	{
		name:     "lsblk.entry",
		init:     initLsblkEntry,
		identity: map[string]*llx.RawData{"name": llx.StringData("nvme0n1p1")},
		partial:  map[string]*llx.RawData{"fstype": llx.StringData("ext4")},
	},
	{
		name:     "journald.config.section",
		init:     initJournaldConfigSection,
		identity: map[string]*llx.RawData{"name": llx.StringData("Journal")},
		partial:  map[string]*llx.RawData{"params": llx.NilData},
	},
	{
		name: "modprobe.blacklist",
		init: initModprobeBlacklist,
		identity: map[string]*llx.RawData{
			"file":       llx.StringData("/etc/modprobe.d/blacklist.conf"),
			"lineNumber": llx.IntData(3),
		},
		partial: map[string]*llx.RawData{"module": llx.StringData("cramfs")},
	},
	{
		name: "modprobe.alias",
		init: initModprobeAlias,
		identity: map[string]*llx.RawData{
			"file":       llx.StringData("/etc/modprobe.d/aliases.conf"),
			"lineNumber": llx.IntData(1),
		},
		partial: map[string]*llx.RawData{"alias": llx.StringData("net-pf-10")},
	},
	{
		name: "modprobe.install",
		init: initModprobeInstall,
		identity: map[string]*llx.RawData{
			"file":       llx.StringData("/etc/modprobe.d/install.conf"),
			"lineNumber": llx.IntData(1),
		},
		partial: map[string]*llx.RawData{"module": llx.StringData("usb-storage")},
	},
	{
		name: "modprobe.option",
		init: initModprobeOption,
		identity: map[string]*llx.RawData{
			"file":       llx.StringData("/etc/modprobe.d/options.conf"),
			"lineNumber": llx.IntData(1),
		},
		partial: map[string]*llx.RawData{"parameters": llx.StringData("nomodeset")},
	},
	{
		name: "modprobe.remove",
		init: initModprobeRemove,
		identity: map[string]*llx.RawData{
			"file":       llx.StringData("/etc/modprobe.d/remove.conf"),
			"lineNumber": llx.IntData(1),
		},
		partial: map[string]*llx.RawData{"command": llx.StringData("/bin/true")},
	},
	{
		name: "modprobe.softdep",
		init: initModprobeSoftdep,
		identity: map[string]*llx.RawData{
			"file":       llx.StringData("/etc/modprobe.d/softdep.conf"),
			"lineNumber": llx.IntData(1),
		},
		partial: map[string]*llx.RawData{"module": llx.StringData("snd")},
	},
}

// A sub-resource named as a static path arrives at its init with no arguments.
// Falling through with (args, nil, nil) there is what builds the husk the
// runtime then reports as "provider returned no data and no error for a field",
// so the init has to refuse.
func TestSubResourceInitRefusesEmptyArgs(t *testing.T) {
	for _, tc := range subResourceInits {
		t.Run(tc.name, func(t *testing.T) {
			args, res, err := tc.init(nil, map[string]*llx.RawData{})
			require.Error(t, err)
			assert.Nil(t, args, "must not hand back args for blank-resource creation")
			assert.Nil(t, res)
			assert.Contains(t, err.Error(), tc.name)
		})
	}
}

// Identity fields that are present but empty are exactly what a standalone
// instantiation produces, so they must not open the fast path either.
func TestSubResourceInitRefusesPartialArgs(t *testing.T) {
	for _, tc := range subResourceInits {
		t.Run(tc.name, func(t *testing.T) {
			args, res, err := tc.init(nil, tc.partial)
			require.Error(t, err)
			assert.Nil(t, args)
			assert.Nil(t, res)
		})
	}
}

// The parent listers and the typed accessors that resolve through NewResource
// supply the identity fields, and they have to keep working untouched.
func TestSubResourceInitAcceptsIdentityArgs(t *testing.T) {
	for _, tc := range subResourceInits {
		t.Run(tc.name, func(t *testing.T) {
			args, res, err := tc.init(nil, tc.identity)
			require.NoError(t, err)
			assert.Nil(t, res, "init resolves through Create, it does not build the resource itself")
			assert.Equal(t, tc.identity, args)
		})
	}
}

// NewResource is the path a static-path lookup takes (plugin service GetData
// with no resource id and no field). Before the inits were wired it returned a
// husk here; it must return an error.
func TestNewResourceRefusesStandaloneSubResource(t *testing.T) {
	for _, tc := range subResourceInits {
		t.Run(tc.name, func(t *testing.T) {
			runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)
			res, err := NewResource(runtime, tc.name, map[string]*llx.RawData{})
			require.Error(t, err)
			assert.Nil(t, res)
		})
	}
}

func TestHasStringArgs(t *testing.T) {
	args := map[string]*llx.RawData{
		"name":   llx.StringData("filter"),
		"empty":  llx.StringData(""),
		"null":   llx.NilData,
		"number": llx.IntData(7),
		"absent": nil,
	}

	assert.True(t, hasStringArgs(args, "name"))
	assert.True(t, hasStringArgs(args), "no requirements is vacuously satisfied")
	assert.False(t, hasStringArgs(args, "empty"), "an empty string does not identify anything")
	assert.False(t, hasStringArgs(args, "null"))
	assert.False(t, hasStringArgs(args, "number"), "a non-string value is not an identity string")
	assert.False(t, hasStringArgs(args, "absent"))
	assert.False(t, hasStringArgs(args, "missing"))
	assert.False(t, hasStringArgs(args, "name", "empty"), "every named arg has to be present")
}
