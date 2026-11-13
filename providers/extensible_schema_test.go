// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

func TestExtensibleSchema(t *testing.T) {
	s := newExtensibleSchema()
	s.coordinator = newCoordinator()

	s.Add("first", &resources.Schema{
		Resources: map[string]*resources.ResourceInfo{
			"eternity": {
				Fields: map[string]*resources.Field{
					"iii": {Provider: "first"},
					"v":   {Provider: "first"},
				},
				Provider: "first",
			},
		},
	})

	s.Add("second", &resources.Schema{
		Resources: map[string]*resources.ResourceInfo{
			"eternity": {
				Fields: map[string]*resources.Field{
					"iii": {Provider: "second"},
				},
				Provider: "second",
			},
		},
	})

	info := s.Lookup("eternity")
	require.NotNil(t, info)
	require.Len(t, info.Others, 1)

	// Check that both providers are present for resource "eternity"
	providers := []string{info.Provider, info.Others[0].Provider}
	assert.ElementsMatch(t, []string{"first", "second"}, providers)

	info, finfo := s.LookupField("eternity", "iii")
	require.NotNil(t, info)
	require.Len(t, info.Others, 1)

	// Check that both providers are present for field "iii"
	providers = []string{finfo.Provider, info.Others[0].Fields["iii"].Provider}
	assert.ElementsMatch(t, []string{"first", "second"}, providers)

	info, finfo = s.LookupField("eternity", "v")
	require.NotNil(t, finfo)
	assert.Equal(t, "first", finfo.Provider)

	// Find field from resource
	filePath, fieldinfos, found := s.FindField(info, "v")
	require.True(t, found)
	require.Equal(t, resources.FieldPath{"v"}, filePath)
	require.Len(t, fieldinfos, 1)
	require.Equal(t, "first", fieldinfos[0].Provider)

	// The aggregate also carries what the builtin providers declare -- iac
	// declares core (ADR 042) -- so the baseline is not empty. What this pins
	// is that the two schemas added above contribute nothing to it.
	baseline := newExtensibleSchema()
	baseline.coordinator = newCoordinator()
	require.Equalf(t, len(baseline.AllDependencies()), len(s.AllDependencies()),
		"the schemas added here should not have contributed dependencies")

	t.Run("with dependencies", func(t *testing.T) {
		s.Add("third", &resources.Schema{
			Resources: map[string]*resources.ResourceInfo{
				"eternity": {
					Fields: map[string]*resources.Field{
						"iii": {Provider: "third"},
						"x":   {Provider: "third"},
					},
					Provider: "third",
				},
			},
			// Deliberately not "core": the builtin providers declare that one
			// too, and the aggregate is keyed by name, so a shared key would
			// make this assert on which schema was merged last rather than on
			// this one contributing anything.
			Dependencies: map[string]*resources.ProviderInfo{
				"eternity-dep": {
					Id:   "go.mondoo.com/mql/v9/providers/eternity-dep",
					Name: "eternity-dep",
				},
			},
		})
		info := s.Lookup("eternity")
		require.NotNil(t, info)
		require.Len(t, info.Others, 2)
		providers := []string{info.Provider, info.Others[0].Provider, info.Others[1].Provider}
		assert.ElementsMatch(t, []string{"first", "second", "third"}, providers)

		// What "third" declared reaches the aggregate.
		deps := s.AllDependencies()
		require.Contains(t, deps, "eternity-dep")
		assert.Equal(t, "go.mondoo.com/mql/v9/providers/eternity-dep", deps["eternity-dep"].Id)
		assert.Len(t, deps, len(baseline.AllDependencies())+1)
	})
}

// A builtin provider's schema is added again every time a runtime asks for
// the provider, and it is the same object every time. That must not rebuild
// the aggregate: with many assets it was rebuilt once per asset.
func TestExtensibleSchema_AddingTheSameSchemaAgain(t *testing.T) {
	s := newExtensibleSchema()
	s.coordinator = newCoordinator()
	aggregate := func() uintptr { return reflect.ValueOf(s.AllResources()).Pointer() }

	first := &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"eternity": {Fields: map[string]*resources.Field{"iii": {Provider: "first"}}, Provider: "first"},
	}}
	s.Add("first", first)
	built := aggregate()
	require.NotNil(t, s.Lookup("eternity"))

	s.Add("first", first)
	assert.Equal(t, built, aggregate(), "the same schema again leaves the aggregate as it is")

	// Another schema under another name is a change, as is another object
	// under the same name, whatever its content.
	s.Add("second", &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"moment": {Fields: map[string]*resources.Field{"v": {Provider: "second"}}, Provider: "second"},
	}})
	rebuilt := aggregate()
	assert.NotEqual(t, built, rebuilt)
	require.NotNil(t, s.Lookup("moment"))

	s.Add("first", &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"aeon": {Fields: map[string]*resources.Field{"x": {Provider: "first"}}, Provider: "first"},
	}})
	assert.NotEqual(t, rebuilt, aggregate())
	assert.NotNil(t, s.Lookup("aeon"))
	assert.Nil(t, s.Lookup("eternity"), "what the replaced schema had is gone")
}

func TestCoordinator_BuiltinProviderDoesNotRebuildTheSchema(t *testing.T) {
	c := newCoordinator()
	aggregate := func() uintptr { return reflect.ValueOf(c.schema.AllResources()).Pointer() }

	_, err := c.GetRunningProvider(BuiltinCoreID, UpdateProvidersConfig{})
	require.NoError(t, err)
	built := aggregate()
	require.NotEmpty(t, c.schema.AllResources())

	for range 3 {
		_, err = c.GetRunningProvider(BuiltinCoreID, UpdateProvidersConfig{})
		require.NoError(t, err)
	}
	assert.Equal(t, built, aggregate())
}

// The version is what tells one state of the schema from another: it moves
// when the aggregate is replaced and only then.
func TestExtensibleSchema_Version(t *testing.T) {
	s := newExtensibleSchema()
	s.coordinator = newCoordinator()
	version := func() uint64 {
		_, v := s.SchemaVersion()
		return v
	}

	first := &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"eternity": {Fields: map[string]*resources.Field{"iii": {Provider: "first"}}, Provider: "first"},
	}}
	s.Add("first", first)
	added := version()

	s.Add("first", first)
	assert.Equal(t, added, version(), "nothing changed")

	s.Add("second", &resources.Schema{Resources: map[string]*resources.ResourceInfo{
		"moment": {Fields: map[string]*resources.Field{"v": {Provider: "second"}}, Provider: "second"},
	}})
	assert.Greater(t, version(), added)

	object, _ := s.SchemaVersion()
	other := newExtensibleSchema()
	otherObject, _ := other.SchemaVersion()
	assert.NotEqual(t, object, otherObject, "two schemas are told apart whatever their versions")
}
