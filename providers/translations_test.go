// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A provider we could not read a catalog from is reported once, naming what was
// affected. One message per field would bury the point in a scan that touches
// thousands of them.
func TestUnavailableProvidersWarning(t *testing.T) {
	assert.Empty(t, UnavailableProviders(nil).Warning())
	assert.Empty(t, UnavailableProviders{}.Warning())

	warning := UnavailableProviders{"aws", "os"}.Warning()
	assert.Contains(t, warning, "aws, os")
	assert.Contains(t, warning, "provider binary not available")
	// It has to say the content still works, or it reads as a failure.
	assert.Contains(t, warning, "content will still run")
}

// The source caches its misses: a provider that cannot be reached is asked once,
// not once per field. Without this a large policy would retry a missing provider
// thousands of times.
func TestTranslationSourceCachesMisses(t *testing.T) {
	src := NewTranslationSource(nil)
	assert.Nil(t, src.TranslationsFor("os"))
	assert.Nil(t, src.TranslationsFor("os"))
	assert.Nil(t, src.TranslationsFor(""))
}

// A provider the runtime has not connected is not consulted, because reaching it
// through the coordinator would start it - and compiling is not always followed
// by executing. Shell autocomplete compiles on every keystroke.
func TestTranslationSourceDoesNotStartProviders(t *testing.T) {
	runtime := &Runtime{providers: map[string]*ConnectedProvider{}}
	src := NewTranslationSource(runtime)

	assert.Nil(t, src.TranslationsFor("go.mondoo.com/mql/providers/os"))

	concrete, ok := src.(*translationSource)
	require.True(t, ok)
	assert.Equal(t, UnavailableProviders{"os"}, concrete.Unavailable(),
		"a provider we declined to start is reported, not silently skipped")
}

// A resource's provider id and the id a runtime keys on can spell the same
// provider differently, so the lookup has to match on the stable name too.
func TestTranslationSourceMatchesLegacyProviderIDs(t *testing.T) {
	runtime := &Runtime{providers: map[string]*ConnectedProvider{
		"go.mondoo.com/mql/providers/os": {},
	}}
	src := NewTranslationSource(runtime).(*translationSource)

	assert.NotNil(t, src.connectedProvider("go.mondoo.com/mql/providers/os"))
	assert.NotNil(t, src.connectedProvider("go.mondoo.com/cnquery/v9/providers/os"))
	assert.NotNil(t, src.connectedProvider("os"))
	assert.Nil(t, src.connectedProvider("go.mondoo.com/mql/providers/aws"))
}
