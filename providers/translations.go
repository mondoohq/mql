// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"errors"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// translationSource answers the compiler's downgrade lookups from the loaded
// providers (ADR 040 part 6).
//
// Reading a catalog means running the provider, because the translation is Go
// the provider author wrote and only the binary knows it. That is the trade this
// design makes for authoring flexibility, and it has a consequence worth
// stating: a host that compiles content for older readers needs the provider
// binaries installed, not just their schemas.
//
// Lookups are cached, including the misses: a provider that cannot be reached is
// asked once, not once per field.
type translationSource struct {
	// runtime scopes the lookup to the providers this runtime already has
	// connected. See fetch for why it is not the coordinator.
	runtime *Runtime

	mu          sync.Mutex
	cache       map[string][]*llx.TranslationStep
	unavailable map[string]struct{}
}

// NewTranslationSource returns a llx.TranslationSource backed by the providers a
// runtime has connected. It is what makes the downgrade mechanism reachable from
// any compile that has a runtime, which is every compile that will execute.
func NewTranslationSource(runtime *Runtime) llx.TranslationSource {
	return &translationSource{
		runtime:     runtime,
		cache:       map[string][]*llx.TranslationStep{},
		unavailable: map[string]struct{}{},
	}
}

func (s *translationSource) TranslationsFor(provider string) []*llx.TranslationStep {
	if s == nil || s.runtime == nil || provider == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := resources.ProviderKey(provider)
	if steps, ok := s.cache[key]; ok {
		return steps
	}

	steps, err := s.fetch(provider)
	if err != nil {
		// Not being able to read a catalog is not a compile error. The content
		// still runs; readers on older versions of this provider just see the
		// affected fields as unavailable instead of translated.
		log.Debug().Err(err).Str("provider", provider).
			Msg("cannot read downgrade translations, compiling without them")
		s.unavailable[key] = struct{}{}
		s.cache[key] = nil
		return nil
	}

	s.cache[key] = steps
	return steps
}

func (s *translationSource) fetch(provider string) ([]*llx.TranslationStep, error) {
	// Only ask a provider this runtime already has connected. Going through the
	// coordinator would *start* one that is not running
	// (coordinator.GetRunningProvider falls through to unsafeStartProvider), and
	// a compile is not always followed by an execution: shell autocomplete
	// compiles on every keystroke, and launching a provider process per
	// keystroke to read a catalog is not a trade worth making.
	//
	// The case that matters is unaffected. A query cannot run against a provider
	// without that provider being connected, so by the time a compile is for
	// something that will execute, the provider is here.
	connected := s.connectedProvider(provider)
	if connected == nil {
		return nil, errors.New("provider '" + provider + "' is not connected, cannot read its translations")
	}
	res, err := connected.Instance.Plugin.Translations(&plugin.TranslationsReq{})
	if err != nil {
		return nil, err
	}

	steps := make([]*llx.TranslationStep, 0, len(res.GetTranslations()))
	for _, t := range res.GetTranslations() {
		if t == nil || t.Block == nil {
			continue
		}
		steps = append(steps, &llx.TranslationStep{
			Resource:  t.Resource,
			Field:     t.Field,
			ChangedIn: t.ChangedIn,
			Block:     t.Block,
		})
	}
	return steps, nil
}

// connectedProvider finds a connected provider by id or by stable name, since a
// resource's provider id and the id a runtime keys on can spell the same
// provider differently.
func (s *translationSource) connectedProvider(provider string) *ConnectedProvider {
	if connected := s.runtime.providers[provider]; connected != nil {
		return connected
	}
	want := resources.ProviderKey(provider)
	for id, connected := range s.runtime.providers {
		if resources.ProviderKey(id) == want {
			return connected
		}
	}
	return nil
}

// Unavailable names the providers a catalog could not be read from, so a caller
// can report them once after compiling rather than once per field.
func (s *translationSource) Unavailable() UnavailableProviders {
	s.mu.Lock()
	defer s.mu.Unlock()

	res := make(UnavailableProviders, 0, len(s.unavailable))
	for name := range s.unavailable {
		res = append(res, name)
	}
	sort.Strings(res)
	return res
}

// UnavailableProviders names providers a catalog could not be read from.
type UnavailableProviders []string

// Warning renders the one aggregate message a caller should log when some
// providers could not supply translations. Deliberately a single line naming the
// providers: one message per affected field would bury the point in a scan that
// touches thousands.
func (u UnavailableProviders) Warning() string {
	if len(u) == 0 {
		return ""
	}
	return "compiled without downgrade fallbacks for " + strings.Join(u, ", ") +
		" (provider binary not available); content will still run, but readers on older" +
		" versions of these providers will see affected fields as unavailable"
}
