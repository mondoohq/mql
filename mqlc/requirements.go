// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc

import (
	"errors"
	"slices"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers/core/resources/versions/semver"
)

// Requirement is one unmet version requirement of a bundle against a reader.
type Requirement struct {
	// Provider is the provider id the requirement is about.
	Provider string
	// Required is the lowest version that can resolve every name the bundle
	// uses from this provider.
	Required string
	// Installed is what the reader actually has, or "" when the reader does not
	// have the provider at all.
	Installed string
}

func (r Requirement) Error() string {
	if r.Installed == "" {
		return "requires the " + providerLabel(r.Provider) + " provider >= " + r.Required + " (not installed)"
	}
	return "requires the " + providerLabel(r.Provider) + " provider >= " + r.Required +
		" (" + r.Installed + " is installed)"
}

// UnmetRequirements reports which of a bundle's recorded requirements the reader
// cannot satisfy (ADR 040 part 1).
//
// This is the reconciliation question asked in its cheapest form: not "how do I
// adapt this content" but "can this reader run it at all". A caller that gets a
// non-empty answer knows to withhold the content, or to say why it was withheld,
// instead of shipping a bundle whose missing fields will degrade to nulls that
// three-valued logic then turns into a passing assertion.
//
// A bundle compiled before provenance existed records no requirements and is
// reported as satisfiable. That is the only safe reading: absence of a
// requirement is absence of information, and refusing every pre-provenance
// bundle would break every client that has one.
func UnmetRequirements(bundle *llx.CodeBundle, reader map[string]string) []Requirement {
	if bundle == nil || len(bundle.MinProviderVersions) == 0 {
		return nil
	}

	parser := semver.Parser{}
	// The reader may describe its providers by id while the bundle records
	// stable names, so both sides are normalized before they are compared.
	have := make(map[string]string, len(reader))
	for k, v := range reader {
		if v != "" {
			have[resources.ProviderKey(k)] = v
		}
	}

	var res []Requirement

	for provider, required := range bundle.MinProviderVersions {
		if required == "" {
			continue
		}
		provider = resources.ProviderKey(provider)
		installed, ok := have[provider]
		if !ok || installed == "" {
			res = append(res, Requirement{Provider: provider, Required: required})
			continue
		}
		diff, err := parser.Compare(installed, required)
		if err != nil {
			// An unparseable version on either side is not evidence of a
			// mismatch. Reporting one would withhold content over a formatting
			// problem.
			continue
		}
		if diff < 0 {
			res = append(res, Requirement{
				Provider:  provider,
				Required:  required,
				Installed: installed,
			})
		}
	}

	sort.Slice(res, func(i, j int) bool { return res[i].Provider < res[j].Provider })
	return res
}

// UnmetRequirementsAgainst is UnmetRequirements against a reader described by
// its schema rather than a bare map.
func UnmetRequirementsAgainst(bundle *llx.CodeBundle, reader resources.ResourcesSchema) []Requirement {
	if reader == nil {
		return UnmetRequirements(bundle, nil)
	}
	return UnmetRequirements(bundle, reader.AllProviderVersions())
}

// FormatRequirements renders requirements as one human-readable line.
func FormatRequirements(reqs []Requirement) string {
	if len(reqs) == 0 {
		return ""
	}
	parts := make([]string, len(reqs))
	for i := range reqs {
		parts[i] = reqs[i].Error()
	}
	return strings.Join(parts, "; ")
}

// ErrRootMismatch identifies a bundle that cannot run on an asset because the
// asset's root is not one the bundle was narrowed to. Match it with errors.Is to
// tell "this asset is not what the content targets" apart from a failure: the
// first is a scoping answer, the second is a problem.
var ErrRootMismatch = errors.New("asset root not supported by this content")

// SupportsRoot reports whether an asset rooted at `root` can execute this
// bundle (ADR 031 point 4).
//
// The bundle carries the roots it was narrowed to while compiling - a query
// reading `iptables` is satisfied only by the Linux root, one reading `hostname`
// by every root. This is the check that turns that into applicability, replacing
// a hand-written platform filter with what the code actually reads.
//
// Two ways to be supported without matching: a bundle that derived no
// requirement runs anywhere, and an asset whose root we do not know is not
// refused - not knowing is not evidence of a mismatch, the same rule the version
// requirements above follow.
func SupportsRoot(bundle *llx.CodeBundle, root string) bool {
	if bundle == nil || len(bundle.CompatibleRoots) == 0 || root == "" {
		return true
	}
	// An asset rooted at exactly what the content was compiled against is
	// trivially compatible. That is the union for a disconnected compile, which
	// is also what a provider reports before it refines its root per connection
	// - refusing those would withhold every narrowed bundle during a rollout.
	if root == bundle.AssetRoot {
		return true
	}
	return slices.Contains(bundle.CompatibleRoots, root)
}

// rootScopeError is a compile failure that is really a scoping answer: the
// field exists, on a root this asset does not have.
//
// It carries the diagnosis as its message - which is what a user reading one
// query wants - while matching ErrRootMismatch under errors.Is, which is what a
// caller running over many assets needs to tell "not for this asset" apart from
// "broken".
type rootScopeError struct{ msg string }

func (e *rootScopeError) Error() string { return e.msg }

func (e *rootScopeError) Is(target error) bool { return target == ErrRootMismatch }
