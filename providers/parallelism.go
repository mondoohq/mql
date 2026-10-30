// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	goruntime "runtime"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// SequentialParallelism scans one asset at a time. It is the fallback whenever
// we cannot establish that every asset in the scan belongs to a provider that
// opted into concurrent scanning.
const SequentialParallelism = 1

// ResolveParallelism decides how many assets may be scanned concurrently.
//
// A requested value greater than zero wins outright and is returned unchanged.
// The CPU cap below exists to keep the *default* safe on small machines, not to
// overrule an operator who named a number.
//
// Without an explicit request we take the smallest DefaultParallelism declared
// by the providers behind the root assets, capped by cpuCap(). If any root
// resolves to a provider that has not opted in -- or to no provider at all --
// the whole scan stays sequential: one shared worker pool serves every asset in
// the tree, so we can only go concurrent when all of the roots agree it is safe.
func ResolveParallelism(requested int, roots []*inventory.Asset) int {
	if requested > 0 {
		return requested
	}

	provs, err := ListActive()
	if err != nil {
		log.Debug().Err(err).Msg("failed to list providers, scanning assets sequentially")
		return SequentialParallelism
	}

	return resolveParallelism(roots, provs, cpuCap())
}

// resolveParallelism is the pure core of ResolveParallelism, with the installed
// providers and the CPU cap passed in so it can be tested without touching the
// provider directory or the host's core count.
func resolveParallelism(roots []*inventory.Asset, provs Providers, cpuLimit int) int {
	declared := 0
	for _, asset := range roots {
		if asset == nil {
			continue
		}

		for _, conf := range asset.Connections {
			if conf == nil || conf.Type == "" {
				continue
			}

			n := declaredParallelism(provs, conf.Type)
			if n <= 0 {
				// Either the provider has not opted in, or we could not resolve
				// the connection type to a provider at all. Either way we do not
				// know that these assets are safe to scan concurrently.
				log.Debug().
					Str("connection-type", conf.Type).
					Msg("provider does not declare a default parallelism, scanning assets sequentially")
				return SequentialParallelism
			}

			if declared == 0 || n < declared {
				declared = n
			}
		}
	}

	if declared <= 0 {
		return SequentialParallelism
	}
	return min(declared, cpuLimit)
}

// declaredParallelism returns the parallelism the provider behind connType
// declares, or 0 when the provider is unknown or has not opted in.
func declaredParallelism(provs Providers, connType string) int {
	provider := provs.Lookup(ProviderLookup{ConnType: connType})
	if provider == nil || provider.Provider == nil {
		return 0
	}
	return provider.DefaultParallelism
}

// cpuCap is the ceiling we apply to any provider-declared default on this
// machine.
func cpuCap() int {
	// GOMAXPROCS, not NumCPU: since Go 1.25 it accounts for the cgroup CPU
	// limit, so a scanner running under a Kubernetes `cpu:` quota sees the
	// share it was actually given. NumCPU reports the node's cores and would
	// have us over-subscribe exactly where it hurts most.
	return cpuCapFor(goruntime.GOMAXPROCS(0))
}

// cpuCapFor keeps half the machine free for the mql runtime, the provider
// subprocesses and everything else sharing the box. Scanning is largely spent
// waiting on remote APIs, so this is deliberately below what the workload alone
// could use.
func cpuCapFor(cpus int) int {
	if cpus <= 2 {
		return SequentialParallelism
	}
	return max(2, cpus/2)
}
