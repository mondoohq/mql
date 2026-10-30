// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package prof is responsible for setting up the go profiler for commands
package prof

import (
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

// InitProfiler sets up the go profiler based on the MONDOO_PROF environment
// variable.
// MONDO_PROF is a list of comma separated key/key=value.
// Allowed keys:
//   - `enable`:          Enables the profiler if no value is provided, or the value of
//     `true` is provided
//
// - `enabled`:        Alias for `enable`
//
//   - `listen`:         Sets the listen address for the profiler http server. See
//     https://pkg.go.dev/net/http/pprof for more info about the
//     endpoints provided
//
// - `memprofilerate`: Sets runtime.MemProfileRate to the provided value
//
// Example:
// MONDOO_PROF='enable,listen=localhost:7474,memprofilerate=1'
func InitProfiler() {
	if profVal := os.Getenv("MONDOO_PROF"); profVal != "" {
		opts, err := parseProf(profVal)
		if err != nil {
			log.Warn().Err(err).Msg("failed to parse MONDOO_PROF")
			return
		}
		setupProfiler(opts)
	}
}

type profilerOpts struct {
	Enabled        bool
	Listen         string
	MemProfileRate *int
}

var defaultOpts = profilerOpts{
	Enabled:        false,
	Listen:         "localhost:6060",
	MemProfileRate: nil,
}

func parseProf(profVal string) (profilerOpts, error) {
	opts := defaultOpts

	sOpts := strings.SplitSeq(profVal, ",")
	for sOpt := range sOpts {
		keyval := strings.SplitN(sOpt, "=", 2)
		key := ""
		val := ""

		if len(keyval) == 0 {
			continue
		}

		key = strings.TrimSpace(keyval[0])
		if len(keyval) == 2 {
			val = strings.TrimSpace(keyval[1])
		}

		switch key {
		case "enable", "enabled":
			opts.Enabled = val == "" || val == "true"
		case "listen":
			if val != "" {
				opts.Listen = val
			}
		case "memprofilerate":
			if val != "" {
				i, err := strconv.Atoi(val)
				if err != nil {
					return opts, errors.Wrapf(err, "invalid value %q for memprofilerate", val)
				}
				opts.MemProfileRate = &i
			}
		}
	}
	return opts, nil
}

func setupProfiler(opts profilerOpts) {
	if !opts.Enabled {
		return
	}

	log.Info().Interface("opts", opts).Msg("Enabling profiler")

	if opts.MemProfileRate != nil {
		runtime.MemProfileRate = *opts.MemProfileRate
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	go func() {
		err := http.ListenAndServe(opts.Listen, mux)
		if err != nil {
			log.Error().Err(err).Msg("failed to start http server")
		}
	}()
}
