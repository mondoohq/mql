// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package prof is responsible for setting up the go profiler for commands
package prof

import (
	"net"
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
	InitProfilerFor("MONDOO_PROF")
}

// InitProfilerFor sets up the go profiler from the named environment variable.
// It takes the same value format as MONDOO_PROF.
//
// Provider plugins run as their own processes and inherit the environment of
// the parent, so they read their own variable. Two processes that share one
// variable would try to bind the same port, and only the first one would win.
func InitProfilerFor(envVar string) {
	profVal := os.Getenv(envVar)
	if profVal == "" {
		return
	}
	opts, err := parseProf(profVal)
	if err != nil {
		log.Warn().Err(err).Str("env", envVar).Msg("failed to parse profiler settings")
		return
	}
	_ = setupProfiler(opts)
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

	sOpts := strings.Split(profVal, ",")
	for _, sOpt := range sOpts {
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

// setupProfiler starts the pprof http server and returns its listener, so a
// caller can close it. It returns nil when the profiler is off or the bind
// failed. The process keeps the server for its whole life, so InitProfilerFor
// drops the listener; only tests close it.
func setupProfiler(opts profilerOpts) net.Listener {
	if !opts.Enabled {
		return nil
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

	// Bind before serving so the port is known here. Port 0 then picks a free
	// port, which lets several processes profile at once, and the log line
	// below tells the user where each one listens.
	l, err := net.Listen("tcp", opts.Listen)
	if err != nil {
		log.Error().Err(err).Str("listen", opts.Listen).Msg("failed to start profiler")
		return nil
	}
	log.Info().Str("address", "http://"+l.Addr().String()+"/debug/pprof/").Msg("profiler listening")

	go func() {
		if err := http.Serve(l, mux); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error().Err(err).Msg("failed to start http server")
		}
	}()

	return l
}
