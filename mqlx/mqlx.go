// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package mqlx provides a high-level API for embedding MQL in Go programs.
//
// It covers two modes of use:
//
// Expression mode evaluates MQL over values you pass in. It needs no
// providers, no asset, and no subprocesses — a bare environment is fully
// usable:
//
//	env, err := mqlx.NewEnv()
//	q, err := env.Compile("props.name == /admin-.*/ && props.count > 3",
//	    mqlx.WithProps(map[string]any{"name": "", "count": 0}))
//	res, err := q.Eval(ctx,
//	    mqlx.WithPropValues(map[string]any{"name": "admin-x", "count": 5}))
//	fmt.Println(res.Value()) // true
//
// Asset mode runs queries against connected infrastructure (a host, a cloud
// account, a cluster). Connect once, compile once, evaluate against as many
// assets as needed:
//
//	conn, err := env.ConnectLocal(ctx)
//	res, err := conn.Query(ctx, "asset { name platform }")
//
//	var info struct {
//	    Name     string `mql:"name"`
//	    Platform string `mql:"platform"`
//	}
//	err = res.Decode(&info)
//
// Compiled queries (Query) and environments (Env) are safe for concurrent
// use; compile once and evaluate from many goroutines.
//
// Schema availability: a query can only reference resources whose provider
// schema is loaded. Expression-mode queries (operators, string/array/map
// methods, and core resources such as regex and time) always compile.
// Resources of other providers require a prior Connect or
// NewEnv(WithProviders("aws", ...)).
package mqlx

import (
	"sync"

	"github.com/cockroachdb/errors"
	mql "go.mondoo.com/mql"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// Env is the environment for compiling and evaluating MQL. It carries the
// feature set and the provider schemas, and lazily maintains an internal
// runtime for expression-mode evaluation. Create one Env per process and
// share it; it is safe for concurrent use.
type Env struct {
	features mql.Features
	strict   bool
	private  []privateProvider

	mu     sync.Mutex
	conns  []*Conn
	closed bool

	exprOnce sync.Once
	exprRT   *providers.Runtime
	exprErr  error
}

// privateProvider is a caller-supplied, in-process provider registered via
// WithPrivateProvider.
type privateProvider struct {
	config plugin.Provider
	schema resources.ResourcesSchema
	plugin plugin.ProviderPlugin
}

// EnvOption configures an Env during NewEnv.
type EnvOption func(*Env) error

// WithFeatures sets the MQL feature flags. Default: mql.DefaultFeatures.
func WithFeatures(features mql.Features) EnvOption {
	return func(e *Env) error {
		e.features = features
		return nil
	}
}

// WithStrict compiles under ADR 043 strict mode: every link in an access chain
// must resolve, and `?` marks one optional. Default: off.
func WithStrict(strict bool) EnvOption {
	return func(e *Env) error {
		e.strict = strict
		return nil
	}
}

// WithProviders eagerly loads the schemas of the named providers (e.g. "aws",
// "os") so that their resources compile before any connection is made. The
// providers must be installed; they are not started by this option.
func WithProviders(names ...string) EnvOption {
	return func(e *Env) error {
		for _, name := range names {
			schema, err := providers.Coordinator.LoadSchema(name)
			if err != nil {
				return errors.Wrap(err, "failed to load schema for provider "+name)
			}
			if ext, ok := providers.Coordinator.Schema().(providers.ExtensibleSchema); ok {
				ext.Add(name, schema)
			}
		}
		return nil
	}
}

// WithPrivateProvider registers a caller-supplied, in-process provider so its
// resources can be compiled and evaluated without running a subprocess. Use
// it when expression mode is not enough because your data is a real resource
// with fields computed lazily in Go — only when an expression reads them —
// rather than plain values mapped into props.
//
// Unlike the providers loaded by WithProviders, which are discovered from the
// shared provider registry, a private provider is one only the caller has: an
// instance you constructed and hand to this Env directly.
//
// config identifies the provider (its ID must match the provider ID recorded
// on the schema's resources), schema is what queries compile against, and
// plug resolves resources and their fields on demand. Generated providers
// expose all three as Config, their schema, and Init(). The provider is wired
// into expression-mode evaluation and into connections opened by this Env.
func WithPrivateProvider(config plugin.Provider, schema resources.ResourcesSchema, plug plugin.ProviderPlugin) EnvOption {
	return func(e *Env) error {
		if schema == nil {
			return errors.New("cannot register private provider '" + config.Name + "': no schema provided")
		}
		if plug == nil {
			return errors.New("cannot register private provider '" + config.Name + "': no plugin provided")
		}
		// Register the schema so queries against the provider's resources
		// compile.
		if ext, ok := providers.Coordinator.Schema().(providers.ExtensibleSchema); ok {
			ext.Add(config.ID, schema)
		}
		e.private = append(e.private, privateProvider{config: config, schema: schema, plugin: plug})
		return nil
	}
}

// attachPrivateProviders wires every registered private provider into a
// runtime so its resources resolve there.
func (e *Env) attachPrivateProviders(rt *providers.Runtime) error {
	for _, bp := range e.private {
		if err := rt.UseInProcessProvider(bp.config, bp.schema, bp.plugin, e.features); err != nil {
			return err
		}
	}
	return nil
}

// NewEnv creates a new environment. With no options it is immediately usable
// for expression-mode queries.
//
// The schema-loading options (WithProviders, WithPrivateProvider) register
// schemas on the process-global provider coordinator as a side effect.
// Calling NewEnv with those options concurrently from multiple goroutines is
// therefore not safe; construct the environment once, before sharing it.
func NewEnv(opts ...EnvOption) (*Env, error) {
	e := &Env{
		features: mql.DefaultFeatures,
	}
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Features returns the feature flags this environment was created with.
func (e *Env) Features() mql.Features {
	return e.features
}

// schema returns the current provider schema. It grows as provider schemas
// are loaded (via Connect or WithProviders).
func (e *Env) schema() resources.ResourcesSchema {
	return providers.Coordinator.Schema()
}

// exprRuntime returns the internal runtime used for expression-mode
// evaluation. It is backed solely by the builtin core provider, which runs
// in-process: creating it never spawns a provider subprocess and never
// touches any infrastructure.
func (e *Env) exprRuntime() (*providers.Runtime, error) {
	e.exprOnce.Do(func() {
		rt := providers.Coordinator.NewRuntime()
		rt.AutoUpdate = providers.UpdateProvidersConfig{Enabled: false}
		// Connect the in-process core provider with the runtime's callbacks, so
		// resources resolved through it (including any reached from a private
		// provider) behave like under a normal connection.
		if err := rt.UseBuiltinProvider(providers.BuiltinCoreID, e.features); err != nil {
			e.exprErr = err
			return
		}

		if err := e.attachPrivateProviders(rt); err != nil {
			e.exprErr = err
			return
		}
		e.exprRT = rt
	})
	return e.exprRT, e.exprErr
}

func (e *Env) trackConn(c *Conn) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("cannot connect: environment is closed")
	}
	e.conns = append(e.conns, c)
	return nil
}

// Close closes all connections opened through this Env and the internal
// expression runtime. It does not shut down the provider coordinator; other
// components in the process may still be using it. Use Shutdown at process
// exit.
func (e *Env) Close() error {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	conns := e.conns
	e.conns = nil
	e.mu.Unlock()

	for _, c := range conns {
		c.Close()
	}
	if e.exprRT != nil {
		e.exprRT.Close()
	}
	return nil
}

// Shutdown closes the Env and additionally shuts down the provider
// coordinator, stopping all provider subprocesses. Call it once at process
// exit; in a process that embeds other MQL consumers, prefer Close.
func (e *Env) Shutdown() error {
	if err := e.Close(); err != nil {
		return err
	}
	providers.Coordinator.Shutdown()
	return nil
}
