# ADR 027: mqlx — A First-Class Go API for Embedding MQL

## Status

Proposed

## Context

MQL is a powerful engine, but Go developers who want to embed it face a wall
of internal machinery. To run a single query and read its results, a consumer
today must:

1. Wire up a runtime: `providers.Coordinator.NewRuntime()`, detect and start
   the right provider, and connect to an asset.
2. Compile: build a `mqlc.CompilerConfig` from the runtime schema and feature
   flags, call `mqlc.Compile`, and handle a `*llx.CodeBundle`.
3. Execute: call `exec.ExecuteCode` and receive a checksum-keyed
   `map[string]*llx.RawResult`.
4. Consume: walk the raw results, dereference blocks (whose keys are code
   checksums, not field names), and map every checksum back to a
   human-readable label through `CodeBundle.Labels` — by hand.

None of these steps is documented as a public workflow; each consumer
rediscovers it from our own CLI internals and test helpers.

### Evidence: what consumers build today

Prism (our Tetragon-based threat detection engine) is the most demanding MQL
embedder and shows the real cost. It carries roughly 250 lines of plumbing:

- Manual schema registration, runtime creation, and `ConnectedProvider`
  wiring for its in-process provider (`detectionengine.go`).
- Event-to-props conversion through `convert.JsonToDict` and
  `llx.DictData(...).Result()`.
- A hand-built 122-line decoder (`mqlcencoding.MQLCDecoder`) that walks
  resources via `GetData` calls and mapstructure hooks to turn results into
  typed structs — with open TODOs for unhandled cases.
- Recompilation of every query for every kernel event, with the TODO
  "pre-compile all queries passed in by the policy" marking the missing
  compile-once API.

Every Go service that embeds MQL repeats some subset of this work.

### The missing use case: MQL without infrastructure

Beyond infrastructure queries, there is demand for using MQL as a standalone
expression engine: evaluating policies and filters over data the caller
already has (an event, a request, a finding) with no asset, no provider
install, and no subprocesses. Prism works exactly this way — every query runs
over an event passed in as a property. The engine supports this today
(operators, string/array/map/dict functions, and the builtin core resources
such as `regex` and `time` all run in-process), but there is no API that
exposes it; consumers must discover the core-provider wiring on their own.

## Desired Outcome

A Go user goes from zero to evaluated, typed query results in a few lines —
in either of two first-class modes.

**Expression mode** — MQL over your own values, with zero setup:

```go
env, err := mqlx.NewEnv()
q, err := env.Compile(`props.name == /admin-.*/ && props.count > 3`,
    mqlx.WithProps(map[string]any{"name": "", "count": 0}))
res, err := q.Eval(ctx,
    mqlx.WithPropValues(map[string]any{"name": "admin-x", "count": 5}))
res.Value() // true
```

**Asset mode** — connect once, compile once, evaluate against any number of
assets, and decode results into native Go structs:

```go
conn, err := env.ConnectLocal(ctx)
res, err := conn.Query(ctx, "users { name uid }")

var users []struct {
    Name string `mql:"name"`
    UID  int64  `mql:"uid"`
}
err = res.Decode(&users)
```

## Decision

Add a new top-level package `mqlx` (`go.mondoo.com/mql/mqlx`, following
the `sqlx` naming precedent) as a purely additive facade over the existing
engine. It introduces four concepts:

| Type | Role | Lifetime / reuse |
|------|------|------------------|
| `Env` | feature flags, provider schemas, expression runtime | one per process, concurrent-safe |
| `Conn` | a connected asset | many queries per Conn, concurrent-safe |
| `Query` | compiled MQL | immutable; evaluate against any Conn or in expression mode |
| `Result` | one evaluation's output | `Value()`, `Decode()`, `Err()`, `Raw()` |

### API contract

```go
// Environment
func NewEnv(opts ...EnvOption) (*Env, error)
func WithFeatures(features mql.Features) EnvOption
func WithProviders(names ...string) EnvOption   // eager schema load
func WithPrivateProvider(config plugin.Provider, schema resources.ResourcesSchema,
    plug plugin.ProviderPlugin) EnvOption        // caller-supplied in-process provider
func (e *Env) Close() error                     // close owned conns + expression runtime
func (e *Env) Shutdown() error                  // Close + stop the provider coordinator

// Connections (asset mode)
func (e *Env) Connect(ctx context.Context, asset *inventory.Asset) (*Conn, error)
func (e *Env) ConnectLocal(ctx context.Context) (*Conn, error)
func (e *Env) WrapRuntime(rt llx.Runtime) *Conn // escape hatch (tests, custom lifecycles)
func LocalAsset() *inventory.Asset
func (c *Conn) Query(ctx context.Context, src string, opts ...CompileOption) (*Result, error)
func (c *Conn) Close()

// Compilation
func (e *Env) Compile(src string, opts ...CompileOption) (*Query, error)
func (e *Env) MustCompile(src string, opts ...CompileOption) *Query
func WithProps(props map[string]any) CompileOption // typed declarations + defaults

// Evaluation
func (q *Query) Eval(ctx context.Context, opts ...EvalOption) (*Result, error)   // expression mode
func (q *Query) EvalOn(ctx context.Context, conn *Conn, opts ...EvalOption) (*Result, error)
func WithPropValues(props map[string]any) EvalOption // per-eval overrides, type-checked

// Results
func (r *Result) Value() any              // label-resolved plain Go values
func (r *Result) Decode(target any) error // struct decoding: mql tag → json tag → field name
func (r *Result) Err() error              // per-value execution errors, joined
func (r *Result) FieldErrors() []FieldError
func (r *Result) Raw() (map[string]*llx.RawResult, *llx.CodeBundle)
```

### Key design points

**Expression mode is the bare default.** `NewEnv()` with no options is fully
usable. Internally, the Env lazily builds one runtime backed solely by the
builtin core provider, which runs in-process — creating it never spawns a
subprocess and never touches infrastructure. Heterogeneous values passed as
props (`map[string]any`, `[]any`) convert to MQL dicts, so queries navigate
them naturally: `props.event.process.binary.contains("/tmp")`.

**The asset binds at evaluation time, not at compile time.** A `Query` is
asset-independent; `EvalOn` takes the `Conn`. This is what makes
compile-once/evaluate-many work across fleets and discovered child assets,
and it matches the engine, where `exec.ExecuteCode` already takes the runtime
per call.

**Results resolve labels and keep errors.** `Value()` returns blocks as
`map[string]any` keyed by field labels (duplicate labels are numbered, as in
the JSON reporter), lists as `[]any`, and scalars as-is. Unlike the existing
`RawData.Dereference`, per-field execution errors are not dropped: they are
collected as `FieldError`s with paths (`users[3].name`), surfaced via `Err()`
and returned by `Decode`, so missing data is never silently zero-valued.

**Decoding preserves fidelity.** `Decode` is a small reflection decoder
rather than a JSON round-trip, because query values must survive intact:
int64 beyond 2^53, time values, and IPs all degrade through JSON. Struct
fields match by `mql` tag, then `json` tag, then field name. Numeric
conversions are overflow-checked and never silently truncate.

**Typed errors stay accessible.** Compile failures return a `*CompileError`
wrapping the source and the underlying compiler error, so callers can still
match typed errors such as `mqlc.ErrIdentifierNotFound` via `errors.As` —
the existing `exec.Exec` flattens these to strings.

**Schema availability is explicit.** A query compiles only against loaded
provider schemas. Expression-mode queries always compile; resources of other
providers require a prior `Connect` or `NewEnv(WithProviders("aws", ...))`.

**Custom resources, not just values.** When data is not a plain value but a
resource with fields computed lazily in Go — only when an expression reads
them — `WithPrivateProvider` registers a caller-supplied, in-process provider
(its `plugin.Provider` config, schema, and `plugin.ProviderPlugin`). "Private"
distinguishes it from the providers `WithProviders` loads from the shared
registry: it is a provider only the caller has, an instance handed to the Env
directly. Its resources compile and evaluate without a subprocess, and field
resolvers may reference other resources, because the connection is backed by
the runtime's own callbacks. This is what lets a consumer evaluate MQL against
a caller-defined resource without implementing `llx.Runtime` by hand. The
wiring is a thin wrapper over a new supported helper,
`providers.Runtime.UseInProcessProvider`, which direct `providers` consumers
can also use.

## Validation

The package ships with a working implementation and a test suite
(`mqlx/*_test.go`) covering both modes end-to-end: expression evaluation
against the real in-process core runtime (operators, core resources, props
with overrides and type checking, concurrent evaluation of one compiled
query), asset-mode queries against a recorded Linux asset, a caller-supplied
in-process provider whose resource fields resolve lazily on read (including a
cross-resource field and error propagation), result normalization (multi-value
queries, duplicate labels, value errors), and struct decoding (tag fallback
chain, overflow checks, nested structures, int64 fidelity).

## Key Files

| File | Role |
|------|------|
| `mqlx/mqlx.go` | package docs, `Env`, options, expression runtime |
| `mqlx/conn.go` | `Conn`, `Connect`/`ConnectLocal`/`WrapRuntime` |
| `mqlx/query.go` | `Query`, `Compile`, `WithProps` |
| `mqlx/eval.go` | `Eval`/`EvalOn`, property merging and type checks |
| `mqlx/value.go` | result normalization: labels, paths, field errors |
| `mqlx/decode.go` | reflection decoder for `Result.Decode` |
| `providers/runtime.go` | `Runtime.UseInProcessProvider`, the supported connect helper |
| `exec/exec.go` | execution entrypoint the facade wraps (unchanged) |
| `mqlc/mqlc.go` | compiler entrypoint the facade wraps (unchanged) |

## Follow-Ups

The facade is designed to absorb these without breaking changes; they are
intentionally not part of the initial implementation:

1. **Context-aware execution.** `exec` has no `context.Context` today; the
   graph executor only honors a timeout. Add `exec.ExecuteCodeCtx` and a
   cancellation case to the executor loop, then thread `ctx` through `Eval`.
   Until then, `Eval` honors `ctx` between, not during, executions.
2. **Resource expansion in Decode.** Decoding a bare resource into a struct
   by fetching its fields through the runtime — replacing prism's
   `MQLCDecoder`. Until then, queries project fields explicitly
   (`resource { field1 field2 }`), which is also the cheaper pattern.
3. **Asset construction sugar and discovery.** `NewAsset(connType, opts...)`
   helpers, credentials, and an `Env.Discover` API wrapping the discovery
   engine for fleet-wide compile-once/evaluate-many.
4. **Consumer migrations.** Move prism and xgrep onto `mqlx` as reference
   consumers: pre-compiled queries, `WithPrivateProvider` for their custom
   resources, and `Decode` replace their bespoke `llx.Runtime` and decoder
   layers.

## Consequences

- Existing APIs (`exec`, `mqlc`, `providers`) are untouched; `mqlx` is purely
  additive and consumers can adopt it incrementally.
- A new public surface must be kept stable. The API is intentionally small
  (four types) and hides engine internals, so the engine keeps freedom to
  evolve underneath it.
- Embedding MQL no longer requires knowledge of checksums, labels, code
  bundles, or provider wiring — which also means fewer consumers depending on
  those internals directly.
- The expression-mode runtime keeps one in-process core connection per Env;
  `Env.Close` releases it.
