// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx

import (
	"context"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"google.golang.org/protobuf/proto"
)

// Conn is a live connection to a single asset. It is safe for concurrent
// evaluations. Close releases the underlying provider connection.
type Conn struct {
	env     *Env
	runtime llx.Runtime
	owned   bool
	close   sync.Once
}

// LocalAsset returns an asset describing the local operating system.
func LocalAsset() *inventory.Asset {
	return &inventory.Asset{
		Connections: []*inventory.Config{{Type: "local"}},
	}
}

// Connect detects the provider for the given asset, starts it, and connects.
// The asset is cloned; the caller's copy is not modified.
func (e *Env) Connect(ctx context.Context, asset *inventory.Asset) (*Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	asset = proto.Clone(asset).(*inventory.Asset)

	rt := providers.Coordinator.NewRuntime()
	if err := rt.DetectProvider(asset); err != nil {
		rt.Close()
		return nil, err
	}
	if err := rt.Connect(&plugin.ConnectReq{
		Features: e.features,
		Asset:    asset,
	}); err != nil {
		rt.Close()
		return nil, err
	}
	if err := e.attachPrivateProviders(rt); err != nil {
		rt.Close()
		return nil, err
	}

	conn := &Conn{env: e, runtime: rt, owned: true}
	if err := e.trackConn(conn); err != nil {
		rt.Close()
		return nil, err
	}
	return conn, nil
}

// ConnectLocal connects to the local operating system.
func (e *Env) ConnectLocal(ctx context.Context) (*Conn, error) {
	return e.Connect(ctx, LocalAsset())
}

// WrapRuntime wraps an existing runtime in a Conn. This is the escape hatch
// for callers that manage runtime lifecycles themselves (tests, custom
// discovery loops). The returned Conn does not own the runtime; its Close is
// a no-op.
func (e *Env) WrapRuntime(rt llx.Runtime) *Conn {
	return &Conn{env: e, runtime: rt}
}

// Close releases the connection. It is a no-op for Conns created via
// WrapRuntime.
func (c *Conn) Close() {
	c.close.Do(func() {
		if c.owned {
			c.runtime.Close()
		}
	})
}

// Asset returns the connected asset with the metadata the provider attached
// during connection, or nil if unavailable.
func (c *Conn) Asset() *inventory.Asset {
	rt, ok := c.runtime.(*providers.Runtime)
	if !ok || rt.Provider == nil || rt.Provider.Connection == nil {
		return nil
	}
	return rt.Provider.Connection.Asset
}

// Runtime exposes the underlying runtime for advanced use.
func (c *Conn) Runtime() llx.Runtime {
	return c.runtime
}

// Query compiles and evaluates src against this connection in one call. For
// repeated evaluation, compile once with Env.Compile and use Query.EvalOn.
func (c *Conn) Query(ctx context.Context, src string, opts ...CompileOption) (*Result, error) {
	q, err := c.env.Compile(src, opts...)
	if err != nil {
		return nil, err
	}
	return q.EvalOn(ctx, c)
}
