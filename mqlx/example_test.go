// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlx_test

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/mqlx"
)

// Evaluate MQL as a pure expression engine: no providers, no asset, no
// subprocesses. Values are passed in as props and the result comes back as a
// plain Go value.
func Example_expressions() {
	env, err := mqlx.NewEnv()
	if err != nil {
		panic(err)
	}
	defer env.Close()

	q, err := env.Compile("props.name == /admin-.*/ && props.count > 3",
		mqlx.WithProps(map[string]any{"name": "", "count": 0}))
	if err != nil {
		panic(err)
	}

	res, err := q.Eval(context.Background(),
		mqlx.WithPropValues(map[string]any{"name": "admin-x", "count": 5}))
	if err != nil {
		panic(err)
	}

	fmt.Println(res.Value())
	// Output: true
}

// Query the local operating system and decode the result into a struct.
// This example connects to a real asset, so it is not executed in tests.
func ExampleEnv_ConnectLocal() {
	ctx := context.Background()

	env, _ := mqlx.NewEnv()
	defer func() { _ = env.Shutdown() }()

	conn, err := env.ConnectLocal(ctx)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	res, err := conn.Query(ctx, "asset { name platform version }")
	if err != nil {
		panic(err)
	}

	var info struct {
		Name     string `mql:"name"`
		Platform string `mql:"platform"`
		Version  string `mql:"version"`
	}
	if err := res.Decode(&info); err != nil {
		panic(err)
	}
	fmt.Println(info.Platform)
}

// Compile a query once and evaluate it against any number of connections,
// overriding properties per evaluation.
func ExampleQuery_EvalOn() {
	ctx := context.Background()

	env, _ := mqlx.NewEnv(mqlx.WithProviders("aws"))
	defer func() { _ = env.Shutdown() }()

	conn, err := env.Connect(ctx, mqlx.LocalAsset())
	if err != nil {
		panic(err)
	}

	q, err := env.Compile("users.where(uid >= props.min) { name uid }",
		mqlx.WithProps(map[string]any{"min": 1000}))
	if err != nil {
		panic(err)
	}

	res, err := q.EvalOn(ctx, conn)
	if err != nil {
		panic(err)
	}
	fmt.Println(res.Value())
}
