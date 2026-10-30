// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestGraphDeadlineIncludesSynchronousProviderCall(t *testing.T) {
	blocked := newBlockedRuntime("field")
	runtime := &cancellableRuntime{blockedRuntime: blocked}
	bundle := compileProbe(t, runtime)
	builder := NewBuilder()
	builder.WithQueryTimeout(100 * time.Millisecond)
	builder.AddQuery(bundle, nil, nil)
	for _, checksum := range CodepointChecksums(bundle) {
		builder.CollectDatapoint(checksum)
	}
	graph, err := builder.Build(runtime.Schema(), runtime, "")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- graph.Execute() }()
	awaitSignal(t, blocked.entered)
	select {
	case err := <-done:
		require.ErrorIs(t, err, errQueryTimeout)
	case <-time.After(5 * time.Second):
		t.Fatal("graph blocked on a timed-out synchronous provider call")
	}
	awaitSignal(t, blocked.returned)
}
