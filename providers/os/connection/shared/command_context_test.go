// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"sync"
	"testing"
	"time"
)

func TestCommandContext(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_TIMEOUT", "")
	ctx, cancel, err := CommandContext(context.Background())
	require.NoError(t, err)
	defer cancel()
	deadline, ok := ctx.Deadline()
	require.True(t, ok)
	assert.InDelta(t, 300, time.Until(deadline).Seconds(), 1)
	t.Setenv("MONDOO_COMMAND_TIMEOUT", "25ms")
	ctx, cancel, err = CommandContext(context.Background())
	require.NoError(t, err)
	defer cancel()
	<-ctx.Done()
	assert.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	parent, stop := context.WithCancel(context.Background())
	stop()
	ctx, cancel, err = CommandContext(parent)
	require.NoError(t, err)
	defer cancel()
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
	for _, value := range []string{"0", "-1s", "invalid"} {
		t.Setenv("MONDOO_COMMAND_TIMEOUT", value)
		_, _, err := CommandContext(context.Background())
		assert.Error(t, err)
	}
}
func TestCommandOutput(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "5")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	output, err := NewCommandOutput(cancel)
	require.NoError(t, err)
	_, err = output.Stdout.Write([]byte("abc"))
	require.NoError(t, err)
	_, err = output.Stderr.Write([]byte("de"))
	require.NoError(t, err)
	assert.NoError(t, output.Error())
	_, err = output.Stdout.Write([]byte("f"))
	require.NoError(t, err)
	assert.ErrorIs(t, output.Error(), ErrCommandOutputLimit)
	assert.ErrorIs(t, ctx.Err(), context.Canceled)
	got, err := io.ReadAll(output.Stdout)
	require.NoError(t, err)
	assert.Equal(t, "abc", string(got))
	got, err = io.ReadAll(output.Stderr)
	require.NoError(t, err)
	assert.Equal(t, "de", string(got))
	// Subsequent SDK writes may drain, but must never allocate captured output.
	_, _ = output.Stdout.Write(make([]byte, 4096))
	got, _ = io.ReadAll(output.Stdout)
	assert.Empty(t, got)
}
func TestCommandOutputInvalidLimit(t *testing.T) {
	for _, value := range []string{"0", "-1", "1MiB", "invalid"} {
		t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", value)
		_, err := NewCommandOutput(nil)
		assert.Error(t, err)
	}
}

func TestCommandOutputConcurrentBudget(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "64")
	output, err := NewCommandOutput(nil)
	require.NoError(t, err)
	var writers sync.WaitGroup
	for i := range 64 {
		writers.Go(func() {
			stream := output.Stdout
			if i%2 == 0 {
				stream = output.Stderr
			}
			_, _ = stream.Write([]byte("data"))
		})
	}
	writers.Wait()
	assert.ErrorIs(t, output.Error(), ErrCommandOutputLimit)
	stdout, err := io.ReadAll(output.Stdout)
	require.NoError(t, err)
	stderr, err := io.ReadAll(output.Stderr)
	require.NoError(t, err)
	assert.Len(t, append(stdout, stderr...), 64, "concurrent accepted writes must fit the combined budget even before cancellation propagates")
}
