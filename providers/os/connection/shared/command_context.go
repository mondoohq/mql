// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ContextCommandRunner is optional so existing connection implementations keep
// satisfying Connection while transports adopt caller cancellation.
type ContextCommandRunner interface {
	RunCommandContext(context.Context, string) (*Command, error)
}

// CommandContext applies a finite command budget even to legacy callers. An
// earlier caller deadline or cancellation always wins.
func CommandContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	timeout := 5 * time.Minute
	if value := strings.TrimSpace(os.Getenv("MONDOO_COMMAND_TIMEOUT")); value != "" {
		var err error
		timeout, err = time.ParseDuration(value)
		if err != nil || timeout <= 0 {
			return nil, nil, fmt.Errorf("invalid MONDOO_COMMAND_TIMEOUT %q: expected a positive duration", value)
		}
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	return ctx, cancel, nil
}

// RunCommandContext uses cancellation when a connection supports it. Legacy
// connections retain their existing behavior; the helper cannot terminate work
// hidden behind their synchronous RunCommand method.
func RunCommandContext(ctx context.Context, runner interface {
	RunCommand(string) (*Command, error)
}, command string) (*Command, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runner, ok := runner.(ContextCommandRunner); ok {
		return runner.RunCommandContext(ctx, command)
	}
	return runner.RunCommand(command)
}

// ErrCommandOutputLimit means the command's combined stdout and stderr could
// not be captured completely. Callers must not treat the captured prefix as a
// successful measurement.
var ErrCommandOutputLimit = errors.New("command output exceeds its byte limit")

// CommandOutput limits both streams together. The sink keeps draining after
// cancellation because some SDKs ignore destination errors and can otherwise
// deadlock while writing their own output pipes. Error must be checked before
// returning any successful command result.
type CommandOutput struct {
	Stdout *commandOutputBuffer
	Stderr *commandOutputBuffer
	mu     sync.Mutex
	limit  int64
	size   int64
	err    error
	cancel func()
}

type commandOutputBuffer struct {
	output *CommandOutput
	buffer bytes.Buffer
}

func NewCommandOutput(cancel func()) (*CommandOutput, error) {
	limit := int64(128 * 1024 * 1024)
	if value := strings.TrimSpace(os.Getenv("MONDOO_COMMAND_OUTPUT_LIMIT")); value != "" {
		var err error
		limit, err = strconv.ParseInt(value, 10, 64)
		if err != nil || limit <= 0 {
			return nil, fmt.Errorf("invalid MONDOO_COMMAND_OUTPUT_LIMIT %q: expected a positive byte count", value)
		}
	}
	output := &CommandOutput{limit: limit, cancel: cancel}
	output.Stdout = &commandOutputBuffer{output: output}
	output.Stderr = &commandOutputBuffer{output: output}
	return output, nil
}

// Reserve also protects framed readers that need to inspect bytes before
// assigning them to a stream. It rejects a chunk before its allocation grows
// a retained command-output buffer past the budget.
func (o *CommandOutput) Reserve(size int) error {
	o.mu.Lock()
	if o.err == nil && int64(size) > o.limit-o.size {
		o.err = fmt.Errorf("%w (%d bytes; MONDOO_COMMAND_OUTPUT_LIMIT)", ErrCommandOutputLimit, o.limit)
	}
	if o.err == nil {
		o.size += int64(size)
	}
	err := o.err
	o.mu.Unlock()
	if err != nil && o.cancel != nil {
		o.cancel()
	}
	return err
}
func (o *CommandOutput) Error() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.err
}

// Write deliberately drains/discards after Reserve has recorded the failure
// and cancelled execution. Some SDKs ignore destination errors; returning one
// here could leave their producer blocked on an unread pipe. Every transport
// checks CommandOutput.Error before returning a successful result.
func (b *commandOutputBuffer) Write(p []byte) (int, error) {
	if err := b.output.Reserve(len(p)); err != nil {
		return len(p), nil
	}
	b.output.mu.Lock()
	defer b.output.mu.Unlock()
	return b.buffer.Write(p)
}
func (b *commandOutputBuffer) Read(p []byte) (int, error) {
	b.output.mu.Lock()
	defer b.output.mu.Unlock()
	return b.buffer.Read(p)
}

// Bytes is used after execution by stderr decoders. It preserves the same
// buffer view contract as bytes.Buffer; writers must have stopped first.
func (b *commandOutputBuffer) Bytes() []byte { return b.buffer.Bytes() }

// Limit is the configured combined stdout/stderr byte budget.
func (o *CommandOutput) Limit() int64 { return o.limit }
