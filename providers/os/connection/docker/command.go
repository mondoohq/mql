// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/moby/moby/client"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type Command struct {
	shared.Command
	Container string
	Client    *client.Client
}

func (c *Command) Exec(command string) (*shared.Command, error) {
	return c.ExecContext(context.Background(), command)
}

func (c *Command) ExecContext(parent context.Context, command string) (*shared.Command, error) {
	ctx, cancel, err := shared.CommandContext(parent)
	if err != nil {
		return nil, err
	}
	defer cancel()
	output, err := shared.NewCommandOutput(cancel)
	if err != nil {
		return nil, err
	}
	c.Command.Command = command
	c.Stats.Start = time.Now()

	res, err := c.Client.ExecCreate(ctx, c.Container, client.ExecCreateOptions{
		Cmd:          []string{"/bin/sh", "-c", c.Command.Command},
		TTY:          false,
		AttachStdin:  false,
		AttachStderr: true,
		AttachStdout: true,
	})
	if err != nil {
		return nil, err
	}

	resp, err := c.Client.ExecAttach(ctx, res.ID, client.ExecAttachOptions{
		TTY: false,
	})
	if err != nil {
		return nil, err
	}
	// The moby SDK requires the caller to close the hijacked response, which
	// closes the underlying net.Conn to the docker daemon. Without this every
	// command run against a running container leaks a socket/goroutine.
	defer resp.Close()
	// The SDK deliberately detaches a hijacked connection from the request
	// context after its handshake. Close it ourselves to interrupt a read.
	stop := context.AfterFunc(ctx, resp.Close)
	defer stop()

	c.Stdout, c.Stderr = output.Stdout, output.Stderr
	if err := c.transformHijack(resp.Reader, c.Stdout, c.Stderr); err != nil {
		if output.Error() != nil {
			return nil, output.Error()
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	if output.Error() != nil {
		return nil, output.Error()
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	c.Stats.Duration = time.Since(c.Stats.Start)

	info, err := c.Client.ExecInspect(ctx, res.ID, client.ExecInspectOptions{})
	if err != nil {
		return nil, err
	}
	c.ExitStatus = info.ExitCode

	return &c.Command, nil
}

const (
	STDIN  byte = 0
	STDOUT byte = 1
	STDERR byte = 2
)

// Format is defined in https://docs.docker.com/reference/api/engine/latest/#tag/Container/operation/ContainerAttach
func (c *Command) transformHijack(docker io.Reader, stdout io.Writer, stderr io.Writer) error {
	var header [8]byte
	for {
		n, err := io.ReadFull(docker, header[:])
		if err == io.EOF && n == 0 {
			return nil
		}
		if err != nil {
			return err
		}
		var stream io.Writer
		switch header[0] {
		case STDIN, STDOUT:
			stream = stdout
		case STDERR:
			stream = stderr
		default:
			return fmt.Errorf("invalid Docker output stream %d", header[0])
		}
		// Copy in bounded chunks instead of allocating the advertised frame
		// length, which is controlled by the daemon.
		if _, err := io.CopyN(stream, docker, int64(binary.BigEndian.Uint32(header[4:]))); err != nil {
			return err
		}
	}
}
