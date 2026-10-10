// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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
	c.Command.Command = command
	c.Stats.Start = time.Now()

	ctx := context.Background()
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

	// TODO: transformHijack breaks for long stdout, but not if we read stdout/stderr in upfront
	content, err := io.ReadAll(resp.Reader)
	if err != nil {
		return nil, err
	}

	var stdoutBuffer bytes.Buffer
	var stderrBuffer bytes.Buffer

	// create buffered stream
	c.Stdout = &stdoutBuffer
	c.Stderr = &stderrBuffer

	stdOutWriter := bufio.NewWriter(&stdoutBuffer)
	stdErrWriter := bufio.NewWriter(&stderrBuffer)

	// extract stdout, stderr
	c.transformHijack(bytes.NewReader(content), stdOutWriter, stdErrWriter)

	defer stdOutWriter.Flush()
	defer stdErrWriter.Flush()

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
func (c *Command) transformHijack(docker io.Reader, stdout io.Writer, stderr io.Writer) {
	header := make([]byte, 8)
	for {
		// read header
		_, err := docker.Read(header)

		// end reached
		if err == io.EOF {
			break
		}

		size := binary.BigEndian.Uint32(header[4:8])
		content := make([]byte, size)
		_, err = docker.Read(content)

		switch header[0] {
		case STDIN, STDOUT:
			stdout.Write(content)
		case STDERR:
			stderr.Write(content)
		}

		// end reached
		if err == io.EOF {
			break
		}
	}
}
