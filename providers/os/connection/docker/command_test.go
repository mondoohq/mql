// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/moby/moby/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func dockerFrame(stream byte, body string) []byte {
	header := make([]byte, 8)
	header[0] = stream
	binary.BigEndian.PutUint32(header[4:], uint32(len(body)))
	return append(header, body...)
}
func TestTransformHijack(t *testing.T) {
	for _, tc := range []struct {
		name           string
		input          []byte
		stdout, stderr string
		bad            bool
	}{
		{name: "streams", input: append(dockerFrame(STDOUT, "hello"), dockerFrame(STDERR, "warning")...), stdout: "hello", stderr: "warning"},
		{name: "incomplete header", input: []byte{1, 0}, bad: true},
		{name: "incomplete body", input: dockerFrame(STDOUT, "hello")[:10], bad: true},
		{name: "unknown stream", input: dockerFrame(9, "hello"), bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, stderr bytes.Buffer
			err := (&Command{}).transformHijack(bytes.NewReader(tc.input), &out, &stderr)
			if tc.bad {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.stdout, out.String())
			assert.Equal(t, tc.stderr, stderr.String())
		})
	}
}
func TestDockerCommandCancellationAndOutput(t *testing.T) {
	for _, mode := range []string{"silent", "output", "normal"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "output" {
				t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "32")
			}
			closed := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/containers/test/exec"):
					_, _ = io.WriteString(w, `{"Id":"command"}`)
				case strings.HasSuffix(r.URL.Path, "/exec/command/start"):
					conn, buffer, err := w.(http.Hijacker).Hijack()
					if err != nil {
						closed <- err
						return
					}
					defer conn.Close()
					_, _ = io.WriteString(buffer, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\n")
					_ = buffer.Flush()
					if mode == "normal" {
						_, _ = conn.Write(dockerFrame(STDOUT, "ready"))
						closed <- nil
						return
					}
					if mode == "output" {
						_, _ = conn.Write(dockerFrame(STDOUT, strings.Repeat("x", 4096)))
					}
					_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
					_, err = io.Copy(io.Discard, conn)
					closed <- err
				case strings.HasSuffix(r.URL.Path, "/exec/command/json"):
					_, _ = io.WriteString(w, `{"ExitCode":0,"Running":false}`)
				default:
					http.Error(w, fmt.Sprintf("unexpected path %s", r.URL.Path), 404)
				}
			}))
			defer server.Close()
			engine, err := client.New(client.WithHost(strings.Replace(server.URL, "http://", "tcp://", 1)), client.WithAPIVersion("1.56"))
			require.NoError(t, err)
			defer engine.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			result, err := (&Command{Client: engine, Container: "test"}).ExecContext(ctx, "harmless")
			switch mode {
			case "silent":
				assert.ErrorIs(t, err, context.DeadlineExceeded)
			case "output":
				assert.ErrorIs(t, err, shared.ErrCommandOutputLimit)
			case "normal":
				require.NoError(t, err)
				out, err := io.ReadAll(result.Stdout)
				require.NoError(t, err)
				assert.Equal(t, "ready", string(out))
				assert.Zero(t, result.ExitStatus)
			}
			select {
			case err := <-closed:
				assert.NoError(t, err, "attachment socket should close on cancellation")
			case <-time.After(time.Second):
				t.Fatal("attachment leaked")
			}
		})
	}
}
