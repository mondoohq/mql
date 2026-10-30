// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package winrm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/masterzen/winrm"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWinRMCommandCancelsShellCreation(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_TIMEOUT", "75ms")
	stopped := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		select {
		case <-r.Context().Done():
			stopped <- struct{}{}
		case <-time.After(2 * time.Second):
		}
	}))
	defer server.Close()
	address, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(address.Port())
	require.NoError(t, err)
	endpoint := &winrm.Endpoint{Host: address.Hostname(), Port: port}
	conn := &Connection{clientFactory: func(ctx context.Context) (*winrm.Client, func(), error) {
		return newClientWithContext(ctx, endpoint, "test", "test")
	}}
	start := time.Now()
	_, err = conn.RunCommand("echo harmless")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), time.Second)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("cancelled shell-creation HTTP socket remained open")
	}
}

func TestWinRMCommandPollingBudgetAndOutput(t *testing.T) {
	for _, mode := range []string{"polling", "output", "normal"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "output" {
				t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "32")
			}
			var polls atomic.Int32
			envelope := func(action, body string) string {
				return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Header><a:Action>` + action + `</a:Action></s:Header><s:Body>` + body + `</s:Body></s:Envelope>`
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				body := string(raw)
				w.Header().Set("Content-Type", "application/soap+xml")
				switch {
				case strings.Contains(body, "/transfer/Create"):
					_, _ = io.WriteString(w, envelope("http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse", `<rsp:Shell><rsp:ShellId>shell</rsp:ShellId></rsp:Shell>`))
				case strings.Contains(body, "/shell/Command"):
					_, _ = io.WriteString(w, envelope("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse", `<rsp:CommandResponse><rsp:CommandId>command</rsp:CommandId></rsp:CommandResponse>`))
				case strings.Contains(body, "/shell/Receive"):
					polls.Add(1)
					if mode == "polling" {
						w.WriteHeader(500)
						_, _ = io.WriteString(w, envelope("http://schemas.dmtf.org/wbem/wsman/1/wsman/fault", `<s:Fault><s:Reason><s:Text>OperationTimeout</s:Text></s:Reason></s:Fault>`))
						return
					}
					text := "ready"
					if mode == "output" {
						text = strings.Repeat("x", 4096)
					}
					result := fmt.Sprintf(`<rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="command">%s</rsp:Stream><rsp:CommandState CommandId="command" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>`, base64.StdEncoding.EncodeToString([]byte(text)))
					_, _ = io.WriteString(w, envelope("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse", result))
				default:
					_, _ = io.WriteString(w, envelope("cleanup", ``))
				}
			}))
			defer server.Close()
			address, err := url.Parse(server.URL)
			require.NoError(t, err)
			port, err := strconv.Atoi(address.Port())
			require.NoError(t, err)
			endpoint := &winrm.Endpoint{Host: address.Hostname(), Port: port}
			conn := &Connection{clientFactory: func(ctx context.Context) (*winrm.Client, func(), error) {
				dial, cleanup := commandDialer(ctx)
				params := *winrm.DefaultParameters
				params.Dial = dial
				params.TransportDecorator = nil
				client, err := winrm.NewClientWithParameters(endpoint, "test", "test", &params)
				return client, cleanup, err
			}}
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			result, err := conn.RunCommandContext(ctx, "echo harmless")
			switch mode {
			case "polling":
				assert.ErrorIs(t, err, context.DeadlineExceeded)
				assert.Greater(t, polls.Load(), int32(1), "fixture must exercise SDK OperationTimeout retries")
			case "output":
				assert.ErrorIs(t, err, shared.ErrCommandOutputLimit)
			case "normal":
				require.NoError(t, err)
				out, err := io.ReadAll(result.Stdout)
				require.NoError(t, err)
				assert.Equal(t, "ready", string(out))
				assert.Zero(t, result.ExitStatus)
			}
		})
	}
}

func TestWinRMEncodedResponseBudget(t *testing.T) {
	t.Setenv("MONDOO_COMMAND_OUTPUT_LIMIT", "65536")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/soap+xml")
		_, _ = io.WriteString(w, strings.Repeat("x", 256*1024))
	}))
	defer server.Close()
	address, err := url.Parse(server.URL)
	require.NoError(t, err)
	port, err := strconv.Atoi(address.Port())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dial, cleanup := commandDialer(ctx)
	defer cleanup()
	params := *winrm.DefaultParameters
	params.Dial = dial
	params.TransportDecorator = nil
	client, err := winrm.NewClientWithParameters(&winrm.Endpoint{Host: address.Hostname(), Port: port}, "test", "test", &params)
	require.NoError(t, err)
	_, err = client.CreateShell()
	assert.ErrorIs(t, err, shared.ErrCommandOutputLimit, "raw response must be capped before SOAP parsing allocates the entire body")
}

type fakeInfo struct {
	name string
	size int64
	mode os.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return f.size }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// statFs answers Stat from stat, as cat.Fs does: what a path points to.
type statFs struct {
	afero.Fs
	stat map[string]os.FileInfo
}

func (s statFs) Stat(name string) (os.FileInfo, error) {
	if fi, ok := s.stat[name]; ok {
		return fi, nil
	}
	return nil, &os.PathError{Op: "stat", Path: name, Err: os.ErrNotExist}
}

// lstatFs also answers LstatIfPossible from lstat: the link itself.
type lstatFs struct {
	statFs
	lstat map[string]os.FileInfo
}

func (l lstatFs) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	if fi, ok := l.lstat[name]; ok {
		return fi, true, nil
	}
	return nil, true, &os.PathError{Op: "lstat", Path: name, Err: os.ErrNotExist}
}

func TestFileInfoReportsLinks(t *testing.T) {
	plain := fakeInfo{name: "plain.txt", size: 5, mode: 0o666}
	target := fakeInfo{name: "target.txt", size: 12, mode: 0o444}
	dir := fakeInfo{name: "dir", mode: os.ModeDir | 0o777}
	link := fakeInfo{name: "link", mode: os.ModeSymlink | 0o666}

	fs := lstatFs{
		Fs: afero.NewMemMapFs(), stat: map[string]os.FileInfo{
			`C:\t\plain.txt`: plain,
			`C:\t\link.txt`:  target,
			`C:\t\junction`:  dir,
		},
		lstat: map[string]os.FileInfo{
			`C:\t\plain.txt`: plain,
			`C:\t\link.txt`:  link,
			`C:\t\junction`:  link,
			`C:\t\dangling`:  link,
		},
	}

	fi, err := fileInfo(fs, `C:\t\plain.txt`)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o666), fi.Mode.FileMode)
	assert.Equal(t, int64(5), fi.Size)
	assert.Equal(t, int64(-1), fi.Uid)
	assert.Equal(t, int64(-1), fi.Gid)

	fi, err = fileInfo(fs, `C:\t\link.txt`)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink|0o444, fi.Mode.FileMode, "the target's permissions, with the link bit")
	assert.Equal(t, int64(12), fi.Size, "the target's size")

	fi, err = fileInfo(fs, `C:\t\junction`)
	require.NoError(t, err)
	assert.Equal(t, os.ModeSymlink|os.ModeDir|0o777, fi.Mode.FileMode)

	fi, err = fileInfo(fs, `C:\t\dangling`)
	require.NoError(t, err)
	assert.Equal(t, link.mode, fi.Mode.FileMode)

	_, err = fileInfo(fs, `C:\t\missing`)
	assert.True(t, errors.Is(err, os.ErrNotExist))
}

func TestFileInfoWithoutLstat(t *testing.T) {
	fs := statFs{Fs: afero.NewMemMapFs(), stat: map[string]os.FileInfo{
		`C:\t\link.txt`: fakeInfo{name: "link.txt", size: 0, mode: 0o666},
	}}
	fi, err := fileInfo(fs, `C:\t\link.txt`)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o666), fi.Mode.FileMode)
}
