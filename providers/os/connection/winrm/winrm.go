// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package winrm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"github.com/masterzen/winrm"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/connection/winrm/cat"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

var _ shared.Connection = (*Connection)(nil)

// maxCommandLength is the longest command WinRM runs. cmd.exe caps its whole
// command line at powershell.MaxCommandLength (8191) UTF-16 units, and that
// line includes cmd.exe's own path and /c, which WinRM puts in front of the
// command: 31 characters for the default C:\Windows\System32\cmd.exe. Measured
// over WinRM on Windows 11: an 8160-character command runs, 8161 does not. A
// host whose system root is longer than C:\Windows fails a little earlier.
const maxCommandLength = powershell.MaxCommandLength - len(`C:\Windows\System32\cmd.exe /c `)

func VerifyConfig(config *inventory.Config) (*winrm.Endpoint, error) {
	if config.Type != string(shared.Type_Winrm) {
		return nil, errors.New("only winrm backend for winrm transport supported")
	}

	winrmEndpoint := &winrm.Endpoint{
		Host: config.Host,
		Port: int(config.Port),
		// everything about winrm is insecure, therefore we always disable TLS verification since
		// only very few actually use valid certificates that are not self-signed
		Insecure: true,
		HTTPS:    true,
		Timeout:  time.Duration(0),
	}

	return winrmEndpoint, nil
}

// NewConnection creates a winrm client and establishes a connection to verify the connection
func NewConnection(id uint32, conf *inventory.Config, asset *inventory.Asset) (*Connection, error) {
	// ensure all required configs are set
	winrmEndpoint, err := VerifyConfig(conf)
	if err != nil {
		return nil, err
	}

	// set default config if required
	winrmEndpoint = DefaultConfig(winrmEndpoint)

	// search for password secret
	c, err := vault.GetPassword(conf.Credentials)
	if err != nil {
		return nil, errors.New("missing password for winrm transport")
	}

	ctx, cancel, err := shared.CommandContext(context.Background())
	if err != nil {
		return nil, err
	}
	defer cancel()
	factory := func(ctx context.Context) (*winrm.Client, func(), error) {
		return newClientWithContext(ctx, winrmEndpoint, c.User, string(c.Secret))
	}
	client, closeTransport, err := factory(ctx)
	if err != nil {
		return nil, err
	}

	defer closeTransport()

	// test connection
	log.Debug().Str("user", c.User).Str("host", conf.Host).Msg("winrm> connecting to remote shell via WinRM")
	shell, err := client.CreateShell()
	if err != nil {
		return nil, err
	}

	err = shell.Close()
	if err != nil {
		return nil, err
	}

	log.Debug().Msg("winrm> connection established")
	return &Connection{
		Connection:    plugin.NewConnection(id, asset),
		conf:          conf,
		asset:         asset,
		Endpoint:      winrmEndpoint,
		clientFactory: factory,
	}, nil
}

type Connection struct {
	plugin.Connection
	conf  *inventory.Config
	asset *inventory.Asset

	fs afero.Fs

	Endpoint      *winrm.Endpoint
	clientFactory func(context.Context) (*winrm.Client, func(), error)
}

func (c *Connection) Name() string {
	return "ssh"
}

func (c *Connection) Type() shared.ConnectionType {
	return shared.Type_Winrm
}

func (p *Connection) Asset() *inventory.Asset {
	return p.asset
}

func (p *Connection) UpdateAsset(asset *inventory.Asset) {
	p.asset = asset
}

func (p *Connection) Capabilities() shared.Capabilities {
	return shared.Capability_File | shared.Capability_RunCommand
}

// utf16Len counts the UTF-16 code units in s, which is the unit Windows
// measures a command line in.
//
// Neither obvious shorthand is right. len(s) counts UTF-8 bytes, which
// over-counts every non-ASCII character and would refuse commands that would
// have run. utf8.RuneCountInString counts code points, which *under*-counts:
// anything outside the basic multilingual plane is one rune but two UTF-16
// code units, so a command padded with emoji could slip past the check and be
// truncated anyway -- the exact failure this guard exists to prevent. Counting
// the code units directly is neither, and costs one pass with no allocation.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func (p *Connection) RunCommand(command string) (*shared.Command, error) {
	return p.RunCommandContext(context.Background(), command)
}

func (p *Connection) RunCommandContext(parent context.Context, command string) (*shared.Command, error) {
	ctx, cancel, err := shared.CommandContext(parent)
	if err != nil {
		return nil, err
	}
	defer cancel()

	log.Debug().Str("command", command).Str("provider", "winrm").Msg("winrm> run command")

	output, err := shared.NewCommandOutput(cancel)
	if err != nil {
		return nil, err
	}
	stdoutBuffer, stderrBuffer := output.Stdout, output.Stderr

	res := &shared.Command{
		Command: command,
		Stats: shared.PerfStats{
			Start: time.Now(),
		},
		Stdout: stdoutBuffer,
		Stderr: stderrBuffer,
	}
	defer func() {
		res.Stats.Duration = time.Since(res.Stats.Start)
	}()

	if n := utf16Len(command); n > maxCommandLength {
		// Past this the command never runs: WinRM hands it to cmd.exe, which
		// refuses it. On Windows 11 that is exit 1 and "The command line is
		// too long." on stderr, with empty stdout; a caller that only parses
		// stdout reports whatever an empty string means to it --
		// "unexpected end of JSON input" -- and never learns the command was
		// too long. Say so instead, before the round trip.
		err := fmt.Errorf(
			"command is %d characters, over the %d WinRM allows, so it would not run: %.120s",
			n, maxCommandLength, command)
		log.Error().Err(err).Msg("winrm command too long")
		return res, err
	}

	if p.clientFactory == nil {
		return nil, errors.New("WinRM connection is missing its client factory")
	}
	client, closeTransport, err := p.clientFactory(ctx)
	if err != nil {
		return nil, err
	}
	defer closeTransport()

	// Note: winrm does not return err of the command was executed with a non-zero exit code
	exitCode, err := client.RunWithContext(ctx, command, stdoutBuffer, stderrBuffer)
	if err := output.Error(); err != nil {
		return res, err
	}
	if errors.Is(err, shared.ErrCommandOutputLimit) {
		return res, err
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	// The socket deadline is the context's and can fire just before the
	// context's own timer, leaving ctx.Err() nil for an i/o timeout.
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return res, context.DeadlineExceeded
	}
	if err != nil {
		log.Error().Err(err).Str("command", command).Msg("could not execute winrm command")
		return res, err
	}

	res.ExitStatus = exitCode
	powershell.DecodeStderr(res)
	return res, nil
}

func (p *Connection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return fileInfo(p.FileSystem(), path)
}

// fileInfo describes a symbolic link or junction the way the local and SSH
// connections do: the mode and size of what it points to, with the link bit
// set. Only a filesystem that can lstat tells a link apart; on one that
// cannot, the path is stat'ed alone. Windows has no uid or gid.
func fileInfo(fs afero.Fs, path string) (shared.FileInfoDetails, error) {
	var stat os.FileInfo
	var err error
	if lstater, ok := fs.(afero.Lstater); ok {
		stat, _, err = lstater.LstatIfPossible(path)
	} else {
		stat, err = fs.Stat(path)
	}
	if err != nil {
		return shared.FileInfoDetails{}, err
	}

	mode := stat.Mode()
	size := stat.Size()
	if mode&os.ModeSymlink != 0 {
		target, err := fs.Stat(path)
		if err == nil {
			mode = target.Mode() | os.ModeSymlink
			size = target.Size()
		} else if !errors.Is(err, os.ErrNotExist) {
			return shared.FileInfoDetails{}, err
		}
		// a dangling link keeps what lstat said about the link itself
	}

	return shared.FileInfoDetails{
		Mode: shared.FileModeDetails{FileMode: mode},
		Size: size,
		Uid:  -1,
		Gid:  -1,
	}, nil
}

func (p *Connection) FileSystem() afero.Fs {
	if p.fs == nil {
		p.fs = cat.New(p)
	}
	return p.fs
}

// The SDK's context does not reach shell creation or HTTP requests. Each
// command owns its transport: cancellation closes its sockets without racing
// other commands, and the socket deadline also bounds TLS/HTTP body reads.
func newClientWithContext(ctx context.Context, endpoint *winrm.Endpoint, user, password string) (*winrm.Client, func(), error) {
	dial, cleanup := commandDialer(ctx)
	params := *winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return winrm.NewClientNTLMWithDial(dial) }
	client, err := winrm.NewClientWithParameters(endpoint, user, password, &params)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return client, cleanup, nil
}

func commandDialer(ctx context.Context) (func(string, string) (net.Conn, error), func()) {
	output, limitErr := shared.NewCommandOutput(nil)
	// WSMan base64 encoding and SOAP/HTTP framing are larger than decoded
	// output. Bound this earlier allocation too, allowing twice the decoded
	// budget plus 64 KiB of protocol overhead for normal small commands.
	wireLimit := int64(math.MaxInt64)
	if limitErr == nil && output.Limit() <= (math.MaxInt64-65536)/2 {
		wireLimit = output.Limit()*2 + 65536
	}
	wireBudget := &commandResponseBudget{limit: wireLimit}
	var mu sync.Mutex
	var connections []net.Conn
	closed := false
	closeAll := func() {
		mu.Lock()
		defer mu.Unlock()
		closed = true
		for _, conn := range connections {
			_ = conn.Close()
		}
	}
	stop := context.AfterFunc(ctx, closeAll)
	cleanup := func() { stop(); closeAll() }
	dial := func(network, addr string) (net.Conn, error) {
		if limitErr != nil {
			return nil, limitErr
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			if err := conn.SetDeadline(deadline); err != nil {
				conn.Close()
				return nil, err
			}
		}
		mu.Lock()
		defer mu.Unlock()
		if closed || ctx.Err() != nil {
			conn.Close()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return nil, net.ErrClosed
		}
		conn = &commandResponseConn{Conn: conn, budget: wireBudget}
		connections = append(connections, conn)
		return conn, nil
	}
	return dial, cleanup
}

type commandResponseBudget struct {
	mu          sync.Mutex
	limit, size int64
	err         error
}
type commandResponseConn struct {
	net.Conn
	budget *commandResponseBudget
}

func (c *commandResponseConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.budget.mu.Lock()
	if c.budget.err == nil && int64(n) > c.budget.limit-c.budget.size {
		c.budget.err = fmt.Errorf("%w (WinRM encoded response exceeds %d bytes)", shared.ErrCommandOutputLimit, c.budget.limit)
	}
	if c.budget.err == nil {
		c.budget.size += int64(n)
	}
	budgetErr := c.budget.err
	c.budget.mu.Unlock()
	if budgetErr != nil {
		_ = c.Close()
		return 0, budgetErr
	}
	return n, err
}
