// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsssmsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func NewAwsSsmSessionManager(cfg aws.Config, profile string) (*AwsSsmSessionManager, error) {
	return &AwsSsmSessionManager{
		profile: profile,
		region:  cfg.Region,
		cfg:     cfg,
	}, nil
}

// AwsSsmSessionManager allows us to connect to a remote ec2 instance without having port 22 open
//
// References:
// - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
// - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html
// - https://us-east-1.console.aws.amazon.com/systems-manager/documents/AWS-StartPortForwardingSession/description
type AwsSsmSessionManager struct {
	profile string
	region  string
	cfg     aws.Config
}

func (a *AwsSsmSessionManager) Dial(tc *inventory.Config, localPort string, remotePort string) (*AwsSsmSessionConnection, error) {
	return NewAwsSsmSessionConnection(a.cfg, a.profile, tc.Host, localPort, remotePort)
}

// NewAwsSsmSessionConnection establishes a new proxy connection via AWS Session Manager plugin. Instead of doing a
// tty session, we forward the ssh port from the remote machine to a local port. This ensures we have full ssh power
// available and the implementation with existing features stays identical.
//
// The following steps are executed:
// 1. Call AWS SSM StartSession to open a websocket on AWS side that forwards to the machine ssh port
// 2. We start the session-manager-plugin process that handles the websocket connection and maps it to a local port
//
// When the connection is closed, we kill the local process and stop the session via the AWS API. The session is also
// stopped when the plugin does not start listening on the local port.
func NewAwsSsmSessionConnection(cfg aws.Config, profile string, instance string, localPort string, remotePort string) (*AwsSsmSessionConnection, error) {
	ctx := context.Background()
	conn := &AwsSsmSessionConnection{
		input: &ssm.StartSessionInput{
			DocumentName: aws.String("AWS-StartPortForwardingSession"),
			Parameters: map[string][]string{
				"portNumber":      {remotePort},
				"localPortNumber": {localPort},
			},
			Target: aws.String(instance),
		},
	}

	// start ssm websocket session
	conn.client = ssm.NewFromConfig(cfg)
	ssmSession, err := conn.client.StartSession(ctx, conn.input)
	if err != nil {
		return nil, err
	}
	conn.session = ssmSession
	conn.terminator = conn.client

	sessJson, err := json.Marshal(ssmSession)
	if err != nil {
		conn.Close()
		return nil, err
	}

	paramsJson, err := json.Marshal(conn.input)
	if err != nil {
		conn.Close()
		return nil, err
	}

	// proxyCommand := fmt.Sprintf("%s '%s' %s %s %s '%s'",
	//	GetSsmPluginBinaryName(), string(sessJson), cfg.Region,
	//	"StartSession", profile, string(paramsJson))

	// start aws ssm session plugin as used by the aws cli
	// https://github.com/aws/session-manager-plugin
	binary := GetSsmPluginBinaryName()
	args := []string{
		fmt.Sprintf("'%s'", string(sessJson)),
		cfg.Region,
		"StartSession",
		profile,
		fmt.Sprintf("'%s'", string(paramsJson)),
	}

	log.Debug().Str("cmd", fmt.Sprintf("%s %s", binary, strings.Join(args, " "))).Msg("start aws session manager plugin")

	cmd := exec.Command(binary, string(sessJson), cfg.Region, "StartSession", profile, string(paramsJson))
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		conn.Close()
		return nil, err
	}

	if cmd.Process == nil {
		conn.Close()
		return nil, errors.New("could not start session-manager-plugin")
	}

	log.Debug().Int("pid", cmd.Process.Pid).Msg("aws session-manager-plugin started")
	conn.process = cmd.Process
	conn.exited = make(chan struct{})
	go func() {
		// reaps the plugin when it exits, whether killed or on its own
		_ = cmd.Wait()
		close(conn.exited)
	}()

	if err := WaitForLocalPort(LocalAddress(localPort), conn.exited, PluginStartTimeout); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// LocalHost is the address the session-manager-plugin listens on for a port
// forwarding session. It is IPv4 only, so "localhost" may resolve to ::1 first
// and miss it.
const LocalHost = "127.0.0.1"

// PluginStartTimeout is how long the session-manager-plugin may take to listen
// on the local port.
var PluginStartTimeout = 30 * time.Second

// LocalAddress is the address of the forwarded port on this machine.
func LocalAddress(localPort string) string {
	return net.JoinHostPort(LocalHost, localPort)
}

// WaitForLocalPort waits until addr accepts TCP connections. It fails when
// exited is closed first, which means the process that should listen there
// ended, or when the timeout passes.
func WaitForLocalPort(addr string, exited <-chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-exited:
			return errors.New("session-manager-plugin exited before it listened on " + addr)
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("session-manager-plugin did not listen on %s within %s: %w", addr, timeout, err)
		}
		select {
		case <-exited:
			return errors.New("session-manager-plugin exited before it listened on " + addr)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// sessionTerminator stops an SSM session; *ssm.Client is one.
type sessionTerminator interface {
	TerminateSession(ctx context.Context, params *ssm.TerminateSessionInput, optFns ...func(*ssm.Options)) (*ssm.TerminateSessionOutput, error)
}

type AwsSsmSessionConnection struct {
	client     *ssm.Client
	terminator sessionTerminator
	input      *ssm.StartSessionInput
	session    *ssm.StartSessionOutput
	process    *os.Process
	// exited is closed when the plugin process has ended and was reaped
	exited    chan struct{}
	closeOnce sync.Once
	closeErr  error
}

// Close stops the session-manager-plugin and terminates the SSM session, so it
// does not stay active after the scan. Later calls return the first result.
func (a *AwsSsmSessionConnection) Close() error {
	a.closeOnce.Do(func() {
		var errs []error
		// kill proxy command if it is still running
		if a.process != nil {
			if err := a.process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				errs = append(errs, fmt.Errorf("stop session-manager-plugin: %w", err))
			}
			if a.exited != nil {
				select {
				case <-a.exited:
				case <-time.After(5 * time.Second):
					log.Debug().Int("pid", a.process.Pid).Msg("aws session-manager-plugin did not exit after kill")
				}
			}
		}

		// close ssm websocket session
		if a.terminator != nil && a.session != nil && a.session.SessionId != nil {
			_, err := a.terminator.TerminateSession(context.Background(), &ssm.TerminateSessionInput{
				SessionId: a.session.SessionId,
			})
			if err != nil {
				errs = append(errs, fmt.Errorf("terminate ssm session %s: %w", aws.ToString(a.session.SessionId), err))
			} else {
				log.Debug().Str("session", aws.ToString(a.session.SessionId)).Msg("terminated aws ssm session")
			}
		}
		a.closeErr = errors.Join(errs...)
	})
	return a.closeErr
}

// GetSsmPluginBinaryName returns filename for aws ssm plugin
func GetSsmPluginBinaryName() string {
	if strings.ToLower(runtime.GOOS) == "windows" {
		return "session-manager-plugin.exe"
	} else {
		return "session-manager-plugin"
	}
}

// CheckPlugin runs the session-manager-plugin binary and asks for the version
func CheckPlugin() error {
	name := GetSsmPluginBinaryName()
	cmd := exec.Command(name, "--version")
	return cmd.Run()
}
