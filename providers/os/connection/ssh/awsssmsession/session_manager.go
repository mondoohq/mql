// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsssmsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
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
	return a.DialContext(context.Background(), tc, localPort, remotePort)
}

func (a *AwsSsmSessionManager) DialContext(ctx context.Context, tc *inventory.Config, localPort string, remotePort string) (*AwsSsmSessionConnection, error) {
	return newAwsSsmSessionConnectionContext(ctx, a.cfg, a.profile, tc.Host, localPort, remotePort)
}

// NewAwsSsmSessionConnection establishes a new proxy connection via AWS Session Manager plugin. Instead of doing a
// tty session, we forward the ssh port from the remote machine to a local port. This ensures we have full ssh power
// available and the implementation with existing features stays identical.
//
// The following steps are executed:
// 1. Call AWS SSM StartSession to open a websocket on AWS side that forwards to the machine ssh port
// 2. We start the session-manager-plugin process that handles the websocket connection and maps it to a local port
//
// When the connection is closed, we kill the local process and stop the session via the AWS API
func NewAwsSsmSessionConnection(cfg aws.Config, profile string, instance string, localPort string, remotePort string) (*AwsSsmSessionConnection, error) {
	return newAwsSsmSessionConnectionContext(context.Background(), cfg, profile, instance, localPort, remotePort)
}

func newAwsSsmSessionConnectionContext(ctx context.Context, cfg aws.Config, profile string, instance string, localPort string, remotePort string) (*AwsSsmSessionConnection, error) {
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
	success := false
	defer func() {
		if !success {
			_ = conn.Close()
		}
	}()

	sessJson, err := json.Marshal(ssmSession)
	if err != nil {
		return nil, err
	}

	paramsJson, err := json.Marshal(conn.input)
	if err != nil {
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
		return nil, err
	}

	if cmd.Process == nil {
		return nil, errors.New("could not start session-manager-plugin")
	}

	log.Debug().Int("pid", cmd.Process.Pid).Msg("aws session-manager-plugin started")
	conn.process = cmd.Process

	// TODO: we may need to implement ssh re-try, the process start takes a bit
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case <-timer.C:
		success = true
		return conn, nil
	case <-ctx.Done():
		// The proxy lifetime extends beyond startup on success only.
		return nil, ctx.Err()
	}
}

type AwsSsmSessionConnection struct {
	client  *ssm.Client
	input   *ssm.StartSessionInput
	session *ssm.StartSessionOutput
	process *os.Process
}

func (a *AwsSsmSessionConnection) Close() error {
	// kill proxy command if it is still running
	var processerr error
	if a.process != nil {
		processerr = a.process.Kill()
	}

	// close ssm websocket session
	if a.client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := a.client.TerminateSession(ctx, &ssm.TerminateSessionInput{
			SessionId: a.session.SessionId,
		})
		if err != nil {
			return err
		}
		if processerr != nil {
			return err
		}
	}
	return nil
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return CheckPluginContext(ctx)
}

func CheckPluginContext(ctx context.Context) error {
	name := GetSsmPluginBinaryName()
	cmd := exec.CommandContext(ctx, name, "--version")
	return cmd.Run()
}
