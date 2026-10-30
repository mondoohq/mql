// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package signers

import (
	"context"
	"net"
	"os"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func GetSignersFromSSHAgent() []ssh.Signer {
	return GetSignersFromSSHAgentContext(context.Background())
}

// The agent may require a hardware-key confirmation while signing. Closing
// its socket on cancellation bounds that wait as well as the initial key list.
func GetSignersFromSSHAgentContext(ctx context.Context) []ssh.Signer {
	signers := []ssh.Signer{}

	if sshAgentConn, err := (&net.Dialer{}).DialContext(ctx, "unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		if deadline, ok := ctx.Deadline(); ok {
			_ = sshAgentConn.SetDeadline(deadline)
		}
		context.AfterFunc(ctx, func() { _ = sshAgentConn.Close() })
		log.Debug().Str("socket", os.Getenv("SSH_AUTH_SOCK")).Msg("ssh agent socket found")
		sshAgentClient := agent.NewClient(sshAgentConn)
		sshAgentSigners, err := sshAgentClient.Signers()
		if err == nil && len(sshAgentSigners) == 0 {
			log.Warn().Msg("could not find keys in ssh agent")
		} else if err == nil {
			signers = append(signers, sshAgentSigners...)
		} else {
			log.Error().Err(err).Msg("could not get public keys from ssh agent")
		}
	} else {
		log.Debug().Msg("could not find valid ssh agent authentication")
	}
	return signers
}
