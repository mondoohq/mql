// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package networkinterface

import (
	"net"

	"github.com/cockroachdb/errors"
)

// GetOutboundIP returns the local IP that is used for outbound connections
// It does not establish a real connection and the destination does not need to valid.
// Since its using udp protocol (unlike TCP) a handshake nor connection is required,
// / then it gets the local up address if it would connect to that target
// conn.LocalAddr().String() returns the local ip and port
//
// # NOTE be aware that this code does not work on remote targets
//
// @see this approach is derived from https://stackoverflow.com/a/37382208
func GetOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return nil, errors.Wrap(err, "could not determine outbound ip")
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	if localAddr == nil {
		return nil, errors.New("could not determine outbound ip")
	}

	return localAddr.IP, nil
}
