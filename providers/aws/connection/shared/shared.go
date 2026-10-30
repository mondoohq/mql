// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"go.mondoo.com/mql/providers/os/connection/shared"
)

type Connection interface {
	shared.Connection

	// Used to avoid verifying a client with the same options more than once
	Verify() (accountID string, err error)
	Hash() uint64
	SetAccountId(string)
}
