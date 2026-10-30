// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package register links in all vault implementations so they self-register
// with the vault registry. Blank-import it from a binary that needs the full
// set of vault backends:
//
//	import _ "go.mondoo.com/mql/vault/register"
//
// To pull in only a single backend, blank-import the individual implementation
// package instead (e.g. go.mondoo.com/mql/vault/hashivault). The in-memory
// backend is always available; it is registered by the SDK itself.
package register

import (
	_ "go.mondoo.com/mql/vault/awsparameterstore"
	_ "go.mondoo.com/mql/vault/awssecretsmanager"
	_ "go.mondoo.com/mql/vault/gcpberglas"
	_ "go.mondoo.com/mql/vault/gcpsecretmanager"
	_ "go.mondoo.com/mql/vault/hashivault"
	_ "go.mondoo.com/mql/vault/keyring"
)
