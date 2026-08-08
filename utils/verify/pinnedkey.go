// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package verify

// PinnedPublicKey is the minisign public key used to verify update downloads
// (both provider plugins and the engine binary). It is the deployment's trust
// anchor and is empty in development builds; release builds set it via
// -ldflags, for example:
//
//	-ldflags "-X go.mondoo.com/mql/v13/utils/verify.PinnedPublicKey=RW...=="
//
// While it is empty, signature verification is unavailable and, under the
// default 'auto' policy, downloads are accepted on checksum alone. Integrity
// (SHA256) is always enforced.
var PinnedPublicKey = ""
