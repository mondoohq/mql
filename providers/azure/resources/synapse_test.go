// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStorageAccountNameFromURL(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want string
	}{
		// URL shape measured from defaultDataLakeStorage of a workspace created
		// with `az synapse workspace create`, 2026-11-14 (resourceId was null);
		// the account name is a placeholder.
		{"data lake endpoint", "https://synapsedemo01.dfs.core.windows.net", "synapsedemo01"},
		// Synthesized: other endpoint shapes the same field can carry.
		{"trailing slash", "https://acct01.dfs.core.windows.net/", "acct01"},
		{"blob endpoint", "https://acct01.blob.core.windows.net", "acct01"},
		{"uppercase host", "https://ACCT01.DFS.CORE.WINDOWS.NET", "acct01"},
		{"no scheme", "acct01.dfs.core.windows.net", "acct01"},
		{"with port and path", "https://acct01.dfs.core.windows.net:443/synfs", "acct01"},
		{"china cloud", "https://acct01.dfs.core.chinacloudapi.cn", "acct01"},
		{"us government cloud", "https://acct01.blob.core.usgovcloudapi.net", "acct01"},
		{"dns zone endpoint", "https://acct01.z12.dfs.storage.azure.net", "acct01"},
		{"empty", "", ""},
		{"not a storage service", "https://acct01.queue.core.windows.net", ""},
		{"key vault url", "https://vault01.vault.azure.net/keys/k1", ""},
		{"too few labels", "https://acct01.dfs", ""},
		{"invalid account name", "https://my-acct.dfs.core.windows.net", ""},
		{"account name too short", "https://ab.dfs.core.windows.net", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, storageAccountNameFromURL(tc.url))
		})
	}
}
