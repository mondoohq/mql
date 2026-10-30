// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureStorageDataPlaneURL(t *testing.T) {
	t.Run("account, service and object become host and path", func(t *testing.T) {
		blob, err := azureStorageDataPlaneURL("contoso", "blob", "logs")
		require.NoError(t, err)
		assert.Equal(t, "https://contoso.blob.core.windows.net/logs", blob)

		queue, err := azureStorageDataPlaneURL("contoso", "queue", "orders")
		require.NoError(t, err)
		assert.Equal(t, "https://contoso.queue.core.windows.net/orders", queue)
	})

	t.Run("the object name is escaped, not pasted into the path", func(t *testing.T) {
		got, err := azureStorageDataPlaneURL("contoso", "blob", "logs/../secrets")
		require.NoError(t, err)
		assert.Equal(t, "https://contoso.blob.core.windows.net/logs%2F..%2Fsecrets", got)
	})

	// The regression this guards: the account name lands in the host, where
	// percent-escaping does not apply. Escaping it there would look like a
	// defence and not be one -- a name carrying a "/" is not encoded away, it
	// moves the request to a different host. Rejecting the name is the defence.
	t.Run("an account name that is not a valid account name is refused", func(t *testing.T) {
		for _, account := range []string{
			"",
			"ab",                              // shorter than the 3 character minimum
			"averyverylongstorageaccountname", // longer than the 24 character maximum
			"Contoso",                         // uppercase is not allowed
			"contoso-logs",                    // hyphens are not allowed
			"evil/../attacker",                // would relocate the host
			"attacker.example.com",            // would relocate the host
			"contoso ",                        // trailing space
		} {
			_, err := azureStorageDataPlaneURL(account, "blob", "logs")
			assert.Error(t, err, "account %q", account)
		}
	})

	t.Run("the shortest and longest legal account names are accepted", func(t *testing.T) {
		shortest, err := azureStorageDataPlaneURL("abc", "blob", "logs")
		require.NoError(t, err)
		assert.Equal(t, "https://abc.blob.core.windows.net/logs", shortest)

		longest, err := azureStorageDataPlaneURL("abcdefghij0123456789wxyz", "blob", "logs")
		require.NoError(t, err)
		assert.Equal(t, "https://abcdefghij0123456789wxyz.blob.core.windows.net/logs", longest)
	})
}
