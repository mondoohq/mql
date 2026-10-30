// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/url"
	"regexp"
)

// azureStorageAccountNameRe is Azure's storage account naming rule: 3 to 24
// characters, lowercase letters and digits only.
var azureStorageAccountNameRe = regexp.MustCompile(`^[a-z0-9]{3,24}$`)

// azureStorageDataPlaneURL builds the URL of one object in a storage account's
// data plane: a container on the blob service, a queue on the queue service.
//
// The two halves are handled differently because they land in different parts
// of the URL. The object name is a path segment, so it is percent-escaped. The
// account name is part of the host, where percent-escaping does not apply: a
// name carrying a "/" would not be encoded away, it would change which host the
// request is sent to. So the account name is validated against Azure's naming
// rule instead of escaped, and a name that fails is an error rather than a URL.
// In practice it always passes, since it is read back out of an ARM resource
// ID, but the URL is only safe to build because that is checked rather than
// assumed.
func azureStorageDataPlaneURL(account, service, name string) (string, error) {
	if !azureStorageAccountNameRe.MatchString(account) {
		return "", fmt.Errorf("%q is not a valid Azure storage account name", account)
	}
	return "https://" + account + "." + service + ".core.windows.net/" + url.PathEscape(name), nil
}
