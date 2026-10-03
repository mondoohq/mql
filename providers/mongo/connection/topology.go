// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "strings"

// namesSingleServer reports whether the host is a bare hostname or address,
// which names exactly one server, rather than a full connection string that
// carries its own topology.
func (c *MongoConnection) namesSingleServer() bool {
	return !strings.HasPrefix(c.host, "mongodb://") && !strings.HasPrefix(c.host, "mongodb+srv://")
}
