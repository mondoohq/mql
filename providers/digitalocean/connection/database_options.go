// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"net/http"
)

// godo's DatabaseOptions omits each engine's version_availability list, so
// the options are read through the client's own NewRequest/Do, which keeps
// the token, rate limiter and error decoding.
const databaseOptionsPath = "v2/databases/options"

// DatabaseVersionAvailability is the lifecycle DigitalOcean publishes for one
// engine version. The dates are RFC 3339 strings, empty when not published.
type DatabaseVersionAvailability struct {
	Version           string `json:"version"`
	EndOfLife         string `json:"end_of_life"`
	EndOfAvailability string `json:"end_of_availability"`
}

// DatabaseEngineOptions holds the per-engine part of the options response
// that the provider reads.
type DatabaseEngineOptions struct {
	VersionAvailability []DatabaseVersionAvailability `json:"version_availability"`
}

// DatabaseOptions maps an engine slug (pg, mysql, redis, ...) to its options.
type DatabaseOptions map[string]DatabaseEngineOptions

type databaseOptionsRoot struct {
	Options DatabaseOptions `json:"options"`
}

// DatabaseOptions returns the managed database options, fetching them once
// per connection. Every cluster shares the one response.
func (c *DigitaloceanConnection) DatabaseOptions() (DatabaseOptions, error) {
	c.databaseOptionsOnce.Do(func() {
		ctx := context.Background()
		req, err := c.client.NewRequest(ctx, http.MethodGet, databaseOptionsPath, nil)
		if err != nil {
			c.databaseOptionsErr = err
			return
		}
		root := new(databaseOptionsRoot)
		if _, err := c.client.Do(ctx, req, root); err != nil {
			c.databaseOptionsErr = err
			return
		}
		c.databaseOptions = root.Options
	})
	return c.databaseOptions, c.databaseOptionsErr
}
