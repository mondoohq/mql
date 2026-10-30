// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// OptionHost is the ClickHouse hostname or IP.
	OptionHost = "host"
	// OptionPort is the ClickHouse native protocol port.
	OptionPort = "port"
	// OptionDatabase is the database to connect to.
	OptionDatabase = "database"
	// OptionTLS enables TLS when "true".
	OptionTLS = "tls"
	// OptionTLSInsecure skips TLS certificate validation when "true".
	OptionTLSInsecure = "tls-insecure"
)

var platformIdClickhousedbInstance = "//platformid.api.mondoo.app/runtime/clickhousedb/instance/"

// NewClickhousedbInstancePlatform returns the platform for a ClickHouse server.
func NewClickhousedbInstancePlatform(instanceID string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "clickhousedb",
		Title:                 "ClickHouse",
		Family:                []string{"clickhousedb"},
		Kind:                  "api",
		Runtime:               "clickhousedb",
		TechnologyUrlSegments: []string{"db", "clickhousedb", "instance", instanceID},
	}
}

// NewClickhousedbInstanceIdentifier returns the stable platform id for a server.
func NewClickhousedbInstanceIdentifier(instanceID string) string {
	return platformIdClickhousedbInstance + instanceID
}
