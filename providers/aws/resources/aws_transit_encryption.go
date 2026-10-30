// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// paramIndicatesTLS reports whether a parameter-group entry enforces TLS/SSL for
// client connections. Different engines expose this through different parameter
// names and truthy values, so all known variants are recognized:
//   - require_secure_transport: Aurora MySQL / MySQL (ON or 1)
//   - rds.force_ssl:            Aurora PostgreSQL / PostgreSQL (1 or ON)
//   - tls:                      DocumentDB (enabled, tls1.2+, tls1.3+ or fips-140-3;
//     every allowed value except disabled requires TLS)
func paramIndicatesTLS(name, value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "require_secure_transport", "rds.force_ssl":
		return v == "on" || v == "1"
	case "tls":
		switch v {
		case "enabled", "tls1.2+", "tls1.3+", "fips-140-3":
			return true
		}
	}
	return false
}

// parameterGroupEnforcesTLS scans a resolved parameter group's parameters for an
// enabled TLS/SSL enforcement setting. Each parameter is expected to expose a
// name and value accessor.
func parameterGroupEnforcesTLS(params *plugin.TValue[[]any]) (bool, error) {
	if params == nil {
		return false, nil
	}
	if params.Error != nil {
		return false, params.Error
	}
	for _, p := range params.Data {
		param, ok := p.(interface {
			GetName() *plugin.TValue[string]
			GetValue() *plugin.TValue[string]
		})
		if !ok {
			continue
		}
		name := param.GetName()
		if name.Error != nil {
			return false, name.Error
		}
		value := param.GetValue()
		if value.Error != nil {
			return false, value.Error
		}
		if paramIndicatesTLS(name.Data, value.Data) {
			return true, nil
		}
	}
	return false, nil
}

func (a *mqlAwsRdsDbcluster) transitEncryptionEnabled() (bool, error) {
	pg := a.GetDbClusterParameterGroup()
	if pg.Error != nil {
		return false, pg.Error
	}
	if pg.Data == nil {
		return false, nil
	}
	return parameterGroupEnforcesTLS(pg.Data.GetParameters())
}

func (a *mqlAwsDocumentdbCluster) transitEncryptionEnabled() (bool, error) {
	pg := a.GetParameterGroup()
	if pg.Error != nil {
		return false, pg.Error
	}
	if pg.Data == nil {
		return false, nil
	}
	return parameterGroupEnforcesTLS(pg.Data.GetParameters())
}
