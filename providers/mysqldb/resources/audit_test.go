// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
)

func TestAuditLogFilterLogsAll(t *testing.T) {
	cases := map[string]bool{
		// CIS MySQL 6.6 remediation
		`{"filter": {"log": true}}`: true,
		// no log item and no class or event items logs everything
		`{"filter": {}}`:                                                 true,
		`{"filter": {"log": false}}`:                                     false,
		`{"filter": {"class": {"name": "connection"}}}`:                  false,
		`{"filter": {"log": true, "class": [{"name": "connection"}]}}`:   false,
		`{"filter": {"class": [{"name": "table_access", "log": true}]}}`: false,
		`{"filter": {"event": {"name": "connect"}}}`:                     false,
		`{"filter": {"log": "true"}}`:                                    false,
		`{"log": true}`:                                                  false,
		`[]`:                                                             false,
		`null`:                                                           false,
	}
	for raw, want := range cases {
		def, err := parseAuditLogFilter(raw)
		if err != nil {
			t.Errorf("parseAuditLogFilter(%s) failed: %v", raw, err)
			continue
		}
		if got := auditLogFilterLogsAll(def); got != want {
			t.Errorf("auditLogFilterLogsAll(%s) = %v, want %v", raw, got, want)
		}
	}
}

func TestParseAuditLogFilter(t *testing.T) {
	def, err := parseAuditLogFilter(`{"filter": {"log": true}}`)
	if err != nil {
		t.Fatal(err)
	}
	filter := def.(map[string]any)["filter"].(map[string]any)
	if filter["log"] != true {
		t.Errorf("definition = %v", def)
	}
	if def, err := parseAuditLogFilter(""); err != nil || def != nil {
		t.Errorf("empty FILTER = %v, %v; want nil, nil", def, err)
	}
	if _, err := parseAuditLogFilter(`{"filter": `); err == nil {
		t.Error("truncated JSON must fail to parse")
	}
	if auditLogFilterLogsAll(nil) {
		t.Error("a missing definition must not log all")
	}
}

func TestQuoteIdentifier(t *testing.T) {
	if got := quoteIdentifier("mysql"); got != "`mysql`" {
		t.Errorf("quoteIdentifier = %s", got)
	}
	if got := quoteIdentifier("a`b"); got != "`a``b`" {
		t.Errorf("quoteIdentifier did not escape a backtick: %s", got)
	}
}

func TestIsUnknownSystemVariable(t *testing.T) {
	err := fmt.Errorf("read: %w", &mysqldriver.MySQLError{Number: 1193, Message: "Unknown system variable 'audit_log_database'"})
	if !isUnknownSystemVariable(err) {
		t.Error("1193 must be an unknown system variable")
	}
	if isUnknownSystemVariable(&mysqldriver.MySQLError{Number: 1146}) {
		t.Error("a missing table is not an unknown variable")
	}
	if isUnknownSystemVariable(errors.New("connection refused")) {
		t.Error("a transport error is not an unknown variable")
	}
}

// Values from performance_schema.keyring_component_status on MySQL 8.4 with
// component_keyring_file loaded but Disabled because its data file is
// unreadable.
func TestKeyringStatusNotApplicable(t *testing.T) {
	if got := keyringStatusString("<NOT APPLICABLE>"); got.Value != nil {
		t.Errorf("Data_file <NOT APPLICABLE> = %v, want null", got.Value)
	}
	if got := keyringStatusBool("<NOT APPLICABLE>"); got.Value != nil {
		t.Errorf("Read_only <NOT APPLICABLE> = %v, want null", got.Value)
	}
	if got := keyringStatusString(""); got.Value != nil {
		t.Errorf("absent Data_file = %v, want null", got.Value)
	}
	if got := keyringStatusString("/var/lib/mysql-keyring/component_keyring_file"); got.Value != "/var/lib/mysql-keyring/component_keyring_file" {
		t.Errorf("Data_file = %v", got.Value)
	}
	if got := keyringStatusBool("No"); got.Value != false {
		t.Errorf("Read_only No = %v, want false", got.Value)
	}
	if got := keyringStatusBool("Yes"); got.Value != true {
		t.Errorf("Read_only Yes = %v, want true", got.Value)
	}
}
