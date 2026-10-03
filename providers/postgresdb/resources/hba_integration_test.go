// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"
)

// TestIntegrationHbaRulesMatchServer compares hbaRules with pg_hba_file_rules
// row by row, in the server's evaluation order. Point it at a PostgreSQL 16+
// server whose pg_hba.conf includes a second file with a rule on the same line
// number as a rule in pg_hba.conf, and which also carries one invalid line
// (for example an unknown auth method). Enable with PG_TEST_HBA_INCLUDE=1.
func TestIntegrationHbaRulesMatchServer(t *testing.T) {
	if os.Getenv("PG_TEST_HBA_INCLUDE") == "" {
		t.Skip("set PG_TEST_HBA_INCLUDE=1 against a server with an included hba file and an invalid line")
	}
	runtime := newIntegrationRuntime(t)
	inst := mustInstance(t, runtime)

	pool, err := pgPool(runtime, "")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(pgContext(),
		`SELECT line_number, COALESCE(auth_method, ''), COALESCE(error, '')
		 FROM pg_hba_file_rules ORDER BY rule_number NULLS LAST, file_name, line_number`)
	if err != nil {
		t.Fatal(err)
	}
	type rule struct {
		line         int64
		method, errm string
	}
	var want []rule
	for rows.Next() {
		var r rule
		if err := rows.Scan(&r.line, &r.method, &r.errm); err != nil {
			t.Fatal(err)
		}
		want = append(want, r)
	}
	rows.Close()

	got := inst.GetHbaRules()
	if got.Error != nil {
		t.Fatalf("hbaRules errored: %v", got.Error)
	}
	if len(got.Data) != len(want) {
		t.Fatalf("hbaRules has %d rules, server has %d", len(got.Data), len(want))
	}
	sawError := false
	for i, x := range got.Data {
		r := x.(*mqlPostgresdbHbaRule)
		g := rule{r.GetLineNumber().Data, r.GetAuthMethod().Data, r.GetError().Data}
		if g != want[i] {
			t.Errorf("rule %d = %+v, server has %+v", i, g, want[i])
		}
		if g.errm != "" {
			sawError = true
		}
	}
	if !sawError {
		t.Error("fixture needs an invalid pg_hba.conf line; none reported")
	}
}
