// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"go.mondoo.com/mql/v13/mqlc"
)

func BenchmarkCompileWithLabels(b *testing.B) {
	queries := []string{
		"mondoo.version == 'yo'",
		"packages.list { name version }",
		"users.list { name uid gid home }",
		"file('/etc/passwd').permissions.user_readable",
		"packages.where(name == 'ssh').list { name }",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for _, q := range queries {
			if _, err := mqlc.Compile(q, nil, conf); err != nil {
				b.Fatal(err)
			}
		}
	}
}
