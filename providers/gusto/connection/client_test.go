// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "testing"

func TestNextPageURL(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"empty", "", ""},
		{"no next", `<https://api.gusto.com/v1/companies?page=1>; rel="first"`, ""},
		{
			"single next",
			`<https://api.gusto.com/v1/companies?page=2>; rel="next"`,
			"https://api.gusto.com/v1/companies?page=2",
		},
		{
			"multiple rels",
			`<https://api.gusto.com/v1/companies?page=1>; rel="first", <https://api.gusto.com/v1/companies?page=3>; rel="next", <https://api.gusto.com/v1/companies?page=10>; rel="last"`,
			"https://api.gusto.com/v1/companies?page=3",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nextPageURL(c.header); got != c.want {
				t.Fatalf("nextPageURL(%q) = %q, want %q", c.header, got, c.want)
			}
		})
	}
}
