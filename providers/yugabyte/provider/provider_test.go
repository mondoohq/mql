// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The first password credential is the YSQL one and the second the YCQL one;
// without flags there is none, so the environment and the default users apply.
func TestParseCLICredentials(t *testing.T) {
	cases := []struct {
		name  string
		flags map[string]string
		want  [][2]string // user, secret of each credential, in order
	}{
		{name: "no flags", flags: map[string]string{}, want: nil},
		{name: "YSQL only", flags: map[string]string{"user": "admin", "password": "a"}, want: [][2]string{{"admin", "a"}}},
		{name: "YCQL only keeps the YSQL place", flags: map[string]string{"ycql-user": "dba", "ycql-password": "b"},
			want: [][2]string{{"", ""}, {"dba", "b"}}},
		{name: "both", flags: map[string]string{"user": "admin", "password": "a", "ycql-user": "dba", "ycql-password": "b"},
			want: [][2]string{{"admin", "a"}, {"dba", "b"}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flags := map[string]*llx.Primitive{}
			for k, v := range c.flags {
				flags[k] = llx.StringPrimitive(v)
			}
			res, err := Init().ParseCLI(&plugin.ParseCLIReq{Connector: "yugabyte", Args: []string{"h"}, Flags: flags})
			if err != nil {
				t.Fatal(err)
			}
			got := res.Asset.Connections[0].Credentials
			if len(got) != len(c.want) {
				t.Fatalf("got %d credentials, want %d", len(got), len(c.want))
			}
			for i, w := range c.want {
				if got[i].User != w[0] || string(got[i].Secret) != w[1] {
					t.Errorf("credential %d: got user %q, want %q", i, got[i].User, w[0])
				}
			}
		})
	}
}
