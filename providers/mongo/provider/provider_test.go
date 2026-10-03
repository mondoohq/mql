// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"strings"
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestParseCLIMovesURIPasswordToCredential(t *testing.T) {
	// A generated stand-in, spliced in so the source holds no literal credential.
	password := strings.Repeat("x", 12)
	res, err := Init().ParseCLI(&plugin.ParseCLIReq{
		Connector: "mongo",
		Flags: map[string]*llx.Primitive{
			"host": llx.StringPrimitive("mongodb://db3admin:" + password + "@127.0.0.1:28002/?authSource=admin&directConnection=true"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	conf := res.Asset.Connections[0]
	if strings.Contains(conf.Host, password) || strings.Contains(conf.Host, "db3admin") {
		t.Errorf("host still carries the user info: %q", conf.Host)
	}
	if conf.Host != "mongodb://127.0.0.1:28002/?authSource=admin&directConnection=true" {
		t.Errorf("unexpected host %q", conf.Host)
	}
	if len(conf.Credentials) != 1 || conf.Credentials[0].User != "db3admin" || string(conf.Credentials[0].Secret) != password {
		t.Errorf("credential not moved: %+v", conf.Credentials)
	}
}
