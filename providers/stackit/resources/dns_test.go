// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"reflect"
	"testing"

	dns "github.com/stackitcloud/stackit-sdk-go/services/dns/v1api"
)

func TestDnsLabels(t *testing.T) {
	if got := dnsLabels(nil); got != nil {
		t.Fatalf("nil input: got %#v, want nil", got)
	}

	k1, v1 := "env", "prod"
	k2, v2 := "team", "sec"
	in := []dns.Label{{Key: k1, Value: &v1}, {Key: k2, Value: &v2}}
	got := dnsLabels(in)
	want := map[string]string{"env": "prod", "team": "sec"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
