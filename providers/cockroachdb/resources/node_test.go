// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"
)

func TestCertificateExpirations(t *testing.T) {
	got := certificateExpirations(map[string]float64{
		"security.certificate.expiration.ca":     2.108648777e+09,
		"security.certificate.expiration.node":   1.950536777e+09,
		"security.certificate.expiration.ui":     0,
		"security.certificate.expiration.client": 3.901074284e+09,
		"security.certificate.ttl.ca":            3.16223985e+08,
		"sql.conns":                              3,
	})
	want := map[string]time.Time{
		"ca":   time.Unix(2108648777, 0).UTC(),
		"node": time.Unix(1950536777, 0).UTC(),
	}
	if len(got) != len(want) {
		t.Fatalf("certificateExpirations = %v, want %v", got, want)
	}
	for typ, w := range want {
		if !got[typ].Equal(w) {
			t.Errorf("%s expires %v, want %v", typ, got[typ], w)
		}
	}
}
