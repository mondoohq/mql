// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// Values from SHOW ALL REPLICAS STATUS on MariaDB 10.11 with a connection that
// presents a client certificate.
func TestMariadbChannelTLSMaterial(t *testing.T) {
	ch := mariadbChannelFromStatus(map[string]string{
		"Connection_name":               "secure",
		"Master_Host":                   "primary.example.com",
		"Master_SSL_Allowed":            "Yes",
		"Master_SSL_Verify_Server_Cert": "Yes",
		"Master_SSL_CA_File":            "/etc/mysql/ssl/ca.pem",
		"Master_SSL_Cert":               "/etc/mysql/ssl/client-cert.pem",
		"Master_SSL_Key":                "/etc/mysql/ssl/client-key.pem",
		"Master_SSL_Cipher":             "ECDHE-RSA-AES256-GCM-SHA384",
	})
	want := replicationChannelRow{
		channel:             "secure",
		host:                "primary.example.com",
		sslAllowed:          true,
		sslVerifyServerCert: true,
		sslCipher:           "ECDHE-RSA-AES256-GCM-SHA384",
		sslCert:             "/etc/mysql/ssl/client-cert.pem",
		sslKey:              "/etc/mysql/ssl/client-key.pem",
		sslCaFile:           "/etc/mysql/ssl/ca.pem",
	}
	if ch != want {
		t.Errorf("channel = %+v, want %+v", ch, want)
	}
}
