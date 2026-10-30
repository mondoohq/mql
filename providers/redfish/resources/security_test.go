// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// idracNetworkProtocol is a recorded ManagerNetworkProtocol document of a Dell
// iDRAC 9. It reports every protocol, with IPMI over LAN and SNMP enabled.
const idracNetworkProtocol = `{
  "@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol",
  "@odata.type": "#ManagerNetworkProtocol.v1_5_0.ManagerNetworkProtocol",
  "FQDN": "bmc-01.example.com",
  "HostName": "bmc-01",
  "HTTP": {"Port": 80, "ProtocolEnabled": false},
  "HTTPS": {
    "Certificates": {"@odata.id": "/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/Certificates"},
    "Port": 443,
    "ProtocolEnabled": true
  },
  "IPMI": {"Port": 623, "ProtocolEnabled": true},
  "KVMIP": {"Port": 5900, "ProtocolEnabled": true},
  "SNMP": {"Port": 161, "ProtocolEnabled": true},
  "SSH": {"Port": 22, "ProtocolEnabled": true},
  "Telnet": {"Port": 23, "ProtocolEnabled": false},
  "VirtualMedia": {"Port": 17990, "ProtocolEnabled": true}
}`

// iloNetworkProtocol is a recorded ManagerNetworkProtocol document of an HPE
// iLO 5. It leaves out telnet and IPMI, which the controller does not report.
const iloNetworkProtocol = `{
  "@odata.id": "/redfish/v1/Managers/1/NetworkProtocol",
  "@odata.type": "#ManagerNetworkProtocol.v1_5_0.ManagerNetworkProtocol",
  "FQDN": "bmc-02.example.com",
  "HostName": "bmc-02",
  "HTTP": {"ProtocolEnabled": false},
  "HTTPS": {"Port": 443, "ProtocolEnabled": true},
  "KVMIP": {"Port": 17990, "ProtocolEnabled": true},
  "SNMP": {"Port": 161, "ProtocolEnabled": false},
  "SSH": {"Port": 22, "ProtocolEnabled": true},
  "VirtualMedia": {"Port": 17988, "ProtocolEnabled": true}
}`

func TestParseNetworkProtocolReportedProtocols(t *testing.T) {
	np, err := parseNetworkProtocol([]byte(idracNetworkProtocol))
	if err != nil {
		t.Fatalf("parseNetworkProtocol() error = %v", err)
	}

	if np.HostName != "bmc-01" || np.FQDN != "bmc-01.example.com" {
		t.Errorf("got identity (%q, %q)", np.HostName, np.FQDN)
	}
	if np.ODataID != "/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol" {
		t.Errorf("got odata id %q", np.ODataID)
	}

	tests := []struct {
		name    string
		setting *protocolSettingJSON
		enabled bool
		port    int64
	}{
		{"http", np.HTTP, false, 80},
		{"https", np.HTTPS, true, 443},
		{"ssh", np.SSH, true, 22},
		{"telnet", np.Telnet, false, 23},
		{"ipmi", np.IPMI, true, 623},
		{"snmp", np.SNMP, true, 161},
		{"kvmip", np.KVMIP, true, 5900},
		{"virtualMedia", np.VirtualMedia, true, 17990},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enabled := protocolEnabled(tt.setting)
			if enabled == nil {
				t.Fatal("enabled is null, want a reported value")
			}
			if *enabled != tt.enabled {
				t.Errorf("enabled = %v, want %v", *enabled, tt.enabled)
			}
			port := protocolPort(tt.setting)
			if port == nil {
				t.Fatal("port is null, want a reported value")
			}
			if *port != tt.port {
				t.Errorf("port = %d, want %d", *port, tt.port)
			}
		})
	}

	if np.HTTPS.Certificates == nil || np.HTTPS.Certificates.ODataID == "" {
		t.Error("HTTPS carries no certificate collection link")
	}
}

func TestParseNetworkProtocolUnreportedProtocolsAreNull(t *testing.T) {
	np, err := parseNetworkProtocol([]byte(iloNetworkProtocol))
	if err != nil {
		t.Fatalf("parseNetworkProtocol() error = %v", err)
	}

	// The controller does not describe telnet or IPMI, so neither may read as
	// disabled. A silent false would hide an IPMI over LAN interface.
	if got := protocolEnabled(np.Telnet); got != nil {
		t.Errorf("telnet enabled = %v, want null", *got)
	}
	if got := protocolEnabled(np.IPMI); got != nil {
		t.Errorf("ipmi enabled = %v, want null", *got)
	}
	if got := protocolPort(np.IPMI); got != nil {
		t.Errorf("ipmi port = %d, want null", *got)
	}

	// HTTP is reported without a port, so the state is known and the port is not.
	enabled := protocolEnabled(np.HTTP)
	if enabled == nil || *enabled {
		t.Errorf("http enabled = %v, want false", enabled)
	}
	if got := protocolPort(np.HTTP); got != nil {
		t.Errorf("http port = %d, want null", *got)
	}

	if np.HTTPS.Certificates != nil {
		t.Error("HTTPS reports a certificate collection that the document does not contain")
	}
}

func TestParseNetworkProtocolMalformed(t *testing.T) {
	if _, err := parseNetworkProtocol([]byte(`{not json`)); err == nil {
		t.Error("parseNetworkProtocol() accepted malformed input")
	}
}

func TestParseManagerNetworkProtocolLink(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "manager with link",
			raw:  `{"Id":"1","NetworkProtocol":{"@odata.id":"/redfish/v1/Managers/1/NetworkProtocol"}}`,
			want: "/redfish/v1/Managers/1/NetworkProtocol",
		},
		{name: "manager without link", raw: `{"Id":"1"}`},
		{name: "empty link", raw: `{"NetworkProtocol":{"@odata.id":""}}`},
		{name: "empty document", raw: ``},
		{name: "malformed json", raw: `{`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseManagerNetworkProtocolLink([]byte(tt.raw)); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseCollectionMembers(t *testing.T) {
	raw := `{
      "@odata.id": "/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates",
      "Members": [
        {"@odata.id": "/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1"},
        {"@odata.id": ""},
        {"@odata.id": "/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/2"}
      ],
      "Members@odata.count": 3
    }`

	members, err := parseCollectionMembers([]byte(raw))
	if err != nil {
		t.Fatalf("parseCollectionMembers() error = %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("got %d members, want 2", len(members))
	}
	if members[0] != "/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1" {
		t.Errorf("got first member %q", members[0])
	}

	if _, err := parseCollectionMembers([]byte(`[`)); err == nil {
		t.Error("parseCollectionMembers() accepted malformed input")
	}
}

// selfSignedPEM returns a self-signed certificate in PEM form.
func selfSignedPEM(t *testing.T, key any, pub any) string {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4096),
		Subject: pkix.Name{
			CommonName:   "bmc-01.example.com",
			Organization: []string{"Example"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatalf("could not create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestParseCertificate(t *testing.T) {
	raw := `{
      "@odata.id": "/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1",
      "@odata.type": "#Certificate.v1_6_0.Certificate",
      "CertificateString": "",
      "CertificateType": "PEM",
      "CertificateUsageTypes": ["Web"],
      "Fingerprint": "3A:7B:11",
      "FingerprintHashAlgorithm": "SHA256",
      "Issuer": {"CommonName": "Example Issuing CA", "Organization": "Example"},
      "SerialNumber": "1000",
      "SignatureAlgorithm": "1.2.840.113549.1.1.11",
      "Subject": {"CommonName": "bmc-01.example.com", "Organization": "Example"},
      "ValidNotAfter": "2027-01-01T00:00:00Z",
      "ValidNotBefore": "2026-01-01T00:00:00Z"
    }`

	cert, err := parseCertificate([]byte(raw))
	if err != nil {
		t.Fatalf("parseCertificate() error = %v", err)
	}
	if cert.Subject.CommonName != "bmc-01.example.com" {
		t.Errorf("got subject %q", cert.Subject.CommonName)
	}
	if cert.Issuer.CommonName != "Example Issuing CA" {
		t.Errorf("got issuer %q", cert.Issuer.CommonName)
	}
	if cert.ValidNotAfter != "2027-01-01T00:00:00Z" {
		t.Errorf("got expiry %q", cert.ValidNotAfter)
	}
	if len(cert.CertificateUsageTypes) != 1 || cert.CertificateUsageTypes[0] != "Web" {
		t.Errorf("got usage types %v", cert.CertificateUsageTypes)
	}

	if _, err := parseCertificate([]byte(`{`)); err == nil {
		t.Error("parseCertificate() accepted malformed input")
	}
}

func TestCertificateKeyInfo(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate an RSA key: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("could not generate an ECDSA key: %v", err)
	}
	pqKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("could not generate an ML-DSA key: %v", err)
	}

	tests := []struct {
		name     string
		pemBody  string
		wantBits int64
		wantAlgo string
	}{
		{
			// Synthetic: crypto/x509 parses ML-DSA certificates from Go 1.27;
			// no BMC showed one. Bits is the encoded public key size.
			name:     "ML-DSA-87",
			pemBody:  selfSignedPEM(t, pqKey, pqKey.Public()),
			wantBits: 20736,
			wantAlgo: "ML-DSA",
		},
		{
			name:     "RSA 2048",
			pemBody:  selfSignedPEM(t, rsaKey, &rsaKey.PublicKey),
			wantBits: 2048,
			wantAlgo: "RSA",
		},
		{
			name:     "ECDSA P-256",
			pemBody:  selfSignedPEM(t, ecKey, &ecKey.PublicKey),
			wantBits: 256,
			wantAlgo: "ECDSA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bits, algo := certificateKeyInfo(parsePEMCertificate(tt.pemBody))
			if bits == nil {
				t.Fatal("key size is null, want a value")
			}
			if *bits != tt.wantBits || algo != tt.wantAlgo {
				t.Errorf("got (%d, %q), want (%d, %q)", *bits, algo, tt.wantBits, tt.wantAlgo)
			}
		})
	}
}

func TestParsePEMCertificateRejectsUnusableBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "empty string"},
		{name: "not PEM", body: "MIIB..."},
		{name: "wrong PEM type", body: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"},
		{name: "PEM with broken body", body: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parsePEMCertificate(tt.body); got != nil {
				t.Error("parsePEMCertificate() returned a certificate, want nil")
			}
			bits, algo := certificateKeyInfo(nil)
			if bits != nil || algo != "" {
				t.Errorf("certificateKeyInfo(nil) = (%v, %q), want (null, \"\")", bits, algo)
			}
		})
	}
}

func TestCertificateSelfSigned(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("could not generate an RSA key: %v", err)
	}
	parsed := parsePEMCertificate(selfSignedPEM(t, rsaKey, &rsaKey.PublicKey))
	if parsed == nil {
		t.Fatal("could not parse the generated certificate")
	}

	t.Run("encoded certificate wins", func(t *testing.T) {
		// Redfish reports a different issuer, the encoded certificate decides.
		cert := &certificateJSON{
			Issuer:  certIdentifierJSON{CommonName: "Example Issuing CA"},
			Subject: certIdentifierJSON{CommonName: "bmc-01.example.com"},
		}
		got := certificateSelfSigned(cert, parsed)
		if got == nil || !*got {
			t.Errorf("got %v, want true", got)
		}
	})

	t.Run("falls back to reported identity", func(t *testing.T) {
		cert := &certificateJSON{
			Issuer:  certIdentifierJSON{CommonName: "Example Issuing CA", Organization: "Example"},
			Subject: certIdentifierJSON{CommonName: "bmc-01.example.com", Organization: "Example"},
		}
		got := certificateSelfSigned(cert, nil)
		if got == nil || *got {
			t.Errorf("got %v, want false", got)
		}
	})

	t.Run("same reported identity is self signed", func(t *testing.T) {
		cert := &certificateJSON{
			Issuer:  certIdentifierJSON{CommonName: "bmc-01", Organization: "Example"},
			Subject: certIdentifierJSON{CommonName: "bmc-01", Organization: "Example"},
		}
		got := certificateSelfSigned(cert, nil)
		if got == nil || !*got {
			t.Errorf("got %v, want true", got)
		}
	})

	t.Run("null without identity", func(t *testing.T) {
		if got := certificateSelfSigned(&certificateJSON{}, nil); got != nil {
			t.Errorf("got %v, want null", *got)
		}
		if got := certificateSelfSigned(nil, nil); got != nil {
			t.Errorf("got %v, want null", *got)
		}
	})
}

func TestParseRedfishTime(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{name: "RFC 3339 in UTC", value: "2027-03-01T12:30:00Z", want: "2027-03-01T12:30:00Z"},
		{name: "RFC 3339 with offset", value: "2027-03-01T13:30:00+01:00", want: "2027-03-01T12:30:00Z"},
		{name: "without a time zone", value: "2027-03-01T12:30:00", want: "2027-03-01T12:30:00Z"},
		{name: "date only", value: "2027-03-01", want: "2027-03-01T00:00:00Z"},
		{name: "surrounding space", value: " 2027-03-01T12:30:00Z ", want: "2027-03-01T12:30:00Z"},
		{name: "empty"},
		{name: "not a timestamp", value: "N/A"},
		{name: "US format", value: "03/01/2027"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRedfishTime(tt.value)
			if tt.want == "" {
				if got != nil {
					t.Errorf("got %v, want null", got)
				}
				return
			}
			if got == nil {
				t.Fatal("got null, want a timestamp")
			}
			if formatted := got.UTC().Format(time.RFC3339); formatted != tt.want {
				t.Errorf("got %q, want %q", formatted, tt.want)
			}
		})
	}
}

func TestIsDefaultVendorAccountName(t *testing.T) {
	tests := []struct {
		userName string
		want     bool
	}{
		{userName: "root", want: true},
		{userName: "Administrator", want: true},
		{userName: "ADMIN", want: true},
		{userName: "USERID", want: true},
		{userName: "sysadmin", want: true},
		{userName: "anonymous", want: true},
		{userName: " root ", want: true},
		{userName: "rootca"},
		{userName: "svc-mondoo"},
		{userName: "administrators"},
		{userName: ""},
	}

	for _, tt := range tests {
		t.Run(tt.userName, func(t *testing.T) {
			if got := isDefaultVendorAccountName(tt.userName); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPersistentBootOverride(t *testing.T) {
	tests := []struct {
		name    string
		enabled string
		target  string
		want    bool
	}{
		{name: "continuous pxe", enabled: "Continuous", target: "Pxe", want: true},
		{name: "continuous usb", enabled: "Continuous", target: "Usb", want: true},
		{name: "continuous lower case", enabled: "continuous", target: "Hdd", want: true},
		{name: "continuous without target", enabled: "Continuous", target: "None"},
		{name: "continuous with empty target", enabled: "Continuous"},
		{name: "once pxe", enabled: "Once", target: "Pxe"},
		{name: "disabled", enabled: "Disabled", target: "Pxe"},
		{name: "unreported"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPersistentBootOverride(tt.enabled, tt.target); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// idracAccountService is a recorded AccountService document of a Dell iDRAC 9.
// It reports a full lockout policy, an LDAP provider, and an Active Directory
// provider that is configured but switched off. PasswordExpirationDays is
// explicitly null, which is how a controller says a password never expires.
const idracAccountService = `{
  "@odata.id": "/redfish/v1/AccountService",
  "@odata.type": "#AccountService.v1_12_0.AccountService",
  "AccountLockoutCounterResetAfter": 60,
  "AccountLockoutCounterResetEnabled": true,
  "AccountLockoutDuration": 60,
  "AccountLockoutThreshold": 3,
  "AuthFailureLoggingThreshold": 3,
  "EnforcePasswordHistoryCount": 5,
  "HTTPBasicAuth": "Enabled",
  "LocalAccountAuth": "Enabled",
  "MaxPasswordLength": 40,
  "MinPasswordLength": 8,
  "PasswordExpirationDays": null,
  "RequireChangePasswordAction": false,
  "ServiceEnabled": true,
  "ActiveDirectory": {
    "ServiceEnabled": false,
    "ServiceAddresses": [],
    "Authentication": {"AuthenticationType": "UsernameAndPassword", "Password": null}
  },
  "LDAP": {
    "ServiceEnabled": true,
    "ServiceAddresses": ["ldaps://dc1.example.com"],
    "Authentication": {"AuthenticationType": "UsernameAndPassword", "Password": null}
  }
}`

// iloAccountService is a recorded AccountService document of an HPE iLO 5. It
// omits most of the policy and reports a lockout threshold of zero, which is
// the controller stating that it never locks an account out.
const iloAccountService = `{
  "@odata.id": "/redfish/v1/AccountService",
  "@odata.type": "#AccountService.v1_3_0.AccountService",
  "AccountLockoutDuration": 0,
  "AccountLockoutThreshold": 0,
  "MinPasswordLength": 8,
  "ServiceEnabled": true
}`

func TestParseAccountServiceReportedPolicy(t *testing.T) {
	svc, err := parseAccountService([]byte(idracAccountService))
	if err != nil {
		t.Fatalf("parseAccountService() error = %v", err)
	}

	intFields := map[string]struct {
		got  *int64
		want int64
	}{
		"MinPasswordLength":               {svc.MinPasswordLength, 8},
		"MaxPasswordLength":               {svc.MaxPasswordLength, 40},
		"AccountLockoutThreshold":         {svc.AccountLockoutThreshold, 3},
		"AccountLockoutDuration":          {svc.AccountLockoutDuration, 60},
		"AccountLockoutCounterResetAfter": {svc.AccountLockoutCounterResetAfter, 60},
		"AuthFailureLoggingThreshold":     {svc.AuthFailureLoggingThreshold, 3},
		"EnforcePasswordHistoryCount":     {svc.EnforcePasswordHistoryCount, 5},
	}
	for name, tc := range intFields {
		if tc.got == nil {
			t.Errorf("%s = null, want %d", name, tc.want)
			continue
		}
		if *tc.got != tc.want {
			t.Errorf("%s = %d, want %d", name, *tc.got, tc.want)
		}
	}

	if svc.HTTPBasicAuth != "Enabled" {
		t.Errorf("HTTPBasicAuth = %q, want %q", svc.HTTPBasicAuth, "Enabled")
	}
	if svc.LocalAccountAuth != "Enabled" {
		t.Errorf("LocalAccountAuth = %q, want %q", svc.LocalAccountAuth, "Enabled")
	}
	if svc.ServiceEnabled == nil || !*svc.ServiceEnabled {
		t.Errorf("ServiceEnabled = %v, want true", svc.ServiceEnabled)
	}
	if svc.AccountLockoutCounterResetEnabled == nil || !*svc.AccountLockoutCounterResetEnabled {
		t.Errorf("AccountLockoutCounterResetEnabled = %v, want true", svc.AccountLockoutCounterResetEnabled)
	}
	// An explicit JSON null means the password never expires, and that is not
	// the same statement as a controller reporting zero days.
	if svc.PasswordExpirationDays != nil {
		t.Errorf("PasswordExpirationDays = %d, want null", *svc.PasswordExpirationDays)
	}
}

func TestParseAccountServiceZeroIsNotNull(t *testing.T) {
	svc, err := parseAccountService([]byte(iloAccountService))
	if err != nil {
		t.Fatalf("parseAccountService() error = %v", err)
	}

	// A reported threshold of zero is a finding: the controller never locks an
	// account out. Reading it as null would hide that.
	if svc.AccountLockoutThreshold == nil {
		t.Fatal("AccountLockoutThreshold = null, want 0")
	}
	if *svc.AccountLockoutThreshold != 0 {
		t.Errorf("AccountLockoutThreshold = %d, want 0", *svc.AccountLockoutThreshold)
	}
	if svc.AccountLockoutDuration == nil || *svc.AccountLockoutDuration != 0 {
		t.Errorf("AccountLockoutDuration = %v, want 0", svc.AccountLockoutDuration)
	}

	// The controller says nothing about these, so none may read as zero or as
	// an empty policy value.
	nullFields := map[string]*int64{
		"MaxPasswordLength":               svc.MaxPasswordLength,
		"AccountLockoutCounterResetAfter": svc.AccountLockoutCounterResetAfter,
		"AuthFailureLoggingThreshold":     svc.AuthFailureLoggingThreshold,
		"EnforcePasswordHistoryCount":     svc.EnforcePasswordHistoryCount,
		"PasswordExpirationDays":          svc.PasswordExpirationDays,
	}
	for name, got := range nullFields {
		if got != nil {
			t.Errorf("%s = %d, want null", name, *got)
		}
	}
	if svc.RequireChangePasswordAction != nil {
		t.Errorf("RequireChangePasswordAction = %v, want null", *svc.RequireChangePasswordAction)
	}
	if svc.HTTPBasicAuth != "" {
		t.Errorf("HTTPBasicAuth = %q, want empty", svc.HTTPBasicAuth)
	}
}

func TestParseAccountServiceExternalProviders(t *testing.T) {
	svc, err := parseAccountService([]byte(idracAccountService))
	if err != nil {
		t.Fatalf("parseAccountService() error = %v", err)
	}

	if svc.LDAP == nil {
		t.Fatal("LDAP = null, want a provider")
	}
	if svc.LDAP.ServiceEnabled == nil || !*svc.LDAP.ServiceEnabled {
		t.Errorf("LDAP.ServiceEnabled = %v, want true", svc.LDAP.ServiceEnabled)
	}
	if len(svc.LDAP.ServiceAddresses) != 1 || svc.LDAP.ServiceAddresses[0] != "ldaps://dc1.example.com" {
		t.Errorf("LDAP.ServiceAddresses = %v, want one ldaps address", svc.LDAP.ServiceAddresses)
	}
	if svc.LDAP.Authentication == nil || svc.LDAP.Authentication.AuthenticationType != "UsernameAndPassword" {
		t.Errorf("LDAP.Authentication = %v, want UsernameAndPassword", svc.LDAP.Authentication)
	}

	// Configured but switched off is not the same as absent, and both differ
	// from a provider the controller never mentions.
	if svc.ActiveDirectory == nil {
		t.Fatal("ActiveDirectory = null, want a disabled provider")
	}
	if svc.ActiveDirectory.ServiceEnabled == nil || *svc.ActiveDirectory.ServiceEnabled {
		t.Errorf("ActiveDirectory.ServiceEnabled = %v, want false", svc.ActiveDirectory.ServiceEnabled)
	}
	if svc.TACACSplus != nil {
		t.Error("TACACSplus is set on a document that does not mention it")
	}
}

// tacacsAccountService is an AccountService document of a controller that
// federates authentication to TACACS+, which the iDRAC and iLO documents above
// do not mention at all.
const tacacsAccountService = `{
  "@odata.id": "/redfish/v1/AccountService",
  "ServiceEnabled": true,
  "LocalAccountAuth": "Fallback",
  "TACACSplus": {
    "ServiceEnabled": true,
    "ServiceAddresses": ["tacacs1.example.com:49", "tacacs2.example.com:49"],
    "Authentication": {"AuthenticationType": "Token", "Token": null},
    "TACACSplusService": {"PasswordExchangeProtocols": ["PAP"]}
  }
}`

func TestParseAccountServiceTACACSplus(t *testing.T) {
	svc, err := parseAccountService([]byte(tacacsAccountService))
	if err != nil {
		t.Fatalf("parseAccountService() error = %v", err)
	}

	if svc.TACACSplus == nil {
		t.Fatal("TACACSplus = null, want a provider")
	}
	if svc.TACACSplus.ServiceEnabled == nil || !*svc.TACACSplus.ServiceEnabled {
		t.Errorf("TACACSplus.ServiceEnabled = %v, want true", svc.TACACSplus.ServiceEnabled)
	}
	if len(svc.TACACSplus.ServiceAddresses) != 2 {
		t.Errorf("TACACSplus.ServiceAddresses = %v, want two servers", svc.TACACSplus.ServiceAddresses)
	}
	// The authentication method is read for TACACS+ the same way it is for LDAP
	// and Active Directory.
	if svc.TACACSplus.Authentication == nil || svc.TACACSplus.Authentication.AuthenticationType != "Token" {
		t.Errorf("TACACSplus.Authentication = %v, want Token", svc.TACACSplus.Authentication)
	}

	// Local accounts stay usable when the directory is unreachable, which is a
	// different posture from Enabled and from Disabled.
	if svc.LocalAccountAuth != "Fallback" {
		t.Errorf("LocalAccountAuth = %q, want Fallback", svc.LocalAccountAuth)
	}
}

func TestParseAccountServiceMalformed(t *testing.T) {
	if _, err := parseAccountService([]byte(`{not json`)); err == nil {
		t.Error("parseAccountService() accepted malformed input")
	}
}

// iloManagerConsoles is a recorded Manager document of an HPE iLO 5. It reports
// a command shell and a graphical console but no serial console.
const iloManagerConsoles = `{
  "@odata.id": "/redfish/v1/Managers/1",
  "@odata.type": "#Manager.v1_5_1.Manager",
  "CommandShell": {
    "ConnectTypesSupported": ["SSH", "Oem"],
    "MaxConcurrentSessions": 9,
    "ServiceEnabled": true
  },
  "GraphicalConsole": {
    "ConnectTypesSupported": ["KVMIP"],
    "MaxConcurrentSessions": 10,
    "ServiceEnabled": false
  }
}`

func TestParseManagerConsoles(t *testing.T) {
	consoles := parseManagerConsoles([]byte(iloManagerConsoles))

	enabled := consoleEnabled(consoles.CommandShell)
	if enabled == nil || !*enabled {
		t.Errorf("command shell enabled = %v, want true", enabled)
	}
	if got := consoleMaxSessions(consoles.CommandShell); got == nil || *got != 9 {
		t.Errorf("command shell max sessions = %v, want 9", got)
	}

	// A console the controller reports as disabled must read false, not null.
	enabled = consoleEnabled(consoles.GraphicalConsole)
	if enabled == nil || *enabled {
		t.Errorf("graphical console enabled = %v, want false", enabled)
	}

	// The document describes no serial console, so it may not read as one that
	// is switched off and accepts no session.
	if got := consoleEnabled(consoles.SerialConsole); got != nil {
		t.Errorf("serial console enabled = %v, want null", *got)
	}
	if got := consoleMaxSessions(consoles.SerialConsole); got != nil {
		t.Errorf("serial console max sessions = %d, want null", *got)
	}
}

func TestParseManagerConsolesMalformed(t *testing.T) {
	// A document that does not decode leaves every console null rather than
	// reporting all three as switched off.
	consoles := parseManagerConsoles([]byte(`{not json`))
	if consoles.CommandShell != nil || consoles.GraphicalConsole != nil || consoles.SerialConsole != nil {
		t.Errorf("parseManagerConsoles(malformed) = %+v, want every console null", consoles)
	}
	if consoles := parseManagerConsoles(nil); consoles.CommandShell != nil {
		t.Error("parseManagerConsoles(nil) reported a command shell")
	}
}

// idracAccount is a recorded ManagerAccount document of a Dell iDRAC 9. It
// reports PasswordChangeRequired and an account expiry, and says nothing about
// StrictAccountTypes or a password expiry.
const idracAccount = `{
  "@odata.id": "/redfish/v1/AccountService/Accounts/2",
  "@odata.type": "#ManagerAccount.v1_6_0.ManagerAccount",
  "UserName": "root",
  "RoleId": "Administrator",
  "Enabled": true,
  "Locked": false,
  "PasswordChangeRequired": false,
  "AccountExpiration": "2027-01-01T00:00:00+00:00"
}`

func TestParseAccountFlags(t *testing.T) {
	flags := parseAccountFlags([]byte(idracAccount))

	// Reported as false: the account has no pending password change.
	if flags.PasswordChangeRequired == nil || *flags.PasswordChangeRequired {
		t.Errorf("PasswordChangeRequired = %v, want false", flags.PasswordChangeRequired)
	}
	// Never mentioned: reading this as false would state that the account is
	// not restricted to its declared categories, which the controller did not say.
	if flags.StrictAccountTypes != nil {
		t.Errorf("StrictAccountTypes = %v, want null", *flags.StrictAccountTypes)
	}
	if flags.AccountExpiration != "2027-01-01T00:00:00+00:00" {
		t.Errorf("AccountExpiration = %q, want the reported timestamp", flags.AccountExpiration)
	}
	if parseRedfishTime(flags.AccountExpiration) == nil {
		t.Error("AccountExpiration does not parse as a Redfish timestamp")
	}
	if flags.PasswordExpiration != "" {
		t.Errorf("PasswordExpiration = %q, want empty", flags.PasswordExpiration)
	}
	if parseRedfishTime(flags.PasswordExpiration) != nil {
		t.Error("an unreported password expiry parsed to a time")
	}
}

func TestParseAccountFlagsMalformed(t *testing.T) {
	flags := parseAccountFlags([]byte(`{not json`))
	if flags.PasswordChangeRequired != nil || flags.StrictAccountTypes != nil {
		t.Errorf("parseAccountFlags(malformed) = %+v, want every flag null", flags)
	}
}
