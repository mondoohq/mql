// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/tls"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
)

func TestDomainToDN(t *testing.T) {
	tests := []struct {
		domain string
		want   string
	}{
		{"mini.lab", "DC=mini,DC=lab"},
		{"corp.example.com", "DC=corp,DC=example,DC=com"},
		{"single", "DC=single"},
		{"a.b.c.d.e", "DC=a,DC=b,DC=c,DC=d,DC=e"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			if got := domainToDN(tt.domain); got != tt.want {
				t.Errorf("domainToDN(%q) = %q, want %q", tt.domain, got, tt.want)
			}
		})
	}
}

func TestSplitPrincipal(t *testing.T) {
	tests := []struct {
		input     string
		wantUser  string
		wantRealm string
	}{
		{"alice@MINI.LAB", "alice", "MINI.LAB"},
		{"admin@CORP.EXAMPLE.COM", "admin", "CORP.EXAMPLE.COM"},
		{"alice", "alice", ""},
		{"", "", ""},
		{"user@realm@extra", "user@realm", "extra"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			user, realm := splitPrincipal(tt.input)
			if user != tt.wantUser || realm != tt.wantRealm {
				t.Errorf("splitPrincipal(%q) = (%q, %q), want (%q, %q)", tt.input, user, realm, tt.wantUser, tt.wantRealm)
			}
		})
	}
}

func TestExistingKrb5ConfPath(t *testing.T) {
	// Explicit --krb5conf always wins, returned as-is even if missing so the
	// later load surfaces a clear error.
	if got := existingKrb5ConfPath(map[string]string{OptionKrb5Conf: "/custom/krb5.conf"}); got != "/custom/krb5.conf" {
		t.Errorf("explicit: got %q, want /custom/krb5.conf", got)
	}

	// KRB5_CONFIG env is honored when no explicit flag is set.
	t.Setenv("KRB5_CONFIG", "/env/krb5.conf")
	if got := existingKrb5ConfPath(map[string]string{}); got != "/env/krb5.conf" {
		t.Errorf("env: got %q, want /env/krb5.conf", got)
	}

	// With neither flag nor env and no default file, the path is empty so the
	// caller falls back to generating a config.
	t.Setenv("KRB5_CONFIG", "")
	if _, err := os.Stat(defaultKrb5ConfPath); os.IsNotExist(err) {
		if got := existingKrb5ConfPath(map[string]string{}); got != "" {
			t.Errorf("no config: got %q, want empty", got)
		}
	}
}

func TestDomainFromHost(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"dc01.corp.local", "corp.local"},
		{"DC01.CORP.LOCAL", "CORP.LOCAL"},
		{"a.b.c.d", "b.c.d"},
		{"singlelabel", ""},
		{"", ""},
		{"10.0.0.1", ""},
		{"2001:db8::1", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			if got := domainFromHost(tt.host); got != tt.want {
				t.Errorf("domainFromHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

func TestGenerateKrb5Config(t *testing.T) {
	t.Run("single realm from DC host and user", func(t *testing.T) {
		text, desc, err := generateKrb5Config("dc01.corp.local", "", "admin@CORP.LOCAL")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// The generated text must parse as a valid krb5 config.
		cfg, err := config.NewFromString(text)
		if err != nil {
			t.Fatalf("generated config does not parse: %v\n---\n%s", err, text)
		}
		if cfg.LibDefaults.DefaultRealm != "CORP.LOCAL" {
			t.Errorf("default_realm = %q, want CORP.LOCAL", cfg.LibDefaults.DefaultRealm)
		}
		if !cfg.LibDefaults.DNSLookupKDC {
			t.Error("dns_lookup_kdc should be enabled for multi-forest KDC discovery")
		}
		// The DC realm's KDC must be pinned to the DC host.
		_, kdcs, err := cfg.GetKDCs("CORP.LOCAL", true)
		if err != nil {
			t.Fatalf("GetKDCs: %v", err)
		}
		if len(kdcs) == 0 || !strings.Contains(kdcs[1], "dc01.corp.local") {
			t.Errorf("KDCs for CORP.LOCAL = %v, want one containing dc01.corp.local", kdcs)
		}
		// The ldap/<dc> service principal must resolve to the DC realm.
		if r := cfg.ResolveRealm("dc01.corp.local"); r != "CORP.LOCAL" {
			t.Errorf("ResolveRealm(dc01.corp.local) = %q, want CORP.LOCAL", r)
		}
		if !strings.Contains(desc, "auto-generated") {
			t.Errorf("desc = %q, want it to mention auto-generated", desc)
		}
	})

	t.Run("cross-forest user in a different realm than the DC", func(t *testing.T) {
		// User lives in FORESTA, the scanned DC in CORP.LOCAL (FORESTB).
		text, _, err := generateKrb5Config("dc01.corp.local", "", "admin@FORESTA.EXAMPLE")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err := config.NewFromString(text)
		if err != nil {
			t.Fatalf("generated config does not parse: %v\n---\n%s", err, text)
		}
		// AS exchange targets the user's own realm.
		if cfg.LibDefaults.DefaultRealm != "FORESTA.EXAMPLE" {
			t.Errorf("default_realm = %q, want FORESTA.EXAMPLE", cfg.LibDefaults.DefaultRealm)
		}
		// The DC's realm is still pinned so cross-realm referral can reach it.
		if r := cfg.ResolveRealm("dc01.corp.local"); r != "CORP.LOCAL" {
			t.Errorf("ResolveRealm(dc01.corp.local) = %q, want CORP.LOCAL", r)
		}
		// The user realm's KDC is found via DNS SRV (dns_lookup_kdc), not pinned.
		if !cfg.LibDefaults.DNSLookupKDC {
			t.Error("dns_lookup_kdc must be enabled so the user realm's KDC is discoverable")
		}
	})

	t.Run("explicit domain overrides DC-host-derived realm", func(t *testing.T) {
		text, _, err := generateKrb5Config("dc01.ad.internal", "corp.local", "admin")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cfg, err := config.NewFromString(text)
		if err != nil {
			t.Fatalf("generated config does not parse: %v", err)
		}
		if cfg.LibDefaults.DefaultRealm != "CORP.LOCAL" {
			t.Errorf("default_realm = %q, want CORP.LOCAL (from --domain)", cfg.LibDefaults.DefaultRealm)
		}
	})

	t.Run("no derivable realm is an actionable error", func(t *testing.T) {
		_, _, err := generateKrb5Config("10.0.0.1", "", "admin")
		if err == nil {
			t.Fatal("expected an error when no realm can be derived")
		}
		if !strings.Contains(err.Error(), "--krb5conf") {
			t.Errorf("error %q should guide the user toward --krb5conf/--domain/--user@REALM", err)
		}
	})
}

func TestNewLDAPTLSConfig(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		insecure bool
	}{
		{name: "strict verification", server: "dc01.example.com", insecure: false},
		{name: "insecure verification", server: "dc01.example.com", insecure: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newLDAPTLSConfig(tt.server, tt.insecure)
			if cfg.MinVersion != tls.VersionTLS12 {
				t.Fatalf("MinVersion = %v, want %v", cfg.MinVersion, tls.VersionTLS12)
			}
			if cfg.ServerName != tt.server {
				t.Fatalf("ServerName = %q, want %q", cfg.ServerName, tt.server)
			}
			if cfg.InsecureSkipVerify != tt.insecure {
				t.Fatalf("InsecureSkipVerify = %v, want %v", cfg.InsecureSkipVerify, tt.insecure)
			}
		})
	}
}

func TestResolveLDAPTransport(t *testing.T) {
	tests := []struct {
		name          string
		opts          map[string]string
		wantTransport ldapTransport
		wantPort      int
		wantTLS       bool
		wantStartTLS  bool
		wantErr       string
	}{
		{
			name:          "default transport is ldaps",
			opts:          map[string]string{},
			wantTransport: ldapTransportLDAPS,
			wantPort:      636,
			wantTLS:       true,
		},
		{
			name:          "explicit ldaps stays ldaps",
			opts:          map[string]string{OptionLDAPS: "true"},
			wantTransport: ldapTransportLDAPS,
			wantPort:      636,
			wantTLS:       true,
		},
		{
			name:          "starttls uses ldap port with TLS upgrade",
			opts:          map[string]string{OptionStartTLS: "true"},
			wantTransport: ldapTransportStartTLS,
			wantPort:      389,
			wantTLS:       true,
			wantStartTLS:  true,
		},
		{
			name:          "plain ldap is explicit",
			opts:          map[string]string{OptionPlainLDAP: "true"},
			wantTransport: ldapTransportPlain,
			wantPort:      389,
		},
		{
			name:    "conflicting transport options error",
			opts:    map[string]string{OptionLDAPS: "true", OptionPlainLDAP: "true"},
			wantErr: "LDAP transport options are mutually exclusive: choose one of ldaps, plain-ldap, or starttls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, err := resolveLDAPTransport(tt.opts)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", tt.wantErr)
				}
				if got := err.Error(); got != tt.wantErr {
					t.Fatalf("error = %q, want %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if transport != tt.wantTransport {
				t.Fatalf("transport = %q, want %q", transport, tt.wantTransport)
			}
			if got := defaultPort(transport); got != tt.wantPort {
				t.Fatalf("defaultPort(%q) = %d, want %d", transport, got, tt.wantPort)
			}
			if got := transport.usesTLS(); got != tt.wantTLS {
				t.Fatalf("usesTLS(%q) = %v, want %v", transport, got, tt.wantTLS)
			}
			if got := transport.usesStartTLS(); got != tt.wantStartTLS {
				t.Fatalf("usesStartTLS(%q) = %v, want %v", transport, got, tt.wantStartTLS)
			}
		})
	}
}

func TestNewKerberosClientRejectsNetBIOSUser(t *testing.T) {
	// DOMAIN\user is valid for simple bind but not Kerberos; it must be
	// rejected with guidance rather than failing obscurely at the KDC.
	_, _, _, _, err := newKerberosClient(`CORP\admin`, "secret", "dc01.corp.local", map[string]string{}, nil)
	if err == nil {
		t.Fatal("expected an error for NetBIOS DOMAIN\\user with --kerberos")
	}
	if !strings.Contains(err.Error(), "user@REALM") {
		t.Errorf("error %q should point the user at the user@REALM form", err)
	}
}

func TestEnrichKerberosBindError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		krb5conf     string
		overTLS      bool
		wantContains string
	}{
		{
			name:         "ldap signing requirement over plaintext",
			err:          errors.New("LDAP Result Code 49 ... 80090308: LdapErr ... data 57"),
			krb5conf:     "/etc/krb5.conf",
			overTLS:      false,
			wantContains: "LDAP signing",
		},
		{
			name:         "channel binding rejected over TLS",
			err:          errors.New("LDAP Result Code 49 ... 80090346: LdapErr ... data 80090346"),
			krb5conf:     "/etc/krb5.conf",
			overTLS:      true,
			wantContains: "channel binding token",
		},
		{
			name:         "channel binding requires TLS over plaintext",
			err:          errors.New("LDAP Result Code 49 ... 80090346: LdapErr ... data 80090346"),
			krb5conf:     "/etc/krb5.conf",
			overTLS:      false,
			wantContains: "channel binding",
		},
		{
			name:         "auto-generated config cannot find KDC -> multi-forest hint",
			err:          errors.New("no KDC SRV records found for realm FORESTA.EXAMPLE"),
			krb5conf:     "auto-generated (default_realm=FORESTA.EXAMPLE, dc_realm=CORP.LOCAL, kdc=dc01.corp.local)",
			overTLS:      true,
			wantContains: "--krb5conf",
		},
		{
			name:         "generic failure is passed through with context",
			err:          errors.New("some other failure"),
			krb5conf:     "/etc/krb5.conf",
			overTLS:      true,
			wantContains: "GSSAPI bind to ldap/dc01.corp.local failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := enrichKerberosBindError(tt.err, "ldap/dc01.corp.local", tt.krb5conf, tt.overTLS)
			if got == nil || !strings.Contains(got.Error(), tt.wantContains) {
				t.Errorf("enrichKerberosBindError = %v, want it to contain %q", got, tt.wantContains)
			}
		})
	}
}

func TestSelectKerberosAuthSource(t *testing.T) {
	tests := []struct {
		name       string
		user       string
		password   string
		opts       map[string]string
		wantSource kerberosAuthSource
		wantErr    string
	}{
		{
			name:    "keytab requires user",
			opts:    map[string]string{OptionKeytab: "/tmp/test.keytab"},
			wantErr: "--user is required with --keytab to identify the principal",
		},
		{
			name:       "keytab with user",
			user:       "alice@CORP.EXAMPLE.COM",
			opts:       map[string]string{OptionKeytab: "/tmp/test.keytab"},
			wantSource: kerberosAuthSourceKeytab,
		},
		{
			name:       "ccache without user is fine",
			opts:       map[string]string{OptionCCache: "/tmp/krb5cc"},
			wantSource: kerberosAuthSourceCCache,
		},
		{
			name:     "password requires user",
			password: "secret",
			opts:     map[string]string{},
			wantErr:  "--user is required with --password for Kerberos authentication",
		},
		{
			name:       "password with user",
			user:       "alice@CORP.EXAMPLE.COM",
			password:   "secret",
			opts:       map[string]string{},
			wantSource: kerberosAuthSourcePassword,
		},
		{
			name:       "implicit current session without explicit creds",
			opts:       map[string]string{},
			wantSource: kerberosAuthSourceCurrentSession,
		},
		{
			name:    "explicit user without kerberos material is rejected",
			user:    "alice@CORP.EXAMPLE.COM",
			opts:    map[string]string{},
			wantErr: "--kerberos with --user also requires --password, --keytab, or --ccache; omit --user to use the current Windows session",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source, err := selectKerberosAuthSource(tt.user, tt.password, tt.opts)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q", tt.wantErr)
				}
				if got := err.Error(); got != tt.wantErr {
					t.Fatalf("error = %q, want %q", got, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if source != tt.wantSource {
				t.Fatalf("source = %q, want %q", source, tt.wantSource)
			}
		})
	}
}
