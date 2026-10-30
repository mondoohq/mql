// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/activedirectory/connection"
)

func TestSetBoolOpt(t *testing.T) {
	tests := []struct {
		name    string
		value   []byte
		wantSet bool
		wantVal string
	}{
		{"binary true (\\x01)", []byte{0x01}, true, "true"},
		{"binary false (\\x00)", []byte{0x00}, false, ""},
		{"string true", []byte("true"), true, "true"},
		{"string false", []byte("false"), true, "true"}, // 'f' != 0, so treated as true
		{"nil", nil, false, ""},
		{"empty", []byte{}, false, ""},
		{"nonzero byte", []byte{0xff}, true, "true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := make(map[string]string)
			setBoolOpt(opts, "test-key", tt.value)
			val, ok := opts["test-key"]
			if ok != tt.wantSet {
				t.Errorf("setBoolOpt() set=%v, want %v", ok, tt.wantSet)
			}
			if val != tt.wantVal {
				t.Errorf("setBoolOpt() val=%q, want %q", val, tt.wantVal)
			}
		})
	}
}

func TestStrVal(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"path with null", []byte("/tmp/keytab\x00"), "/tmp/keytab"},
		{"clean string", []byte("alice@REALM"), "alice@REALM"},
		{"nil", nil, ""},
		{"empty", []byte{}, ""},
		{"only null", []byte{0x00}, ""},
		{"multi null", []byte("val\x00\x00"), "val"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strVal(tt.in); got != tt.want {
				t.Errorf("strVal(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestSetStrOpt(t *testing.T) {
	opts := make(map[string]string)
	setStrOpt(opts, "k1", []byte("val\x00"))
	setStrOpt(opts, "k2", []byte{0x00})
	setStrOpt(opts, "k3", nil)
	if opts["k1"] != "val" {
		t.Errorf("k1 = %q, want %q", opts["k1"], "val")
	}
	if _, ok := opts["k2"]; ok {
		t.Error("k2 should not be set")
	}
	if _, ok := opts["k3"]; ok {
		t.Error("k3 should not be set")
	}
}

func TestParseCLINilFlagsDoesNotPanic(t *testing.T) {
	svc := Init()
	_, err := svc.ParseCLI(&plugin.ParseCLIReq{})
	if err == nil {
		t.Fatal("expected missing dc error")
	}
	if got, want := err.Error(), "dc flag is required: specify the domain controller hostname or IP address (or set LOGONSERVER)"; got != want {
		t.Fatalf("ParseCLI() error = %q, want %q", got, want)
	}
}

func TestParseCLIEnvFallbacks(t *testing.T) {
	t.Run("LOGONSERVER provides dc", func(t *testing.T) {
		t.Setenv("LOGONSERVER", `\\DC01`)
		t.Setenv("USERDNSDOMAIN", "CORP.EXAMPLE.COM")
		t.Setenv("USERDOMAIN", "CORP")
		t.Setenv("USERNAME", "alice")
		svc := Init()
		res, err := svc.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"password": {Value: []byte("secret")},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		opts := res.Asset.Connections[0].Options
		if got := opts[connection.OptionDC]; got != "DC01" {
			t.Errorf("dc = %q, want %q", got, "DC01")
		}
		if got := opts[connection.OptionDomain]; got != "CORP.EXAMPLE.COM" {
			t.Errorf("domain = %q, want %q", got, "CORP.EXAMPLE.COM")
		}
		if got := opts[connection.OptionUser]; got != "alice@CORP.EXAMPLE.COM" {
			t.Errorf("user = %q, want %q", got, "alice@CORP.EXAMPLE.COM")
		}
		if got := opts[connection.OptionLDAPS]; got != "true" {
			t.Fatalf("ldaps = %q, want %q", got, "true")
		}
	})

	t.Run("USERDNSDOMAIN without USERDOMAIN does not infer user", func(t *testing.T) {
		t.Setenv("LOGONSERVER", `\\DC01`)
		t.Setenv("USERDNSDOMAIN", "CORP.EXAMPLE.COM")
		t.Setenv("USERDOMAIN", "")
		t.Setenv("USERNAME", "alice")
		svc := Init()
		res, err := svc.ParseCLI(&plugin.ParseCLIReq{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		opts := res.Asset.Connections[0].Options
		if got := opts[connection.OptionDC]; got != "DC01" {
			t.Errorf("dc = %q, want %q", got, "DC01")
		}
		if got := opts[connection.OptionDomain]; got != "CORP.EXAMPLE.COM" {
			t.Errorf("domain = %q, want %q", got, "CORP.EXAMPLE.COM")
		}
		if _, ok := opts[connection.OptionUser]; ok {
			t.Fatalf("user should not be inferred without USERDOMAIN: got %q", opts[connection.OptionUser])
		}
		if got := opts[connection.OptionLDAPS]; got != "true" {
			t.Fatalf("ldaps = %q, want %q", got, "true")
		}
	})

	t.Run("explicit flags override env", func(t *testing.T) {
		t.Setenv("LOGONSERVER", `\\DC01`)
		t.Setenv("USERDNSDOMAIN", "CORP.EXAMPLE.COM")
		t.Setenv("USERDOMAIN", "CORP")
		t.Setenv("USERNAME", "alice")
		svc := Init()
		res, err := svc.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"dc":       {Value: []byte("MYDC")},
				"user":     {Value: []byte("bob@OTHER.COM")},
				"domain":   {Value: []byte("OTHER.COM")},
				"password": {Value: []byte("secret")},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		opts := res.Asset.Connections[0].Options
		if got := opts[connection.OptionDC]; got != "MYDC" {
			t.Errorf("dc = %q, want %q", got, "MYDC")
		}
		if got := opts[connection.OptionDomain]; got != "OTHER.COM" {
			t.Errorf("domain = %q, want %q", got, "OTHER.COM")
		}
		if got := opts[connection.OptionUser]; got != "bob@OTHER.COM" {
			t.Errorf("user = %q, want %q", got, "bob@OTHER.COM")
		}
		if got := opts[connection.OptionLDAPS]; got != "true" {
			t.Fatalf("ldaps = %q, want %q", got, "true")
		}
	})

	t.Run("kerberos without explicit credentials leaves user unset for current session auth", func(t *testing.T) {
		t.Setenv("LOGONSERVER", `\\DC01`)
		t.Setenv("USERDNSDOMAIN", "CORP.EXAMPLE.COM")
		t.Setenv("USERDOMAIN", "CORP")
		t.Setenv("USERNAME", "alice")
		svc := Init()
		res, err := svc.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"kerberos": {Value: []byte{0x01}},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		opts := res.Asset.Connections[0].Options
		if _, ok := opts[connection.OptionUser]; ok {
			t.Fatalf("user should stay unset for implicit Windows session auth: got %q", opts[connection.OptionUser])
		}
		if got := opts[connection.OptionKerberos]; got != "true" {
			t.Fatalf("kerberos = %q, want %q", got, "true")
		}
		if got := opts[connection.OptionLDAPS]; got != "true" {
			t.Fatalf("ldaps = %q, want %q", got, "true")
		}
	})

	t.Run("keytab still infers a Windows UPN when user is omitted", func(t *testing.T) {
		t.Setenv("LOGONSERVER", `\\DC01`)
		t.Setenv("USERDNSDOMAIN", "CORP.EXAMPLE.COM")
		t.Setenv("USERDOMAIN", "CORP")
		t.Setenv("USERNAME", "alice")
		svc := Init()
		res, err := svc.ParseCLI(&plugin.ParseCLIReq{
			Flags: map[string]*llx.Primitive{
				"kerberos": {Value: []byte{0x01}},
				"keytab":   {Value: []byte("/tmp/test.keytab")},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		opts := res.Asset.Connections[0].Options
		if got := opts[connection.OptionUser]; got != "alice@CORP.EXAMPLE.COM" {
			t.Fatalf("user = %q, want %q", got, "alice@CORP.EXAMPLE.COM")
		}
	})
}

func TestParseCLITransportSelection(t *testing.T) {
	svc := Init()
	boolFlag := func() *llx.Primitive {
		return &llx.Primitive{Value: []byte{0x01}}
	}

	tests := []struct {
		name             string
		flags            map[string]*llx.Primitive
		wantTransportKey string
		wantErr          string
	}{
		{
			name:             "default transport is ldaps",
			flags:            map[string]*llx.Primitive{"dc": {Value: []byte("dc01")}},
			wantTransportKey: connection.OptionLDAPS,
		},
		{
			name:             "explicit ldaps stays ldaps",
			flags:            map[string]*llx.Primitive{"dc": {Value: []byte("dc01")}, "ldaps": boolFlag()},
			wantTransportKey: connection.OptionLDAPS,
		},
		{
			name:             "starttls overrides default ldaps",
			flags:            map[string]*llx.Primitive{"dc": {Value: []byte("dc01")}, "starttls": boolFlag()},
			wantTransportKey: connection.OptionStartTLS,
		},
		{
			name:             "plain ldap is explicit opt in",
			flags:            map[string]*llx.Primitive{"dc": {Value: []byte("dc01")}, "plain-ldap": boolFlag()},
			wantTransportKey: connection.OptionPlainLDAP,
		},
		{
			name:    "conflicting transport flags are rejected",
			flags:   map[string]*llx.Primitive{"dc": {Value: []byte("dc01")}, "starttls": boolFlag(), "plain-ldap": boolFlag()},
			wantErr: "--ldaps, --plain-ldap, and --starttls are mutually exclusive; use one transport override or rely on the default LDAPS transport",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := svc.ParseCLI(&plugin.ParseCLIReq{Flags: tt.flags})
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
			opts := res.Asset.Connections[0].Options
			if got := opts[tt.wantTransportKey]; got != "true" {
				t.Fatalf("%s = %q, want %q", tt.wantTransportKey, got, "true")
			}
			for _, other := range []string{connection.OptionLDAPS, connection.OptionStartTLS, connection.OptionPlainLDAP} {
				if other != tt.wantTransportKey {
					if _, ok := opts[other]; ok {
						t.Fatalf("unexpected transport option %s=%q", other, opts[other])
					}
				}
			}
		})
	}
}
