// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers/activedirectory/connection"
	"go.mondoo.com/mql/providers/activedirectory/resources"
)

const ConnectionType = "activedirectory"

type Service struct {
	*plugin.Service
}

func Init() *Service {
	return &Service{
		Service: plugin.NewService(),
	}
}

func (s *Service) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	flags := req.GetFlags()
	flagValue := func(name string) []byte {
		if flags == nil {
			return nil
		}
		flag, ok := flags[name]
		if !ok || flag == nil {
			return nil
		}
		return flag.Value
	}

	dc := flagValue("dc")
	user := flagValue("user")
	password := flagValue("password")
	domain := flagValue("domain")
	baseDN := flagValue("base-dn")
	ldaps := flagValue("ldaps")
	plainLDAP := flagValue("plain-ldap")
	starttls := flagValue("starttls")
	port := flagValue("port")
	insecure := flagValue("insecure")
	kerberos := flagValue("kerberos")
	keytab := flagValue("keytab")
	krb5conf := flagValue("krb5conf")
	ccache := flagValue("ccache")
	backend := flagValue("backend")

	// Fall back to Windows domain-joined environment variables when
	// flags are not explicitly provided.
	if len(dc) == 0 {
		if logonServer := os.Getenv("LOGONSERVER"); logonServer != "" {
			dc = []byte(strings.TrimLeft(logonServer, `\`))
		}
	}
	if len(dc) == 0 {
		return nil, errors.New("dc flag is required: specify the domain controller hostname or IP address (or set LOGONSERVER)")
	}

	dnsDomain := os.Getenv("USERDNSDOMAIN")
	userDomain := os.Getenv("USERDOMAIN")
	if len(domain) == 0 && dnsDomain != "" {
		domain = []byte(dnsDomain)
	}

	transportSelections := 0
	if isTrueFlagValue(ldaps) {
		transportSelections++
	}
	if isTrueFlagValue(plainLDAP) {
		transportSelections++
	}
	if isTrueFlagValue(starttls) {
		transportSelections++
	}
	if transportSelections > 1 {
		return nil, errors.New("--ldaps, --plain-ldap, and --starttls are mutually exclusive; use one transport override or rely on the default LDAPS transport")
	}

	opts := map[string]string{}
	opts[connection.OptionDC] = strVal(dc)
	switch {
	case isTrueFlagValue(plainLDAP):
		opts[connection.OptionPlainLDAP] = "true"
	case isTrueFlagValue(starttls):
		opts[connection.OptionStartTLS] = "true"
	default:
		opts[connection.OptionLDAPS] = "true"
	}

	setStrOpt(opts, connection.OptionDomain, domain)
	setStrOpt(opts, connection.OptionBaseDN, baseDN)
	portStr := strVal(port)
	if portStr != "" && portStr != "0" {
		if _, err := strconv.Atoi(portStr); err != nil {
			return nil, errors.New("port flag must be a valid integer: " + err.Error())
		}
		opts[connection.OptionPort] = portStr
	}
	setBoolOpt(opts, connection.OptionInsecure, insecure)
	setBoolOpt(opts, connection.OptionKerberos, kerberos)
	setStrOpt(opts, connection.OptionKeytab, keytab)
	setStrOpt(opts, connection.OptionKrb5Conf, krb5conf)
	setStrOpt(opts, connection.OptionCCache, ccache)
	if b := strVal(backend); b != "" {
		if b != "ldap" && b != "rsat" {
			return nil, errors.New("backend flag must be 'ldap' or 'rsat'")
		}
		opts[connection.OptionBackend] = b
	}

	// Always store user in options when we need an explicit principal, for example
	// simple bind or Kerberos keytab/ccache/password flows. On Windows current-
	// session Kerberos we deliberately leave it empty so the connection layer can
	// select SSPI-backed single sign-on.
	userStr := strVal(user)
	hasExplicitSecretMaterial := strVal(password) != "" || strVal(keytab) != "" || strVal(ccache) != ""
	if userStr == "" && hasExplicitSecretMaterial {
		// Infer a default UPN only from Windows account environment variables.
		// USERNAME is commonly set on Unix too, so require USERDOMAIN as a
		// Windows-specific guard before treating it as an AD username.
		if userDomain != "" && dnsDomain != "" {
			if winUser := os.Getenv("USERNAME"); winUser != "" {
				userStr = winUser + "@" + dnsDomain
			}
		}
	}
	if userStr != "" {
		opts[connection.OptionUser] = userStr
	}

	creds := []*vault.Credential{}
	if len(password) > 0 {
		creds = append(creds, &vault.Credential{
			Type:   vault.CredentialType_password,
			User:   userStr,
			Secret: password,
		})
	}

	config := &inventory.Config{
		Type:        ConnectionType,
		Credentials: creds,
		Options:     opts,
	}
	asset := inventory.Asset{
		Connections: []*inventory.Config{config},
	}

	return &plugin.ParseCLIRes{Asset: &asset}, nil
}

func (s *Service) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, errors.New("mock connect not yet implemented")
}

func (s *Service) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	if req == nil || req.Asset == nil {
		return nil, errors.New("no connection data provided")
	}

	conn, err := s.connect(req, callback)
	if err != nil {
		return nil, err
	}

	if req.Asset.Platform == nil {
		if err := s.detect(req.Asset, conn); err != nil {
			return nil, err
		}
	}

	return &plugin.ConnectRes{
		Id:    uint32(conn.ID()),
		Name:  conn.Name(),
		Asset: req.Asset,
	}, nil
}

func (s *Service) connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*connection.ActiveDirectoryConnection, error) {
	if len(req.Asset.Connections) == 0 {
		return nil, errors.New("no connection options for asset")
	}

	asset := req.Asset
	conf := asset.Connections[0]
	runtime, err := s.AddRuntime(conf, func(connId uint32) (*plugin.Runtime, error) {
		conn, err := connection.NewActiveDirectoryConnection(connId, asset, conf)
		if err != nil {
			return nil, err
		}

		var upstream *upstream.UpstreamClient
		if req.Upstream != nil && !req.Upstream.Incognito {
			upstream, err = req.Upstream.InitClient(context.Background())
			if err != nil {
				conn.Close()
				return nil, err
			}
		}

		asset.Connections[0].Id = conn.ID()
		return plugin.NewRuntime(
			conn,
			callback,
			req.HasRecording,
			resources.CreateResource,
			resources.NewResource,
			resources.GetData,
			resources.SetData,
			upstream), nil
	})
	if err != nil {
		return nil, err
	}

	return runtime.Connection.(*connection.ActiveDirectoryConnection), nil
}

func (s *Service) detect(asset *inventory.Asset, conn *connection.ActiveDirectoryConnection) error {
	asset.Name = "Active Directory " + conn.FQDN()
	platform := &inventory.Platform{
		TechnologyUrlSegments: []string{"directory-service", "activedirectory"},
	}
	if pi, ok := PlatformByName("activedirectory"); ok {
		pi.Apply(platform)
	}
	asset.Platform = platform
	asset.PlatformIds = []string{conn.PlatformId()}

	return nil
}

// isTrueFlagValue interprets the plugin framework's bool encoding, where a
// non-zero first byte means true and false/unset values should be omitted.
func isTrueFlagValue(value []byte) bool {
	return len(value) > 0 && value[0] != 0
}

// setBoolOpt converts a plugin bool flag value (which may be \x01 for true
// or \x00 for false) to the string "true" and stores it in the options map.
// Only "true" values are stored; false/unset flags are omitted.
func setBoolOpt(opts map[string]string, key string, value []byte) {
	if isTrueFlagValue(value) {
		opts[key] = "true"
	}
}

// strVal converts a plugin flag value to a clean Go string, stripping
// trailing null bytes that the plugin framework appends to string values.
func strVal(b []byte) string {
	return strings.TrimRight(string(b), "\x00")
}

// setStrOpt stores a non-empty, null-trimmed string flag value in opts.
func setStrOpt(opts map[string]string, key string, value []byte) {
	if s := strVal(value); s != "" {
		opts[key] = s
	}
}
