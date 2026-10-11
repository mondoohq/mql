// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/cryptopolicies"
	"go.mondoo.com/mql/types"
)

// cryptoPoliciesDir is the configuration directory of crypto-policies.
const cryptoPoliciesDir = "/etc/crypto-policies"

type mqlCryptoPolicyInternal struct {
	lock       sync.Mutex
	policy     *cryptopolicies.Policy
	policyErr  error
	policyRead bool
}

func (s *mqlCryptoPolicy) id() (string, error) {
	return "cryptoPolicy", nil
}

func cryptoPolicyFs(runtime *plugin.Runtime) (afero.Fs, error) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok {
		return nil, errors.New("cryptoPolicy requires a connection with a file system")
	}
	return conn.FileSystem(), nil
}

// readOptional reads a file, reporting false when it does not exist.
func readOptional(fs afero.Fs, p string) ([]byte, bool, error) {
	data, err := afero.ReadFile(fs, p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to read %s: %w", p, err)
	}
	return data, true, nil
}

func (s *mqlCryptoPolicy) installed() (bool, error) {
	fs, err := cryptoPolicyFs(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	st, err := fs.Stat(cryptoPoliciesDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return st.IsDir(), nil
}

func (s *mqlCryptoPolicy) file() (*mqlFile, error) {
	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(cryptopolicies.ConfigFile)})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (s *mqlCryptoPolicy) configured() (string, error) {
	installed := s.GetInstalled()
	if installed.Error != nil {
		return "", installed.Error
	}
	if !installed.Data {
		s.Configured.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	fs, err := cryptoPolicyFs(s.MqlRuntime)
	if err != nil {
		return "", err
	}

	// As parse_pconfig in update-crypto-policies: the configuration file,
	// else FIPS in FIPS mode, else the distribution's default.
	data, ok, err := readOptional(fs, cryptopolicies.ConfigFile)
	if err != nil {
		return "", err
	}
	if !ok {
		fips := s.GetFips()
		if fips.Error != nil {
			return "", fips.Error
		}
		if fips.Data {
			return "FIPS", nil
		}
		if data, ok, err = readOptional(fs, cryptopolicies.DefaultConfigFile); err != nil {
			return "", err
		}
		if !ok {
			s.Configured.State = plugin.StateIsSet | plugin.StateIsNull
			return "", nil
		}
	}
	cfg, err := cryptopolicies.ParseConfig(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	return cfg.String(), nil
}

func (s *mqlCryptoPolicy) name(configured string) (string, error) {
	cfg, err := cryptopolicies.ParseConfig(strings.NewReader(configured))
	return cfg.Policy, err
}

func (s *mqlCryptoPolicy) subpolicies(configured string) ([]any, error) {
	cfg, err := cryptopolicies.ParseConfig(strings.NewReader(configured))
	if err != nil {
		return nil, err
	}
	return llx.TArr2Raw(cfg.Subpolicies), nil
}

func (s *mqlCryptoPolicy) current() (string, error) {
	fs, err := cryptoPolicyFs(s.MqlRuntime)
	if err != nil {
		return "", err
	}
	data, ok, err := readOptional(fs, cryptopolicies.CurrentFile)
	if err != nil {
		return "", err
	}
	if !ok {
		s.Current.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return strings.TrimSpace(string(data)), nil
}

// applied reports whether the back ends were generated for the configured
// policy: the state file names the configured policy and was written no
// earlier than the configuration file. update-crypto-policies --is-applied
// compares the two files byte for byte instead, so a comment in the
// configuration (`DEFAULT:NO-SHA1 # hardened`) makes it report a policy as
// not applied after update-crypto-policies applied it; the parsed policies
// are compared here.
func (s *mqlCryptoPolicy) applied() (bool, error) {
	fs, err := cryptoPolicyFs(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	currentSt, err1 := fs.Stat(cryptopolicies.CurrentFile)
	configSt, err2 := fs.Stat(cryptopolicies.ConfigFile)
	if errors.Is(err1, os.ErrNotExist) || errors.Is(err2, os.ErrNotExist) {
		s.Applied.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if err1 != nil {
		return false, err1
	}
	if err2 != nil {
		return false, err2
	}
	configured := s.GetConfigured()
	if configured.Error != nil {
		return false, configured.Error
	}
	current, _, err := readOptional(fs, cryptopolicies.CurrentFile)
	if err != nil {
		return false, err
	}
	applied, err := cryptopolicies.ParseConfig(bytes.NewReader(current))
	if err != nil {
		return false, err
	}
	return !currentSt.ModTime().Before(configSt.ModTime()) && applied.String() == configured.Data, nil
}

func (s *mqlCryptoPolicy) fips() (bool, error) {
	fs, err := cryptoPolicyFs(s.MqlRuntime)
	if err != nil {
		return false, err
	}
	data, ok, err := readOptional(fs, cryptopolicies.FipsFile)
	if err != nil || !ok {
		return false, err
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(data)))
	return err == nil && v > 0, nil
}

// loadPolicy parses the policy dump once; it is nil when there is none. An
// error is kept as well, so it is not read again for every field.
func (s *mqlCryptoPolicy) loadPolicy() (*cryptopolicies.Policy, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.policyRead {
		s.policy, s.policyErr = s.readPolicy()
		s.policyRead = true
	}
	return s.policy, s.policyErr
}

func (s *mqlCryptoPolicy) readPolicy() (*cryptopolicies.Policy, error) {
	fs, err := cryptoPolicyFs(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	data, ok, err := readOptional(fs, cryptopolicies.PolicyDumpFile)
	if err != nil || !ok {
		return nil, err
	}
	policy, err := cryptopolicies.ParsePolicy(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", cryptopolicies.PolicyDumpFile, err)
	}
	// The installed update-crypto-policies wrote the dump; its source says
	// how scoped lines relate. Without it, assume the current form.
	source, ok, err := readOptional(fs, cryptopolicies.LibraryFile)
	if err != nil {
		return nil, err
	}
	if ok {
		policy.RelativeToParent = cryptopolicies.DumpsRelativeToParent(string(source))
	}
	return policy, nil
}

func (s *mqlCryptoPolicy) settings() (map[string]any, error) {
	p, err := s.loadPolicy()
	if err != nil {
		return nil, err
	}
	if p == nil {
		s.Settings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return p.Baseline, nil
}

func (s *mqlCryptoPolicy) scopes() ([]any, error) {
	p, err := s.loadPolicy()
	if err != nil {
		return nil, err
	}
	if p == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, name := range p.Scopes() {
		scope, err := NewResource(s.MqlRuntime, "cryptoPolicy.scope", map[string]*llx.RawData{"name": llx.StringData(name)})
		if err != nil {
			return nil, err
		}
		res = append(res, scope)
	}
	return res, nil
}

func initCryptoPolicyScope(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["name"]
	if !ok {
		return nil, nil, errors.New("cryptoPolicy.scope requires a name")
	}
	name, ok := raw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New("cryptoPolicy.scope requires a name")
	}
	name = strings.ToLower(name)

	obj, err := CreateResource(runtime, "cryptoPolicy", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	p, err := obj.(*mqlCryptoPolicy).loadPolicy()
	if err != nil {
		return nil, nil, err
	}

	res := map[string]*llx.RawData{
		"__id": llx.StringData("cryptoPolicy.scope/" + name),
		"name": llx.StringData(name),
	}
	fields := map[string]string{
		"ciphers":      "cipher",
		"macs":         "mac",
		"hashes":       "hash",
		"signatures":   "sign",
		"keyExchanges": "key_exchange",
		"groups":       "group",
		"protocols":    "protocol",
	}
	if p == nil {
		res["settings"] = llx.NilData
		for field := range fields {
			res[field] = llx.NilData
		}
		return res, nil, nil
	}

	settings := p.Resolve(name)
	res["settings"] = llx.MapData(settings, types.Dict)
	for field, prop := range fields {
		list, ok := settings[prop].([]any)
		if !ok {
			res[field] = llx.NilData
			continue
		}
		res[field] = llx.ArrayData(list, types.String)
	}
	return res, nil, nil
}
