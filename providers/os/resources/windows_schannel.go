// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"maps"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/os/registry"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// Registry locations of the effective Schannel TLS configuration, held in the
// local SSL configuration store. The store has one subkey per NCRYPT interface,
// named after the interface id, and each subkey names itself in its default
// value:
//
//   - 00010002 is NCRYPT_SCHANNEL_INTERFACE. Its `Functions` REG_MULTI_SZ is the
//     ordered cipher-suite list and its `EccCurves` REG_MULTI_SZ is the ordered
//     elliptic-curve / supported-group list, which is what `Get-TlsEccCurve`
//     reports and where post-quantum ML-KEM groups appear on Windows 11 24H2 and
//     Windows Server 2025.
//   - 00010003 is NCRYPT_SCHANNEL_SIGNATURE_INTERFACE. Its `Functions`
//     REG_MULTI_SZ is the ordered signature-algorithm list (RSA/SHA256,
//     ECDSA/SHA384, DSA/SHA1, and on newer releases the RSAE-PSS entries).
//
// The two interfaces both spell their list `Functions`, which is why the
// supported groups have to come from the `EccCurves` value of the first rather
// than the `Functions` value of the second.
const (
	schannelCipherSuitesPath  = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002`
	schannelSignatureAlgoPath = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003`
	schannelFunctionsValue    = "Functions"
	schannelEccCurvesValue    = "EccCurves"
)

func (r *mqlWindowsSchannel) id() (string, error) {
	return "windows.schannel", nil
}

// readMultiString reads the named REG_MULTI_SZ value from a registry key and
// returns its ordered entries. A missing key or a missing value yields an empty
// slice rather than an error, so the field degrades gracefully on older Windows,
// on systems using the default order, and on non-Windows platforms.
func (r *mqlWindowsSchannel) readMultiString(path, name string) ([]string, error) {
	o, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		// a missing key is expected (e.g. the default order is in effect); treat
		// it as empty so the field resolves to an empty list rather than erroring
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return []string{}, nil
		}
		return nil, err
	}

	for i := range entries {
		if strings.EqualFold(entries[i].Key, name) {
			return entries[i].Value.MultiString, nil
		}
	}
	return []string{}, nil
}

func (r *mqlWindowsSchannel) cipherSuites() ([]any, error) {
	suites, err := r.readMultiString(schannelCipherSuitesPath, schannelFunctionsValue)
	if err != nil {
		return nil, err
	}
	return strSliceToAny(suites), nil
}

func (r *mqlWindowsSchannel) ellipticCurves() ([]any, error) {
	curves, err := r.readMultiString(schannelCipherSuitesPath, schannelEccCurvesValue)
	if err != nil {
		return nil, err
	}
	return strSliceToAny(curves), nil
}

func (r *mqlWindowsSchannel) signatureAlgorithms() ([]any, error) {
	algorithms, err := r.readMultiString(schannelSignatureAlgoPath, schannelFunctionsValue)
	if err != nil {
		return nil, err
	}
	return strSliceToAny(algorithms), nil
}

func (r *mqlWindowsSchannel) pqcKeyExchangeEnabled() (bool, error) {
	// Derive from the already-resolved ellipticCurves field rather than reading
	// the registry again, so a query for both fields reads the supported-group
	// key once and the two fields stay consistent by construction.
	raw := r.GetEllipticCurves()
	if raw.Error != nil {
		return false, raw.Error
	}

	curves := make([]string, 0, len(raw.Data))
	for _, v := range raw.Data {
		if s, ok := v.(string); ok {
			curves = append(curves, s)
		}
	}
	return pqcKeyExchangeEnabled(curves), nil
}

// pqcKeyExchangeEnabled reports whether any supported group is a post-quantum
// ML-KEM key-exchange group. Windows names these groups with an "mlkem" segment
// (for example x25519_mlkem768, secp256r1_mlkem768, secp384r1_mlkem1024), so the
// match is a case-insensitive substring test for "MLKEM".
func pqcKeyExchangeEnabled(curves []string) bool {
	for _, c := range curves {
		if strings.Contains(strings.ToUpper(c), "MLKEM") {
			return true
		}
	}
	return false
}

// Registry locations of the per-algorithm Schannel overrides. Unlike the
// effective cipher-suite and supported-group order above, these keys hold
// explicit per-protocol, per-cipher, per-hash, and per-key-exchange overrides.
// Windows applies a built-in default to anything not named here, and that
// default varies by release, so an absent key or value means "no override",
// not "disabled".
const (
	schannelPath            = `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL`
	schannelProtocolsPath   = schannelPath + `\Protocols`
	schannelCiphersPath     = schannelPath + `\Ciphers`
	schannelHashesPath      = schannelPath + `\Hashes`
	schannelKeyExchangePath = schannelPath + `\KeyExchangeAlgorithms`

	schannelClientSubkey = "Client"
	schannelServerSubkey = "Server"

	schannelEnabledValue           = "Enabled"
	schannelDisabledByDefaultValue = "DisabledByDefault"
	schannelServerMinKeyBitLength  = "ServerMinKeyBitLength"
	schannelClientMinKeyBitLength  = "ClientMinKeyBitLength"
)

// The well-known algorithm names Windows recognises under each SCHANNEL branch.
// Every one of these is reported whether or not the registry mentions it: a
// list built only from the subkeys that happen to exist would make
// `protocols.where(name == "TLS 1.0").all(...)` match nothing and pass
// vacuously on a host that never configured TLS 1.0, which is precisely the
// host the audit is looking for.
var (
	schannelWellKnownProtocols = []string{
		"SSL 2.0",
		"SSL 3.0",
		"TLS 1.0",
		"TLS 1.1",
		"TLS 1.2",
		"TLS 1.3",
		"DTLS 1.0",
		"DTLS 1.2",
		"PCT 1.0",
		"Multi-Protocol Unified Hello",
	}

	schannelWellKnownCiphers = []string{
		"RC4 40/128",
		"RC4 56/128",
		"RC4 64/128",
		"RC4 128/128",
		"DES 56/56",
		"Triple DES 168",
		"NULL",
		"AES 128/128",
		"AES 256/256",
	}

	schannelWellKnownHashes = []string{
		"MD5",
		"SHA",
		"SHA256",
		"SHA384",
		"SHA512",
	}

	schannelWellKnownKeyExchangeAlgorithms = []string{
		"PKCS",
		"ECDH",
		"Diffie-Hellman",
	}
)

// readSchannelKey reads a single registry key and returns its values keyed by
// the lower-cased value name, together with whether the key carried any value
// at all. A missing key yields an empty map rather than an error so callers
// report "no override" instead of failing.
func (r *mqlWindowsSchannel) readSchannelKey(path string) (map[string]registry.RegistryKeyItem, error) {
	o, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	entries, err := o.(*mqlRegistrykey).getEntries()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return map[string]registry.RegistryKeyItem{}, nil
		}
		return nil, err
	}

	res := make(map[string]registry.RegistryKeyItem, len(entries))
	for i := range entries {
		res[strings.ToLower(entries[i].Key)] = entries[i]
	}
	return res, nil
}

// readSchannelChildNames returns the names of the immediate subkeys of path. A
// missing key yields an empty slice, so a branch that Windows never created
// still produces the well-known list with nothing configured.
func (r *mqlWindowsSchannel) readSchannelChildNames(path string) ([]string, error) {
	o, err := CreateResource(r.MqlRuntime, "registrykey", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}

	children, err := o.(*mqlRegistrykey).getChildren()
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return []string{}, nil
		}
		return nil, err
	}
	return schannelChildNames(path, children), nil
}

// schannelChildNames reduces a registry child listing to the names of the
// immediate subkeys of parent.
//
// The two registry backends describe a child differently, and the difference
// matters here because Schannel key names contain spaces and slashes. The
// native Windows enumeration is one level deep and reports the leaf in Name
// while Path repeats the parent, whereas the PowerShell fallback enumerates
// recursively and reports the child's full path in Path (so Name is the leaf of
// a grandchild such as Client, not of the protocol). Preferring the path
// relative to parent, and only falling back to Name when there is none,
// handles both. Names are deduplicated case-insensitively, keeping the first
// spelling seen.
func schannelChildNames(parent string, children []registry.RegistryKeyChild) []string {
	prefix := strings.TrimSuffix(parent, `\`) + `\`

	names := []string{}
	seen := map[string]struct{}{}
	for _, child := range children {
		name := child.Name
		if len(child.Path) > len(prefix) && strings.EqualFold(child.Path[:len(prefix)], prefix) {
			// first segment of the path below parent
			rel := child.Path[len(prefix):]
			if i := strings.Index(rel, `\`); i >= 0 {
				rel = rel[:i]
			}
			name = rel
		}
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		names = append(names, name)
	}
	return names
}

// mergeSchannelNames returns the well-known names in their canonical order
// followed by any additional name discovered in the registry, sorted for a
// stable list. Comparison is case-insensitive because the registry does not
// enforce a spelling, and the well-known spelling wins so audits can match on a
// fixed string.
func mergeSchannelNames(wellKnown, discovered []string) []string {
	known := make(map[string]struct{}, len(wellKnown))
	for _, n := range wellKnown {
		known[strings.ToLower(n)] = struct{}{}
	}

	extra := []string{}
	seen := map[string]struct{}{}
	for _, n := range discovered {
		key := strings.ToLower(n)
		if _, ok := known[key]; ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		extra = append(extra, n)
	}
	sort.Slice(extra, func(i, j int) bool {
		return strings.ToLower(extra[i]) < strings.ToLower(extra[j])
	})

	res := make([]string, 0, len(wellKnown)+len(extra))
	res = append(res, wellKnown...)
	return append(res, extra...)
}

// schannelConfigured reports whether the key carries at least one of the value
// names this resource reads. It is what separates "the administrator set this"
// from "Windows is applying its own default", which is the distinction every
// Schannel audit turns on.
func schannelConfigured(items map[string]registry.RegistryKeyItem, names ...string) bool {
	for _, name := range names {
		if _, ok := items[strings.ToLower(name)]; ok {
			return true
		}
	}
	return false
}

// schannelEnabled decodes an Enabled or DisabledByDefault DWORD. Windows writes
// 0 for off and a non-zero value for on, conventionally 1 or 0xFFFFFFFF. The
// two registry backends surface 0xFFFFFFFF differently (PowerShell reports the
// signed -1, the native API the unsigned 4294967295), so the test is against
// zero rather than against either spelling of "all bits set". A nil result
// means the value is absent and no override applies.
func schannelEnabled(items map[string]registry.RegistryKeyItem, name string) *bool {
	return regBoolPtr(items, name)
}

// schannelProtocolSideArgs builds the client-side or server-side args for one
// protocol from that side's registry values. The prefix is "client" or
// "server".
func schannelProtocolSideArgs(prefix string, items map[string]registry.RegistryKeyItem) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		prefix + "Configured": llx.BoolData(
			schannelConfigured(items, schannelEnabledValue, schannelDisabledByDefaultValue)),
		prefix + "Enabled": llx.BoolDataPtr(schannelEnabled(items, schannelEnabledValue)),
		prefix + "DisabledByDefault": llx.BoolDataPtr(
			schannelEnabled(items, schannelDisabledByDefaultValue)),
	}
}

// schannelProtocolArgs assembles the full arg set for one protocol resource.
func schannelProtocolArgs(name string, client, server map[string]registry.RegistryKeyItem) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"__id": llx.StringData(schannelProtocolsPath + `\` + name),
		"name": llx.StringData(name),
	}
	maps.Copy(args, schannelProtocolSideArgs("client", client))
	maps.Copy(args, schannelProtocolSideArgs("server", server))
	return args
}

func (r *mqlWindowsSchannel) protocols() ([]any, error) {
	discovered, err := r.readSchannelChildNames(schannelProtocolsPath)
	if err != nil {
		return nil, err
	}

	names := mergeSchannelNames(schannelWellKnownProtocols, discovered)
	present := make(map[string]struct{}, len(discovered))
	for _, n := range discovered {
		present[strings.ToLower(n)] = struct{}{}
	}

	res := make([]any, 0, len(names))
	for _, name := range names {
		// A protocol with no subkey has no override on either side; skip the two
		// registry reads that would come back empty and report it unconfigured.
		var client, server map[string]registry.RegistryKeyItem
		if _, ok := present[strings.ToLower(name)]; ok {
			client, err = r.readSchannelKey(schannelProtocolsPath + `\` + name + `\` + schannelClientSubkey)
			if err != nil {
				return nil, err
			}
			server, err = r.readSchannelKey(schannelProtocolsPath + `\` + name + `\` + schannelServerSubkey)
			if err != nil {
				return nil, err
			}
		}

		o, err := CreateResource(r.MqlRuntime, "windows.schannel.protocol",
			schannelProtocolArgs(name, client, server))
		if err != nil {
			return nil, err
		}
		res = append(res, o.(*mqlWindowsSchannelProtocol))
	}
	return res, nil
}

func (r *mqlWindowsSchannelProtocol) id() (string, error) {
	return schannelProtocolsPath + `\` + r.Name.Data, nil
}

// schannelEnablementArgs builds the args shared by the cipher and hash
// resources, both of which carry only a name and an Enabled override.
func schannelEnablementArgs(branch, name string, items map[string]registry.RegistryKeyItem) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":       llx.StringData(branch + `\` + name),
		"name":       llx.StringData(name),
		"configured": llx.BoolData(schannelConfigured(items, schannelEnabledValue)),
		"enabled":    llx.BoolDataPtr(schannelEnabled(items, schannelEnabledValue)),
	}
}

// readSchannelBranch resolves the merged name list for a branch and the
// registry values behind each name. Names with no subkey are returned with an
// empty value map, which reports them as unconfigured without a registry read.
func (r *mqlWindowsSchannel) readSchannelBranch(branch string, wellKnown []string) ([]string, map[string]map[string]registry.RegistryKeyItem, error) {
	discovered, err := r.readSchannelChildNames(branch)
	if err != nil {
		return nil, nil, err
	}

	present := make(map[string]struct{}, len(discovered))
	for _, n := range discovered {
		present[strings.ToLower(n)] = struct{}{}
	}

	names := mergeSchannelNames(wellKnown, discovered)
	values := make(map[string]map[string]registry.RegistryKeyItem, len(names))
	for _, name := range names {
		if _, ok := present[strings.ToLower(name)]; !ok {
			values[name] = map[string]registry.RegistryKeyItem{}
			continue
		}
		items, err := r.readSchannelKey(branch + `\` + name)
		if err != nil {
			return nil, nil, err
		}
		values[name] = items
	}
	return names, values, nil
}

func (r *mqlWindowsSchannel) ciphers() ([]any, error) {
	names, values, err := r.readSchannelBranch(schannelCiphersPath, schannelWellKnownCiphers)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(names))
	for _, name := range names {
		o, err := CreateResource(r.MqlRuntime, "windows.schannel.cipher",
			schannelEnablementArgs(schannelCiphersPath, name, values[name]))
		if err != nil {
			return nil, err
		}
		res = append(res, o.(*mqlWindowsSchannelCipher))
	}
	return res, nil
}

func (r *mqlWindowsSchannelCipher) id() (string, error) {
	return schannelCiphersPath + `\` + r.Name.Data, nil
}

func (r *mqlWindowsSchannel) hashes() ([]any, error) {
	names, values, err := r.readSchannelBranch(schannelHashesPath, schannelWellKnownHashes)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(names))
	for _, name := range names {
		o, err := CreateResource(r.MqlRuntime, "windows.schannel.hash",
			schannelEnablementArgs(schannelHashesPath, name, values[name]))
		if err != nil {
			return nil, err
		}
		res = append(res, o.(*mqlWindowsSchannelHash))
	}
	return res, nil
}

func (r *mqlWindowsSchannelHash) id() (string, error) {
	return schannelHashesPath + `\` + r.Name.Data, nil
}

// schannelKeyExchangeArgs assembles the arg set for one key exchange
// algorithm. configured covers the minimum key length values as well as
// Enabled, because Diffie-Hellman is commonly configured with a minimum key
// size and no Enabled value at all.
func schannelKeyExchangeArgs(name string, items map[string]registry.RegistryKeyItem) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id": llx.StringData(schannelKeyExchangePath + `\` + name),
		"name": llx.StringData(name),
		"configured": llx.BoolData(schannelConfigured(items,
			schannelEnabledValue, schannelServerMinKeyBitLength, schannelClientMinKeyBitLength)),
		"enabled":               llx.BoolDataPtr(schannelEnabled(items, schannelEnabledValue)),
		"serverMinKeyBitLength": llx.IntDataPtr(regIntPtr(items, schannelServerMinKeyBitLength)),
		"clientMinKeyBitLength": llx.IntDataPtr(regIntPtr(items, schannelClientMinKeyBitLength)),
	}
}

func (r *mqlWindowsSchannel) keyExchangeAlgorithms() ([]any, error) {
	names, values, err := r.readSchannelBranch(schannelKeyExchangePath, schannelWellKnownKeyExchangeAlgorithms)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(names))
	for _, name := range names {
		o, err := CreateResource(r.MqlRuntime, "windows.schannel.keyExchangeAlgorithm",
			schannelKeyExchangeArgs(name, values[name]))
		if err != nil {
			return nil, err
		}
		res = append(res, o.(*mqlWindowsSchannelKeyExchangeAlgorithm))
	}
	return res, nil
}

func (r *mqlWindowsSchannelKeyExchangeAlgorithm) id() (string, error) {
	return schannelKeyExchangePath + `\` + r.Name.Data, nil
}
