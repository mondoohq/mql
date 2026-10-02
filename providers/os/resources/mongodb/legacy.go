// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb

import (
	"fmt"
	"strconv"
	"strings"
)

// The legacy configuration format is the one mongod read before 2.6
// introduced YAML, and it still accepts it: `name = value` lines whose names
// are the command-line options (`bind_ip`, `auth`, `sslMode`). The Ubuntu and
// Debian archive packages kept shipping /etc/mongodb.conf in this format
// (MongoDB 2.6 on Ubuntu 16.04, 3.6 on 18.04). mongod tells the formats
// apart by parsing the file as YAML first: a legacy file reads as a single
// scalar, where any YAML configuration reads as a mapping.
//
// parseLegacy translates such a file into the YAML tree, so every accessor
// reads it at the same key path it reads a YAML file at.

// legacyKind says how a legacy option's value is stored in the tree.
type legacyKind int

const (
	legacyString legacyKind = iota
	legacyInt
	legacyBool
)

type legacyOption struct {
	path []string
	kind legacyKind
}

// legacyOptions maps a legacy option name, lowercased, to the YAML path of
// the setting it is the command-line spelling of. Options that change
// meaning on the way (auth, noauth, noscripting, ...) are handled in
// applyLegacySwitch instead.
var legacyOptions = map[string]legacyOption{
	"port":             {[]string{"net", "port"}, legacyInt},
	"bind_ip":          {[]string{"net", "bindIp"}, legacyString},
	"bind_ip_all":      {[]string{"net", "bindIpAll"}, legacyBool},
	"ipv6":             {[]string{"net", "ipv6"}, legacyBool},
	"maxconns":         {[]string{"net", "maxIncomingConnections"}, legacyInt},
	"unixsocketprefix": {[]string{"net", "unixDomainSocket", "pathPrefix"}, legacyString},
	"filepermissions":  {[]string{"net", "unixDomainSocket", "filePermissions"}, legacyString},

	"sslmode":                                {[]string{"net", "ssl", "mode"}, legacyString},
	"sslpemkeyfile":                          {[]string{"net", "ssl", "PEMKeyFile"}, legacyString},
	"sslpemkeypassword":                      {[]string{"net", "ssl", "PEMKeyPassword"}, legacyString},
	"sslcafile":                              {[]string{"net", "ssl", "CAFile"}, legacyString},
	"sslcrlfile":                             {[]string{"net", "ssl", "CRLFile"}, legacyString},
	"sslclusterfile":                         {[]string{"net", "ssl", "clusterFile"}, legacyString},
	"sslclustercafile":                       {[]string{"net", "ssl", "clusterCAFile"}, legacyString},
	"sslallowinvalidcertificates":            {[]string{"net", "ssl", "allowInvalidCertificates"}, legacyBool},
	"sslallowinvalidhostnames":               {[]string{"net", "ssl", "allowInvalidHostnames"}, legacyBool},
	"sslallowconnectionswithoutcertificates": {[]string{"net", "ssl", "allowConnectionsWithoutCertificates"}, legacyBool},
	"sslweakcertificatevalidation":           {[]string{"net", "ssl", "allowConnectionsWithoutCertificates"}, legacyBool},
	"ssldisabledprotocols":                   {[]string{"net", "ssl", "disabledProtocols"}, legacyString},
	"sslfipsmode":                            {[]string{"net", "ssl", "FIPSMode"}, legacyBool},

	"tlsmode":                                {[]string{"net", "tls", "mode"}, legacyString},
	"tlscertificatekeyfile":                  {[]string{"net", "tls", "certificateKeyFile"}, legacyString},
	"tlscafile":                              {[]string{"net", "tls", "CAFile"}, legacyString},
	"tlscrlfile":                             {[]string{"net", "tls", "CRLFile"}, legacyString},
	"tlsclusterfile":                         {[]string{"net", "tls", "clusterFile"}, legacyString},
	"tlsclustercafile":                       {[]string{"net", "tls", "clusterCAFile"}, legacyString},
	"tlsallowinvalidcertificates":            {[]string{"net", "tls", "allowInvalidCertificates"}, legacyBool},
	"tlsallowinvalidhostnames":               {[]string{"net", "tls", "allowInvalidHostnames"}, legacyBool},
	"tlsallowconnectionswithoutcertificates": {[]string{"net", "tls", "allowConnectionsWithoutCertificates"}, legacyBool},
	"tlsdisabledprotocols":                   {[]string{"net", "tls", "disabledProtocols"}, legacyString},
	"tlsfipsmode":                            {[]string{"net", "tls", "FIPSMode"}, legacyBool},

	"keyfile":               {[]string{"security", "keyFile"}, legacyString},
	"clusterauthmode":       {[]string{"security", "clusterAuthMode"}, legacyString},
	"redactclientlogdata":   {[]string{"security", "redactClientLogData"}, legacyBool},
	"enableencryption":      {[]string{"security", "enableEncryption"}, legacyBool},
	"encryptionkeyfile":     {[]string{"security", "encryptionKeyFile"}, legacyString},
	"encryptionciphermode":  {[]string{"security", "encryptionCipherMode"}, legacyString},
	"ldapservers":           {[]string{"security", "ldap", "servers"}, legacyString},
	"ldaptransportsecurity": {[]string{"security", "ldap", "transportSecurity"}, legacyString},

	"auditdestination": {[]string{"auditLog", "destination"}, legacyString},
	"auditformat":      {[]string{"auditLog", "format"}, legacyString},
	"auditpath":        {[]string{"auditLog", "path"}, legacyString},
	"auditfilter":      {[]string{"auditLog", "filter"}, legacyString},

	"logappend": {[]string{"systemLog", "logAppend"}, legacyBool},
	"logrotate": {[]string{"systemLog", "logRotate"}, legacyString},
	"quiet":     {[]string{"systemLog", "quiet"}, legacyBool},

	"dbpath":         {[]string{"storage", "dbPath"}, legacyString},
	"directoryperdb": {[]string{"storage", "directoryPerDB"}, legacyBool},
	"storageengine":  {[]string{"storage", "engine"}, legacyString},
	"journal":        {[]string{"storage", "journal", "enabled"}, legacyBool},

	"fork":        {[]string{"processManagement", "fork"}, legacyBool},
	"pidfilepath": {[]string{"processManagement", "pidFilePath"}, legacyString},

	"replset":                   {[]string{"replication", "replSetName"}, legacyString},
	"oplogsize":                 {[]string{"replication", "oplogSizeMB"}, legacyInt},
	"enablemajorityreadconcern": {[]string{"replication", "enableMajorityReadConcern"}, legacyBool},

	"slowms": {[]string{"operationProfiling", "slowOpThresholdMs"}, legacyInt},
}

// legacyProfileModes maps the numeric `profile` level to operationProfiling.mode.
var legacyProfileModes = map[string]string{"0": "off", "1": "slowOp", "2": "all"}

// parseLegacy reads a legacy `name = value` configuration file into the YAML
// tree. Like the option parser mongod uses for it, a `#` starts a comment
// anywhere on a line, and a line that is neither blank, a comment, a
// `[section]` header nor an assignment is a syntax error. An option with no
// YAML counterpart is kept at the top level under its legacy name, so
// `params` still shows it.
func parseLegacy(content string) (map[string]any, error) {
	params := map[string]any{}
	for i, raw := range strings.Split(content, "\n") {
		line := raw
		if hash := strings.IndexByte(line, '#'); hash >= 0 {
			line = line[:hash]
		}
		line = strings.TrimSpace(line)
		if line == "" || (strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]")) {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("mongod.conf line %d: %q is neither YAML nor a legacy name = value option", i+1, line)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("mongod.conf line %d: option without a name", i+1)
		}
		applyLegacyOption(params, name, value)
	}
	return params, nil
}

func applyLegacyOption(params map[string]any, name, value string) {
	key := strings.ToLower(name)
	if opt, ok := legacyOptions[key]; ok {
		setPath(params, legacyValue(opt.kind, value), opt.path...)
		return
	}
	if applyLegacySwitch(params, key, value) {
		return
	}
	params[name] = legacyScalar(value)
}

// applyLegacySwitch handles the options that do not carry their value
// straight across. A switch set to false is the same as leaving it out, which
// is how mongod reads it too. It reports whether name was one of them.
func applyLegacySwitch(params map[string]any, name, value string) bool {
	on, isBool := parseLegacyBool(value)
	switch name {
	case "auth":
		if isBool && on {
			setPath(params, "enabled", "security", "authorization")
		}
	case "noauth":
		if isBool && on {
			setPath(params, "disabled", "security", "authorization")
		}
	case "noscripting":
		if isBool && on {
			setPath(params, false, "security", "javascriptEnabled")
		}
	case "nounixsocket":
		if isBool && on {
			setPath(params, false, "net", "unixDomainSocket", "enabled")
		}
	case "sslonnormalports":
		// The 2.4 switch that 2.6 replaced with sslMode=requireSSL.
		if isBool && on {
			setPath(params, "requireSSL", "net", "ssl", "mode")
		}
	case "shardsvr", "configsvr":
		if isBool && on {
			setPath(params, name, "sharding", "clusterRole")
		}
	case "logpath":
		setPath(params, value, "systemLog", "path")
		setPath(params, "file", "systemLog", "destination")
	case "syslog":
		if isBool && on {
			setPath(params, "syslog", "systemLog", "destination")
		}
	case "profile":
		if mode, ok := legacyProfileModes[value]; ok {
			setPath(params, mode, "operationProfiling", "mode")
		} else {
			setPath(params, value, "operationProfiling", "mode")
		}
	case "verbose":
		// `verbose = true` is one level; `verbose = vvv` is three.
		if isBool {
			if on {
				setPath(params, int64(1), "systemLog", "verbosity")
			}
		} else if strings.Trim(value, "v") == "" {
			setPath(params, int64(len(value)), "systemLog", "verbosity")
		}
	case "setparameter":
		// Repeatable, one `setParameter = name=value` per line.
		pname, pvalue, ok := strings.Cut(value, "=")
		if !ok {
			return true
		}
		setPath(params, legacyScalar(strings.TrimSpace(pvalue)), "setParameter", strings.TrimSpace(pname))
	default:
		return false
	}
	return true
}

func legacyValue(kind legacyKind, value string) any {
	switch kind {
	case legacyInt:
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return n
		}
	case legacyBool:
		if b, ok := parseLegacyBool(value); ok {
			return b
		}
	}
	return value
}

// legacyScalar types a value whose option is not known: a whole number or
// true/false becomes one, anything else stays a string.
func legacyScalar(value string) any {
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		return n
	}
	switch strings.ToLower(value) {
	case "true":
		return true
	case "false":
		return false
	}
	return value
}

func parseLegacyBool(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "true", "1", "yes", "on":
		return true, true
	case "false", "0", "no", "off":
		return false, true
	}
	return false, false
}

// setPath stores value at the key path, creating the intermediate maps.
func setPath(params map[string]any, value any, path ...string) {
	m := params
	for _, key := range path[:len(path)-1] {
		next, ok := m[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[key] = next
		}
		m = next
	}
	m[path[len(path)-1]] = value
}
