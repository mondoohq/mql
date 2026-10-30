// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mongodb

import (
	"path"
	"strings"
)

// ConfigFromArgs returns the configuration file a mongod command line loads,
// from `-f <file>`, `-f<file>`, `--config <file>` or `--config=<file>`. argv
// excludes the program name. It is empty when the command line names no
// file, in which case mongod reads none.
//
// A relative path is resolved against the root directory, which is where
// systemd starts a service that sets no WorkingDirectory=.
func ConfigFromArgs(argv []string) string {
	// A repeated -f/--config keeps the last one, as a later option on a
	// command line overrides an earlier one.
	var conf string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "-f" || arg == "--config":
			if i+1 < len(argv) {
				conf = argv[i+1]
				i++
			}
		case strings.HasPrefix(arg, "--config="):
			conf = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-f") && !strings.HasPrefix(arg, "--"):
			conf = strings.TrimPrefix(arg, "-f")
		}
	}
	if conf == "" {
		return ""
	}
	if !path.IsAbs(conf) {
		conf = path.Join("/", conf)
	}
	return conf
}

// ArgOverride is a setting given on the mongod command line, with the path
// the same setting has in the YAML configuration file.
type ArgOverride struct {
	Path  []string
	Value any
}

// argFlags maps the command line flags that take no value to the setting
// they turn on (or, for --noauth and --noscripting, off).
var argFlags = map[string]ArgOverride{
	"--bind_ip_all":                 {Path: []string{"net", "bindIpAll"}, Value: true},
	"--ipv6":                        {Path: []string{"net", "ipv6"}, Value: true},
	"--auth":                        {Path: []string{"security", "authorization"}, Value: "enabled"},
	"--noauth":                      {Path: []string{"security", "authorization"}, Value: "disabled"},
	"--noscripting":                 {Path: []string{"security", "javascriptEnabled"}, Value: false},
	"--fork":                        {Path: []string{"processManagement", "fork"}, Value: true},
	"--logappend":                   {Path: []string{"systemLog", "logAppend"}, Value: true},
	"--quiet":                       {Path: []string{"systemLog", "quiet"}, Value: true},
	"--enableEncryption":            {Path: []string{"security", "enableEncryption"}, Value: true},
	"--redactClientLogData":         {Path: []string{"security", "redactClientLogData"}, Value: true},
	"--directoryperdb":              {Path: []string{"storage", "directoryPerDB"}, Value: true},
	"--tlsAllowInvalidCertificates": {Path: []string{"net", "tls", "allowInvalidCertificates"}, Value: true},
	"--tlsAllowInvalidHostnames":    {Path: []string{"net", "tls", "allowInvalidHostnames"}, Value: true},
	"--tlsAllowConnectionsWithoutCertificates": {Path: []string{"net", "tls", "allowConnectionsWithoutCertificates"}, Value: true},
	"--tlsFIPSMode": {Path: []string{"net", "tls", "FIPSMode"}, Value: true},
}

// argValues maps the command line options that take a value to the setting
// they set. --setParameter is handled on its own.
var argValues = map[string][]string{
	"--bind_ip":               {"net", "bindIp"},
	"--port":                  {"net", "port"},
	"--maxConns":              {"net", "maxIncomingConnections"},
	"--tlsMode":               {"net", "tls", "mode"},
	"--tlsCertificateKeyFile": {"net", "tls", "certificateKeyFile"},
	"--tlsCAFile":             {"net", "tls", "CAFile"},
	"--tlsCRLFile":            {"net", "tls", "CRLFile"},
	"--tlsClusterFile":        {"net", "tls", "clusterFile"},
	"--tlsClusterCAFile":      {"net", "tls", "clusterCAFile"},
	"--tlsDisabledProtocols":  {"net", "tls", "disabledProtocols"},
	"--sslMode":               {"net", "ssl", "mode"},
	"--sslPEMKeyFile":         {"net", "ssl", "PEMKeyFile"},
	"--sslCAFile":             {"net", "ssl", "CAFile"},
	"--keyFile":               {"security", "keyFile"},
	"--clusterAuthMode":       {"security", "clusterAuthMode"},
	"--encryptionKeyFile":     {"security", "encryptionKeyFile"},
	"--encryptionCipherMode":  {"security", "encryptionCipherMode"},
	"--replSet":               {"replication", "replSetName"},
	"--oplogSize":             {"replication", "oplogSizeMB"},
	"--dbpath":                {"storage", "dbPath"},
	"--storageEngine":         {"storage", "engine"},
	"--logpath":               {"systemLog", "path"},
	"--pidfilepath":           {"processManagement", "pidFilePath"},
	"--profile":               {"operationProfiling", "mode"},
	"--slowms":                {"operationProfiling", "slowOpThresholdMs"},
	"--auditDestination":      {"auditLog", "destination"},
	"--auditFormat":           {"auditLog", "format"},
	"--auditPath":             {"auditLog", "path"},
	"--auditFilter":           {"auditLog", "filter"},
}

// ArgOverrides reads the settings a mongod command line gives besides the
// configuration file. mongod applies its command line over the file, so each
// of these wins over what the file says. argv excludes the program name. Both
// `--port 27018` and `--port=27018` are accepted; options this package does
// not report are skipped.
func ArgOverrides(argv []string) []ArgOverride {
	var out []ArgOverride
	for i := 0; i < len(argv); i++ {
		name, value, hasValue := strings.Cut(argv[i], "=")
		if o, ok := argFlags[name]; ok && !hasValue {
			out = append(out, o)
			continue
		}
		if name == "--shardsvr" && !hasValue {
			out = append(out, ArgOverride{Path: []string{"sharding", "clusterRole"}, Value: "shardsvr"})
			continue
		}
		if name == "--configsvr" && !hasValue {
			out = append(out, ArgOverride{Path: []string{"sharding", "clusterRole"}, Value: "configsvr"})
			continue
		}
		p, isValue := argValues[name]
		if !isValue && name != "--setParameter" {
			continue
		}
		if !hasValue {
			if i+1 >= len(argv) {
				break
			}
			value = argv[i+1]
			i++
		}
		if name == "--setParameter" {
			k, v, ok := strings.Cut(value, "=")
			if ok && k != "" {
				out = append(out, ArgOverride{Path: []string{"setParameter", k}, Value: v})
			}
			continue
		}
		out = append(out, ArgOverride{Path: p, Value: value})
	}
	return out
}

// ApplyArgOverrides sets each override in a parsed configuration tree,
// creating the sections it needs, and returns the tree.
func ApplyArgOverrides(params map[string]any, overrides []ArgOverride) map[string]any {
	if params == nil {
		params = map[string]any{}
	}
	for _, o := range overrides {
		node := params
		for _, key := range o.Path[:len(o.Path)-1] {
			next, ok := node[key].(map[string]any)
			if !ok {
				next = map[string]any{}
				node[key] = next
			}
			node = next
		}
		node[o.Path[len(o.Path)-1]] = o.Value
	}
	return params
}
