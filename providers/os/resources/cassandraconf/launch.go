// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cassandraconf

import (
	"net/url"
	"path"
	"strings"
)

// ConfigFromJVMArgs returns the cassandra.yaml a Cassandra JVM loads, from its
// -Dcassandra.config system property, and whether the command line belongs to
// a Cassandra daemon at all. The property is a URL (file:///etc/cassandra/x.yaml)
// or, as the daemon also accepts, a plain path. It is empty when the property
// is not set, in which case the daemon loads cassandra.yaml from its classpath
// (the conf directory).
func ConfigFromJVMArgs(argv []string) (string, bool) {
	daemon := false
	conf := ""
	for _, arg := range argv {
		if arg == "org.apache.cassandra.service.CassandraDaemon" {
			daemon = true
		}
		v, ok := strings.CutPrefix(arg, "-Dcassandra.config=")
		if !ok || v == "" {
			continue
		}
		conf = v
	}
	if !daemon {
		return "", false
	}
	return configPath(conf), true
}

// configPath turns the property's value into a file path.
func configPath(v string) string {
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") || strings.HasPrefix(v, "file:") {
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "file" {
			return ""
		}
		v = u.Path
		if v == "" {
			v = u.Opaque
		}
	}
	if !path.IsAbs(v) {
		return ""
	}
	return path.Clean(v)
}
