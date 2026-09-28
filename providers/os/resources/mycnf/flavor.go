// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mycnf

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Recognized products. MySQL and Percona Server share the option file layout
// and the mysqld binary name, so they share one config resource; MariaDB gets
// its own because its option groups and its security-relevant options differ.
const (
	FlavorMySQL   = "mysql"
	FlavorMariaDB = "mariadb"
	FlavorPercona = "percona"
)

// FileProbe reports whether path exists on the target and whether it is a
// directory. Detection is deliberately expressed against this narrow hook
// rather than a filesystem so it can be exercised against inlined fixtures.
type FileProbe func(path string) (exists bool, isDir bool)

// mariadbBinaries are the paths MariaDB installs its server binary at. The
// presence of any of them identifies MariaDB; the absence of them does not
// identify MySQL, because MariaDB also installs a mysqld name pointing here.
var mariadbBinaries = []string{
	"/usr/sbin/mariadbd",
	"/usr/libexec/mariadbd",
	"/usr/local/libexec/mariadbd", // FreeBSD ports
	"/usr/local/mariadb/bin/mariadbd",
	"/opt/homebrew/bin/mariadbd",
}

// mysqldBinaries are the paths a MySQL or Percona server binary is installed
// at. Checked only after every MariaDB signal has failed, because MariaDB
// installs these same names as links to mariadbd.
var mysqldBinaries = []string{
	"/usr/sbin/mysqld",
	"/usr/libexec/mysqld",
	"/usr/local/libexec/mysqld", // FreeBSD ports
	"/usr/local/mysql/bin/mysqld",
	"/opt/homebrew/bin/mysqld",
}

// ServerBinaries returns the known server binary paths, MariaDB's first.
func ServerBinaries() []string {
	return append(slices.Clone(mariadbBinaries), mysqldBinaries...)
}

// DetectFlavor decides which product a parsed option file belongs to.
//
// Detection runs against the fully expanded configuration, not the root file
// alone, because on RHEL-family hosts the two products' root files are
// indistinguishable: both MariaDB and MySQL ship an /etc/my.cnf holding only
// a [client-server] header and `!includedir /etc/my.cnf.d`, and only the
// fragments inside that directory name the product.
//
// It returns FlavorMariaDB, FlavorMySQL, or the empty string when neither
// product can be identified. Percona is reported as FlavorMySQL here; it is
// distinguished only by the server binary's version string, which
// ParseVersion handles.
func DetectFlavor(c *Conf, probe FileProbe) string {
	// An option group naming MariaDB is decisive, and it is the only signal
	// that works on RHEL-family hosts. Groups that declare no options count,
	// which is why this reads SectionNames rather than the parsed options:
	// MariaDB's packaged fragments announce the product with bare [mariadb]
	// and [galera] headers whose bodies are entirely commented out.
	if slices.ContainsFunc(c.SectionNames(), isMariadbGroup) {
		return FlavorMariaDB
	}

	// The fragment directory a distribution includes names the product on
	// Debian and Ubuntu, where both products otherwise reach their root
	// config through the same /etc/mysql/my.cnf link.
	for _, dir := range c.Includes {
		switch strings.ToLower(filepath.Base(strings.TrimSuffix(dir, "/"))) {
		case "mariadb.conf.d":
			return FlavorMariaDB
		case "mysql.conf.d":
			return FlavorMySQL
		}
	}

	if probe != nil {
		for _, bin := range mariadbBinaries {
			if exists, isDir := probe(bin); exists && !isDir {
				return FlavorMariaDB
			}
		}
		for _, bin := range mysqldBinaries {
			if exists, isDir := probe(bin); exists && !isDir {
				return FlavorMySQL
			}
		}
	}

	// Fall back to the configuration itself. A [mysqld] group with no
	// MariaDB signal anywhere is a MySQL server; MariaDB always ships at
	// least one of the groups isMariadbGroup recognizes.
	for _, name := range c.SectionNames() {
		if MatchesGroup(name, "mysqld") || MatchesGroup(name, "server") {
			return FlavorMySQL
		}
	}

	return ""
}

// isMariadbGroup reports whether an option group name only ever appears in a
// MariaDB configuration. Any group whose name begins with "mariadb" qualifies
// ([mariadb], [mariadbd], [mariadb-11.4], [mariadb-client], ...), as do
// [galera] and [client-mariadb]. No MySQL or Percona distribution ships a
// group by any of these names.
func isMariadbGroup(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	return strings.HasPrefix(name, "mariadb") ||
		name == "galera" ||
		name == "client-mariadb"
}

// reVersion pulls the version token out of a `mysqld --version` banner, for
// example "8.0.46", "8.0.46-37" or "11.8.6-MariaDB-0+deb13u1".
var reVersion = regexp.MustCompile(`\bVer\s+(\S+)`)

// reSemver matches the leading dotted-numeric portion of a version token.
var reSemver = regexp.MustCompile(`^\d+(\.\d+)*`)

// ParseVersion extracts the server version and product from the banner a
// server binary prints for --version, and from the banner string embedded in
// the binary itself.
//
// The product cannot be inferred from the binary's name: MariaDB installs a
// mysqld that reports "11.8.6-MariaDB", and the same banner is what both
// mysqld and mariadbd print. Only the version token and the parenthesized
// distribution note distinguish them.
func ParseVersion(output string) (version string, flavor string) {
	m := reVersion.FindStringSubmatch(output)
	if m == nil {
		return "", ""
	}
	token := m[1]
	version = reSemver.FindString(token)
	if version == "" {
		return "", ""
	}

	switch {
	case strings.Contains(strings.ToLower(token), "mariadb"),
		strings.Contains(strings.ToLower(output), "mariadb.org"):
		flavor = FlavorMariaDB
	case strings.Contains(strings.ToLower(output), "percona"):
		flavor = FlavorPercona
	default:
		flavor = FlavorMySQL
	}
	return version, flavor
}

// ServerGroups lists the option groups a server of the given flavor reads.
// The order of the returned names carries no precedence: Merge resolves
// last-write-wins by the order options were read from the files, which is how
// the server itself resolves them, so only membership in this set matters.
//
// MariaDB's set is not an extension of MySQL's. Since 11.0 its packaged
// fragments configure the server under [mariadbd] and ship no [mysqld] group
// at all, so a server-scope view built only from [mysqld] and [server] comes
// back empty on a current MariaDB host. MariaDB also reads [client-server],
// which is where its packages put the socket path; Oracle MySQL does not.
//
// [galera] is deliberately excluded even though a wsrep-enabled MariaDB reads
// it, so that cluster transport settings stay separable from server settings.
func ServerGroups(flavor string) []string {
	if flavor == FlavorMariaDB {
		return []string{"client-server", "mysqld", "server", "mariadb", "mariadbd"}
	}
	return []string{"mysqld", "server"}
}

// ClientGroups lists the option groups the client programs read. [client-server]
// is read by both the server and the clients, so it appears here as well as in
// ServerGroups for MariaDB.
func ClientGroups(flavor string) []string {
	if flavor == FlavorMariaDB {
		return []string{"client-server", "client", "client-mariadb", "mariadb-client"}
	}
	return []string{"client-server", "client", "mysql"}
}
