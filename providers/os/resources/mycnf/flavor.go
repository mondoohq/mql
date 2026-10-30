// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mycnf

import (
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

// mysqldBinaries are the paths a server binary named mysqld is installed at.
// That is MySQL's and Percona's only name, but MariaDB installs it too: as a
// link to mariadbd from 10.4 on, and as its only server binary before that.
// So a binary here identifies a server without identifying the product.
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

// BannerProbe returns the product the installed server binary names in its
// --version banner (FlavorMySQL, FlavorPercona or FlavorMariaDB), or the empty
// string when no server binary could be run, for example over a transport
// without command execution. See ParseVersion.
type BannerProbe func() string

// DetectFlavor decides which server product an option file chain belongs to.
//
// The server binary decides, not the option files. Both products' client
// libraries ship option files of their own, and those files carry the other
// product's name: mariadb-connector-c-config, which mysql-server pulls in on
// RHEL 8 and later and on Fedora, installs a client.cnf holding
// [client-mariadb], and RHEL 7's mariadb-libs installs an /etc/my.cnf holding
// [mysqld] on a host with no server at all. Reading the configuration first
// reported MySQL's configuration as MariaDB's on the former and a MySQL
// server that does not exist on the latter.
//
// So the server binaries are probed first. A mariadbd at any known path is
// MariaDB. A mysqld is whatever its --version banner says, since MariaDB
// before 10.4 installs its server only under that name; when the banner
// cannot be read, the option groups only a MariaDB server reads decide, and
// MySQL is the answer when there are none. With no server binary at any
// known path the host runs neither server and DetectFlavor returns the empty
// string, whatever the client libraries left in /etc.
//
// probe may be nil when the caller cannot inspect the filesystem. The option
// files then decide alone, and only a server group or the fragment directory
// a distribution includes counts; a [mysqld] group on its own does not,
// because client-only packages ship one.
//
// It returns FlavorMariaDB, FlavorMySQL, or the empty string. Percona is
// reported as FlavorMySQL here; it is distinguished only by the server
// binary's version string, which ParseVersion handles.
func DetectFlavor(c *Conf, probe FileProbe, banner BannerProbe) string {
	if probe == nil {
		return flavorFromConfig(c)
	}

	for _, bin := range mariadbBinaries {
		if exists, isDir := probe(bin); exists && !isDir {
			return FlavorMariaDB
		}
	}

	hasMysqld := slices.ContainsFunc(mysqldBinaries, func(bin string) bool {
		exists, isDir := probe(bin)
		return exists && !isDir
	})
	if !hasMysqld {
		return ""
	}

	if banner != nil {
		switch banner() {
		case FlavorMariaDB:
			return FlavorMariaDB
		case FlavorMySQL, FlavorPercona:
			return FlavorMySQL
		}
	}
	if flavorFromConfig(c) == FlavorMariaDB {
		return FlavorMariaDB
	}
	return FlavorMySQL
}

// flavorFromConfig names the product from the option files alone, counting
// only what a server package ships: a group that only a MariaDB server reads,
// or the fragment directory Debian and Ubuntu include for each product. It
// returns the empty string when neither is present.
func flavorFromConfig(c *Conf) string {
	// Groups that declare no options count, which is why this reads
	// SectionNames rather than the parsed options: MariaDB's packaged
	// fragments announce the server with bare [mariadb] and [galera]
	// headers whose bodies are entirely commented out.
	if slices.ContainsFunc(c.SectionNames(), isMariadbServerGroup) {
		return FlavorMariaDB
	}

	// On Debian and Ubuntu both products reach their root config through
	// the same /etc/mysql/my.cnf link, and the directory it includes names
	// the product.
	for _, dir := range c.Includes {
		switch strings.ToLower(filepath.Base(strings.TrimSuffix(dir, "/"))) {
		case "mariadb.conf.d":
			return FlavorMariaDB
		case "mysql.conf.d":
			return FlavorMySQL
		}
	}
	return ""
}

// isMariadbServerGroup reports whether an option group is one only a MariaDB
// server reads: [mariadb], [mariadbd], their version-suffixed forms such as
// [mariadb-10.3], and [galera]. No MySQL or Percona distribution ships any of
// them.
//
// MariaDB's client groups ([client-mariadb], [mariadb-client]) are left out
// on purpose. The MariaDB client library's packaged config declares
// [client-mariadb], and RHEL and Fedora install that package alongside
// mysql-server, so a client group says nothing about which server runs.
func isMariadbServerGroup(name string) bool {
	name = strings.ToLower(name)
	return MatchesGroup(name, "mariadb") ||
		MatchesGroup(name, "mariadbd") ||
		name == "galera"
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

// ServerGroups lists the option groups a server of the given flavor and
// version reads. The order of the returned names carries no precedence: Merge
// resolves last-write-wins by the order options were read from the files,
// which is how the server itself resolves them, so only membership in this set
// matters.
//
// A server reads the version-suffixed form of its groups only for its own
// major.minor version: an 8.0 server reads [mysqld-8.0] and ignores
// [mysqld-8.4] and [mysqld-9.9]. version is the full server version
// ("10.11.14"); when it is empty the server version is unknown and no
// version-suffixed group is included, because a group written for another
// version would otherwise override the options the server does read.
//
// MariaDB's set is not an extension of MySQL's. Since 11.0 its packaged
// fragments configure the server under [mariadbd] and ship no [mysqld] group
// at all, so a server-scope view built only from [mysqld] and [server] comes
// back empty on a current MariaDB host. [mariadbd] is read from 10.4 on, the
// first series whose GA release reads it; an older server ignores it, which
// `mysqld --verbose --help` lists as "The following groups are read". When the
// version is unknown [mariadbd] is included, since every supported series
// reads it. MariaDB also reads [client-server], which is where its packages put
// the socket path; Oracle MySQL does not. Neither product reads a
// version-suffixed [server] group.
//
// This is the fallback for when the server binary cannot be asked: the list
// the binary prints (ParseServerHelp) is the authority, since it varies by
// build. [galera] is left out here. Only a server built with wsrep reads it:
// the Rocky, SUSE and mariadb.org builds do, Amazon Linux's mariadb118 and
// mariadb123 do not, and the version says nothing about which build this is.
// MariaDB also reads its groups suffixed with the major version alone
// ([mariadb-11], [mariadbd-11]) from 11.8.7 and 12.3.2 on, and in every later
// series; 11.4 and 12.0 to 12.2 do not. MySQL 8.4 reads [mysql_cluster] in
// every build seen; on 8.0 only Oracle's and Percona's builds do, so it is
// left out there.
func ServerGroups(flavor string, version string) []string {
	mm := majorMinor(version)
	if flavor == FlavorMariaDB {
		groups := []string{"client-server", "mysqld", "server", "mariadb"}
		readsMariadbd := mm == "" || versionAtLeast(mm, 10, 4)
		if readsMariadbd {
			groups = append(groups, "mariadbd")
		}
		if mm != "" {
			groups = append(groups, "mysqld-"+mm, "mariadb-"+mm)
			if readsMariadbd {
				groups = append(groups, "mariadbd-"+mm)
			}
		}
		if major, ok := mariadbReadsMajorGroups(version); ok {
			groups = append(groups, "mariadb-"+major, "mariadbd-"+major)
		}
		return groups
	}
	groups := []string{"mysqld", "server"}
	if mm != "" {
		groups = append(groups, "mysqld-"+mm)
		if versionAtLeast(mm, 8, 4) {
			groups = append(groups, "mysql_cluster")
		}
	}
	return groups
}

// majorMinor reduces a server version such as "10.11.14" to the "10.11" a
// version-suffixed option group names. It returns the empty string for a
// version that does not start with two numeric components.
func majorMinor(version string) string {
	parts := strings.SplitN(reSemver.FindString(strings.TrimSpace(version)), ".", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "." + parts[1]
}

// mariadbReadsMajorGroups reports whether a MariaDB server of the given full
// version reads [mariadb-<major>] and [mariadbd-<major>], and returns the
// major version. MariaDB added them (MARIADB_MAJOR_VERSION in
// mysql_version.h) in 11.8.7 and 12.3.2; 11.8.6, every 11.4 and 12.0 to
// 12.3.1 read no such group.
func mariadbReadsMajorGroups(version string) (string, bool) {
	parts := strings.Split(reSemver.FindString(strings.TrimSpace(version)), ".")
	if len(parts) < 3 {
		return "", false
	}
	nums := make([]int, 3)
	for i, p := range parts[:3] {
		n, err := strconv.Atoi(p)
		if err != nil {
			return "", false
		}
		nums[i] = n
	}
	at := func(major, minor, patch int) bool {
		return slices.Compare(nums, []int{major, minor, patch}) >= 0
	}
	switch {
	case nums[0] == 11 && nums[1] == 8:
		return parts[0], at(11, 8, 7)
	case nums[0] == 12 && nums[1] == 3:
		return parts[0], at(12, 3, 2)
	}
	return parts[0], at(12, 4, 0)
}

// versionAtLeast reports whether a "major.minor" version is at least
// major.minor.
func versionAtLeast(mm string, major, minor int) bool {
	a, b, ok := strings.Cut(mm, ".")
	if !ok {
		return false
	}
	maj, err1 := strconv.Atoi(a)
	mnr, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > major || (maj == major && mnr >= minor)
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
