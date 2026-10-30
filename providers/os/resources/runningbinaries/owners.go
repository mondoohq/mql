// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"bufio"
	"errors"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"

	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
)

// Owners maps an executable path to the names of the installed packages
// that own it. A path no package owns has no entry.
type Owners map[string][]string

func (o Owners) add(p, name string) {
	if !slices.Contains(o[p], name) {
		o[p] = append(o[p], name)
	}
}

// LinuxOwners asks the package managers behind formats which installed
// packages own paths. formats are the package formats the asset's package
// inventory reported (deb, rpm, apk, pacman, snap).
//
// It fails when one of the formats keeps no file database to ask: reporting
// every binary as unowned there would claim software the package manager
// may well have installed.
func LinuxOwners(conn shared.Connection, formats []string, paths []string) (Owners, error) {
	if len(paths) == 0 {
		return Owners{}, nil
	}
	files := lookupPaths(paths)

	// recorded maps each path a package database lists, a binary's own path
	// or an alias of it, to the packages that list it
	recorded := Owners{}
	for _, format := range formats {
		var found Owners
		var err error
		switch format {
		case packages.DpkgPkgFormat:
			found, err = listFileOwners(conn, "dpkg", []string{dpkgInfoDir}, files)
		case packages.OpkgPkgFormat:
			found, err = listFileOwners(conn, "opkg", opkgInfoDirs, files)
		case packages.RpmPkgFormat:
			found, err = rpmOwners(conn, files)
		case packages.PacmanPkgFormat:
			found, err = pacmanOwners(conn, files)
		case packages.AlpinePkgFormat:
			found, err = apkOwners(conn, files)
		case packages.GentooPkgFormat:
			found, err = gentooOwners(conn, packages.PortageDB, files)
		case packages.XbpsPkgFormat:
			found, err = xbpsOwners(conn, xbpsDbDir, files)
		case "snap":
			found = pathOwners(paths, snapPackage)
		case packages.NixPkgFormat:
			found = pathOwners(paths, packages.NixStorePathPackage)
		case packages.HomebrewPkgFormat:
			found = pathOwners(paths, HomebrewPackage)
		case "flatpak":
			found = pathOwners(paths, flatpakPackage)
		default:
			return nil, llx.NotApplicable(errors.New("cannot tell which package owns a file for package format " + format + ", which keeps no file database"))
		}
		if err != nil {
			return nil, err
		}
		for file, names := range found {
			for _, name := range names {
				recorded.add(file, name)
			}
		}
	}
	return resolveAliases(paths, recorded), nil
}

// resolveAliases gives each path the packages that list it, followed by the
// packages that list one of its aliases. On a merged-/usr system
// /usr/bin/x and /usr/sbin/x are one file, which two packages may both
// list; the package that lists the path the process runs comes first.
func resolveAliases(paths []string, recorded Owners) Owners {
	owners := Owners{}
	for _, p := range paths {
		for _, a := range pathAliases(p) {
			for _, name := range recorded[a] {
				owners.add(p, name)
			}
		}
	}
	return owners
}

// pathAliases returns path and the other paths a package database may have
// recorded the same file under.
//
// /proc reports the path the kernel resolved, so on a merged-/usr system
// (/bin a symlink to /usr/bin) bash runs as /usr/bin/bash while dpkg still
// records /bin/bash. Distributions that merged /usr/sbin into /usr/bin do
// the same with packages built before the merge.
func pathAliases(p string) []string {
	res := []string{p}
	add := func(a string) {
		if !slices.Contains(res, a) {
			res = append(res, a)
		}
	}

	// the path without the /usr prefix and with it, for the directories
	// /usr was merged with
	rest := p
	if after, ok := strings.CutPrefix(p, "/usr"); ok && mergedUsrDir(after) {
		rest = after
		add(rest)
	} else if mergedUsrDir(p) {
		add("/usr" + p)
	} else {
		return res
	}

	// bin and sbin, both with and without /usr
	for _, pair := range [][2]string{{"/bin/", "/sbin/"}, {"/sbin/", "/bin/"}} {
		if after, ok := strings.CutPrefix(rest, pair[0]); ok {
			add(pair[1] + after)
			add("/usr" + pair[1] + after)
		}
	}
	return res
}

// mergedUsrDir reports whether p is in a top-level directory that a merged
// /usr replaces with a symlink into /usr.
func mergedUsrDir(p string) bool {
	for _, d := range []string{"/bin/", "/sbin/", "/lib/", "/lib32/", "/lib64/", "/libx32/"} {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}

// lookupPaths expands paths into every path to look up: each path and its
// aliases, once.
func lookupPaths(paths []string) []string {
	var all []string
	seen := map[string]bool{}
	for _, p := range paths {
		for _, a := range pathAliases(p) {
			if !seen[a] {
				seen[a] = true
				all = append(all, a)
			}
		}
	}
	return all
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// missingDatabase is a shell command that ends the script as a missing tool
// does, for a package database that is not where it should be.
func missingDatabase(what string) string {
	return "{ echo 'no " + what + " database' >&2; exit " + strconv.Itoa(exitToolMissing) + "; }"
}

// requireTool is a shell command that ends the script as a missing tool when
// tool is not installed.
func requireTool(tool string) string {
	return "command -v " + tool + " >/dev/null 2>&1 || { echo '" + tool + " not found' >&2; exit " + strconv.Itoa(exitToolMissing) + "; }\n"
}

const dpkgInfoDir = "/var/lib/dpkg/info"

// opkgInfoDirs are where opkg keeps its file lists, depending on how it was
// configured. OpenWrt uses /usr/lib/opkg.
var opkgInfoDirs = []string{"/usr/lib/opkg/info", "/var/lib/opkg/info"}

// listFileOwners searches the file lists dpkg and opkg keep per package,
// <dir>/<package>.list with one path per line, in the first of dirs that
// exists. One grep over every list rather than `dpkg -S` per path: dpkg -S
// takes as long as the grep for each path it is given.
func listFileOwners(conn shared.Connection, manager string, dirs []string, files []string) (Owners, error) {
	var b strings.Builder
	b.WriteString("d=; for x in")
	for _, dir := range dirs {
		b.WriteString(" " + shellQuote(dir))
	}
	b.WriteString("; do [ -d \"$x\" ] && { d=$x; break; }; done; [ -n \"$d\" ] || " + missingDatabase(manager) + "; grep -H -x -F")
	for _, p := range files {
		b.WriteString(" -e ")
		b.WriteString(shellQuote(p))
	}
	b.WriteString(" \"$d\"/*.list")

	cmd, err := runCommand(conn, b.String())
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	// grep exits 1 when nothing matched, which is an answer, and 2 when a
	// list was unreadable, which still leaves the matches it did print.
	if cmd.ExitStatus > 1 && len(out) == 0 {
		return nil, commandFailed(cmd, "could not read the "+manager+" file lists")
	}
	return parseListMatches(strings.NewReader(string(out))), nil
}

// parseListMatches reads grep -H output over dpkg's or opkg's file lists,
// "<dir>/<package>[:<arch>].list:<path>".
func parseListMatches(r io.Reader) Owners {
	owners := Owners{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		listFile, file, ok := strings.Cut(scanner.Text(), ".list:")
		if !ok {
			continue
		}
		name, _, _ := strings.Cut(path.Base(listFile), ":")
		owners.add(file, name)
	}
	return owners
}

// rpmQuery prints, for each path it is given, the file list of the package
// that owns it, one "<file>\t<package>" line per file: %{=NAME} repeats the
// package name on every line of the list.
const rpmQuery = "rpm -qf --qf '[%{FILENAMES}\\t%{=NAME}\\n]'"

// rpmOwners asks rpm for the owners of every path in one query, which takes
// as long as a single one: rpm opens its database once rather than once per
// path. grep keeps the lines of the paths looked up, so the thousands of
// other files of their packages do not travel back. A path no package owns
// prints a line of its own, which matches none.
func rpmOwners(conn shared.Connection, files []string) (Owners, error) {
	var b strings.Builder
	b.WriteString(requireTool("rpm") + rpmQuery)
	for _, p := range files {
		b.WriteString(" " + shellQuote(p))
	}
	b.WriteString(" 2>/dev/null | grep -F")
	for _, p := range files {
		b.WriteString(" -e " + shellQuote(p+"\t"))
	}
	b.WriteString("; exit 0")
	return bulkOwners(conn, "rpm", b.String(), files, parseRpmOwners)
}

// parseRpmOwners reads "<file>\t<package>" lines.
func parseRpmOwners(r io.Reader) Owners {
	owners := Owners{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		file, name, ok := strings.Cut(scanner.Text(), "\t")
		if ok && name != "" {
			owners.add(file, name)
		}
	}
	return owners
}

// pacmanOwners asks pacman for the owners of every path in one query. It
// prints "<path> is owned by <package> <version>" for each path a package
// owns, in the C locale, and an error for one no package owns.
func pacmanOwners(conn shared.Connection, files []string) (Owners, error) {
	var b strings.Builder
	b.WriteString(requireTool("pacman") + "LC_ALL=C pacman -Qo")
	for _, p := range files {
		b.WriteString(" " + shellQuote(p))
	}
	b.WriteString(" 2>/dev/null; exit 0")
	return bulkOwners(conn, "pacman", b.String(), files, parsePacmanOwners)
}

func parsePacmanOwners(r io.Reader) Owners {
	owners := Owners{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		before, after, ok := strings.CutLast(line, " is owned by ")
		if !ok {
			continue
		}
		if fields := strings.Fields(after); len(fields) > 0 {
			owners.add(before, fields[0])
		}
	}
	return owners
}

// bulkOwners runs a package manager's owner query for all files at once. A
// missing tool is an error rather than an empty answer, which would read as
// every binary being unowned. The answer is limited to the files asked for.
func bulkOwners(conn shared.Connection, tool string, script string, files []string, parse func(io.Reader) Owners) (Owners, error) {
	cmd, err := runCommand(conn, script)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not look up file owners with "+tool)
	}
	found := parse(cmd.Stdout)
	owners := Owners{}
	for _, p := range files {
		if names, ok := found[p]; ok {
			owners[p] = names
		}
	}
	return owners, nil
}

// awkOwners runs an awk program over a package database's files. The paths
// to look up arrive on standard input, ahead of the database files, and the
// program prints "<database file>\t<path>" for every path a file lists.
func awkOwners(conn shared.Connection, manager string, dbDir string, dbFiles string, program string, files []string) (*bufio.Scanner, error) {
	var b strings.Builder
	b.WriteString(requireTool("awk"))
	b.WriteString("[ -d " + shellQuote(dbDir) + " ] || " + missingDatabase(manager) + "\nprintf '%s\\n'")
	for _, p := range files {
		b.WriteString(" ")
		b.WriteString(shellQuote(p))
	}
	b.WriteString(" | awk 'NR == FNR { want[$0] = 1; next }\n" + program + "' - " + dbFiles)

	cmd, err := runCommand(conn, b.String())
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return nil, err
	}
	// an unreadable database file fails awk, which still leaves the matches
	// it printed from the others
	if cmd.ExitStatus != 0 && len(out) == 0 {
		return nil, commandFailed(cmd, "could not read the "+manager+" database")
	}
	return bufio.NewScanner(strings.NewReader(string(out))), nil
}

// gentooOwners searches Portage's database in dbDir, /var/db/pkg, where
// every installed package lists its files in
// <category>/<name>-<version>/CONTENTS, a regular file as
// "obj <path> <md5> <mtime>".
func gentooOwners(conn shared.Connection, dbDir string, files []string) (Owners, error) {
	const program = `$1 == "obj" { p = substr($0, 5); sub(/ [^ ]+ [^ ]+$/, "", p); if (p in want) print FILENAME "\t" p }`
	scanner, err := awkOwners(conn, "portage", dbDir, shellQuote(dbDir)+"/*/*/CONTENTS", program, files)
	if err != nil {
		return nil, err
	}
	return parseGentooOwners(scanner), nil
}

func parseGentooOwners(scanner *bufio.Scanner) Owners {
	owners := Owners{}
	for scanner.Scan() {
		contents, file, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		if name := packages.PortageDBPackageName(path.Dir(contents)); name != "" {
			owners.add(file, name)
		}
	}
	return owners
}

const xbpsDbDir = "/var/db/xbps"

// xmlEscaper escapes a path the way a property list stores it.
var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// xbpsOwners searches the file lists xbps keeps per package in dbDir,
// /var/db/xbps, as .<package>-files.plist, where a file's path is the string
// that follows <key>file</key>. A link's target is a string too, which
// follows <key>target</key> and is not taken for a file.
func xbpsOwners(conn shared.Connection, dbDir string, files []string) (Owners, error) {
	const program = `{ s = $0; gsub(/^[ \t]+|[ \t]+$/, "", s) }
prev == "<key>file</key>" && (s in want) { print FILENAME "\t" s }
{ prev = s }`
	escaped := make([]string, len(files))
	for i, p := range files {
		escaped[i] = "<string>" + xmlEscaper.Replace(p) + "</string>"
	}
	scanner, err := awkOwners(conn, "xbps", dbDir, shellQuote(dbDir)+"/.*-files.plist", program, escaped)
	if err != nil {
		return nil, err
	}
	return parseXbpsOwners(scanner), nil
}

var xmlUnescaper = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&")

func parseXbpsOwners(scanner *bufio.Scanner) Owners {
	owners := Owners{}
	for scanner.Scan() {
		list, s, ok := strings.Cut(scanner.Text(), "\t")
		if !ok {
			continue
		}
		name, ok := strings.CutSuffix(strings.TrimPrefix(path.Base(list), "."), "-files.plist")
		file, ok2 := strings.CutPrefix(s, "<string>")
		file, ok3 := strings.CutSuffix(file, "</string>")
		if ok && ok2 && ok3 && name != "" {
			owners.add(xmlUnescaper.Replace(file), name)
		}
	}
	return owners
}

var apkInstalledDBs = []string{packages.ApkDbInstalled, packages.ApkDbInstalledUsr, packages.ApkDbInstalledVar}

// apkOwners reads apk's installed database, which lists every package's files.
func apkOwners(conn shared.Connection, files []string) (Owners, error) {
	fs := conn.FileSystem()
	for _, db := range apkInstalledDBs {
		f, err := fs.Open(db)
		if err != nil {
			continue
		}
		owners := parseApkInstalledOwners(f, files)
		f.Close()
		return owners, nil
	}
	return nil, llx.NotFound(errors.New("could not read the apk installed database"))
}

// parseApkInstalledOwners reads apk's installed database: one block per
// package, P: the package name, F: a directory relative to the root, and
// R: a file in the directory of the F: line before it.
func parseApkInstalledOwners(r io.Reader, files []string) Owners {
	want := map[string]bool{}
	for _, p := range files {
		want[p] = true
	}
	owners := Owners{}
	var name, dir string
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			name, dir = "", ""
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		switch line[0] {
		case 'P':
			name = line[2:]
		case 'F':
			dir = "/" + line[2:]
		case 'R':
			file := path.Join(dir, line[2:])
			if want[file] && name != "" {
				owners.add(file, name)
			}
		}
	}
	return owners
}

// pathOwners attributes each path to the package that the path itself
// names. Package managers that install every package into a directory of
// its own (snap, nix, Homebrew, flatpak) need no database to answer.
func pathOwners(paths []string, owner func(string) (string, bool)) Owners {
	owners := Owners{}
	for _, p := range paths {
		if name, ok := owner(p); ok {
			owners[p] = []string{name}
		}
	}
	return owners
}

// snapPackage reads /snap/<name>/<revision>/..., where snapd mounts every
// installed snap.
func snapPackage(p string) (string, bool) {
	return pathSegmentAfter(p, "/snap/", "bin")
}

// HomebrewPackage reads <prefix>/Cellar/<name>/<version>/..., where Homebrew
// installs every formula.
func HomebrewPackage(p string) (string, bool) {
	return pathSegmentAfter(p, "/Cellar/", "")
}

// flatpakPackage reads .../flatpak/app/<application id>/..., in the system
// installation (/var/lib/flatpak) and a user's (~/.local/share/flatpak).
func flatpakPackage(p string) (string, bool) {
	return pathSegmentAfter(p, "/flatpak/app/", "")
}

// pathSegmentAfter returns the directory name that follows marker in p, when
// p continues below it. reserved is a name under marker that is no package.
func pathSegmentAfter(p, marker, reserved string) (string, bool) {
	_, after, ok0 := strings.Cut(p, marker)
	if !ok0 {
		return "", false
	}
	name, _, ok := strings.Cut(after, "/")
	if !ok || name == "" || name == reserved {
		return "", false
	}
	return name, true
}

// InstallDir is a directory an installed package was installed to.
type InstallDir struct {
	Package string
	Dir     string
}

// broadWindowsDirs are directories that hold many products. A package whose
// recorded install location is one of them, which some installers write, is
// not taken to own every file below it.
var broadWindowsDirs = []string{
	`program files`,
	`program files (x86)`,
	`programdata`,
	`windows`,
	`users`,
}

// WindowsOwner returns the package whose install directory contains p, the
// most specific one when install directories nest, and false when none does.
func WindowsOwner(p string, dirs []InstallDir) (string, bool) {
	return installDirOwner(dirs, func(dir string) (int, bool) {
		dir = strings.TrimRight(normalizeWindowsPath(dir), `\`)
		if !isSpecificWindowsDir(dir) || !windowsPathWithin(p, dir) {
			return 0, false
		}
		return len(dir), true
	})
}

// isSpecificWindowsDir reports whether a normalized directory is specific
// enough to belong to one product: below a drive, and not one of the shared
// directories every product installs into.
func isSpecificWindowsDir(dir string) bool {
	parts := strings.Split(dir, `\`)
	if len(parts) < 2 || parts[1] == "" {
		return false
	}
	switch {
	case len(parts) == 2 && slices.Contains(broadWindowsDirs, parts[1]):
		return false
	// the operating system's own directories, such as System32
	case parts[1] == "windows":
		return false
	case len(parts) == 3 && strings.HasPrefix(parts[1], "program files") && parts[2] == "common files":
		return false
	case parts[1] == "users":
		return isSpecificUserDir(parts[2:])
	}
	return true
}

// isSpecificUserDir reports whether a directory below C:\Users, given as the
// path parts after it, belongs to one product rather than being a profile
// directory per-user installers share.
func isSpecificUserDir(parts []string) bool {
	switch len(parts) {
	case 0, 1: // C:\Users\<user>
		return false
	case 2: // C:\Users\<user>\AppData
		return parts[1] != "appdata"
	case 3: // AppData\Local, AppData\Roaming, AppData\LocalLow
		return parts[1] != "appdata"
	case 4: // AppData\Local\Programs
		return parts[1] != "appdata" || parts[2] != "local" || parts[3] != "programs"
	}
	return true
}

// broadDarwinDirs are macOS directories that hold many products.
var broadDarwinDirs = []string{
	"/applications",
	"/library",
	"/opt",
	"/usr",
	"/usr/local",
	"/users",
}

// DarwinOwner returns the package whose install location, an application
// bundle for a macOS application, contains p. macOS file systems compare
// names case-insensitively by default.
func DarwinOwner(p string, dirs []InstallDir) (string, bool) {
	lp := strings.ToLower(p)
	return installDirOwner(dirs, func(dir string) (int, bool) {
		dir = strings.TrimRight(strings.ToLower(dir), "/")
		if dir == "" || slices.Contains(broadDarwinDirs, dir) {
			return 0, false
		}
		if lp != dir && !strings.HasPrefix(lp, dir+"/") {
			return 0, false
		}
		return len(dir), true
	})
}

// installDirOwner returns the package of the most specific directory that
// within accepts, reporting the length it matched on.
func installDirOwner(dirs []InstallDir, within func(dir string) (int, bool)) (string, bool) {
	best, bestLen := "", -1
	for _, d := range dirs {
		if n, ok := within(d.Dir); ok && n > bestLen {
			best, bestLen = d.Package, n
		}
	}
	return best, bestLen >= 0
}
