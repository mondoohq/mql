// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package runningbinaries

import (
	"strings"

	"go.mondoo.com/mql/providers/os/connection/shared"
)

// darwinPidPathScript is a JavaScript for Automation script that prints
// "<pid>\t<path>" for each pid it is given, from proc_pidpath. Unlike ps
// and lsof, proc_pidpath answers for the processes of other users without
// root, and osascript ships with every macOS.
const darwinPidPathScript = `ObjC.bindFunction("proc_pidpath", ["int", ["int", "void *", "unsigned int"]])
function run(argv) {
  var d = $.NSMutableData.dataWithLength(4096), out = []
  for (var i = 0; i < argv.length; i++) {
    var n = $.proc_pidpath(parseInt(argv[i]), d.mutableBytes, 4096)
    var p = n > 0 ? $.NSString.alloc.initWithDataEncoding(d.subdataWithRange($.NSMakeRange(0, n)), $.NSUTF8StringEncoding).js : ""
    if (p) out.push(argv[i] + "\t" + p)
  }
  return out.join("\n")
}`

// darwinProcExeScript prints one line per process: the pid and the
// executable path with symlinks resolved, tab separated. macOS has no
// /proc.
//
// proc_pidpath, through osascript (darwinPidPathScript), names the file
// every process runs, symlinks resolved, in one command for all of them and
// without root. ps and lsof answer for the processes it leaves, such as on
// a system without osascript. ps prints the executable path a process was
// started with as its comm column, which a symlink such as Homebrew's
// /opt/homebrew/bin/node leaves pointing away from the installed file, so
// realpath resolves it. A process started by a relative path (node from a
// shell's PATH), a login shell ("-zsh") and a process that renamed itself
// have no path in comm; lsof names the file they run, but sees only the
// scanning user's own processes unless the scan runs as root: the first
// txt entry of a process is its executable.
const darwinProcExeScript = `procs=$(ps -axww -o pid=,comm=) || exit 1
got=
if command -v osascript >/dev/null 2>&1; then
  got=$(osascript -l JavaScript -e '` + darwinPidPathScript + `' $(printf '%s\n' "$procs" | awk '{ print $1 }') 2>/dev/null)
  [ -n "$got" ] && printf '%s\n' "$got"
fi
# the processes proc_pidpath left: its answers, a separator, then the ps
# lines, which awk reads in one pass
{ printf '%s\n--\n' "$got"; printf '%s\n' "$procs"; } | awk -F '\t' '
  !ps { if ($0 == "--") ps = 1; else seen[$1] = 1; next }
  { line = $0; sub(/^[ ]+/, "", line); pid = line; sub(/[ ].*/, "", pid); sub(/^[0-9]+[ ]/, "", line)
    if (pid != "" && !(pid in seen)) print pid "\t" line }' | {
  rel=
  while IFS='	' read -r pid comm; do
    case "$comm" in
      /*) printf '%s\t%s\n' "$pid" "$(realpath "$comm" 2>/dev/null || printf '%s' "$comm")" ;;
      *) rel="$rel,$pid" ;;
    esac
  done
  if [ -n "$rel" ] && command -v lsof >/dev/null 2>&1; then
    lsof -nP -a -d txt -Fpn -p "${rel#,}" 2>/dev/null |
      awk '/^p/ { pid = substr($0, 2); first = 1; next }
        /^n/ && first { printf "%s\t%s\n", pid, substr($0, 2); first = 0 }'
  fi
  exit 0
}`

func listDarwin(conn shared.Connection) ([]Binary, error) {
	cmd, err := runCommand(conn, darwinProcExeScript)
	if err != nil {
		return nil, err
	}
	if cmd.ExitStatus != 0 {
		return nil, commandFailed(cmd, "could not list process executables")
	}
	bins, err := parseProcExe(cmd.Stdout, false)
	if err != nil {
		return nil, err
	}
	for i := range bins {
		bins[i].System = darwinSystemPath(bins[i].Path)
	}
	return bins, nil
}

// darwinSystemDirs hold the operating system's own files, on the read-only,
// sealed system volume or under System Integrity Protection. Safari and the
// other cryptex-delivered parts resolve to /System/Volumes/Preboot/Cryptexes.
var darwinSystemDirs = []string{
	"/System/",
	"/bin/",
	"/sbin/",
	"/usr/bin/",
	"/usr/sbin/",
	"/usr/lib/",
	"/usr/libexec/",
	"/Library/Apple/",
}

// darwinSystemPath reports whether p ships with macOS.
func darwinSystemPath(p string) bool {
	for _, d := range darwinSystemDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return false
}
