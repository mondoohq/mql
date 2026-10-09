// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package kernel

import (
	"bufio"
	"io"
	"strings"
)

// AixTunableCommands are the AIX commands that each own a set of kernel
// tunables: network options, virtual memory, I/O, the scheduler,
// reliability and availability, and NFS. vmo, ioo, schedo and raso only run
// for root; a command that cannot run prints nothing and its tunables are
// left out.
var AixTunableCommands = []string{"no", "vmo", "ioo", "schedo", "raso", "nfso"}

// AixTunablesCommand lists every tunable of every command, the restricted
// ones (-F) included, each command's output under a [command] line.
var AixTunablesCommand = "for c in " + strings.Join(AixTunableCommands, " ") +
	`; do echo "[$c]"; $c -F -a 2>/dev/null; done`

// ParseAixTunables reads the output of AixTunablesCommand. Each command
// prints its tunables as `name = value`. A tunable is named after the
// command that owns it, `no.tcp_keepidle`, which is how /etc/tunables
// files group them and keeps names apart that two commands might share.
func ParseAixTunables(r io.Reader) (map[string]string, error) {
	params := map[string]string{}
	command := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			command = line[1 : len(line)-1]
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		name = strings.TrimSpace(name)
		if command == "" || !ok || name == "" || strings.ContainsAny(name, " \t#") {
			continue
		}
		params[command+"."+name] = strings.TrimSpace(value)
	}
	return params, scanner.Err()
}

// AixNextbootFile holds the tunables AIX applies at boot. `<command> -p -o`
// and `-r -o` write it.
const AixNextbootFile = "/etc/tunables/nextboot"

// ParseAixNextboot appends the assignments of an AIX tunables file to the
// configuration. The file is a list of stanzas, one per command:
//
//	no:
//		ipforwarding = "1"
//		tcp_keepidle = "7201"
//
// Each assignment is named the way ParseAixTunables names the live value.
func (c *SysctlConfig) ParseAixNextboot(r io.Reader, file string) error {
	scanner := bufio.NewScanner(r)
	line := 0
	command := ""
	for scanner.Scan() {
		line++
		raw := scanner.Text()
		text := strings.TrimSpace(raw)
		if text == "" || text[0] == '#' || text[0] == '*' {
			continue
		}
		// a stanza starts in the first column
		if raw[0] != ' ' && raw[0] != '\t' && strings.HasSuffix(text, ":") {
			command = strings.TrimSuffix(text, ":")
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if command == "" || !ok || key == "" {
			continue
		}
		a := SysctlAssignment{
			Key:   key,
			Name:  command + "." + key,
			Value: NormalizeSysctlValue(strings.Trim(strings.TrimSpace(value), `"`)),
			File:  file,
			Line:  line,
		}
		c.Assignments = append(c.Assignments, a)
		c.explicit[a.Name] = true
	}
	return scanner.Err()
}
