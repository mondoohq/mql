// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package ports holds the per-platform socket listings that back the `ports`
// resource. This file parses FreeBSD's sockstat, which ships in the base
// system, unlike lsof.
package ports

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// SockstatEntry is one socket row from `sockstat -46 -s`.
type SockstatEntry struct {
	User          string
	Command       string
	Pid           int64
	Protocol      string // tcp4, tcp6, udp4, udp6 (a dual-stack tcp46/udp46 socket reads tcp6/udp6)
	LocalAddress  string
	LocalPort     int64
	RemoteAddress string
	RemotePort    int64
	State         string // CONN STATE column, empty for udp
}

// ParseSockstat reads the output of `sockstat -46 -s -w`.
//
//	USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS   FOREIGN ADDRESS  CONN STATE
//	root     sshd       1718  7   tcp4   *:22            *:*              LISTEN
//	ntpd     ntpd       1666  22  udp4   10.45.1.14:123  *:*
//
// Columns are whitespace separated and the command may be truncated, but never
// contains a space, so splitting on fields is safe. The CONN STATE column is
// absent for udp rows before FreeBSD 15 (which prints "??" there instead) and
// on releases whose sockstat has no -s flag, so a row is accepted with
// anything from 7 fields up.
//
// Without -w, sockstat cuts addresses to the column width, so a scoped IPv6
// address such as [fe80::4ff:daff:febe:3ed9%ena0]:123 arrives as
// [fe80::4ff:daff:febe: with no port at all.
func ParseSockstat(r io.Reader) ([]SockstatEntry, error) {
	var res []SockstatEntry

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		if fields[0] == "USER" {
			// header
			continue
		}

		proto, ok := inetProtocol(fields[4])
		if !ok {
			// unix domain sockets and anything else sockstat may list
			continue
		}

		pid, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			// a kernel socket has no pid ("?"); keep the row, report pid 0
			pid = 0
		}

		localAddr, localPort := splitHostPort(fields[5])
		remoteAddr, remotePort := splitHostPort(fields[6])

		state := ""
		if len(fields) > 7 {
			state = strings.Join(fields[7:], " ")
		}
		if state == "??" {
			// FreeBSD 15 prints ?? where a udp socket has no connection state;
			// earlier releases leave the column blank.
			state = ""
		}

		res = append(res, SockstatEntry{
			User:          fields[0],
			Command:       fields[1],
			Pid:           pid,
			Protocol:      proto,
			LocalAddress:  localAddr,
			LocalPort:     localPort,
			RemoteAddress: remoteAddr,
			RemotePort:    remotePort,
			State:         state,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

// inetProtocol reports whether a sockstat PROTO value is an inet socket and
// names it the way the other platforms do. A tcp46 or udp46 socket is an IPv6
// socket that also accepts IPv4 (IPV6_V6ONLY off, as mysqld and many Java
// servers open them); Linux lists the same socket in /proc/net/tcp6 and lsof
// as IPv6, so it reads tcp6/udp6 here too.
func inetProtocol(p string) (string, bool) {
	switch p {
	case "tcp4", "tcp6", "udp4", "udp6":
		return p, true
	case "tcp46":
		return "tcp6", true
	case "udp46":
		return "udp6", true
	}
	return "", false
}

// splitHostPort splits sockstat's ADDRESS:PORT, where the host may be "*", a
// bare IPv4 address, or a bracketed IPv6 address that carries its own colons
// and may include a zone ("[fe80::1%lo0]:123"). A wildcard or unknown port
// yields 0.
func splitHostPort(s string) (string, int64) {
	if s == "" || s == "*:*" {
		return "", 0
	}

	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return s, 0
	}

	host := s[:idx]
	portStr := s[idx+1:]

	// strip the brackets IPv6 literals are wrapped in
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}

	port, err := strconv.ParseInt(portStr, 10, 64)
	if err != nil {
		// "*" for a wildcard port, or a service name
		port = 0
	}

	return host, port
}

// MergeSharedSockets folds rows that describe one socket into a single entry.
//
// sockstat lists a socket once per process holding a descriptor to it, so a
// forking server shows its listener twice or more: nginx's master and each
// worker, all on *:80. A port is one socket, as on Linux, where /proc/net/tcp
// carries each socket once, and the port resource's identity (protocol, both
// endpoints, state) names no process. The row with the lowest pid is kept,
// which is the parent that bound the socket before forking; a kernel row with
// no pid loses to any real one. First-seen order is preserved.
func MergeSharedSockets(entries []SockstatEntry) []SockstatEntry {
	type key struct {
		proto, local, remote string
		lport, rport         int64
		state                string
	}

	res := make([]SockstatEntry, 0, len(entries))
	idx := make(map[key]int, len(entries))
	for _, e := range entries {
		k := key{e.Protocol, e.LocalAddress, e.RemoteAddress, e.LocalPort, e.RemotePort, e.State}
		i, ok := idx[k]
		if !ok {
			idx[k] = len(res)
			res = append(res, e)
			continue
		}
		if cur := res[i]; e.Pid > 0 && (cur.Pid <= 0 || e.Pid < cur.Pid) {
			res[i] = e
		}
	}
	return res
}
