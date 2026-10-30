// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package nfs

import (
	"sort"
	"strings"
)

// MountInfo is the parsed view of a single NFS mount that backs an
// `nfs.mount` resource. Server and RemotePath are split from the
// kernel-reported `server:/path` device string, Version and
// Security are pulled from mount options (with Version falling back
// to the fstype trailing digits), and HardMount/ReadOnly are
// derived from the option set.
type MountInfo struct {
	Device     string
	MountPoint string
	Server     string
	RemotePath string
	Version    string
	Security   string
	HardMount  bool
	ReadOnly   bool
	Options    []string
}

// IsNFSFsType reports whether the given filesystem type belongs to
// the NFS family — `nfs`, `nfs3`, `nfs4`, `nfsv4`, etc. The check is
// case-insensitive and matches any fstype with the `nfs` prefix
// followed by optional version digits.
func IsNFSFsType(fstype string) bool {
	t := strings.ToLower(fstype)
	if t == "nfs" {
		return true
	}
	rest, ok := strings.CutPrefix(t, "nfs")
	if !ok {
		return false
	}
	rest = strings.TrimPrefix(rest, "v")
	if rest == "" {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// BuildMountInfo composes a [MountInfo] from the device string,
// mountpoint, fstype, and mount options. Options is the
// kernel-reported map (flag options have an empty value); the result
// keeps the option list sorted and formatted as either `key` or
// `key=value` so callers see a stable order.
func BuildMountInfo(device, mountpoint, fstype string, options map[string]string) MountInfo {
	server, remotePath := splitNFSDevice(device)
	flat := flattenOptions(options)
	return MountInfo{
		Device:     device,
		MountPoint: mountpoint,
		Server:     server,
		RemotePath: remotePath,
		Version:    nfsVersion(options, fstype),
		Security:   options["sec"],
		HardMount:  !hasFlag(options, "soft"),
		ReadOnly:   hasFlag(options, "ro"),
		Options:    flat,
	}
}

// splitNFSDevice splits a `server:/remote/path` device string into
// the server portion and the remote path. IPv6 addresses written as
// `[fe80::1]:/path` are recognized via the bracketed host form;
// otherwise the split happens at the first colon. A device with no
// colon returns server == device and an empty remote path.
func splitNFSDevice(device string) (string, string) {
	if device == "" {
		return "", ""
	}
	if strings.HasPrefix(device, "[") {
		if end := strings.Index(device, "]:"); end != -1 {
			return device[:end+1], device[end+2:]
		}
	}
	if before, after, ok := strings.Cut(device, ":"); ok {
		return before, after
	}
	return device, ""
}

// nfsVersion pulls the NFS protocol version from the mount option
// map. The `vers`, `nfsvers`, and `version` options are checked in
// that order; if none are set, a trailing digit suffix on the fstype
// (e.g. `nfs4`, `nfs3`) is used as a fallback. Returns an empty
// string when the version cannot be determined.
func nfsVersion(options map[string]string, fstype string) string {
	for _, key := range []string{"vers", "nfsvers", "version"} {
		if v, ok := options[key]; ok && v != "" {
			return v
		}
	}
	t := strings.ToLower(fstype)
	rest, ok := strings.CutPrefix(t, "nfs")
	if !ok {
		return ""
	}
	rest = strings.TrimPrefix(rest, "v")
	if rest == "" {
		return ""
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && r != '.' {
			return ""
		}
	}
	return rest
}

func hasFlag(options map[string]string, name string) bool {
	v, ok := options[name]
	return ok && v == ""
}

func flattenOptions(options map[string]string) []string {
	if len(options) == 0 {
		return nil
	}
	out := make([]string, 0, len(options))
	for k, v := range options {
		if v == "" {
			out = append(out, k)
		} else {
			out = append(out, k+"="+v)
		}
	}
	sort.Strings(out)
	return out
}
