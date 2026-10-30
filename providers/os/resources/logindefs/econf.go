// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logindefs

import (
	"bytes"
	"debug/elf"
	"io"
	"strings"

	"github.com/spf13/afero"
)

// useraddPaths are the places shadow installs useradd: /usr/sbin on most
// distributions, /usr/bin on Fedora with merged bin and sbin, /sbin on
// releases without a merged /usr.
var useraddPaths = []string{"/usr/sbin/useradd", "/usr/bin/useradd", "/sbin/useradd"}

// ShadowLinksLibeconf reports whether the system's useradd is linked against
// libeconf. shadow built with libeconf applies /etc/login.defs.d/*.defs on
// top of login.defs; built without it, shadow reads login.defs alone, even
// when a login.defs.d directory exists. Measured with useradd: RHEL 10,
// CentOS Stream 10, AlmaLinux 10 (shadow-utils 4.15) and Fedora 44 (4.19)
// link it and apply the drop-ins; RHEL 7 to 9, Debian 9 to 13 and Ubuntu
// 18.04 to 26.04 (up to shadow 4.17) do not link it and ignore them.
func ShadowLinksLibeconf(fs afero.Fs) bool {
	if fs == nil {
		return false
	}
	for _, p := range useraddPaths {
		f, err := fs.Open(p)
		if err != nil {
			continue
		}
		links := fileLinksLibeconf(f)
		f.Close()
		return links
	}
	return false
}

// maxShadowBinarySize bounds how much of useradd is read when the file system
// cannot serve random access. useradd is about 150 KB.
const maxShadowBinarySize = 16 << 20

// fileLinksLibeconf reads only the ELF headers and dynamic section when the
// file supports random access (local and SFTP). The cat file system used over
// SSH --sudo streams the whole file instead, up to maxShadowBinarySize.
func fileLinksLibeconf(f afero.File) bool {
	if ra, ok := f.(io.ReaderAt); ok {
		if ef, err := elf.NewFile(ra); err == nil {
			defer ef.Close()
			return importsLibeconf(ef)
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxShadowBinarySize))
	if err != nil {
		return false
	}
	return LinksLibeconf(data)
}

// LinksLibeconf reports whether the ELF binary lists libeconf as a needed
// shared library.
func LinksLibeconf(binary []byte) bool {
	f, err := elf.NewFile(bytes.NewReader(binary))
	if err != nil {
		return false
	}
	defer f.Close()
	return importsLibeconf(f)
}

func importsLibeconf(f *elf.File) bool {
	libs, err := f.ImportedLibraries()
	if err != nil {
		return false
	}
	for _, lib := range libs {
		if strings.HasPrefix(lib, "libeconf.so") {
			return true
		}
	}
	return false
}
