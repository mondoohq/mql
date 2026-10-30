// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logindefs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildELF writes a minimal little-endian ELF64 executable whose dynamic
// section lists needed as DT_NEEDED entries, the shape `readelf -d` shows for
// useradd: RHEL 10 lists libeconf.so.0 next to libc.so.6, RHEL 9 does not.
func buildELF(t *testing.T, needed ...string) []byte {
	t.Helper()
	dynstr := []byte{0}
	var dyn []elf.Dyn64
	for _, lib := range needed {
		dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NEEDED), Val: uint64(len(dynstr))})
		dynstr = append(append(dynstr, lib...), 0)
	}
	dyn = append(dyn, elf.Dyn64{Tag: int64(elf.DT_NULL)})
	shstr := []byte("\x00.dynstr\x00.dynamic\x00.shstrtab\x00")

	var dynBuf bytes.Buffer
	require.NoError(t, binary.Write(&dynBuf, binary.LittleEndian, dyn))

	const ehsize, shentsize = 64, 64
	dynstrOff := uint64(ehsize)
	dynOff := dynstrOff + uint64(len(dynstr))
	shstrOff := dynOff + uint64(dynBuf.Len())
	shOff := shstrOff + uint64(len(shstr))

	hdr := elf.Header64{
		Type: uint16(elf.ET_EXEC), Machine: uint16(elf.EM_X86_64), Version: uint32(elf.EV_CURRENT),
		Shoff: shOff, Ehsize: ehsize, Shentsize: shentsize, Shnum: 4, Shstrndx: 3,
	}
	copy(hdr.Ident[:], elf.ELFMAG)
	hdr.Ident[elf.EI_CLASS] = byte(elf.ELFCLASS64)
	hdr.Ident[elf.EI_DATA] = byte(elf.ELFDATA2LSB)
	hdr.Ident[elf.EI_VERSION] = byte(elf.EV_CURRENT)

	sections := []elf.Section64{
		{},
		{Name: 1, Type: uint32(elf.SHT_STRTAB), Off: dynstrOff, Size: uint64(len(dynstr)), Addralign: 1},
		{Name: 9, Type: uint32(elf.SHT_DYNAMIC), Off: dynOff, Size: uint64(dynBuf.Len()), Link: 1, Entsize: 16, Addralign: 8},
		{Name: 18, Type: uint32(elf.SHT_STRTAB), Off: shstrOff, Size: uint64(len(shstr)), Addralign: 1},
	}

	var out bytes.Buffer
	require.NoError(t, binary.Write(&out, binary.LittleEndian, hdr))
	out.Write(dynstr)
	out.Write(dynBuf.Bytes())
	out.Write(shstr)
	require.NoError(t, binary.Write(&out, binary.LittleEndian, sections))
	return out.Bytes()
}

func TestLinksLibeconf(t *testing.T) {
	// readelf -d /usr/sbin/useradd on RHEL 10 (shadow-utils 4.15)
	assert.True(t, LinksLibeconf(buildELF(t, "libcrypt.so.2", "libaudit.so.1", "libselinux.so.1", "libeconf.so.0", "libc.so.6")))
	// RHEL 9 (shadow-utils 4.9) and Ubuntu 26.04 (shadow 4.17)
	assert.False(t, LinksLibeconf(buildELF(t, "libaudit.so.1", "libselinux.so.1", "libsemanage.so.2", "libacl.so.1", "libc.so.6")))
	assert.False(t, LinksLibeconf([]byte("#!/bin/sh\nexec useradd.real \"$@\"\n")), "not an ELF file")
	assert.False(t, LinksLibeconf(nil))
}

func TestShadowLinksLibeconf(t *testing.T) {
	econf := buildELF(t, "libeconf.so.0", "libc.so.6")
	plain := buildELF(t, "libc.so.6")

	t.Run("RHEL 10 keeps useradd in /usr/sbin", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/usr/sbin/useradd", econf, 0o755))
		assert.True(t, ShadowLinksLibeconf(fs))
	})

	t.Run("Fedora 44 keeps useradd in /usr/bin", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/usr/bin/useradd", econf, 0o755))
		assert.True(t, ShadowLinksLibeconf(fs))
	})

	t.Run("useradd without libeconf", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/usr/sbin/useradd", plain, 0o755))
		assert.False(t, ShadowLinksLibeconf(fs))
	})

	t.Run("file system without random access, as over SSH --sudo", func(t *testing.T) {
		fs := afero.NewMemMapFs()
		require.NoError(t, afero.WriteFile(fs, "/usr/sbin/useradd", econf, 0o755))
		assert.True(t, ShadowLinksLibeconf(&streamOnlyFs{fs}))
	})

	t.Run("no useradd", func(t *testing.T) {
		assert.False(t, ShadowLinksLibeconf(afero.NewMemMapFs()))
		assert.False(t, ShadowLinksLibeconf(nil))
	})
}

// streamOnlyFs serves files whose ReadAt fails, like the cat file system.
type streamOnlyFs struct{ afero.Fs }

type streamOnlyFile struct{ afero.File }

func (f streamOnlyFile) ReadAt([]byte, int64) (int, error) { return 0, errors.New("not implemented") }

func (s *streamOnlyFs) Open(name string) (afero.File, error) {
	f, err := s.Fs.Open(name)
	if err != nil {
		return nil, err
	}
	return streamOnlyFile{f}, nil
}
