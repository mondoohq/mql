// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/registry/regf"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// hiveFile reads a Windows registry hive file (SOFTWARE, SYSTEM, NTUSER.DAT, ...)
// without the Windows registry API, so a Linux or macOS scanner can read the
// registry of a mounted Windows disk. It is the cross-platform counterpart of
// RegLoadKey plus the native registry readers: values decode through
// decodeRawRegistryValue and a missing key is a NotFound error, as there.
//
// The hive is parsed by the regf package, which treats the file as untrusted
// input: damaged structures fail or are skipped, they never crash the scanner.
//
// Key paths are relative to the hive root and use `\` as separator. Only `\`
// separates, because real key names contain `/` (for example
// `MIME\Database\Content Type\application/json`). Names match case-insensitively.
//
// A hive copied from a running or crashed system is often dirty: the sequence
// numbers in its base block differ, and the newest changes only exist in the
// transaction logs (<hive>.LOG1, <hive>.LOG2) next to it. When the hive is
// dirty and such logs exist, they are replayed in memory, nothing is written.
// If that fails, the hive is read as it is.
type hiveFile struct {
	file *os.File
	// logs are the transaction log files the recovered view reads from; empty
	// when the hive is read as it is.
	logs      []*os.File
	recovered int
	hive      *regf.Hive
	root      regf.Key

	mu       sync.Mutex
	children map[uint32]*keyChildren
}

// keyChildren is the lazily built index of a key's subkeys.
type keyChildren struct {
	list   []regf.Key
	byName map[string]regf.Key
	err    error
}

// openHiveFile opens and validates the hive at path.
func openHiveFile(path string) (*hiveFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	logs := openHiveLogs(path)
	var rlogs []regf.Log
	for _, l := range logs {
		if ls, err := l.Stat(); err == nil {
			rlogs = append(rlogs, regf.Log{Name: l.Name(), R: l, Size: ls.Size()})
		}
	}
	hive, err := regf.Open(f, st.Size(), rlogs...)
	if err != nil {
		closeAll(logs)
		f.Close()
		return nil, fmt.Errorf("%s is not a valid registry hive: %w", path, err)
	}
	h := &hiveFile{file: f, hive: hive, recovered: hive.Replayed(), children: map[uint32]*keyChildren{}}
	if h.recovered > 0 {
		h.logs = logs
	} else {
		if hive.Dirty() {
			log.Debug().Str("path", path).Msg("registry hive is dirty and was not recovered, reading it as is")
		}
		closeAll(logs)
	}
	if h.root, err = hive.Root(); err != nil {
		h.Close()
		return nil, fmt.Errorf("%s has no root key: %w", path, err)
	}
	return h, nil
}

// openHiveLogs opens the transaction logs next to the hive.
func openHiveLogs(path string) []*os.File {
	var logs []*os.File
	for _, ext := range []string{".LOG1", ".LOG2", ".log1", ".log2"} {
		l, err := os.Open(path + ext)
		if err != nil {
			continue
		}
		// on case-insensitive file systems both spellings are the same file
		dup := false
		for _, other := range logs {
			dup = dup || sameFile(other, l)
		}
		if dup {
			l.Close()
			continue
		}
		logs = append(logs, l)
	}
	return logs
}

func closeAll(files []*os.File) {
	for _, f := range files {
		f.Close()
	}
}

func sameFile(a, b *os.File) bool {
	ai, err := a.Stat()
	if err != nil {
		return false
	}
	bi, err := b.Stat()
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// Close closes the hive and its transaction logs.
func (h *hiveFile) Close() error {
	closeAll(h.logs)
	return h.file.Close()
}

// maxItemsBytes bounds the value data decoded by one Items call, so a key that
// holds many large values (or the same large cell listed by many values)
// cannot exhaust memory. A value past the budget fails alone.
const maxItemsBytes = 256 << 20

func decodeHiveName(raw string, ascii bool) string {
	return regf.DecodeName([]byte(raw), ascii)
}

// childrenOf returns the subkeys of nk, building the case-insensitive name
// index once per key. Callers list a key with thousands of subkeys and then
// read each child by path, so lookups must not rescan the list.
func (h *hiveFile) childrenOf(nk regf.Key) *keyChildren {
	h.mu.Lock()
	defer h.mu.Unlock()
	if c, ok := h.children[nk.Offset]; ok {
		return c
	}
	c := &keyChildren{byName: map[string]regf.Key{}}
	c.list, c.err = nk.Subkeys()
	for _, sub := range c.list {
		name := strings.ToLower(sub.Name)
		if _, dup := c.byName[name]; !dup {
			c.byName[name] = sub
		}
	}
	h.children[nk.Offset] = c
	return c
}

// openKey walks the path from the root. It returns false when a component is
// missing, and an error when a key on the path cannot be read.
func (h *hiveFile) openKey(keyPath string) (regf.Key, bool, error) {
	nk := h.root
	for part := range strings.SplitSeq(keyPath, "\\") {
		if part == "" {
			continue
		}
		c := h.childrenOf(nk)
		sub, ok := c.byName[strings.ToLower(part)]
		if !ok {
			return regf.Key{}, false, c.err
		}
		nk = sub
	}
	return nk, true, nil
}

func (h *hiveFile) mustOpenKey(keyPath string) (regf.Key, error) {
	nk, ok, err := h.openKey(keyPath)
	if err != nil {
		return regf.Key{}, fmt.Errorf("registry key %s: %w", keyPath, err)
	}
	if !ok {
		return regf.Key{}, status.Error(codes.NotFound, "registry key not found: "+keyPath)
	}
	return nk, nil
}

// Exists reports whether the key exists, whatever it holds.
func (h *hiveFile) Exists(keyPath string) bool {
	_, ok, _ := h.openKey(keyPath)
	return ok
}

// Children returns the names of the key's subkeys in hive order.
func (h *hiveFile) Children(keyPath string) ([]string, error) {
	nk, err := h.mustOpenKey(keyPath)
	if err != nil {
		return nil, err
	}
	c := h.childrenOf(nk)
	if c.err != nil {
		return nil, fmt.Errorf("subkeys of registry key %s: %w", keyPath, c.err)
	}
	names := make([]string, len(c.list))
	for i, sub := range c.list {
		names[i] = sub.Name
	}
	return names, nil
}

// Items returns all values of the key in stored order. The default value has
// the empty name. A value whose data cannot be read is returned with its Err
// set, like a value of the wrong size.
func (h *hiveFile) Items(keyPath string) ([]RegistryKeyItem, error) {
	nk, err := h.mustOpenKey(keyPath)
	if err != nil {
		return nil, err
	}
	vals, err := nk.Values()
	if err != nil {
		return nil, fmt.Errorf("values of registry key %s: %w", keyPath, err)
	}
	res := make([]RegistryKeyItem, 0, len(vals))
	budget := maxItemsBytes
	for _, v := range vals {
		item := RegistryKeyItem{Key: v.Name}
		if v.Size() > budget {
			item.Value = RegistryKeyValue{Kind: int(v.Type), Err: errors.New("registry key holds more value data than is read at once")}
		} else {
			budget -= v.Size()
			item.Value = decodeHiveValue(v)
		}
		res = append(res, item)
	}
	return res, nil
}

// decodeHiveValue reads and decodes a value; unreadable data fails the value.
func decodeHiveValue(v regf.Value) RegistryKeyValue {
	data, err := v.Data()
	if err != nil {
		return RegistryKeyValue{Kind: int(v.Type), Err: err}
	}
	return decodeRawRegistryValue(v.Type, data)
}

// Item returns the named value, matching the name case-insensitively. Only the
// matching value is decoded.
func (h *hiveFile) Item(keyPath, name string) (RegistryKeyItem, error) {
	nk, err := h.mustOpenKey(keyPath)
	if err != nil {
		return RegistryKeyItem{}, err
	}
	vals, err := nk.Values()
	if err != nil {
		return RegistryKeyItem{}, fmt.Errorf("values of registry key %s: %w", keyPath, err)
	}
	for _, v := range vals {
		if strings.EqualFold(v.Name, name) {
			return RegistryKeyItem{Key: v.Name, Value: decodeHiveValue(v)}, nil
		}
	}
	return RegistryKeyItem{}, status.Error(codes.NotFound, fmt.Sprintf("registry value %s not found under %s", name, keyPath))
}
