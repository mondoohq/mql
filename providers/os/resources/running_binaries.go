// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/pem"
	"errors"
	"io/fs"
	"slices"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/runningbinaries"
	"go.mondoo.com/mql/types"
)

type mqlRunningBinariesInternal struct {
	lock       sync.Mutex
	binaries   []*mqlBinary
	ownersDone bool
	ownersErr  error

	signaturesDone bool
	signaturesErr  error

	hashesDone bool
	hashes     map[string]string
	hashesErr  error
}

func (r *mqlRunningBinaries) list() ([]any, error) {
	conn := r.MqlRuntime.Connection.(shared.Connection)
	bins, err := runningbinaries.List(conn)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(bins))
	for _, b := range bins {
		procs := make([]any, 0, len(b.Pids))
		for _, pid := range b.Pids {
			p, err := CreateResource(r.MqlRuntime, "process", map[string]*llx.RawData{
				"pid": llx.IntData(pid),
			})
			if err != nil {
				return nil, err
			}
			procs = append(procs, p)
		}

		o, err := CreateResource(r.MqlRuntime, "binary", map[string]*llx.RawData{
			"__id":      llx.StringData("binary\x00" + b.Path),
			"path":      llx.StringData(b.Path),
			"system":    llx.BoolData(b.System),
			"processes": llx.ArrayData(procs, types.Resource("process")),
		})
		if err != nil {
			return nil, err
		}
		bin := o.(*mqlBinary)
		bin.info = b
		bin.parent = r
		r.binaries = append(r.binaries, bin)
		res = append(res, bin)
	}
	return res, nil
}

// resolveOwners looks up the owning package of every listed binary at once:
// one package-manager query for all of them is as cheap as one for each.
func (r *mqlRunningBinaries) resolveOwners() error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.ownersDone {
		return r.ownersErr
	}
	r.ownersDone = true
	r.ownersErr = r.lookupOwners()
	return r.ownersErr
}

func (r *mqlRunningBinaries) lookupOwners() error {
	raw, err := CreateResource(r.MqlRuntime, "packages", map[string]*llx.RawData{})
	if err != nil {
		return err
	}
	pkgs := raw.(*mqlPackages)
	list := pkgs.GetList()
	if list.Error != nil {
		return list.Error
	}
	pkgs.lock.Lock()
	err = pkgs.refreshCache(list.Data)
	byName := pkgs.packagesByName
	pkgs.lock.Unlock()
	if err != nil {
		return err
	}

	conn := r.MqlRuntime.Connection.(shared.Connection)
	if isWindowsAsset(conn) {
		var dirs []runningbinaries.InstallDir
		for _, x := range list.Data {
			pkg := x.(*mqlPackage)
			for _, f := range pkg.filesOnDisks {
				dirs = append(dirs, runningbinaries.InstallDir{Package: pkg.Name.Data, Dir: f.Path})
			}
		}
		var unowned []string
		for _, bin := range r.binaries {
			if name, ok := runningbinaries.WindowsOwner(bin.Path.Data, dirs); ok {
				bin.owner = byName[name]
			}
			if bin.owner == nil {
				unowned = append(unowned, bin.Path.Data)
			}
		}
		if len(unowned) == 0 {
			return nil
		}
		// a product installed with Windows Installer that records no
		// install location is known by the files it installed
		products, err := runningbinaries.WindowsInstallerOwners(conn, unowned)
		if err != nil {
			return err
		}
		for _, bin := range r.binaries {
			if name, ok := products[runningbinaries.WindowsPathKey(bin.Path.Data)]; ok && bin.owner == nil {
				bin.owner = byName[name]
			}
		}
		return nil
	}

	if conn.Asset().Platform.IsFamily("darwin") {
		var dirs []runningbinaries.InstallDir
		for _, x := range list.Data {
			pkg := x.(*mqlPackage)
			for _, f := range pkg.filesOnDisks {
				dirs = append(dirs, runningbinaries.InstallDir{Package: pkg.Name.Data, Dir: f.Path})
			}
		}
		for _, bin := range r.binaries {
			name, ok := runningbinaries.DarwinOwner(bin.Path.Data, dirs)
			if !ok {
				name, ok = runningbinaries.HomebrewPackage(bin.Path.Data)
			}
			if ok {
				bin.owner = byName[name]
			}
		}
		return nil
	}

	var formats []string
	for _, x := range list.Data {
		if f := x.(*mqlPackage).Format.Data; f != "" && !slices.Contains(formats, f) {
			formats = append(formats, f)
		}
	}
	paths := make([]string, 0, len(r.binaries))
	for _, bin := range r.binaries {
		paths = append(paths, bin.Path.Data)
	}
	owners, err := runningbinaries.LinuxOwners(conn, formats, paths)
	if err != nil {
		return err
	}
	for _, bin := range r.binaries {
		for _, name := range owners[bin.Path.Data] {
			if pkg, ok := byName[name]; ok {
				bin.owner = pkg
				break
			}
		}
	}
	return nil
}

// resolveHashes computes the digest of every listed binary on the asset at
// once, in one command for all of them.
func (r *mqlRunningBinaries) resolveHashes() (map[string]string, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if !r.hashesDone {
		r.hashesDone = true
		bins := make([]runningbinaries.Binary, 0, len(r.binaries))
		for _, bin := range r.binaries {
			bins = append(bins, bin.info)
		}
		r.hashes, r.hashesErr = runningbinaries.SHA256s(r.MqlRuntime.Connection.(shared.Connection), bins)
	}
	return r.hashes, r.hashesErr
}

// resolveSignatures verifies the code signature of every listed binary at
// once, in one command for all of them.
func (r *mqlRunningBinaries) resolveSignatures() error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.signaturesDone {
		return r.signaturesErr
	}
	r.signaturesDone = true
	r.signaturesErr = r.lookupSignatures()
	return r.signaturesErr
}

func (r *mqlRunningBinaries) lookupSignatures() error {
	conn := r.MqlRuntime.Connection.(shared.Connection)
	platform := conn.Asset().Platform
	switch {
	case platform.IsFamily("windows"):
		paths := make([]string, 0, len(r.binaries))
		for _, bin := range r.binaries {
			paths = append(paths, bin.Path.Data)
		}
		sigs, err := runningbinaries.WindowsSignatures(conn, paths)
		if err != nil {
			return err
		}
		for _, bin := range r.binaries {
			if sig, ok := sigs[runningbinaries.WindowsPathKey(bin.Path.Data)]; ok {
				bin.sig = &sig
			}
		}
	case platform.IsFamily("darwin"):
		paths := make([]string, 0, len(r.binaries))
		for _, bin := range r.binaries {
			paths = append(paths, bin.Path.Data)
		}
		sigs, err := runningbinaries.DarwinSignatures(conn, paths)
		if err != nil {
			return err
		}
		for _, bin := range r.binaries {
			if sig, ok := sigs[bin.Path.Data]; ok {
				bin.sig = &sig
			}
		}
	}
	return nil
}

type mqlBinaryInternal struct {
	info   runningbinaries.Binary
	parent *mqlRunningBinaries
	owner  *mqlPackage
	// sig is nil where none was read: on Linux, and for a process that
	// exited before its file was verified
	sig *runningbinaries.Signature

	lock       sync.Mutex
	identified bool
}

// identify reads what the binary is from the file once, for every identity
// field: the read can take a large part of the file.
func (b *mqlBinary) identify() {
	b.lock.Lock()
	defer b.lock.Unlock()
	if b.identified {
		return
	}
	b.identified = true

	conn := b.MqlRuntime.Connection.(shared.Connection)
	id := runningbinaries.Identify(conn.FileSystem(), b.info)

	b.Name = plugin.TValue[string]{Data: id.Name, State: plugin.StateIsSet}
	b.Version = plugin.TValue[string]{Data: id.Version, State: plugin.StateIsSet}
	b.VersionSource = plugin.TValue[string]{Data: id.VersionSource, State: plugin.StateIsSet}
	b.Vendor = plugin.TValue[string]{Data: id.Vendor, State: plugin.StateIsSet}
}

func (b *mqlBinary) name() (string, error) {
	b.identify()
	return b.Name.Data, nil
}

func (b *mqlBinary) version() (string, error) {
	b.identify()
	return b.Version.Data, nil
}

func (b *mqlBinary) versionSource() (string, error) {
	b.identify()
	return b.VersionSource.Data, nil
}

func (b *mqlBinary) vendor() (string, error) {
	b.identify()
	return b.Vendor.Data, nil
}

func (b *mqlBinary) sha256() (string, error) {
	conn := b.MqlRuntime.Connection.(shared.Connection)
	if b.parent != nil && runningbinaries.HashOnAsset(conn) {
		hashes, err := b.parent.resolveHashes()
		if err != nil {
			return "", err
		}
		if digest, ok := hashes[b.Path.Data]; ok {
			return digest, nil
		}
		// the command could not read the file: reading it says why
	}
	digest, err := runningbinaries.SHA256(conn.FileSystem(), b.info)
	// an update removed the file, and on Linux the process exited too:
	// there is nothing left to hash, which is no reason to fail the list
	if errors.Is(err, fs.ErrNotExist) {
		b.Sha256.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	// another user's executable, read without the privileges to
	if errors.Is(err, fs.ErrPermission) {
		return "", llx.Forbidden(err)
	}
	return digest, err
}

func (b *mqlBinary) file() (*mqlFile, error) {
	f, err := NewResource(b.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(b.Path.Data),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (b *mqlBinary) compute_package() (*mqlPackage, error) {
	if b.parent == nil {
		b.Package.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if err := b.parent.resolveOwners(); err != nil {
		return nil, err
	}
	if b.owner == nil {
		b.Package.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return b.owner, nil
}

// signature resolves the binary's code signature, nil where none was read.
func (b *mqlBinary) signature() (*runningbinaries.Signature, error) {
	if b.parent != nil {
		if err := b.parent.resolveSignatures(); err != nil {
			return nil, err
		}
	}
	return b.sig, nil
}

func (b *mqlBinary) signatureStatus() (string, error) {
	sig, err := b.signature()
	if err != nil {
		return "", err
	}
	if sig == nil {
		b.SignatureStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return sig.Status, nil
}

func (b *mqlBinary) signer() (plugin.Resource, error) {
	sig, err := b.signature()
	if err != nil {
		return nil, err
	}
	if sig != nil && len(sig.Certificate) != 0 {
		block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sig.Certificate})
		cert, err := parsedCertificate(b.MqlRuntime, string(block))
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}
	b.Signer.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
