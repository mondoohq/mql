// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/registry"
)

// CBSPackagesHiveKey is the Component Based Servicing package store, relative
// to the root of the SOFTWARE hive.
const CBSPackagesHiveKey = `Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages`

// cbsMumDir is where the package manifests live, relative to the root of the
// system volume.
const cbsMumDir = "Windows/servicing/Packages"

// cbsUpdatePackagePrefix marks the CBS packages that stand for an update
// (Package_for_RollupFix, Package_for_HotpatchFix_N, Package_N_for_KBnnn, ...).
// Component packages (Microsoft-Windows-...) and the Shared-/Wrapper- payload
// packages are implementation detail of an update and are not reported.
const cbsUpdatePackagePrefix = "Package_"

var cbsKBIdentifier = regexp.MustCompile(`(?i)^KB\d+$`)

// CBSPackageValues are the registry values of one CBS package key that the
// update inventory needs.
type CBSPackageValues struct {
	CurrentState int64
	// InstallTimeHigh and InstallTimeLow are the two halves of a FILETIME.
	InstallTimeHigh uint32
	InstallTimeLow  uint32
}

// CBSReader reads the CBS store of a Windows installation. It is an interface
// so the selection logic runs without a registry hive.
type CBSReader interface {
	// PackageNames lists the subkey names below the Packages key.
	PackageNames() ([]string, error)
	// PackageValues reads the values of one package key.
	PackageValues(name string) (CBSPackageValues, error)
	// OpenMUM opens the servicing manifest of one package
	// (<windir>\servicing\Packages\<name>.mum).
	OpenMUM(name string) (io.ReadCloser, error)
}

// CBSUpdate is an installed update found in the CBS store.
type CBSUpdate struct {
	// KB is the upper-case knowledge base id, e.g. "KB5120228".
	KB string
	// ReleaseType is the manifest's releaseType, e.g. "Security Update".
	ReleaseType string
	// InstalledOn is the install time (UTC), nil when the package has none.
	InstalledOn *time.Time
	// PackageName is the CBS package key the update was read from.
	PackageName string
}

// InstalledCBSUpdates returns the updates the Windows servicing stack reports
// as installed, one per KB. It reproduces what Get-HotFix lists: packages in
// state "installed" whose key starts with "Package_", with the KB taken from
// the identifier of the package manifest, because the key name carries the KB
// only for some of them (Package_for_RollupFix and Package_for_HotpatchFix_N
// do not). A package whose values or manifest cannot be read is skipped. An
// error is returned only when the packages cannot be listed.
func InstalledCBSUpdates(r CBSReader) ([]CBSUpdate, error) {
	names, err := r.PackageNames()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)

	seen := map[string]int{}
	res := []CBSUpdate{}
	for _, name := range names {
		if !strings.HasPrefix(name, cbsUpdatePackagePrefix) {
			continue
		}
		vals, err := r.PackageValues(name)
		if err != nil {
			log.Debug().Err(err).Str("package", name).Msg("windows.cbs> could not read package values")
			continue
		}
		if vals.CurrentState != CBSStateInstalled {
			continue
		}
		f, err := r.OpenMUM(name)
		if err != nil {
			log.Debug().Err(err).Str("package", name).Msg("windows.cbs> could not open package manifest")
			continue
		}
		identifier, releaseType, err := parseMUMPackage(f)
		f.Close()
		if err != nil {
			log.Debug().Err(err).Str("package", name).Msg("windows.cbs> could not parse package manifest")
			continue
		}
		if !cbsKBIdentifier.MatchString(identifier) {
			continue
		}
		kb := strings.ToUpper(identifier)
		installed := FileTimeToTime(vals.InstallTimeHigh, vals.InstallTimeLow)

		if i, ok := seen[kb]; ok {
			// several packages carry one KB (Package_6_for_KB..Package_22_for_KB..);
			// keep the first, but do not lose a date it lacks.
			if res[i].InstalledOn == nil && installed != nil {
				res[i].InstalledOn = installed
			}
			continue
		}
		seen[kb] = len(res)
		res = append(res, CBSUpdate{KB: kb, ReleaseType: releaseType, InstalledOn: installed, PackageName: name})
	}
	return res, nil
}

// parseMUMPackage returns the identifier and releaseType attributes of the
// first <package> element of a servicing manifest. Manifests can be large
// (the cumulative update's is over 1 MB) and the attributes are at the top, so
// the document is decoded as a stream and reading stops at that element.
func parseMUMPackage(r io.Reader) (identifier, releaseType string, err error) {
	br := bufio.NewReader(r)
	if head, perr := br.Peek(3); perr == nil && bytes.Equal(head, []byte{0xEF, 0xBB, 0xBF}) {
		_, _ = br.Discard(3)
	}
	dec := xml.NewDecoder(br)
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", "", errors.New("manifest has no package element")
			}
			return "", "", err
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "package" {
			continue
		}
		for _, a := range se.Attr {
			switch a.Name.Local {
			case "identifier":
				identifier = a.Value
			case "releaseType":
				releaseType = a.Value
			}
		}
		return identifier, releaseType, nil
	}
}

// filetimeEpochDiff is the number of seconds between 1601-01-01 (FILETIME
// epoch) and 1970-01-01.
const filetimeEpochDiff = 11644473600

// FileTimeToTime converts the two halves of a Windows FILETIME (100 ns ticks
// since 1601-01-01 UTC) into a UTC time. A zero or pre-1970 FILETIME is "not
// set" and yields nil.
func FileTimeToTime(high, low uint32) *time.Time {
	ticks := uint64(high)<<32 | uint64(low)
	secs := int64(ticks/10_000_000) - filetimeEpochDiff
	if secs <= 0 {
		return nil
	}
	t := time.Unix(secs, int64(ticks%10_000_000)*100).UTC()
	return &t
}

// OfflineCBSReader reads the CBS store out of a loaded SOFTWARE hive and the
// package manifests from the target's filesystem. Loading the hive only works
// when the scanner itself runs on Windows (see registry.RegistryHandler).
type OfflineCBSReader struct {
	rh *registry.RegistryHandler
	fs afero.Fs

	paths map[string]string
}

// NewOfflineCBSReader returns a reader over a handler that already has the
// SOFTWARE hive loaded and the filesystem rooted at the target's system volume.
func NewOfflineCBSReader(rh *registry.RegistryHandler, fs afero.Fs) *OfflineCBSReader {
	return &OfflineCBSReader{rh: rh, fs: fs, paths: map[string]string{}}
}

func (o *OfflineCBSReader) PackageNames() ([]string, error) {
	kids, err := o.rh.GetNativeRegistryKeyChildren(registry.Software, CBSPackagesHiveKey)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(kids))
	for _, k := range kids {
		names = append(names, k.Name)
		o.paths[k.Name] = cbsChildKeyPath(k)
	}
	return names, nil
}

// cbsChildKeyPath returns the full path of a child key. A child's Path is its
// PARENT's fully-qualified path (hive root resolved into it), so the name has
// to be appended, and the values must be read through the package-level
// reader, not through the handler again.
func cbsChildKeyPath(k registry.RegistryKeyChild) string {
	return k.Path + `\` + k.Name
}

func (o *OfflineCBSReader) PackageValues(name string) (CBSPackageValues, error) {
	path, ok := o.paths[name]
	if !ok {
		return CBSPackageValues{}, errors.New("unknown CBS package " + name)
	}
	items, err := registry.GetNativeRegistryKeyItems(path)
	if err != nil {
		return CBSPackageValues{}, err
	}
	var v CBSPackageValues
	for _, it := range items {
		switch strings.ToLower(it.Key) {
		case "currentstate":
			v.CurrentState = it.Value.Number
		case "installtimehigh":
			v.InstallTimeHigh = uint32(it.Value.Number)
		case "installtimelow":
			v.InstallTimeLow = uint32(it.Value.Number)
		}
	}
	return v, nil
}

func (o *OfflineCBSReader) OpenMUM(name string) (io.ReadCloser, error) {
	return o.fs.Open(cbsMumDir + "/" + name + ".mum")
}

// LoadOfflineCBSReader loads the SOFTWARE hive file at softwareHivePath and
// returns a reader over it, plus a function that unloads the hive again.
func LoadOfflineCBSReader(softwareHivePath string, fs afero.Fs) (*OfflineCBSReader, func(), error) {
	rh := registry.NewRegistryHandler()
	if err := rh.LoadSubkey(registry.Software, softwareHivePath); err != nil {
		return nil, func() {}, err
	}
	return NewOfflineCBSReader(rh, fs), func() {
		if err := rh.UnloadSubkeys(); err != nil {
			log.Debug().Err(err).Msg("windows.cbs> could not unload registry subkeys")
		}
	}, nil
}
