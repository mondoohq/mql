// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"encoding/json"
	"io"
	"path"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// macOSSystemSigner is the leaf certificate Apple signs the operating system's
// own applications with: Calculator, Finder, the CoreServices helpers, and the
// OS components Software Update keeps current under /Library/Apple. Apple's
// optional applications are signed differently: the App Store ones with
// "Apple Mac OS Application Signing", the Command Line Tools with "Software
// Signing".
const macOSSystemSigner = "macOS Software Signing"

// macOSSealedPrefixes are where only the operating system can put an
// application. /System is the sealed system volume, and the cryptexes Safari
// ships in are mounted under /System/Cryptexes. An application found there by
// listing the folders carries no signer, so the path has to decide.
var macOSSealedPrefixes = []string{
	"/System/",
}

// macOSCaskrooms are where Homebrew keeps an installed cask: Apple silicon
// installs under /opt/homebrew, Intel ones under /usr/local.
var macOSCaskrooms = []string{
	"/opt/homebrew/Caskroom",
	"/usr/local/Caskroom",
}

// macOSAppStoreInstallers are the processes that write a receipt when the App
// Store installs a package. Everything else that writes one (installer,
// Installer, softwareupdated, an MDM agent) runs an installer package.
var macOSAppStoreInstallers = map[string]bool{
	"appstoreagent": true,
	"appstored":     true,
}

// Sources says where each application came from (ADR 049). The first record
// that claims a bundle wins, in this order:
//
//  1. the operating system's own signature or the sealed system volume: os
//  2. the App Store's signature or receipt in the bundle: app-store
//  3. a Homebrew cask that links to the bundle: homebrew
//  4. an installer receipt that laid the bundle down: installer, or app-store
//     when the App Store wrote the receipt
//  5. anything else was copied in, usually from a disk image: direct
//
// The order matters because records go stale. The App Store can replace an
// application a cask installed and leave the cask's link behind, but it cannot
// leave a bundle signed by someone else.
func (mpm *MacOSPkgManager) Sources(pkgs []Package) ([]Source, error) {
	casks := readMacOSCaskApps(mpm.conn)
	receipts := mpm.receipts
	out := make([]Source, len(pkgs))
	for i := range pkgs {
		out[i] = macOSAppSource(pkgs[i], casks, receipts)
	}
	return out, nil
}

func macOSAppSource(pkg Package, casks map[string]string, receipts map[string]macOSReceipt) Source {
	if pkg.Format != MacosPkgFormat {
		return DefaultSource(pkg)
	}
	bundle := ""
	if len(pkg.Files) > 0 {
		bundle = path.Clean(pkg.Files[0].Path)
	}
	signer := ""
	appStore := false
	if pkg.MacOS != nil {
		signer = pkg.MacOS.Signer
		appStore = pkg.MacOS.AppStore
	}

	if signer == macOSSystemSigner || isMacOSSealedPath(bundle) {
		return Source{OSProvided: osProvided(true), Channel: ChannelOS, Name: "macOS"}
	}
	third := osProvided(false)
	switch {
	case pkg.Origin == "ios_app_store":
		return Source{OSProvided: third, Channel: ChannelAppStore, Name: "ios-app-store"}
	case appStore || pkg.Origin == "mac_app_store":
		return Source{OSProvided: third, Channel: ChannelAppStore, Name: "mac-app-store"}
	}
	if token, ok := casks[bundle]; ok && bundle != "" {
		return Source{OSProvided: third, Channel: ChannelHomebrew, Name: token}
	}
	if receipt, ok := receipts[bundle]; ok && bundle != "" {
		if macOSAppStoreInstallers[receipt.InstallProcessName] {
			return Source{OSProvided: third, Channel: ChannelAppStore, Name: "mac-app-store"}
		}
		return Source{OSProvided: third, Channel: ChannelInstaller, Name: receipt.PackageIdentifier}
	}
	return Source{OSProvided: third, Channel: ChannelDirect}
}

func isMacOSSealedPath(bundle string) bool {
	for _, prefix := range macOSSealedPrefixes {
		if strings.HasPrefix(bundle, prefix) {
			return true
		}
	}
	return false
}

// readMacOSCaskApps maps every application bundle a Homebrew cask installed to
// the cask's token.
//
// A cask that installs an application moves the bundle into the application
// folder and leaves a symlink to it in its version directory:
// /opt/homebrew/Caskroom/alfred/5.8,2348/Alfred 5.app -> /Applications/Alfred 5.app.
// The link is what ties the bundle to the cask, so it is read rather than
// assumed: a cask installed with --appdir puts the bundle elsewhere.
//
// Where links cannot be read, the cask's install receipt names the bundles
// (uninstall_artifacts, "app"), and they are taken to be in /Applications,
// Homebrew's default.
func readMacOSCaskApps(conn shared.Connection) map[string]string {
	out := map[string]string{}
	if conn == nil {
		return out
	}
	fs := conn.FileSystem()
	linkReader, canReadLinks := fs.(afero.LinkReader)
	for _, room := range macOSCaskrooms {
		tokens, err := readDirNames(fs, room)
		if err != nil {
			continue
		}
		for _, token := range tokens {
			caskDir := path.Join(room, token)
			linked := 0
			versions, err := readDirNames(fs, caskDir)
			if err != nil {
				continue
			}
			for _, version := range versions {
				if strings.HasPrefix(version, ".") {
					continue
				}
				entries, err := readDirNames(fs, path.Join(caskDir, version))
				if err != nil {
					continue
				}
				for _, entry := range entries {
					if !strings.EqualFold(path.Ext(entry), ".app") || !canReadLinks {
						continue
					}
					target, err := linkReader.ReadlinkIfPossible(path.Join(caskDir, version, entry))
					if err != nil || target == "" {
						continue
					}
					if !path.IsAbs(target) {
						target = path.Join(caskDir, version, target)
					}
					out[path.Clean(target)] = token
					linked++
				}
			}
			if linked > 0 {
				continue
			}
			for _, app := range readCaskReceiptApps(fs, path.Join(caskDir, ".metadata", "INSTALL_RECEIPT.json")) {
				out[path.Join("/Applications", app)] = token
			}
		}
	}
	return out
}

// caskInstallReceipt is the part of a cask's INSTALL_RECEIPT.json that names
// the bundles it installed. Each artifact is an object with one key; an "app"
// artifact holds a list of bundle names, or of [source, target] pairs when the
// cask renames the bundle.
type caskInstallReceipt struct {
	UninstallArtifacts []map[string]json.RawMessage `json:"uninstall_artifacts"`
}

func readCaskReceiptApps(fs afero.Fs, receiptPath string) []string {
	f, err := fs.Open(receiptPath)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil
	}
	return parseCaskReceiptApps(data)
}

func parseCaskReceiptApps(data []byte) []string {
	var receipt caskInstallReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		log.Debug().Err(err).Msg("could not parse Homebrew cask install receipt")
		return nil
	}
	var apps []string
	for _, artifact := range receipt.UninstallArtifacts {
		raw, ok := artifact["app"]
		if !ok {
			continue
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			continue
		}
		for _, entry := range entries {
			var name string
			if json.Unmarshal(entry, &name) == nil {
				apps = append(apps, path.Base(name))
				continue
			}
			// a renamed bundle: [source, {"target": "Name.app"}] or [source, target]
			var pair []json.RawMessage
			if json.Unmarshal(entry, &pair) != nil || len(pair) == 0 {
				continue
			}
			target := ""
			if len(pair) > 1 {
				var opts struct {
					Target string `json:"target"`
				}
				if json.Unmarshal(pair[1], &opts) == nil && opts.Target != "" {
					target = opts.Target
				} else {
					_ = json.Unmarshal(pair[1], &target)
				}
			}
			if target == "" {
				_ = json.Unmarshal(pair[0], &target)
			}
			if target != "" {
				apps = append(apps, path.Base(target))
			}
		}
	}
	return apps
}
