// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bufio"
	"io"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/os/connection/shared"
	plist "howett.net/plist"
)

// macOSReceiptDirs are where the macOS installer keeps one receipt per
// installed flat package: <package id>.plist records when and at which version
// the package was installed, <package id>.bom lists the paths it laid down.
// /var/db/receipts holds the receipts of third-party installers and the App
// Store. /Library/Apple/System/Library/Receipts holds those of the Apple
// packages Software Update installs outside a full OS update, such as XProtect
// and the Command Line Tools.
var macOSReceiptDirs = []string{
	"/var/db/receipts",
	"/Library/Apple/System/Library/Receipts",
}

// macOSReceiptBundlesCmd lists, for every receipt, the application bundles its
// bill of materials installed. It is one command for the whole host rather
// than one per application: each receipt's name is printed behind a "#", and
// the bundle directories it lists follow, relative to the receipt's install
// prefix. Only directories are listed and only those ending in .app are kept,
// which drops the thousands of files an application ships with.
//
// A directory without receipts leaves its glob unexpanded; lsbom then fails on
// the literal path and prints nothing, which reads as no receipts.
var macOSReceiptBundlesCmd = `for b in ` + strings.Join(macOSReceiptDirs, "/*.bom ") + `/*.bom; do printf '#%s\n' "$b"; lsbom -s -d "$b" 2>/dev/null | grep -i '\.app$'; done`

// macOSReceipt is the part of an installer receipt that dates an install.
type macOSReceipt struct {
	PackageIdentifier string    `plist:"PackageIdentifier"`
	PackageVersion    string    `plist:"PackageVersion"`
	InstallDate       time.Time `plist:"InstallDate"`
	// InstallPrefixPath is the directory the bill of materials is relative
	// to. Usually "/", but App Store receipts carry "Applications", with no
	// leading slash.
	InstallPrefixPath string `plist:"InstallPrefixPath"`
}

// parseMacOSReceiptBundles reads the output of macOSReceiptBundlesCmd into a
// map from each receipt's bill of materials to the bundle paths it lists.
func parseMacOSReceiptBundles(r io.Reader) (map[string][]string, error) {
	out := map[string][]string{}
	current := ""
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if bom, ok := strings.CutPrefix(line, "#"); ok {
			current = bom
			continue
		}
		if current == "" || line == "" {
			continue
		}
		out[current] = append(out[current], line)
	}
	return out, scanner.Err()
}

// readMacOSReceipts maps every application bundle an installer receipt claims
// to that receipt. It runs one command to list the bundles of all receipts and
// reads each receipt's plist once.
//
// When several receipts claim the same bundle, the one installed last wins:
// Keynote 14 and Keynote 15 ship as separately named packages that both install
// /Applications/Keynote.app, and the later install is the one on disk.
func readMacOSReceipts(conn shared.Connection) map[string]macOSReceipt {
	if conn == nil || !conn.Capabilities().Has(shared.Capability_RunCommand) {
		return nil
	}
	cmd, err := conn.RunCommand(macOSReceiptBundlesCmd)
	if err != nil {
		log.Debug().Err(err).Msg("could not list macOS installer receipts")
		return nil
	}
	boms, err := parseMacOSReceiptBundles(cmd.Stdout)
	if err != nil {
		log.Debug().Err(err).Msg("could not read macOS installer receipts")
		return nil
	}

	byPath := map[string]macOSReceipt{}
	for bom, bundles := range boms {
		receipt, ok := readMacOSReceipt(conn, strings.TrimSuffix(bom, ".bom")+".plist")
		if !ok {
			continue
		}
		prefix := path.Join("/", receipt.InstallPrefixPath)
		for _, bundle := range bundles {
			p := path.Join(prefix, bundle)
			if prev, ok := byPath[p]; ok && !receipt.InstallDate.After(prev.InstallDate) {
				continue
			}
			byPath[p] = receipt
		}
	}
	return byPath
}

func readMacOSReceipt(conn shared.Connection, plistPath string) (macOSReceipt, bool) {
	var receipt macOSReceipt
	f, err := conn.FileSystem().Open(plistPath)
	if err != nil {
		log.Debug().Err(err).Str("path", plistPath).Msg("could not open installer receipt")
		return receipt, false
	}
	defer f.Close()
	content, err := io.ReadAll(f)
	if err != nil {
		log.Debug().Err(err).Str("path", plistPath).Msg("could not read installer receipt")
		return receipt, false
	}
	if _, err := plist.Unmarshal(content, &receipt); err != nil {
		log.Debug().Err(err).Str("path", plistPath).Msg("could not parse installer receipt")
		return macOSReceipt{}, false
	}
	return receipt, !receipt.InstallDate.IsZero()
}

var versionNumbers = regexp.MustCompile(`\d+`)

// receiptMatchesVersion reports whether a receipt records the install of the
// application version that is on disk now.
//
// A receipt is written when a package is installed and is not touched when the
// application later replaces itself: an app with its own updater, or an App
// Store app restored by Migration Assistant and updated afterwards, keeps a
// receipt naming the version it was first installed at. That receipt's date
// is when a version no longer on disk was installed, so it is not reported.
//
// The comparison is on the numeric components. The application's must equal
// the receipt's or be a leading run of them, because package versions often
// append a build number the bundle's short version leaves out: Keynote 15.3.1
// ships as package version 15.3.1.1.1785016684, and Zoom's "7.2.2 (88465)" as
// 7.2.2.88465. A package version of "0", which some vendors ship regardless of
// the application inside, matches nothing.
func receiptMatchesVersion(appVersion, receiptVersion string) bool {
	app := versionNumbers.FindAllString(appVersion, -1)
	rec := versionNumbers.FindAllString(receiptVersion, -1)
	if len(app) == 0 || len(app) > len(rec) {
		return false
	}
	for i := range app {
		if strings.TrimLeft(app[i], "0") != strings.TrimLeft(rec[i], "0") {
			return false
		}
	}
	return true
}

// applyMacOSReceiptInstallDates sets the install date of every application an
// installer receipt dates. Applications without a receipt, or whose receipt
// names another version, keep a zero install date.
func applyMacOSReceiptInstallDates(pkgs []Package, receipts map[string]macOSReceipt) {
	if len(receipts) == 0 {
		return
	}
	for i := range pkgs {
		if len(pkgs[i].Files) == 0 {
			continue
		}
		receipt, ok := receipts[path.Clean(pkgs[i].Files[0].Path)]
		if !ok || !receiptMatchesVersion(pkgs[i].Version, receipt.PackageVersion) {
			continue
		}
		pkgs[i].InstallDate = receipt.InstallDate.UTC()
	}
}
