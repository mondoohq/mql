// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Command gen builds the Windows time zone ID to IANA name table from the
// Unicode CLDR.
//
// Two CLDR data files go into it, both taken from the same tagged release:
//
//   - common/supplemental/windowsZones.xml maps each Windows zone ID to a
//     CLDR zone ID. The entry for territory "001" is the default for that
//     Windows zone.
//   - common/bcp47/timezone.xml says which IANA name each CLDR zone ID stands
//     for today. CLDR keeps the names it first used ("Asia/Calcutta",
//     "Asia/Katmandu"), and records the current IANA name ("Asia/Kolkata",
//     "Asia/Kathmandu") in the `iana` attribute, so the table reports the same
//     names a Linux or macOS system does.
//
// Usage, from providers/os/resources/date (or `go generate` there):
//
//	go run ./gen -release release-48-2 -out windows_zones.gen.go
//
// -windows-zones and -timezones read local copies of the two files instead of
// downloading them.
package main

import (
	"bytes"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const rawBase = "https://raw.githubusercontent.com/unicode-org/cldr/"

const (
	windowsZonesPath = "common/supplemental/windowsZones.xml"
	timezonesPath    = "common/bcp47/timezone.xml"
	licensePath      = "LICENSE"
)

func main() {
	release := flag.String("release", "", "CLDR release tag, e.g. release-48-2")
	out := flag.String("out", "windows_zones.gen.go", "path of the Go file to write")
	windowsZonesFile := flag.String("windows-zones", "", "local windowsZones.xml (default: download)")
	timezonesFile := flag.String("timezones", "", "local bcp47 timezone.xml (default: download)")
	licenseFile := flag.String("license", "", "local CLDR LICENSE (default: download)")
	flag.Parse()

	if *release == "" {
		fmt.Fprintln(os.Stderr, "gen: -release is required")
		os.Exit(1)
	}
	if err := run(*release, *out, *windowsZonesFile, *timezonesFile, *licenseFile); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run(release, out, windowsZonesFile, timezonesFile, licenseFile string) error {
	windowsZones, err := load(release, windowsZonesPath, windowsZonesFile)
	if err != nil {
		return err
	}
	timezones, err := load(release, timezonesPath, timezonesFile)
	if err != nil {
		return err
	}
	license, err := load(release, licensePath, licenseFile)
	if err != nil {
		return err
	}

	table, err := buildTable(windowsZones, timezones)
	if err != nil {
		return err
	}
	// A truncated download or an error page parses as a short table. CLDR
	// has mapped well over a hundred Windows zones for years.
	if len(table.zones) < 100 {
		return fmt.Errorf("only %d Windows zones mapped, the CLDR data looks incomplete", len(table.zones))
	}

	src, err := render(release, table, string(license))
	if err != nil {
		return err
	}
	return os.WriteFile(out, src, 0o644)
}

func load(release, path, local string) ([]byte, error) {
	if local != "" {
		return os.ReadFile(local)
	}
	url := rawBase + release + "/" + path
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

type windowsZonesDoc struct {
	MapTimezones struct {
		OtherVersion string `xml:"otherVersion,attr"`
		TypeVersion  string `xml:"typeVersion,attr"`
		MapZones     []struct {
			Other     string `xml:"other,attr"`
			Territory string `xml:"territory,attr"`
			Type      string `xml:"type,attr"`
		} `xml:"mapZone"`
	} `xml:"windowsZones>mapTimezones"`
}

type timezonesDoc struct {
	Keys []struct {
		Name  string `xml:"name,attr"`
		Types []struct {
			Alias string `xml:"alias,attr"`
			IANA  string `xml:"iana,attr"`
		} `xml:"type"`
	} `xml:"keyword>key"`
}

type table struct {
	// windowsVersion and tzVersion are the otherVersion and typeVersion
	// attributes windowsZones.xml carries.
	windowsVersion string
	tzVersion      string
	// zones maps a Windows zone ID to an IANA name.
	zones map[string]string
}

// buildTable maps every Windows zone ID to the current IANA name of its
// territory "001" CLDR zone.
func buildTable(windowsZonesXML, timezonesXML []byte) (*table, error) {
	var wz windowsZonesDoc
	if err := decodeXML(windowsZonesXML, &wz); err != nil {
		return nil, fmt.Errorf("windowsZones.xml: %w", err)
	}
	var tz timezonesDoc
	if err := decodeXML(timezonesXML, &tz); err != nil {
		return nil, fmt.Errorf("timezone.xml: %w", err)
	}

	// Every alias of a CLDR zone resolves to its current IANA name: the
	// `iana` attribute when CLDR records one, otherwise the first alias,
	// which is then both the CLDR and the IANA name.
	ianaName := map[string]string{}
	for _, key := range tz.Keys {
		if key.Name != "tz" {
			continue
		}
		for _, t := range key.Types {
			aliases := strings.Fields(t.Alias)
			if len(aliases) == 0 {
				continue
			}
			canonical := t.IANA
			if canonical == "" {
				canonical = aliases[0]
			}
			for _, a := range aliases {
				ianaName[a] = canonical
			}
		}
	}
	if len(ianaName) == 0 {
		return nil, errors.New("timezone.xml: no tz aliases found")
	}

	res := &table{
		windowsVersion: wz.MapTimezones.OtherVersion,
		tzVersion:      wz.MapTimezones.TypeVersion,
		zones:          map[string]string{},
	}
	for _, mz := range wz.MapTimezones.MapZones {
		if mz.Territory != "001" {
			continue
		}
		// The 001 entry carries a single zone, but the attribute is a list
		// in the other territories, so take the first name to be safe.
		fields := strings.Fields(mz.Type)
		if mz.Other == "" || len(fields) == 0 {
			return nil, fmt.Errorf("windowsZones.xml: incomplete 001 entry %q -> %q", mz.Other, mz.Type)
		}
		zone := fields[0]
		if canonical, ok := ianaName[zone]; ok {
			zone = canonical
		}
		if prev, ok := res.zones[mz.Other]; ok && prev != zone {
			return nil, fmt.Errorf("windowsZones.xml: %q maps to both %q and %q", mz.Other, prev, zone)
		}
		res.zones[mz.Other] = zone
	}
	return res, nil
}

func decodeXML(data []byte, v any) error {
	// The files reference a DTD, which the decoder skips: the attributes
	// read here carry no defaults from it.
	return xml.NewDecoder(bytes.NewReader(data)).Decode(v)
}

func render(release string, t *table, license string) ([]byte, error) {
	ids := make([]string, 0, len(t.zones))
	for id := range t.zones {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var b bytes.Buffer
	b.WriteString("// Code generated by go run ./gen; DO NOT EDIT.\n\n")
	fmt.Fprintf(&b, "// Windows time zone IDs mapped to IANA time zone names, from the Unicode\n")
	fmt.Fprintf(&b, "// CLDR %s:\n//\n", release)
	fmt.Fprintf(&b, "//\t%s%s/%s (territory \"001\")\n", rawBase, release, windowsZonesPath)
	fmt.Fprintf(&b, "//\t%s%s/%s (current IANA names)\n//\n", rawBase, release, timezonesPath)
	fmt.Fprintf(&b, "// windowsZones.xml records otherVersion=%q and typeVersion=%q.\n", t.windowsVersion, t.tzVersion)
	b.WriteString("//\n// The data is distributed under the following license:\n//\n")
	for _, line := range strings.Split(strings.TrimRight(license, "\n"), "\n") {
		line = strings.TrimRight(line, " \t\r")
		if line == "" {
			b.WriteString("//\n")
			continue
		}
		b.WriteString("//\t" + line + "\n")
	}
	b.WriteString("\npackage date\n\n")
	b.WriteString("// windowsZoneToIANA maps a Windows time zone ID to its IANA name.\n")
	b.WriteString("var windowsZoneToIANA = map[string]string{\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "\t%q: %q,\n", id, t.zones[id])
	}
	b.WriteString("}\n")

	return format.Source(b.Bytes())
}
