// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"context"
	"errors"
	"github.com/Ullaakut/nmap/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
	"io"
	"strings"
	"time"
)

type nmapVersion struct {
	Version               string
	Platform              string
	CompiledWith          []string
	CompiledWithout       []string
	AvailableNsockEngines []string
}

func parseNmapVersionOutput(r io.Reader) nmapVersion {
	version := nmapVersion{
		CompiledWith:          []string{},
		CompiledWithout:       []string{},
		AvailableNsockEngines: []string{},
	}
	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Nmap version") {
			// "Nmap version 7.95 ( https://nmap.org )" -> the third field is the version
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				version.Version = fields[2]
			}
			continue
		}
		m := strings.Split(line, ":")
		if len(m) != 2 {
			continue
		}
		key := strings.TrimSpace(m[0])
		value := strings.TrimSpace(m[1])
		if value == "" {
			continue
		}
		switch key {
		case "Platform":
			version.Platform = value
		case "Compiled with":
			version.CompiledWith = strings.Split(value, " ")
		case "Compiled without":
			version.CompiledWithout = strings.Split(value, " ")
		case "Available nsock engines":
			version.AvailableNsockEngines = strings.Split(value, " ")
		}
	}

	return version
}

func (r *mqlNmap) version() (*mqlNmapVersionInformation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// retrieve nmap version. We let the SDK resolve the nmap binary from PATH
	// (as the scan resources do) rather than hardcoding an install path.
	scanner, err := nmap.NewScanner(
		ctx,
		// we can ignore the deprecation warning since the -V flag is not supported by the nmap library
		nmap.WithCustomArguments("-V"),
	)
	if err != nil {
		return nil, err
	}

	// NOTE: -V does not return xml output, so Run cannot parse it and returns a
	// non-nil error we intentionally ignore. But Run also returns a nil result
	// when the nmap process fails to start (e.g. the binary is missing), so we
	// must guard against a nil result before reading it to avoid a panic.
	results, _, _ := scanner.Run()
	if results == nil {
		return nil, errors.New("unable to run nmap to determine its version")
	}

	info := parseNmapVersionOutput(results.ToReader())

	runtime := r.MqlRuntime
	resource, err := CreateResource(runtime, "nmap.versionInformation", map[string]*llx.RawData{
		"__id":            llx.StringData("nmap.versionInformation"),
		"version":         llx.StringData(info.Version),
		"platform":        llx.StringData(info.Platform),
		"compiledWith":    llx.ArrayData(convert.SliceAnyToInterface(info.CompiledWith), types.String),
		"compiledWithout": llx.ArrayData(convert.SliceAnyToInterface(info.CompiledWithout), types.String),
		"nsockEngines":    llx.ArrayData(convert.SliceAnyToInterface(info.AvailableNsockEngines), types.String),
	})
	return resource.(*mqlNmapVersionInformation), err
}
