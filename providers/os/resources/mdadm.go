// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
)

// validMdDevicePath matches standard md device paths like /dev/md0, /dev/md127, /dev/md/name
var validMdDevicePath = regexp.MustCompile(`^/dev/md[0-9a-zA-Z/_-]+$`)

type mqlMdadmArrayInternal struct {
	cachedDevices []parsedMdadmDevice
}

type mqlMdadmDeviceInternal struct {
	parentArrayName string
}

func (m *mqlMdadm) id() (string, error) {
	return "mdadm", nil
}

func (m *mqlMdadm) arrays() ([]any, error) {
	// Discover arrays via mdadm --detail --scan
	o, err := CreateResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData("mdadm --detail --scan"),
	})
	if err != nil {
		return nil, err
	}
	cmd := o.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return nil, err
	}
	if run.exitcode != 0 {
		// mdadm not installed or no arrays
		return []any{}, nil
	}

	arrayNames := parseMdadmScan(run.stdout)
	if len(arrayNames) == 0 {
		return []any{}, nil
	}

	var results []any
	for _, name := range arrayNames {
		if !validMdDevicePath.MatchString(name) {
			continue
		}
		o, err := CreateResource(m.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(fmt.Sprintf("mdadm --detail %q", name)),
		})
		if err != nil {
			return nil, err
		}
		detail := o.(*mqlCommand)
		detailRun, err := commandResult(detail)
		if err != nil {
			return nil, err
		}
		if detailRun.exitcode != 0 {
			continue
		}

		arr := parseMdadmDetail(detailRun.stdout)

		mqlArray, err := CreateResource(m.MqlRuntime, "mdadm.array", map[string]*llx.RawData{
			"name":           llx.StringData(name),
			"level":          llx.StringData(arr.level),
			"state":          llx.StringData(arr.state),
			"activeDevices":  llx.IntData(arr.activeDevices),
			"workingDevices": llx.IntData(arr.workingDevices),
			"failedDevices":  llx.IntData(arr.failedDevices),
			"spareDevices":   llx.IntData(arr.spareDevices),
			"size":           llx.IntData(arr.size),
			"uuid":           llx.StringData(arr.uuid),
			"resyncProgress": llx.FloatData(arr.resyncProgress),
		})
		if err != nil {
			return nil, err
		}

		mqlArr := mqlArray.(*mqlMdadmArray)
		mqlArr.cachedDevices = arr.devices

		results = append(results, mqlArray)
	}
	return results, nil
}

func (a *mqlMdadmArray) id() (string, error) {
	return a.Name.Data, nil
}

func (a *mqlMdadmArray) devices() ([]any, error) {
	arrayName := a.Name.Data
	var results []any
	for _, d := range a.cachedDevices {
		mqlDev, err := CreateResource(a.MqlRuntime, "mdadm.device", map[string]*llx.RawData{
			"name":  llx.StringData(d.name),
			"role":  llx.IntData(d.role),
			"state": llx.StringData(d.state),
		})
		if err != nil {
			return nil, err
		}
		dev := mqlDev.(*mqlMdadmDevice)
		dev.parentArrayName = arrayName
		results = append(results, mqlDev)
	}
	return results, nil
}

func (d *mqlMdadmDevice) id() (string, error) {
	return "mdadm.device:" + d.parentArrayName + ":" + d.Name.Data, nil
}

// parseMdadmScan extracts array device names from `mdadm --detail --scan` output.
// Each line looks like: ARRAY /dev/md0 metadata=1.2 name=... UUID=...
func parseMdadmScan(output string) []string {
	var names []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "ARRAY ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			names = append(names, fields[1])
		}
	}
	return names
}

type parsedMdadmArray struct {
	level          string
	state          string
	activeDevices  int64
	workingDevices int64
	failedDevices  int64
	spareDevices   int64
	size           int64
	uuid           string
	resyncProgress float64
	devices        []parsedMdadmDevice
}

type parsedMdadmDevice struct {
	name  string
	role  int64
	state string
}

var mdadmDeviceLineRe = regexp.MustCompile(`^\s*\d+\s+\d+\s+\d+\s+(-?\d+)\s+(.+\S)\s+(/\S+)\s*$`)

// parseMdadmDetail parses the output of `mdadm --detail /dev/mdX`.
//
// Example output:
//
//	/dev/md0:
//	        Version : 1.2
//	  Creation Time : Mon Jan  1 00:00:00 2024
//	     Raid Level : raid1
//	     Array Size : 1048576 (1024.00 MiB 1073.74 MB)
//	        State : clean
//	   Active Devices : 2
//	  Working Devices : 2
//	   Failed Devices : 0
//	    Spare Devices : 0
//	             UUID : 12345678:abcdef01:23456789:abcdef01
//	    Rebuild Status : 45% complete
//
//	    Number   Major   Minor   RaidDevice   State
//	       0       8        1        0      active sync   /dev/sda1
//	       1       8       17        1      active sync   /dev/sdb1
func parseMdadmDetail(output string) parsedMdadmArray {
	arr := parsedMdadmArray{
		resyncProgress: -1,
	}

	inDeviceTable := false
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if inDeviceTable {
			matches := mdadmDeviceLineRe.FindStringSubmatch(line)
			if matches == nil {
				continue
			}
			role, _ := strconv.ParseInt(matches[1], 10, 64)
			arr.devices = append(arr.devices, parsedMdadmDevice{
				name:  matches[3],
				role:  role,
				state: strings.TrimSpace(matches[2]),
			})
			continue
		}

		if strings.Contains(line, "Number") && strings.Contains(line, "Major") && strings.Contains(line, "RaidDevice") {
			inDeviceTable = true
			continue
		}

		if !strings.Contains(line, " : ") {
			continue
		}

		parts := strings.SplitN(line, " : ", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch key {
		case "Raid Level":
			arr.level = val
		case "State":
			arr.state = val
		case "Active Devices":
			arr.activeDevices, _ = strconv.ParseInt(val, 10, 64)
		case "Working Devices":
			arr.workingDevices, _ = strconv.ParseInt(val, 10, 64)
		case "Failed Devices":
			arr.failedDevices, _ = strconv.ParseInt(val, 10, 64)
		case "Spare Devices":
			arr.spareDevices, _ = strconv.ParseInt(val, 10, 64)
		case "Array Size":
			// Format: "1048576 (1024.00 MiB 1073.74 MB)" - first token is KiB
			sizeStr := strings.Fields(val)
			if len(sizeStr) > 0 {
				arr.size, _ = strconv.ParseInt(sizeStr[0], 10, 64)
			}
		case "UUID":
			arr.uuid = val
		case "Rebuild Status":
			// Format: "45% complete"
			arr.resyncProgress = parseRebuildPercent(val)
		}
	}

	return arr
}

// parseRebuildPercent extracts the percentage from "45% complete"
func parseRebuildPercent(val string) float64 {
	val = strings.TrimSpace(val)
	if idx := strings.Index(val, "%"); idx > 0 {
		f, err := strconv.ParseFloat(val[:idx], 64)
		if err != nil {
			return -1
		}
		return f
	}
	return -1
}
