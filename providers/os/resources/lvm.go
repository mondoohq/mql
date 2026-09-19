// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (l *mqlLvm) id() (string, error) {
	return "lvm", nil
}

func (l *mqlLvm) physicalVolumes() ([]any, error) {
	stdout, ok, err := l.runLvmReport("pvs --reportformat json --units b --nosuffix -o pv_name,pv_uuid,vg_name,pv_fmt,pv_attr,pv_size,pv_free")
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}

	pvs, err := parseLvmPVs(stdout)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(pvs))
	for _, p := range pvs {
		mqlPV, err := CreateResource(l.MqlRuntime, "lvm.physicalVolume", map[string]*llx.RawData{
			"name":            llx.StringData(p.Name),
			"uuid":            llx.StringData(p.UUID),
			"volumeGroupName": llx.StringData(p.VGName),
			"format":          llx.StringData(p.Format),
			"attributes":      llx.StringData(p.Attributes),
			"sizeBytes":       llx.IntData(p.SizeBytes),
			"freeBytes":       llx.IntData(p.FreeBytes),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPV)
	}
	return res, nil
}

func (l *mqlLvm) volumeGroups() ([]any, error) {
	stdout, ok, err := l.runLvmReport("vgs --reportformat json --units b --nosuffix -o vg_name,vg_uuid,vg_attr,vg_size,vg_free,pv_count,lv_count,snap_count")
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}

	vgs, err := parseLvmVGs(stdout)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(vgs))
	for _, v := range vgs {
		mqlVG, err := CreateResource(l.MqlRuntime, "lvm.volumeGroup", map[string]*llx.RawData{
			"name":                llx.StringData(v.Name),
			"uuid":                llx.StringData(v.UUID),
			"attributes":          llx.StringData(v.Attributes),
			"sizeBytes":           llx.IntData(v.SizeBytes),
			"freeBytes":           llx.IntData(v.FreeBytes),
			"physicalVolumeCount": llx.IntData(v.PVCount),
			"logicalVolumeCount":  llx.IntData(v.LVCount),
			"snapshotCount":       llx.IntData(v.SnapshotCount),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlVG)
	}
	return res, nil
}

func (l *mqlLvm) logicalVolumes() ([]any, error) {
	stdout, ok, err := l.runLvmReport("lvs --reportformat json --units b --nosuffix -o lv_name,lv_path,lv_uuid,vg_name,lv_attr,lv_size,origin,data_percent,pool_lv")
	if err != nil {
		return nil, err
	}
	if !ok {
		return []any{}, nil
	}

	lvs, err := parseLvmLVs(stdout)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(lvs))
	for _, v := range lvs {
		mqlLV, err := CreateResource(l.MqlRuntime, "lvm.logicalVolume", map[string]*llx.RawData{
			"name":            llx.StringData(v.Name),
			"path":            llx.StringData(v.Path),
			"uuid":            llx.StringData(v.UUID),
			"volumeGroupName": llx.StringData(v.VGName),
			"attributes":      llx.StringData(v.Attributes),
			"sizeBytes":       llx.IntData(v.SizeBytes),
			"origin":          llx.StringData(v.Origin),
			"poolName":        llx.StringData(v.PoolName),
		})
		if err != nil {
			return nil, err
		}
		mqlLV.(*mqlLvmLogicalVolume).cacheDataPercent = v.DataPercent
		res = append(res, mqlLV)
	}
	return res, nil
}

// runLvmReport executes an lvm reporting command via the command resource.
// The second return value is false when lvm is not installed on the host —
// treated as "empty list" so a query against a non-LVM host succeeds with `[]`.
// Any other non-zero exit (permission denied, broken metadata, etc.) is
// surfaced as an error rather than silently producing an empty result.
func (l *mqlLvm) runLvmReport(cmdline string) (string, bool, error) {
	o, err := CreateResource(l.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(cmdline),
	})
	if err != nil {
		return "", false, err
	}
	cmd := o.(*mqlCommand)
	run, err := commandResult(cmd)
	if err != nil {
		return "", false, err
	}
	if run.exitcode == 0 {
		return run.stdout, true, nil
	}

	if isLvmNotInstalled(run.exitcode, run.stderr) {
		return "", false, nil
	}
	return "", false, fmt.Errorf("lvm command failed (exit %d): %s", run.exitcode, strings.TrimSpace(run.stderr))
}

// isLvmNotInstalled reports whether the failure of an lvm reporting command
// indicates that lvm tooling is missing on the host. Shells signal "command
// not found" with exit code 127; some environments instead emit a textual
// hint on stderr — we accept both as "not installed".
func isLvmNotInstalled(exitCode int64, stderr string) bool {
	if exitCode == 127 {
		return true
	}
	s := strings.ToLower(stderr)
	return strings.Contains(s, "command not found") ||
		strings.Contains(s, "no such file or directory")
}

func (l *mqlLvmPhysicalVolume) id() (string, error) {
	if l.Uuid.Data != "" {
		return "lvm.physicalVolume/" + l.Uuid.Data, nil
	}
	return "lvm.physicalVolume/" + l.Name.Data, nil
}

func (l *mqlLvmVolumeGroup) id() (string, error) {
	if l.Uuid.Data != "" {
		return "lvm.volumeGroup/" + l.Uuid.Data, nil
	}
	return "lvm.volumeGroup/" + l.Name.Data, nil
}

func (l *mqlLvmLogicalVolume) id() (string, error) {
	if l.Uuid.Data != "" {
		return "lvm.logicalVolume/" + l.Uuid.Data, nil
	}
	return "lvm.logicalVolume/" + l.VolumeGroupName.Data + "/" + l.Name.Data, nil
}

// mqlLvmLogicalVolumeInternal carries per-LV values that aren't directly
// surfaced as schema fields. cacheDataPercent is nil when the lvs report
// emitted an empty data_percent for this LV (e.g. a non-thin, non-snapshot
// LV) — distinct from a real 0.0 reading on a thin pool with no data
// written yet.
type mqlLvmLogicalVolumeInternal struct {
	cacheDataPercent *float64
}

func (l *mqlLvmLogicalVolume) dataPercent() (float64, error) {
	if l.cacheDataPercent == nil {
		l.DataPercent.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *l.cacheDataPercent, nil
}

// LVM reporting commands print all values as strings, even with --nosuffix
// and --units b. Numeric columns therefore need string-to-int/float parsing.
// Empty strings on integer columns (e.g. snap_count on a brand-new VG) are
// treated as zero; empty strings on float columns (e.g. data_percent on a
// non-thin LV) are surfaced as nil so callers can distinguish "absent" from
// a real 0.0 reading.

type parsedLvmPV struct {
	Name       string
	UUID       string
	VGName     string
	Format     string
	Attributes string
	SizeBytes  int64
	FreeBytes  int64
}

type parsedLvmVG struct {
	Name          string
	UUID          string
	Attributes    string
	SizeBytes     int64
	FreeBytes     int64
	PVCount       int64
	LVCount       int64
	SnapshotCount int64
}

type parsedLvmLV struct {
	Name       string
	Path       string
	UUID       string
	VGName     string
	Attributes string
	SizeBytes  int64
	Origin     string
	// DataPercent is nil when the column is empty (e.g. data_percent on a
	// non-thin LV) — distinct from a real 0.0 reading on a thin pool that
	// happens to have no data written yet.
	DataPercent *float64
	PoolName    string
}

type lvmReport[T any] struct {
	Report []map[string][]T `json:"report"`
}

type rawPV struct {
	PvName string `json:"pv_name"`
	PvUUID string `json:"pv_uuid"`
	VgName string `json:"vg_name"`
	PvFmt  string `json:"pv_fmt"`
	PvAttr string `json:"pv_attr"`
	PvSize string `json:"pv_size"`
	PvFree string `json:"pv_free"`
}

type rawVG struct {
	VgName    string `json:"vg_name"`
	VgUUID    string `json:"vg_uuid"`
	VgAttr    string `json:"vg_attr"`
	VgSize    string `json:"vg_size"`
	VgFree    string `json:"vg_free"`
	PvCount   string `json:"pv_count"`
	LvCount   string `json:"lv_count"`
	SnapCount string `json:"snap_count"`
}

type rawLV struct {
	LvName      string `json:"lv_name"`
	LvPath      string `json:"lv_path"`
	LvUUID      string `json:"lv_uuid"`
	VgName      string `json:"vg_name"`
	LvAttr      string `json:"lv_attr"`
	LvSize      string `json:"lv_size"`
	Origin      string `json:"origin"`
	DataPercent string `json:"data_percent"`
	PoolLv      string `json:"pool_lv"`
}

func parseLvmPVs(stdout string) ([]parsedLvmPV, error) {
	rows, err := decodeLvmReport[rawPV](stdout, "pv")
	if err != nil {
		return nil, err
	}
	out := make([]parsedLvmPV, 0, len(rows))
	for _, r := range rows {
		size, err := parseLvmInt("pv_size", r.PvSize)
		if err != nil {
			return nil, err
		}
		free, err := parseLvmInt("pv_free", r.PvFree)
		if err != nil {
			return nil, err
		}
		out = append(out, parsedLvmPV{
			Name:       r.PvName,
			UUID:       r.PvUUID,
			VGName:     r.VgName,
			Format:     r.PvFmt,
			Attributes: strings.TrimSpace(r.PvAttr),
			SizeBytes:  size,
			FreeBytes:  free,
		})
	}
	return out, nil
}

func parseLvmVGs(stdout string) ([]parsedLvmVG, error) {
	rows, err := decodeLvmReport[rawVG](stdout, "vg")
	if err != nil {
		return nil, err
	}
	out := make([]parsedLvmVG, 0, len(rows))
	for _, r := range rows {
		size, err := parseLvmInt("vg_size", r.VgSize)
		if err != nil {
			return nil, err
		}
		free, err := parseLvmInt("vg_free", r.VgFree)
		if err != nil {
			return nil, err
		}
		pvCount, err := parseLvmInt("pv_count", r.PvCount)
		if err != nil {
			return nil, err
		}
		lvCount, err := parseLvmInt("lv_count", r.LvCount)
		if err != nil {
			return nil, err
		}
		snapCount, err := parseLvmInt("snap_count", r.SnapCount)
		if err != nil {
			return nil, err
		}
		out = append(out, parsedLvmVG{
			Name:          r.VgName,
			UUID:          r.VgUUID,
			Attributes:    strings.TrimSpace(r.VgAttr),
			SizeBytes:     size,
			FreeBytes:     free,
			PVCount:       pvCount,
			LVCount:       lvCount,
			SnapshotCount: snapCount,
		})
	}
	return out, nil
}

func parseLvmLVs(stdout string) ([]parsedLvmLV, error) {
	rows, err := decodeLvmReport[rawLV](stdout, "lv")
	if err != nil {
		return nil, err
	}
	out := make([]parsedLvmLV, 0, len(rows))
	for _, r := range rows {
		size, err := parseLvmInt("lv_size", r.LvSize)
		if err != nil {
			return nil, err
		}
		dataPercent, err := parseLvmFloat("data_percent", r.DataPercent)
		if err != nil {
			return nil, err
		}
		out = append(out, parsedLvmLV{
			Name:        r.LvName,
			Path:        r.LvPath,
			UUID:        r.LvUUID,
			VGName:      r.VgName,
			Attributes:  strings.TrimSpace(r.LvAttr),
			SizeBytes:   size,
			Origin:      r.Origin,
			DataPercent: dataPercent,
			PoolName:    r.PoolLv,
		})
	}
	return out, nil
}

func decodeLvmReport[T any](stdout, key string) ([]T, error) {
	var report lvmReport[T]
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		return nil, err
	}
	var rows []T
	for _, section := range report.Report {
		rows = append(rows, section[key]...)
	}
	return rows, nil
}

// parseLvmInt parses an integer column from an lvm report. An empty string
// is treated as zero (lvm omits values for columns that don't apply to a row,
// e.g. snap_count on a brand-new VG), but any non-empty value that fails to
// parse is surfaced so callers don't silently treat "0" as "unparseable".
func parseLvmInt(field, s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("lvm: parse %s=%q as int: %w", field, s, err)
	}
	return v, nil
}

// parseLvmFloat parses a float column from an lvm report. Empty values
// (e.g. data_percent on a non-thin LV) return nil to signal "not
// applicable" — distinct from a real 0.0 reading. Non-empty values that
// fail to parse are surfaced as errors so a malformed report doesn't get
// silently coerced to nil.
func parseLvmFloat(field, s string) (*float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil, fmt.Errorf("lvm: parse %s=%q as float: %w", field, s, err)
	}
	return &v, nil
}
