// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestParseLvmPVs(t *testing.T) {
	// Output of: pvs --reportformat json --units b --nosuffix -o pv_name,pv_uuid,vg_name,pv_fmt,pv_attr,pv_size,pv_free
	input := `{
      "report": [
          {
              "pv": [
                  {"pv_name":"/dev/sda1", "pv_uuid":"abc-123", "vg_name":"vg0",    "pv_fmt":"lvm2", "pv_attr":"a--", "pv_size":"10737418240", "pv_free":"2147483648"},
                  {"pv_name":"/dev/sdb1", "pv_uuid":"def-456", "vg_name":"",       "pv_fmt":"lvm2", "pv_attr":"---", "pv_size":"5368709120",  "pv_free":"5368709120"}
              ]
          }
      ]
  }
`
	pvs, err := parseLvmPVs(input)
	require.NoError(t, err)
	require.Len(t, pvs, 2)

	assert.Equal(t, "/dev/sda1", pvs[0].Name)
	assert.Equal(t, "abc-123", pvs[0].UUID)
	assert.Equal(t, "vg0", pvs[0].VGName)
	assert.Equal(t, "lvm2", pvs[0].Format)
	assert.Equal(t, "a--", pvs[0].Attributes)
	assert.Equal(t, int64(10737418240), pvs[0].SizeBytes)
	assert.Equal(t, int64(2147483648), pvs[0].FreeBytes)

	// Unassigned PV — vg_name empty
	assert.Equal(t, "/dev/sdb1", pvs[1].Name)
	assert.Equal(t, "", pvs[1].VGName)
}

func TestParseLvmVGs(t *testing.T) {
	input := `{
      "report": [
          {
              "vg": [
                  {"vg_name":"vg0", "vg_uuid":"vg-uuid-1", "vg_attr":"wz--n-", "vg_size":"21474836480", "vg_free":"5368709120", "pv_count":"2", "lv_count":"3", "snap_count":"1"}
              ]
          }
      ]
  }
`
	vgs, err := parseLvmVGs(input)
	require.NoError(t, err)
	require.Len(t, vgs, 1)

	v := vgs[0]
	assert.Equal(t, "vg0", v.Name)
	assert.Equal(t, "vg-uuid-1", v.UUID)
	assert.Equal(t, "wz--n-", v.Attributes)
	assert.Equal(t, int64(21474836480), v.SizeBytes)
	assert.Equal(t, int64(5368709120), v.FreeBytes)
	assert.Equal(t, int64(2), v.PVCount)
	assert.Equal(t, int64(3), v.LVCount)
	assert.Equal(t, int64(1), v.SnapshotCount)
}

func TestParseLvmLVs(t *testing.T) {
	// Mix of: regular LV, snapshot (origin set), thin pool (data_percent set, pool_lv empty),
	// thin LV (pool_lv set).
	input := `{
      "report": [
          {
              "lv": [
                  {"lv_name":"root",    "lv_path":"/dev/vg0/root",    "lv_uuid":"lv-1", "vg_name":"vg0", "lv_attr":"-wi-ao----", "lv_size":"10737418240", "origin":"",     "data_percent":"",      "pool_lv":""},
                  {"lv_name":"snap",    "lv_path":"/dev/vg0/snap",    "lv_uuid":"lv-2", "vg_name":"vg0", "lv_attr":"swi-a-s---", "lv_size":"1073741824",  "origin":"root", "data_percent":"12.50", "pool_lv":""},
                  {"lv_name":"pool",    "lv_path":"",                  "lv_uuid":"lv-3", "vg_name":"vg0", "lv_attr":"twi-aotz--", "lv_size":"5368709120",  "origin":"",     "data_percent":"45.00", "pool_lv":""},
                  {"lv_name":"thindata","lv_path":"/dev/vg0/thindata", "lv_uuid":"lv-4", "vg_name":"vg0", "lv_attr":"Vwi-a-tz--", "lv_size":"2147483648",  "origin":"",     "data_percent":"30.25", "pool_lv":"pool"}
              ]
          }
      ]
  }
`
	lvs, err := parseLvmLVs(input)
	require.NoError(t, err)
	require.Len(t, lvs, 4)

	// Regular LV — data_percent is empty -> nil
	assert.Equal(t, "root", lvs[0].Name)
	assert.Equal(t, "/dev/vg0/root", lvs[0].Path)
	assert.Equal(t, "-wi-ao----", lvs[0].Attributes)
	assert.Equal(t, int64(10737418240), lvs[0].SizeBytes)
	assert.Equal(t, "", lvs[0].Origin)
	assert.Nil(t, lvs[0].DataPercent)
	assert.Equal(t, "", lvs[0].PoolName)

	// Snapshot
	assert.Equal(t, "snap", lvs[1].Name)
	assert.Equal(t, "root", lvs[1].Origin)
	require.NotNil(t, lvs[1].DataPercent)
	assert.Equal(t, 12.5, *lvs[1].DataPercent)

	// Thin pool
	assert.Equal(t, "pool", lvs[2].Name)
	require.NotNil(t, lvs[2].DataPercent)
	assert.Equal(t, 45.0, *lvs[2].DataPercent)

	// Thin volume
	assert.Equal(t, "thindata", lvs[3].Name)
	assert.Equal(t, "pool", lvs[3].PoolName)
	require.NotNil(t, lvs[3].DataPercent)
	assert.Equal(t, 30.25, *lvs[3].DataPercent)
}

func TestParseLvmEmptyReport(t *testing.T) {
	// LVM emits an empty array when no objects exist.
	input := `{"report": [{"pv": []}]}`
	pvs, err := parseLvmPVs(input)
	require.NoError(t, err)
	assert.Empty(t, pvs)
}

func TestParseLvmInt(t *testing.T) {
	v, err := parseLvmInt("pv_size", "")
	require.NoError(t, err)
	assert.Equal(t, int64(0), v)

	v, err = parseLvmInt("pv_size", "   ")
	require.NoError(t, err)
	assert.Equal(t, int64(0), v)

	v, err = parseLvmInt("pv_size", "12345")
	require.NoError(t, err)
	assert.Equal(t, int64(12345), v)

	v, err = parseLvmInt("pv_size", "  12345 ")
	require.NoError(t, err)
	assert.Equal(t, int64(12345), v)

	// Garbage values are surfaced as errors so callers don't silently
	// substitute 0 for an unparseable column.
	_, err = parseLvmInt("pv_size", "not a number")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pv_size")
}

func TestParseLvmFloat(t *testing.T) {
	// Empty is "not applicable" — nil pointer.
	v, err := parseLvmFloat("data_percent", "")
	require.NoError(t, err)
	assert.Nil(t, v)

	v, err = parseLvmFloat("data_percent", "12.5")
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, 12.5, *v)

	v, err = parseLvmFloat("data_percent", "100.00")
	require.NoError(t, err)
	require.NotNil(t, v)
	assert.Equal(t, 100.0, *v)

	// Garbage values are surfaced as errors.
	_, err = parseLvmFloat("data_percent", "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "data_percent")
}

// Output of LVM2 2.02.133 (Ubuntu 16.04), which predates --reportformat json,
// for a loopback VG holding a linear LV, a snapshot of it, a thin pool and a
// thin LV:
//
//	pvs --noheadings --nameprefixes --units b --nosuffix -o pv_name,pv_uuid,vg_name,pv_fmt,pv_attr,pv_size,pv_free
//	vgs --noheadings --nameprefixes --units b --nosuffix -o vg_name,vg_uuid,vg_attr,vg_size,vg_free,pv_count,lv_count,snap_count
//	lvs --noheadings --nameprefixes --units b --nosuffix -o lv_name,lv_path,lv_uuid,vg_name,lv_attr,lv_size,origin,data_percent,pool_lv
const (
	lvmLegacyPVs = `  LVM2_PV_NAME='/dev/loop5' LVM2_PV_UUID='EOWMaC-AeEB-gOKl-vvNm-Z5cc-POyg-7xe11O' LVM2_VG_NAME='mqltestvg' LVM2_PV_FMT='lvm2' LVM2_PV_ATTR='a--' LVM2_PV_SIZE='532676608' LVM2_PV_FREE='356515840'
`
	lvmLegacyVGs = `  LVM2_VG_NAME='mqltestvg' LVM2_VG_UUID='MZMDJ9-E9kQ-Y31i-2lHf-ipVN-GYOf-9Wjd0f' LVM2_VG_ATTR='wz--n-' LVM2_VG_SIZE='532676608' LVM2_VG_FREE='356515840' LVM2_PV_COUNT='1' LVM2_LV_COUNT='4' LVM2_SNAP_COUNT='1'
`
	lvmLegacyLVs = `  LVM2_LV_NAME='data' LVM2_LV_PATH='/dev/mqltestvg/data' LVM2_LV_UUID='4r6T3p-NLKn-pTCh-1JKj-nItX-LFs9-ONJzPu' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='owi-a-s---' LVM2_LV_SIZE='67108864' LVM2_ORIGIN='' LVM2_DATA_PERCENT='' LVM2_POOL_LV=''
  LVM2_LV_NAME='datasnap' LVM2_LV_PATH='/dev/mqltestvg/datasnap' LVM2_LV_UUID='FIHvj1-7fD8-WO3q-EsM1-yt6x-ov6I-CsXFVi' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='swi-a-s---' LVM2_LV_SIZE='33554432' LVM2_ORIGIN='data' LVM2_DATA_PERCENT='0.00' LVM2_POOL_LV=''
  LVM2_LV_NAME='pool' LVM2_LV_PATH='' LVM2_LV_UUID='40aJzM-Ef71-39cj-Zgq5-ThA4-yK3E-bctBfO' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='twi-aotz--' LVM2_LV_SIZE='67108864' LVM2_ORIGIN='' LVM2_DATA_PERCENT='0.00' LVM2_POOL_LV=''
  LVM2_LV_NAME='thin' LVM2_LV_PATH='/dev/mqltestvg/thin' LVM2_LV_UUID='F3h0RV-foJL-M9GG-MgND-3cWD-aoVA-ovHVJG' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='Vwi-a-tz--' LVM2_LV_SIZE='33554432' LVM2_ORIGIN='' LVM2_DATA_PERCENT='0.00' LVM2_POOL_LV='pool'
`
)

func TestParseLvmLegacyPVs(t *testing.T) {
	report, err := lvmNamePrefixedToJSON(lvmLegacyPVs, "pv")
	require.NoError(t, err)
	pvs, err := parseLvmPVs(report)
	require.NoError(t, err)
	require.Equal(t, []parsedLvmPV{{
		Name:       "/dev/loop5",
		UUID:       "EOWMaC-AeEB-gOKl-vvNm-Z5cc-POyg-7xe11O",
		VGName:     "mqltestvg",
		Format:     "lvm2",
		Attributes: "a--",
		SizeBytes:  532676608,
		FreeBytes:  356515840,
	}}, pvs)
}

func TestParseLvmLegacyVGs(t *testing.T) {
	report, err := lvmNamePrefixedToJSON(lvmLegacyVGs, "vg")
	require.NoError(t, err)
	vgs, err := parseLvmVGs(report)
	require.NoError(t, err)
	require.Equal(t, []parsedLvmVG{{
		Name:          "mqltestvg",
		UUID:          "MZMDJ9-E9kQ-Y31i-2lHf-ipVN-GYOf-9Wjd0f",
		Attributes:    "wz--n-",
		SizeBytes:     532676608,
		FreeBytes:     356515840,
		PVCount:       1,
		LVCount:       4,
		SnapshotCount: 1,
	}}, vgs)
}

func TestParseLvmLegacyLVs(t *testing.T) {
	report, err := lvmNamePrefixedToJSON(lvmLegacyLVs, "lv")
	require.NoError(t, err)
	lvs, err := parseLvmLVs(report)
	require.NoError(t, err)
	require.Len(t, lvs, 4)

	assert.Equal(t, "data", lvs[0].Name)
	assert.Equal(t, "/dev/mqltestvg/data", lvs[0].Path)
	assert.Equal(t, "4r6T3p-NLKn-pTCh-1JKj-nItX-LFs9-ONJzPu", lvs[0].UUID)
	assert.Equal(t, "mqltestvg", lvs[0].VGName)
	assert.Equal(t, "owi-a-s---", lvs[0].Attributes)
	assert.Equal(t, int64(67108864), lvs[0].SizeBytes)
	assert.Nil(t, lvs[0].DataPercent)

	assert.Equal(t, "datasnap", lvs[1].Name)
	assert.Equal(t, "data", lvs[1].Origin)
	require.NotNil(t, lvs[1].DataPercent)
	assert.Equal(t, 0.0, *lvs[1].DataPercent)

	assert.Equal(t, "pool", lvs[2].Name)
	assert.Equal(t, "", lvs[2].Path)

	assert.Equal(t, "thin", lvs[3].Name)
	assert.Equal(t, "pool", lvs[3].PoolName)
	assert.Equal(t, int64(33554432), lvs[3].SizeBytes)
}

func TestParseLvmLegacyEmpty(t *testing.T) {
	// A host with no volume groups prints nothing and exits 0.
	report, err := lvmNamePrefixedToJSON("", "vg")
	require.NoError(t, err)
	vgs, err := parseLvmVGs(report)
	require.NoError(t, err)
	assert.Empty(t, vgs)
}

func TestParseLvmNamePrefixedLine(t *testing.T) {
	row, err := parseLvmNamePrefixedLine(`LVM2_PV_NAME='/dev/it's here' LVM2_VG_NAME=''`)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"pv_name": "/dev/it's here", "vg_name": ""}, row)

	row, err = parseLvmNamePrefixedLine(`LVM2_VG_NAME=vg0 LVM2_PV_COUNT=1`)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"vg_name": "vg0", "pv_count": "1"}, row)

	_, err = parseLvmNamePrefixedLine(`LVM2_VG_NAME='vg0`)
	require.Error(t, err)

	_, err = parseLvmNamePrefixedLine(`garbage`)
	require.Error(t, err)
}

func TestIsLvmReportFormatUnsupported(t *testing.T) {
	// stderr of vgs --reportformat json on LVM2 2.02.133 (Ubuntu 16.04), exit 3
	assert.True(t, isLvmReportFormatUnsupported("vgs: unrecognized option '--reportformat'\n  Error during parsing of command line.\n"))
	assert.False(t, isLvmReportFormatUnsupported("  Volume group \"nosuchvg\" not found\n"))
	assert.False(t, isLvmReportFormatUnsupported("  WARNING: Running as a non-root user. Functionality may be unavailable.\n  /run/lock/lvm/P_global:aux: open failed: Permission denied\n"))
}

func TestParseLvmLegacyMatchesJSON(t *testing.T) {
	// LVM2 2.03.33 (RHEL 9) supports both formats. The same lvs report in
	// each must parse to the same values, so hosts on the fallback path see
	// what JSON-capable hosts see.
	jsonOut := `  {
      "report": [
          {
              "lv": [
                  {"lv_name":"data", "lv_path":"/dev/mqltestvg/data", "lv_uuid":"8PbvRT-0Gl3-Sjm5-3By3-8jNq-cNDH-b1gaPC", "vg_name":"mqltestvg", "lv_attr":"owi-a-s---", "lv_size":"67108864", "origin":"", "data_percent":"", "pool_lv":""},
                  {"lv_name":"datasnap", "lv_path":"/dev/mqltestvg/datasnap", "lv_uuid":"Tgv0NB-1U0f-FFB4-I1IX-PCKm-0m6h-t3z12o", "vg_name":"mqltestvg", "lv_attr":"swi-a-s---", "lv_size":"33554432", "origin":"data", "data_percent":"0.00", "pool_lv":""},
                  {"lv_name":"pool", "lv_path":"", "lv_uuid":"Ra5S47-m5Ps-J7Yj-Rovd-3gQu-bY4B-617aPr", "vg_name":"mqltestvg", "lv_attr":"twi-aotz--", "lv_size":"67108864", "origin":"", "data_percent":"0.00", "pool_lv":""},
                  {"lv_name":"thin", "lv_path":"/dev/mqltestvg/thin", "lv_uuid":"v0pnIs-wRbH-KoU7-7ehN-xxnV-PN0v-FazEc3", "vg_name":"mqltestvg", "lv_attr":"Vwi-a-tz--", "lv_size":"33554432", "origin":"", "data_percent":"0.00", "pool_lv":"pool"}
              ]
          }
      ]
      ,
      "log": [
      ]
  }
`
	legacyOut := `  LVM2_LV_NAME='data' LVM2_LV_PATH='/dev/mqltestvg/data' LVM2_LV_UUID='8PbvRT-0Gl3-Sjm5-3By3-8jNq-cNDH-b1gaPC' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='owi-a-s---' LVM2_LV_SIZE='67108864' LVM2_ORIGIN='' LVM2_DATA_PERCENT='' LVM2_POOL_LV=''
  LVM2_LV_NAME='datasnap' LVM2_LV_PATH='/dev/mqltestvg/datasnap' LVM2_LV_UUID='Tgv0NB-1U0f-FFB4-I1IX-PCKm-0m6h-t3z12o' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='swi-a-s---' LVM2_LV_SIZE='33554432' LVM2_ORIGIN='data' LVM2_DATA_PERCENT='0.00' LVM2_POOL_LV=''
  LVM2_LV_NAME='pool' LVM2_LV_PATH='' LVM2_LV_UUID='Ra5S47-m5Ps-J7Yj-Rovd-3gQu-bY4B-617aPr' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='twi-aotz--' LVM2_LV_SIZE='67108864' LVM2_ORIGIN='' LVM2_DATA_PERCENT='0.00' LVM2_POOL_LV=''
  LVM2_LV_NAME='thin' LVM2_LV_PATH='/dev/mqltestvg/thin' LVM2_LV_UUID='v0pnIs-wRbH-KoU7-7ehN-xxnV-PN0v-FazEc3' LVM2_VG_NAME='mqltestvg' LVM2_LV_ATTR='Vwi-a-tz--' LVM2_LV_SIZE='33554432' LVM2_ORIGIN='' LVM2_DATA_PERCENT='0.00' LVM2_POOL_LV='pool'
`
	fromJSON, err := parseLvmLVs(jsonOut)
	require.NoError(t, err)
	report, err := lvmNamePrefixedToJSON(legacyOut, "lv")
	require.NoError(t, err)
	fromLegacy, err := parseLvmLVs(report)
	require.NoError(t, err)
	require.Len(t, fromJSON, 4)
	assert.Equal(t, fromJSON, fromLegacy)
}

// vgs run by a non-root user on RHEL 7 (LVM2 2.02.187): it exits 0 with an
// empty report and names every refused open on stderr.
const rhel7NonRootVgsStdout = `  {
      "report": [
          {
              "vg": [
              ]
          }
      ]
  }
`

const rhel7NonRootVgsStderr = `  WARNING: Running as a non-root user. Functionality may be unavailable.
  /run/lvm/lvmetad.socket: connect failed: Permission denied
  WARNING: Failed to connect to lvmetad. Falling back to device scanning.
  /dev/mapper/control: open failed: Permission denied
  Failure to communicate with kernel device-mapper driver.
  Incompatible libdevmapper 1.02.170-RHEL7 (2020-03-24) and kernel driver (unknown version).
`

func TestIsLvmReportRefused(t *testing.T) {
	t.Run("non-root RHEL 7 empty report is refused", func(t *testing.T) {
		refused, err := isLvmReportRefused(rhel7NonRootVgsStdout, "vg", rhel7NonRootVgsStderr)
		require.NoError(t, err)
		assert.True(t, refused)
	})

	t.Run("an empty report without a refusal is a host without LVM", func(t *testing.T) {
		refused, err := isLvmReportRefused(rhel7NonRootVgsStdout, "vg", "")
		require.NoError(t, err)
		assert.False(t, refused)
	})

	t.Run("rows are reported even when some opens were refused", func(t *testing.T) {
		report := `{"report": [{"vg": [{"vg_name":"vg-data"}]}]}`
		refused, err := isLvmReportRefused(report, "vg", rhel7NonRootVgsStderr)
		require.NoError(t, err)
		assert.False(t, refused)
	})

	t.Run("empty --nameprefixes output with a refusal is refused", func(t *testing.T) {
		report, err := lvmNamePrefixedToJSON("", "lv")
		require.NoError(t, err)
		refused, err := isLvmReportRefused(report, "lv", "  /dev/mapper/control: open failed: Permission denied\n")
		require.NoError(t, err)
		assert.True(t, refused)
	})
}

func TestLvmCommandFailure(t *testing.T) {
	// LVM2 2.03 on RHEL 9 exits 5 for a non-root user and logs the refused
	// open in the JSON report on stdout; stderr carries only the warning.
	stdout := `  {
      "report": [
          {
              "vg": [
              ]
          }
      ]
      ,
      "log": [
          {"log_seq_num":"1", "log_type":"error", "log_context":"processing", "log_object_type":"vg", "log_object_name":"", "log_object_id":"", "log_object_group":"", "log_object_group_id":"", "log_message":"/run/lock/lvm/P_global:aux: open failed: Permission denied", "log_errno":"-1", "log_ret_code":"0"}
      ]
  }
`
	stderr := "  WARNING: Running as a non-root user. Functionality may be unavailable.\n"

	withStructuredErrors(t, false)
	// v13 returned this run as an unclassified error, never as an empty list
	err := lvmCommandFailure("vgs", 5, stdout, stderr)
	require.Error(t, err)
	assert.NotErrorIs(t, err, llx.ErrForbidden)

	withStructuredErrors(t, true)
	err = lvmCommandFailure("vgs", 5, stdout, stderr)
	assert.ErrorIs(t, err, llx.ErrForbidden)

	err = lvmCommandFailure("vgs", 5, "", "  Volume group \"vg0\" not found\n")
	require.Error(t, err)
	assert.NotErrorIs(t, err, llx.ErrForbidden)
}
