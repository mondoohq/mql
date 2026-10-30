// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCanonicalLivepatchStatusApplied(t *testing.T) {
	// canonical-livepatch v11.0.2 on Ubuntu 24.04, kernel 6.8.0-1047-aws with
	// livepatch 121.4 applied (machine id and digest redacted).
	data, err := os.ReadFile("testdata/livepatch/canonical-applied.json")
	require.NoError(t, err)

	report, err := parseCanonicalLivepatchStatus(data)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "121.4", report.version)
	assert.Equal(t, "applied", report.state)
	assert.Len(t, report.cves, 38)
	assert.Equal(t, "CVE-2025-68263", report.cves[0])
	assert.Contains(t, report.cves, "CVE-2026-31431")
}

func TestParseCanonicalLivepatchStatusNothingToApply(t *testing.T) {
	// The same client on kernel 7.0.0-1013-aws, for which no livepatch exists.
	data := []byte(`{
  "Client-Version": "v11.0.2",
  "Status": [
    {
      "Kernel": "7.0.0-1013.13~24.04.1-aws",
      "Running": true,
      "Livepatch": {"CheckState": "checked", "State": "nothing-to-apply", "Version": ""},
      "Supported": "supported",
      "UpgradeRequiredDate": "2027-10-05"
    }
  ],
  "Fixed-CVEs": {"Timestamp": "", "Kernel-Package-Fixes": [], "Installed-Kernels": [], "Patched-CVEs": [], "Digest": ""}
}`)
	report, err := parseCanonicalLivepatchStatus(data)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "nothing-to-apply", report.state)
	assert.Equal(t, "", report.version)
	assert.Empty(t, report.cves)
	assert.NotNil(t, report.cves, "no fixes is an empty list, not null")
}

func TestParseCanonicalLivepatchStatusOnlyRunningKernel(t *testing.T) {
	data := []byte(`{"Status": [
  {"Kernel": "6.8.0-1060.63-aws", "Running": false, "Livepatch": {"State": "applied", "Version": "9.9", "Fixes": [{"Name": "cve-2000-0001", "Patched": true}]}},
  {"Kernel": "6.8.0-1047.50-aws", "Running": true, "Livepatch": {"State": "applied", "Version": "121.4", "Fixes": [
    {"Name": "cve-2026-31431", "Patched": true},
    {"Name": "cve-2026-99999", "Patched": false}
  ]}}
]}`)
	report, err := parseCanonicalLivepatchStatus(data)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, "121.4", report.version)
	assert.Equal(t, []string{"CVE-2026-31431"}, report.cves, "unpatched fixes and other kernels are not reported")

	report, err = parseCanonicalLivepatchStatus([]byte(`{"Status": [{"Kernel": "x", "Running": false}]}`))
	require.NoError(t, err)
	assert.Nil(t, report, "no entry for the running kernel")

	_, err = parseCanonicalLivepatchStatus([]byte("Machine is not enabled."))
	assert.Error(t, err)
}

func livepatchFs(t *testing.T, files map[string]string, dirs ...string) *afero.Afero {
	t.Helper()
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}
	for _, d := range dirs {
		require.NoError(t, afs.MkdirAll(d, 0o755))
	}
	for p, content := range files {
		require.NoError(t, afs.WriteFile(p, []byte(content), 0o644))
	}
	return afs
}

func TestReadKernelLivepatches(t *testing.T) {
	// The layout on Ubuntu 24.04 with Canonical livepatch 121.4 applied.
	const p = "/sys/kernel/livepatch/lkp_Ubuntu_6_8_0_1047_50_aws_121"
	afs := livepatchFs(t, map[string]string{
		p + "/enabled":    "1\n",
		p + "/transition": "0\n",
		p + "/force":      "",
		"/sys/kernel/livepatch/livepatch_sample/enabled":    "0\n",
		"/sys/kernel/livepatch/livepatch_sample/transition": "1\n",
	}, p+"/vmlinux", p+"/af_alg", p+"/cifs", "/sys/kernel/livepatch/livepatch_sample")

	patches, ok, err := readKernelLivepatches(afs)
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, []kernelLivepatch{
		{name: "livepatch_sample", enabled: false, transition: true, objects: []string{}},
		{name: "lkp_Ubuntu_6_8_0_1047_50_aws_121", enabled: true, transition: false, objects: []string{"af_alg", "cifs", "vmlinux"}},
	}, patches)
}

func TestReadKernelLivepatchesAbsent(t *testing.T) {
	t.Run("kernel without live patching", func(t *testing.T) {
		patches, ok, err := readKernelLivepatches(livepatchFs(t, nil, "/sys/kernel"))
		require.NoError(t, err)
		assert.True(t, ok)
		assert.Empty(t, patches)
		assert.NotNil(t, patches)
	})
	t.Run("no running kernel to read, as in an image scan", func(t *testing.T) {
		patches, ok, err := readKernelLivepatches(livepatchFs(t, nil))
		require.NoError(t, err)
		assert.False(t, ok)
		assert.Nil(t, patches)
	})
	t.Run("unexpected enabled value", func(t *testing.T) {
		_, _, err := readKernelLivepatches(livepatchFs(t, map[string]string{
			"/sys/kernel/livepatch/p/enabled":    "maybe\n",
			"/sys/kernel/livepatch/p/transition": "0\n",
		}))
		assert.Error(t, err)
	})
}

func TestLivepatchProvider(t *testing.T) {
	canonical := []kernelLivepatch{{name: "lkp_Ubuntu_6_8_0_1047_50_aws_121", enabled: true}}
	other := []kernelLivepatch{{name: "kpatch_cve_2026_1234", enabled: true}}

	assert.Equal(t, "canonical-livepatch", livepatchProvider(canonical, false))
	assert.Equal(t, "canonical-livepatch", livepatchProvider(nil, true), "client installed, nothing applied")
	assert.Equal(t, "klp", livepatchProvider(other, false))
	assert.Equal(t, "", livepatchProvider([]kernelLivepatch{}, false))
}
