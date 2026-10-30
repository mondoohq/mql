// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// the head of credentials.jpi's MANIFEST.MF, as the vendor Jenkins rpm's
// plugin and a copy of it in a second plugins directory carry it on Rocky 9
const credentialsManifest = "Manifest-Version: 1.0\r\n" +
	"Short-Name: credentials\r\n" +
	"Long-Name: Credentials Plugin\r\n" +
	"Plugin-Version: 1309.v8835d63eb_d8a_\r\n" +
	"Plugin-Dependencies: configuration-as-code:1647.ve39ca_b_829b_42;resolut\r\n" +
	" ion:=optional,structs:324.va_f5d6774f3a_d\r\n"

func jenkinsTestPlugin(t *testing.T, manifest string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("META-INF/MANIFEST.MF")
	require.NoError(t, err)
	_, err = f.Write([]byte(manifest))
	require.NoError(t, err)
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// Two inventories of the same plugin, at the same version, in one scan: each
// reports the plugin file in its own directory.
func TestJenkinsPackagesOfTwoDirectoriesKeepTheirFiles(t *testing.T) {
	mockFS := afero.NewMemMapFs()
	jpi := jenkinsTestPlugin(t, credentialsManifest)
	writeMemFSFile(t, mockFS, "/var/lib/jenkins/plugins/credentials.jpi", jpi)
	writeMemFSFile(t, mockFS, "/srv/g09/fx/jenkins/plugins/credentials.jpi", jpi)
	runtime := memFSRuntime(t, mockFS)

	list := func(p string) []any {
		res, err := CreateResource(runtime, "jenkins.packages", map[string]*llx.RawData{"path": llx.StringData(p)})
		require.NoError(t, err)
		pkgs := res.(*mqlJenkinsPackages)
		require.NoError(t, pkgs.gatherData())
		return pkgs.List.Data
	}
	assert.Equal(t, []string{"/var/lib/jenkins/plugins/credentials.jpi"}, jenkinsFilePaths(t, list("/var/lib/jenkins/plugins")))
	assert.Equal(t, []string{"/srv/g09/fx/jenkins/plugins/credentials.jpi"}, jenkinsFilePaths(t, list("/srv/g09/fx/jenkins/plugins")))
}

func jenkinsFilePaths(t *testing.T, list []any) []string {
	var res []string
	for _, item := range list {
		files := item.(*mqlJenkinsPackage).Files.Data
		require.NotEmpty(t, files)
		res = append(res, files[0].(*mqlPkgFileInfo).Path.Data)
	}
	return res
}
