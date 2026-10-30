// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestOSReleaseParser(t *testing.T) {
	osRelease := `NAME="Ubuntu"
VERSION="16.04.3 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.3 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial`

	m, err := detector.ParseOsRelease(osRelease)
	assert.Nil(t, err)

	assert.Equal(t, "Ubuntu", m["NAME"], "NAME should be parsed properly")
	assert.Equal(t, "16.04.3 LTS (Xenial Xerus)", m["VERSION"], "VERSION should be parsed properly")
	assert.Equal(t, "ubuntu", m["ID"], "ID should be parsed properly")
	assert.Equal(t, "debian", m["ID_LIKE"], "ID_LIKE should be parsed properly")
	assert.Equal(t, "Ubuntu 16.04.3 LTS", m["PRETTY_NAME"], "PRETTY_NAME should be parsed properly")
	assert.Equal(t, "16.04", m["VERSION_ID"], "VERSION_ID should be parsed properly")
	assert.Equal(t, "http://www.ubuntu.com/", m["HOME_URL"], "HOME_URL should be parsed properly")
	assert.Equal(t, "http://help.ubuntu.com/", m["SUPPORT_URL"], "SUPPORT_URL should be parsed properly")
	assert.Equal(t, "http://bugs.launchpad.net/ubuntu/", m["BUG_REPORT_URL"], "BUG_REPORT_URL should be parsed properly")
	assert.Equal(t, "xenial", m["VERSION_CODENAME"], "VERSION_CODENAME should be parsed properly")
	assert.Equal(t, "xenial", m["UBUNTU_CODENAME"], "UBUNTU_CODENAME should be parsed properly")

	osRelease = `NAME="Oracle Linux Server"
VERSION="6.9"
ID="ol"
VERSION_ID="6.9"
PRETTY_NAME="Oracle Linux Server 6.9"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:oracle:linux:6:9:server"
HOME_URL="https://linux.oracle.com/"
BUG_REPORT_URL="https://bugzilla.oracle.com/"

ORACLE_BUGZILLA_PRODUCT="Oracle Linux 6"
ORACLE_BUGZILLA_PRODUCT_VERSION=6.9
ORACLE_SUPPORT_PRODUCT="Oracle Linux"
ORACLE_SUPPORT_PRODUCT_VERSION=6.9`

	m, err = detector.ParseOsRelease(osRelease)
	require.NoError(t, err)
	assert.Equal(t, "Oracle Linux Server", m["NAME"], "NAME should be parsed properly")
	assert.Equal(t, "ol", m["ID"], "ID should be parsed properly")
	assert.Equal(t, "6.9", m["VERSION"], "VERSION should be parsed properly")
}

func TestEtcLsbReleaseParser(t *testing.T) {
	lsbRelease := `DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.3 LTS"`

	m, err := detector.ParseLsbRelease(lsbRelease)
	require.NoError(t, err)

	assert.Equal(t, "Ubuntu", m["DISTRIB_ID"], "DISTRIB_ID should be parsed properly")
	assert.Equal(t, "16.04", m["DISTRIB_RELEASE"], "DISTRIB_RELEASE should be parsed properly")
	assert.Equal(t, "xenial", m["DISTRIB_CODENAME"], "DISTRIB_CODENAME should be parsed properly")
	assert.Equal(t, "Ubuntu 16.04.3 LTS", m["DISTRIB_DESCRIPTION"], "DISTRIB_DESCRIPTION should be parsed properly")
}

func TestRedhatRelease(t *testing.T) {
	rhRelease := "CentOS Linux release 7.4.1708 (Core)"
	name, release, err := detector.ParseRhelVersion(rhRelease)
	require.NoError(t, err)
	assert.Equal(t, "CentOS Linux", name, "parse os name")
	assert.Equal(t, "7.4.1708", release, "parse release version")

	rhRelease = "CentOS release 6.9 (Final)"
	name, release, err = detector.ParseRhelVersion(rhRelease)
	require.NoError(t, err)
	assert.Equal(t, "CentOS", name, "parse os name")
	assert.Equal(t, "6.9", release, "parse release version")

	rhRelease = "Red Hat Enterprise Linux Server release 7.4 (Maipo)"
	name, release, err = detector.ParseRhelVersion(rhRelease)
	assert.Nil(t, err)
	assert.Equal(t, "Red Hat Enterprise Linux Server", name, "parse os name")
	assert.Equal(t, "7.4", release, "parse release version")

	rhRelease = "Oracle Linux Server release 7.4 (Maipo)"
	name, release, err = detector.ParseRhelVersion(rhRelease)
	require.NoError(t, err)
	assert.Equal(t, "Oracle Linux Server", name, "parse os name")
	assert.Equal(t, "7.4", release, "parse release version")
}
