// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package detector

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func detectPlatformFromMock(filepath string) (*inventory.Platform, error) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath(filepath))
	if err != nil {
		return nil, err
	}

	var foundErr error
	di, found := OperatingSystems.Resolve(mockConn)
	if !found {
		foundErr = errors.New("no platform found")
	}
	return di, foundErr
}

func TestRhel6OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhel-6.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "redhat", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Linux", di.Title, "os title should be identified")
	assert.Equal(t, "6.2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestRhel7OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhel-7.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "redhat", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Enterprise Linux Server 7.2 (Maipo)", di.Title, "os title should be identified")
	assert.Equal(t, "7.2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestRhel7SLESOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhel-7-sles.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "redhat", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Enterprise Linux Server 7.4", di.Title, "os title should be identified")
	assert.Equal(t, "7.4", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestRhel8OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhel-8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "redhat", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Enterprise Linux 8.0 (Ootpa)", di.Title, "os title should be identified")
	assert.Equal(t, "8.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestRhel9OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhel-9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "redhat", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Enterprise Linux 9.0 (Plow)", di.Title, "os title should be identified")
	assert.Equal(t, "9.0", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestFedora29OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-fedora29.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "fedora", di.Name, "os name should be identified")
	assert.Equal(t, "Fedora 29 (Container Image)", di.Title, "os title should be identified")
	assert.Equal(t, "29", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestFedoraCoreOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-coreos-fedora.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "fedora", di.Name, "os name should be identified")
	assert.Equal(t, "Fedora CoreOS 31.20200310.3.0", di.Title, "os title should be identified")
	assert.Equal(t, "31", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestCentos5Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-centos-5.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "centos", di.Name, "os name should be identified")
	assert.Equal(t, "CentOS", di.Title, "os title should be identified")
	assert.Equal(t, "5.11", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestCentos6Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-centos-6.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "centos", di.Name, "os name should be identified")
	assert.Equal(t, "CentOS", di.Title, "os title should be identified")
	assert.Equal(t, "6.9", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestCentos7OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-centos-7.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "centos", di.Name, "os name should be identified")
	assert.Equal(t, "CentOS Linux 7 (Core)", di.Title, "os title should be identified")
	assert.Equal(t, "7.9.2009", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestCentos8OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-centos-8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "centos", di.Name, "os name should be identified")
	assert.Equal(t, "CentOS Linux 8", di.Title, "os title should be identified")
	assert.Equal(t, "8.5.2111", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestCentos8StreamOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-centos-8-stream.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "centos", di.Name, "os name should be identified")
	assert.Equal(t, "CentOS Stream 8", di.Title, "os title should be identified")
	assert.Equal(t, "8", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestCentos9StreamOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-centos-9-stream.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "centos", di.Name, "os name should be identified")
	assert.Equal(t, "CentOS Stream 9", di.Title, "os title should be identified")
	assert.Equal(t, "9", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestAlmaLinux8OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-almalinux-8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "almalinux", di.Name, "os name should be identified")
	assert.Equal(t, "AlmaLinux 8.3 Beta (Purple Manul)", di.Title, "os title should be identified")
	assert.Equal(t, "8.3", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestAlmaLinux9OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-almalinux-9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "almalinux", di.Name, "os name should be identified")
	assert.Equal(t, "AlmaLinux 9.0 Beta (Emerald Puma)", di.Title, "os title should be identified")
	assert.Equal(t, "9.0", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestRockyLinux8OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rocky-linux-8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "rockylinux", di.Name, "os name should be identified")
	assert.Equal(t, "Rocky Linux 8.5 (Green Obsidian)", di.Title, "os title should be identified")
	assert.Equal(t, "8.5", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestRockyLinux9OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rocky-linux-9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "rockylinux", di.Name, "os name should be identified")
	assert.Equal(t, "Rocky Linux 9.0 (Blue Onyx)", di.Title, "os title should be identified")
	assert.Equal(t, "9.0", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestEuroLinux7OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-eurolinux-7.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "eurolinux", di.Name, "os name should be identified")
	assert.Equal(t, "EuroLinux 7.9 (Minsk)", di.Title, "os title should be identified")
	assert.Equal(t, "7.9", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestEuroLinux8OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-eurolinux-8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "eurolinux", di.Name, "os name should be identified")
	assert.Equal(t, "EuroLinux 8.7 (Brussels)", di.Title, "os title should be identified")
	assert.Equal(t, "8.7", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestEuroLinux9OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-eurolinux-9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "eurolinux", di.Name, "os name should be identified")
	assert.Equal(t, "EuroLinux 9.1 (Stockholm)", di.Title, "os title should be identified")
	assert.Equal(t, "9.1", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestRhcosDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhcos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "rhcos", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Enterprise Linux CoreOS", di.Title, "os title should be identified")
	assert.Equal(t, "9.6", di.Version, "os version should be the rhel release, not the image build")
	assert.Equal(t, "9.6.20250523-0", di.Build, "image build should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
	assert.Equal(t, "4.19", di.Metadata["openshift/version"], "openshift version should be identified")
}

// rpm-ostree systems ship the real file at /usr/lib/os-release and symlink
// /etc/os-release at it. Scanning the raw root partition can leave the symlink
// unresolved, so detection has to work off the /usr/lib copy alone.
func TestRhcosUsrLibOsReleaseDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhcos-usrlib.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "rhcos", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Enterprise Linux CoreOS", di.Title, "os title should be identified")
	assert.Equal(t, "9.6", di.Version, "os version should be the rhel release, not the image build")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestCloudLinux9OSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-cloudlinux-9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "cloudlinux", di.Name, "os name should be identified")
	assert.Equal(t, "CloudLinux 9.6 (Vladimir Lyakhov)", di.Title, "os title should be identified")
	assert.Equal(t, "9.6", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

// A host with no /etc/os-release still reaches the resolver with the title the
// redhat family parsed out of /etc/redhat-release ("CloudLinux release 9.6
// (Vladimir Lyakhov)" yields the title "CloudLinux").
func TestCloudLinuxDetectFromReleaseTitle(t *testing.T) {
	pf := &inventory.Platform{Title: "CloudLinux"}
	detected, err := cloudlinux.Detect(cloudlinux, pf, nil)
	assert.NoError(t, err)
	assert.True(t, detected, "cloudlinux should be detected from the release title")
	assert.Equal(t, "cloudlinux", pf.Name, "os name should be set")
}

func TestUbuntu1204Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu1204.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu precise (12.04.5 LTS)", di.Title, "os title should be identified")
	assert.Equal(t, "12.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestUbuntu1404Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu1404.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu 14.04.6 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "14.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestUbuntu1604Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu1604.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu 16.04.4 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "16.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestUbuntu1804Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu1804.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu 18.04.3 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "18.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestUbuntu2004Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu2004.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu Focal Fossa (development branch)", di.Title, "os title should be identified")
	assert.Equal(t, "20.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestUbuntu2204Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu2204.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu Jammy Jellyfish (development branch)", di.Title, "os title should be identified")
	assert.Equal(t, "22.04", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
}

func TestUbuntu2204ProDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu2204-pro.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu 22.04.3 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "22.04", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, "enabled", di.Metadata["ubuntu/pro"], "ubuntu pro metadata should be identified")
}

func TestUbuntu2204NoProDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu2204-nopro.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu 22.04.3 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "22.04", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, "disabled", di.Metadata["ubuntu/pro"], "ubuntu pro metadata should be identified")
}

func TestPoposDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-popos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "pop", di.Name, "os name should be identified")
	assert.Equal(t, "Pop!_OS 20.04 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "20.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestLedeDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-lede.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "lede", di.Name, "os name should be identified")
	assert.Equal(t, "LEDE Reboot 17.01.6", di.Title, "os title should be identified")
	assert.Equal(t, "17.01.6", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestOpenWrtDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-openwrt.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "openwrt", di.Name, "os name should be identified")
	assert.Equal(t, "OpenWrt", di.Title, "os title should be identified")
	assert.Equal(t, "22.03.4", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestDebian7Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian7.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "debian", di.Name, "os name should be identified")
	assert.Equal(t, "Debian GNU/Linux 7 (wheezy)", di.Title, "os title should be identified")
	assert.Equal(t, "7.11", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestDebian8Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "debian", di.Name, "os name should be identified")
	assert.Equal(t, "Debian GNU/Linux 8 (jessie)", di.Title, "os title should be identified")
	assert.Equal(t, "8.11", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestDebian9Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "debian", di.Name, "os name should be identified")
	assert.Equal(t, "Debian GNU/Linux 9 (stretch)", di.Title, "os title should be identified")
	assert.Equal(t, "9.4", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestDebian10Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian10.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "debian", di.Name, "os name should be identified")
	assert.Equal(t, "Debian GNU/Linux 10 (buster)", di.Title, "os title should be identified")
	assert.Equal(t, "10.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestRaspian10Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-raspbian.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "raspbian", di.Name, "os name should be identified")
	assert.Equal(t, "Raspbian GNU/Linux 10 (buster)", di.Title, "os title should be identified")
	assert.Equal(t, "10", di.Version, "os version should be identified")
	assert.Equal(t, "armv7l", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestKaliRollingDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-kalirolling.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "kali", di.Name, "os name should be identified")
	assert.Equal(t, "Kali GNU/Linux Rolling", di.Title, "os title should be identified")
	assert.Equal(t, "2019.4", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestOpenSuse13Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-opensuse-13.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "opensuse", di.Name, "os name should be identified")
	assert.Equal(t, "openSUSE 13.2 (Harlequin) (x86_64)", di.Title, "os title should be identified")
	assert.Equal(t, "13.2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

func TestOpenSuseLeap42Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-opensuse-leap-42.3.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "opensuse", di.Name, "os name should be identified")
	assert.Equal(t, "openSUSE Leap 42.3", di.Title, "os title should be identified")
	assert.Equal(t, "42.3", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

func TestOpenSuseLeap15Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-opensuse-leap-15.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "opensuse-leap", di.Name, "os name should be identified")
	assert.Equal(t, "openSUSE Leap 15.6", di.Title, "os title should be identified")
	assert.Equal(t, "15.6", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

// Leap 16 is a full rebase onto the SLE 16 codebase: it drops YaST, moves
// packaged configuration to /usr/etc, and ships an /etc/os-release whose
// ID_LIKE now also names SLE. It still has to resolve as opensuse-leap and
// not fall through to the sles resolver or read as a Leap 15 point release.
func TestOpenSuseLeap16Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-opensuse-leap-16.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "opensuse-leap", di.Name, "os name should be identified")
	assert.Equal(t, "openSUSE Leap 16.0", di.Title, "os title should be identified")
	assert.Equal(t, "16.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

func TestOpenSuseTumbleweedDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-opensuse-tumbleweed.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "opensuse-tumbleweed", di.Name, "os name should be identified")
	assert.Equal(t, "openSUSE Tumbleweed", di.Title, "os title should be identified")
	assert.Equal(t, "20251007", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

func TestSuse12Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-suse-sles-12.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "sles", di.Name, "os name should be identified")
	assert.Equal(t, "SUSE Linux Enterprise Server 12 SP3", di.Title, "os title should be identified")
	assert.Equal(t, "12.3", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

func TestSuse125Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-suse-sles-12.5.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "sles", di.Name, "os name should be identified")
	assert.Equal(t, "SUSE Linux Enterprise Server 12 SP5", di.Title, "os title should be identified")
	assert.Equal(t, "12.5", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

func TestSuse15Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-suse-sles-15.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "sles", di.Name, "os name should be identified")
	assert.Equal(t, "SUSE Linux Enterprise Server 15 SP1", di.Title, "os title should be identified")
	assert.Equal(t, "15.1", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

func TestSuse15SapDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-suse-sles-15-sap.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "sles", di.Name, "os name should be identified")
	assert.Equal(t, "SUSE Linux Enterprise Server 15 SP2", di.Title, "os title should be identified")
	assert.Equal(t, "15.2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
	assert.Equal(t, map[string]string{
		"distro-id":  "sles",
		"variant-id": "sles-sap",
	}, di.Labels)
}

func TestSuse5MicroDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-suse-micro-5.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "suse-microos", di.Name, "os name should be identified")
	assert.Equal(t, "SUSE Linux Enterprise Micro 5.1", di.Title, "os title should be identified")
	assert.Equal(t, "5.1", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

// openSUSE MicroOS sets ID=opensuse-microos, which no resolver claimed: the
// suse family's only micro leaf matched SLE Micro's ID=suse-microos. Detection
// fell through to the generic resolver, so the platform carried no suse family
// and a container image or running container was renamed to "scratch", which
// routes to ScratchPkgManager and reports an empty package list with no error.
func TestOpenSuseMicroOsIsClaimedByTheMicroOsResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-opensuse-microos.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.Equal(t, suseMicroOs, leaf, "openSUSE MicroOS must be claimed by the micro resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf),
		"a container image claimed only by the generic resolver is reported as scratch")
}

func TestOpenSuseMicroOsDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-opensuse-microos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "opensuse-microos", di.Name, "os name should be identified")
	assert.Equal(t, "openSUSE MicroOS", di.Title, "os title should be identified")
	assert.Equal(t, "20260822", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	// the suse family is what routes it to zypper/rpm packages, the suse
	// kernel filter and the suse update manager
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
	assert.Equal(t, map[string]string{"distro-id": "opensuse-microos"}, di.Labels)
}

func TestAmazon1LinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-amazonlinux-2017.09.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "amazonlinux", di.Name, "os name should be identified")
	assert.Equal(t, "Amazon Linux AMI 2017.09", di.Title, "os title should be identified")
	assert.Equal(t, "2017.09", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestAmazon2LinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-amzn-2.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "amazonlinux", di.Name, "os name should be identified")
	assert.Equal(t, "Amazon Linux 2", di.Title, "os title should be identified")
	assert.Equal(t, "2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestAmazon2022LinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-amzn-2022.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "amazonlinux", di.Name, "os name should be identified")
	assert.Equal(t, "Amazon Linux 2022", di.Title, "os title should be identified")
	assert.Equal(t, "2022", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestBottlerocketDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-bottlerocket.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "bottlerocket", di.Name, "os name should be identified")
	assert.Equal(t, "Bottlerocket OS 1.33.0 (aws-ecs-2-fips)", di.Title, "os title should be identified")
	assert.Equal(t, "1.33.0", di.Version, "os version should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// TestBottlerocketEBSDetector tests Bottlerocket detection when scanning via
// EBS volume snapshot. On Bottlerocket, /etc is an overlay filesystem and
// /etc/os-release only exists in the overlay upper layer, not on the raw root
// partition. The detector must fall back to /usr/lib/os-release.
func TestBottlerocketEBSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-bottlerocket-ebs.toml")
	assert.Nil(t, err, "was able to detect the platform")

	assert.Equal(t, "bottlerocket", di.Name, "os name should be identified")
	assert.Equal(t, "Bottlerocket OS 1.50.0 (aws-ecs-2)", di.Title, "os title should be identified")
	assert.Equal(t, "1.50.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// Newer Bottlerocket ships no /etc/bottlerocket-release, and a root-partition
// scan sees no /etc/os-release either. Detection gated the claim on opening the
// release file, so the generic resolver took those systems and a container
// image was reported as "scratch". Name, title and version still looked right,
// because the family detection had already read /usr/lib/os-release.
func TestBottlerocketEBSIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-bottlerocket-ebs.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.Equal(t, bottlerocket, leaf, "bottlerocket must claim its own root partition")
	assert.False(t, isUnidentifiedPlatform(pf, leaf),
		"a container image claimed only by the generic resolver is reported as scratch")
}

// The release file still wins where it exists: it carries BUILD_ID, which
// /usr/lib/os-release on that variant does not.
func TestBottlerocketReleaseFileStillEnriches(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-bottlerocket.toml"))
	require.NoError(t, err)

	_, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	assert.Equal(t, bottlerocket, leaf)
}

func TestScientificLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-scientific.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "scientific", di.Name, "os name should be identified")
	assert.Equal(t, "Scientific Linux CERN SLC", di.Title, "os title should be identified")
	assert.Equal(t, "6.9", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestArchLinuxVmDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-arch-vm.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "arch", di.Name, "os name should be identified")
	assert.Equal(t, "Arch Linux", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family)
}

func TestArchLinuxContainerDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-arch-container.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "arch", di.Name, "os name should be identified")
	assert.Equal(t, "Arch Linux", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family)
}

func TestManjaroLinuxContainerDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-manjaro.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "manjaro", di.Name, "os name should be identified")
	assert.Equal(t, "Manjaro Linux", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family)
}

func TestOracleLinux6Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-oracle6.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "oraclelinux", di.Name, "os name should be identified")
	assert.Equal(t, "Oracle Linux Server 6.9", di.Title, "os title should be identified")
	assert.Equal(t, "6.9", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestOracleLinux7Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-oracle7.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "oraclelinux", di.Name, "os name should be identified")
	assert.Equal(t, "Oracle Linux Server 7.5", di.Title, "os title should be identified")
	assert.Equal(t, "7.5", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestOracleLinux8Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-oracle8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "oraclelinux", di.Name, "os name should be identified")
	assert.Equal(t, "Oracle Linux Server 8.0", di.Title, "os title should be identified")
	assert.Equal(t, "8.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestNixOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-nixos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "nixos", di.Name, "os name should be identified")
	assert.Equal(t, "NixOS 24.11 (Vicuna)", di.Title, "os title should be identified")
	assert.Equal(t, "24.11", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestNixOSContainerDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-nixos-container.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "nixos", di.Name, "os name should be identified")
	assert.Equal(t, "NixOS", di.Title, "os title should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestGentooLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-gentoo.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "gentoo", di.Name, "os name should be identified")
	assert.Equal(t, "Gentoo Linux", di.Title, "os title should be identified")
	assert.Equal(t, "2.18", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestCirrOSLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-cirros.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "cirros", di.Name, "os name should be identified")
	assert.Equal(t, "CirrOS 0.6.0", di.Title, "os title should be identified")
	assert.Equal(t, "0.6.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestAlpineLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-alpine.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "alpine", di.Name, "os name should be identified")
	assert.Equal(t, "Alpine Linux v3.7", di.Title, "os title should be identified")
	assert.Equal(t, "3.7.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestAlpineEdgeLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-alpine-edge.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "alpine", di.Name, "os name should be identified")
	assert.Equal(t, "Alpine Linux edge", di.Title, "os title should be identified")
	assert.Equal(t, "edge", di.Version, "os version should be identified")
	assert.Equal(t, "3.13.0_alpha20201218", di.Build, "os build should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestWolfiLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-wolfi.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "wolfi", di.Name, "os name should be identified")
	assert.Equal(t, "Wolfi", di.Title, "os title should be identified")
	assert.Equal(t, "20230201", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestWizOSLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-wizos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "wizos", di.Name, "os name should be identified")
	assert.Equal(t, "WizOS", di.Title, "os title should be identified")
	assert.Equal(t, "1.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// ALT Linux (BaseALT) ships /etc/redhat-release, /etc/fedora-release and
// /etc/system-release for compatibility, all carrying just "ALT Container" with
// no version and no distro name. Nothing claimed it, so it fell through to the
// generic resolver and container images were reported as "scratch".
func TestAltLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-altlinux-p10.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "altlinux", di.Name, "os name should be identified")
	assert.Equal(t, "ALT Container", di.Title, "os title should be identified")
	assert.Equal(t, "10", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// The name above is right even without a resolver of its own, because the
// generic fallback leaves a name that os-release already supplied. What it does
// not survive is a container image scan: an image whose platform was only
// claimed by the generic resolver is reported as "scratch", which is how ALT
// images were coming back.
func TestAltLinuxIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-altlinux-p10.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.NotEqual(t, defaultLinux, leaf, "ALT must not be left to the generic linux resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf),
		"a container image claimed only by the generic resolver is reported as scratch")
}

// Arch Linux ARM sets ID=archarm and reports as arch.
func TestArchArmDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-archarm.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "arch", di.Name, "Arch Linux ARM is arch, not a platform of its own")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family,
		"Arch Linux ARM belongs to the arch family")
}

// A container image whose platform is only claimed by the generic resolver is
// reported as "scratch", which is how Arch Linux ARM images were coming back -
// and an undetected platform takes the package manager with it, so `packages`
// errored on an image pacman happily lists.
func TestArchArmIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-archarm.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.NotEqual(t, defaultLinux, leaf, "Arch Linux ARM must not be left to the generic linux resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf))
}

// Manjaro ARM sets ID=manjaro-arm and reports as manjaro.
func TestManjaroArmDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-manjaro-arm.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "manjaro", di.Name, "Manjaro ARM is manjaro, not a platform of its own")
	assert.Equal(t, "24.03", di.Version, "os version should come from lsb")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family,
		"Manjaro ARM belongs to the arch family")
}

// A container image whose platform is only claimed by the generic resolver is
// reported as "scratch", which is how Manjaro ARM images were coming back.
func TestManjaroArmIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-manjaro-arm.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.NotEqual(t, defaultLinux, leaf, "Manjaro ARM must not be left to the generic linux resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf))
}

// Void Linux ships only /etc/os-release, with ID=void and no version of any
// kind (it is a rolling release). Nothing claimed it, so the generic resolver
// did, and container images were reported as "scratch" even though the image
// says exactly what it is.
func TestVoidLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-void.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "void", di.Name, "os name should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestVoidLinuxIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-void.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.NotEqual(t, defaultLinux, leaf, "Void must not be left to the generic linux resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf),
		"a container image claimed only by the generic resolver is reported as scratch")
}

// Clear Linux OS ships only /etc/os-release (a symlink to /usr/lib/os-release),
// carrying ID=clear-linux-os. Nothing claimed it, so the generic resolver did
// and container images were reported as "scratch".
func TestClearLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-clearlinux.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "clear-linux-os", di.Name, "os name should be identified")
	assert.Equal(t, "43630", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestClearLinuxIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-clearlinux.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.NotEqual(t, defaultLinux, leaf, "Clear Linux must not be left to the generic linux resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf),
		"a container image claimed only by the generic resolver is reported as scratch")
}

// A distribution with no resolver of its own is still claimed by the generic
// linux resolver, which leaves the name os-release supplied. Container images
// in that state were reported as "scratch", discarding an identity the image
// states outright. Reserve "scratch" for images that genuinely say nothing.
func TestOsReleaseNameSurvivesTheGenericResolver(t *testing.T) {
	for _, tc := range []struct {
		fixture string
		name    string
		version string
	}{
		{"detect-slackware.toml", "slackware", "15.0"},
		{"detect-deepin.toml", "deepin", "25"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/"+tc.fixture))
			require.NoError(t, err)

			pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
			require.True(t, resolved)
			assert.Equal(t, tc.name, pf.Name)
			assert.Equal(t, tc.version, pf.Version)
			assert.False(t, isUnidentifiedPlatform(pf, leaf),
				"os-release named this distribution, so a container image must not report scratch")
		})
	}
}

// An image that names nothing is still unidentified, and "scratch" stays the
// honest answer for it.
func TestImageWithNoOsReleaseStaysUnidentified(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-generic-linux.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved)
	assert.True(t, isUnidentifiedPlatform(pf, leaf),
		"nothing named this system, so it stays scratch")
}

func TestBusyboxLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-busybox.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "busybox", di.Name, "os name should be identified")
	assert.Equal(t, "BusyBox", di.Title, "os title should be identified")
	assert.Equal(t, "1.34.1", di.Version, "os version should not carry busybox's v prefix")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestPlcNextLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-plcnext.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "plcnext", di.Name, "os name should be identified")
	assert.Equal(t, "PLCnext", di.Title, "os title should be identified")
	assert.Equal(t, "23.0.0.65", di.Version, "os version should be identified")
	assert.Equal(t, "d755854b5b21ecb8dca26b0a560e6842a0c638d7", di.Build, "os build version should be identified")
	assert.Equal(t, "armv7l", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestWindows2016Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-windows2016.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "windows", di.Name, "os name should be identified")
	assert.Equal(t, "Microsoft Windows Server 2016 Standard Evaluation", di.Title, "os title should be identified")
	assert.Equal(t, "14393", di.Version, "os version should be identified")
	assert.Equal(t, "64-bit", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"windows", "os"}, di.Family)
}

func TestWindows2019Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-windows2019.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "windows", di.Name, "os name should be identified")
	assert.Equal(t, "Windows Server 2019 Datacenter", di.Title, "os title should be identified")
	assert.Equal(t, "17763", di.Version, "os version should be identified")
	assert.Equal(t, "6414", di.Build, "os build version should be identified")
	assert.Equal(t, "AMD64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"windows", "os"}, di.Family)
}

func TestWindows2022Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-windows2022.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "windows", di.Name, "os name should be identified")
	assert.Equal(t, "Windows Server 2022 Datacenter", di.Title, "os title should be identified")
	assert.Equal(t, "20348", di.Version, "os version should be identified")
	assert.Equal(t, "2762", di.Build, "os build version should be identified")
	assert.Equal(t, "AMD64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"windows", "os"}, di.Family)
}

func TestWindows2025Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-windows2025.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "windows", di.Name, "os name should be identified")
	assert.Equal(t, "Windows Server 2025 Datacenter", di.Title, "os title should be identified")
	assert.Equal(t, "26311", di.Version, "os version should be identified")
	assert.Equal(t, "5000", di.Build, "os build version should be identified")
	assert.Equal(t, "ARM64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"windows", "os"}, di.Family)
}

func TestAzureWindows2025Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-azure-windows2025.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "windows", di.Name, "os name should be identified")
	assert.Equal(t, "Windows Server 2025 Datacenter Azure Edition", di.Title, "os title should be identified")
	assert.Equal(t, "26311", di.Version, "os version should be identified")
	assert.Equal(t, "5000", di.Build, "os build version should be identified")
	assert.Equal(t, "AMD64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"windows", "os"}, di.Family)
	assert.Equal(t, "ServerTurbine", di.Labels["windows.mondoo.com/edition-id"])
	assert.Equal(t, "false", di.Labels["windows.mondoo.com/hotpatch"])
}

func TestWindows11_24H2Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-windows11-24h2.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "windows", di.Name, "os name should be identified")
	assert.Equal(t, "Windows 11 Enterprise LTSC", di.Title, "os title should be identified")
	assert.Equal(t, "26100", di.Version, "os version should be identified")
	assert.Equal(t, "3000", di.Build, "os build version should be identified")
	assert.Equal(t, "AMD64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"windows", "os"}, di.Family)
	assert.Equal(t, "1", di.Labels["windows.mondoo.com/product-type"])
	assert.Equal(t, "24H2", di.Labels["windows.mondoo.com/display-version"])
	assert.Equal(t, "false", di.Labels["windows.mondoo.com/hotpatch"])
}

func TestWindows11_24H2HotpatchDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-windows11-24h2-hotpatch.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "windows", di.Name, "os name should be identified")
	assert.Equal(t, "Windows 11 Enterprise", di.Title, "os title should be identified")
	assert.Equal(t, "26100", di.Version, "os version should be identified")
	assert.Equal(t, "1", di.Labels["windows.mondoo.com/product-type"])
	assert.Equal(t, "true", di.Labels["windows.mondoo.com/hotpatch"])
}

func TestPhoton1Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-photon1.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "photon", di.Name, "os name should be identified")
	assert.Equal(t, "VMware Photon/Linux", di.Title, "os title should be identified")
	assert.Equal(t, "1.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestPhoton2Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-photon2.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "photon", di.Name, "os name should be identified")
	assert.Equal(t, "VMware Photon OS/Linux", di.Title, "os title should be identified")
	assert.Equal(t, "2.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestPhoton3Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-photon3.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "photon", di.Name, "os name should be identified")
	assert.Equal(t, "VMware Photon OS/Linux", di.Title, "os title should be identified")
	assert.Equal(t, "3.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestMacOSsDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-macos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "macos", di.Name, "os name should be identified")
	assert.Equal(t, "Mac OS X", di.Title, "os title should be identified")
	assert.Equal(t, "10.14.5", di.Version, "os version should be identified")
	assert.Equal(t, "18F132", di.Build, "os build should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"darwin", "bsd", "unix", "os"}, di.Family)
}

// A darwin system whose system version property list is unreadable is still
// macOS: the details come from sw_vers instead of the property list.
func TestMacOSWithoutSystemVersionPlistDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-macos-no-plist.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "macos", di.Name, "os name should be identified")
	assert.Equal(t, "macOS", di.Title, "os title should be identified")
	assert.Equal(t, "15.5", di.Version, "os version should be identified")
	assert.Equal(t, "24F74", di.Build, "os build should be identified")
	assert.Equal(t, "arm64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"darwin", "bsd", "unix", "os"}, di.Family)
}

// A darwin system that reports neither sw_vers nor a system version property
// list is reported as macOS without a version, never as the kernel name.
func TestMacOSWithoutSwVersDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-darwin-bare.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "macos", di.Name, "os name should be identified")
	assert.Equal(t, "macOS", di.Title, "os title should be identified")
	assert.Empty(t, di.Version, "os version is unknown")
	assert.Equal(t, "arm64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"darwin", "bsd", "unix", "os"}, di.Family)
}

func TestBuildrootDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-buildroot.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "buildroot", di.Name, "os name should be identified")
	assert.Equal(t, "Buildroot 2019.02.9", di.Title, "os title should be identified")
	assert.Equal(t, "2019.02.9", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestSolaris11Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-solaris11.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "solaris", di.Name, "os name should be identified")
	assert.Equal(t, "Oracle Solaris", di.Title, "os title should be identified")
	assert.Equal(t, "11.1", di.Version, "os version should be identified")
	assert.Equal(t, "i86pc", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"unix", "os"}, di.Family)
}

// uname already proves the host is SunOS, so an unreadable /etc/release must
// still detect solaris - just without a title and version.
func TestSolarisDetectorWithoutReleaseFile(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-solaris11-no-release.toml")
	require.NoError(t, err, "platform is still detected without /etc/release")

	assert.Equal(t, "solaris", di.Name, "os name should be identified")
	assert.Equal(t, "i86pc", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"unix", "os"}, di.Family)
}

func TestAix72Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-aix72.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "aix", di.Name, "os name should be identified")
	assert.Equal(t, "AIX", di.Title, "os title should be identified")
	assert.Equal(t, "7.2", di.Version, "os version should be identified")
	assert.Equal(t, "powerpc", di.Arch, "os arch should be identified")
	assert.Equal(t, "7200-05-02-2114", di.Build, "os build should be identified")
	assert.Equal(t, []string{"unix", "os"}, di.Family)

	// hardware facts required to scope POWER-gated security advisories
	assert.Equal(t, "IBM,9009-42A", di.Labels[AixLabelSystemModel])
	assert.Equal(t, "PowerPC_POWER9", di.Labels[AixLabelProcessorType])
}

func TestAixDetectorWithoutHardwareFacts(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-aix71-no-hardware.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "aix", di.Name, "os name should be identified")
	assert.Equal(t, "7.1", di.Version, "os version should be identified")

	// uname -M and lsattr are unavailable here. The labels must stay absent rather
	// than be recorded as empty, so that consumers can tell "unknown" apart from a
	// value that genuinely does not match.
	_, hasModel := di.Labels[AixLabelSystemModel]
	assert.False(t, hasModel, "system model label should be absent")
	_, hasProcType := di.Labels[AixLabelProcessorType]
	assert.False(t, hasProcType, "processor type label should be absent")
}

func TestNetbsd8Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-netbsd8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "netbsd", di.Name, "os name should be identified")
	assert.Equal(t, "NetBSD", di.Title, "os title should be identified")
	assert.Equal(t, "8.0", di.Version, "os version should be identified")
	assert.Equal(t, "amd64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"bsd", "unix", "os"}, di.Family)
}

func TestFreebsd12Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-freebsd12.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "freebsd", di.Name, "os name should be identified")
	assert.Equal(t, "FreeBSD", di.Title, "os title should be identified")
	assert.Equal(t, "12.0-CURRENT", di.Version, "os version should be identified")
	assert.Equal(t, "amd64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"bsd", "unix", "os"}, di.Family)
}

func TestFreebsd14Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-freebsd14.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "freebsd", di.Name, "os name should be identified")
	assert.Equal(t, "FreeBSD", di.Title, "os title should be identified")
	assert.Equal(t, "14.3-RELEASE", di.Version, "os version should be identified")
	assert.Equal(t, "arm64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"bsd", "unix", "os"}, di.Family)
}

func TestFreebsd15Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-freebsd15.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "freebsd", di.Name, "os name should be identified")
	assert.Equal(t, "FreeBSD", di.Title, "os title should be identified")
	assert.Equal(t, "15.0-BETA4", di.Version, "os version should be identified")
	assert.Equal(t, "arm64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"bsd", "unix", "os"}, di.Family)
}

func TestOpenBsd6Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-openbsd6.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "openbsd", di.Name, "os name should be identified")
	assert.Equal(t, "OpenBSD", di.Title, "os title should be identified")
	assert.Equal(t, "6.7", di.Version, "os version should be identified")
	assert.Equal(t, "amd64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"bsd", "unix", "os"}, di.Family)
}

func TestOpenBsd7Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-openbsd7.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "openbsd", di.Name, "os name should be identified")
	assert.Equal(t, "OpenBSD", di.Title, "os title should be identified")
	assert.Equal(t, "7.8", di.Version, "os version should be identified")
	assert.Equal(t, "arm64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"bsd", "unix", "os"}, di.Family)
}

func TestDragonFlyBsd5Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-dragonflybsd5.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "dragonflybsd", di.Name, "os name should be identified")
	assert.Equal(t, "DragonFly", di.Title, "os title should be identified")
	assert.Equal(t, "5.8-RELEASE", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"bsd", "unix", "os"}, di.Family)
}

func TestMint20Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-mint20.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "linuxmint", di.Name, "os name should be identified")
	assert.Equal(t, "Linux Mint 20", di.Title, "os title should be identified")
	assert.Equal(t, "20", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestGoogleCOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-google-cos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "cos", di.Name, "os name should be identified")
	assert.Equal(t, "Container-Optimized OS from Google", di.Title, "os title should be identified")
	assert.Equal(t, "97", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, "16919.103.16", di.Build, "os build should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// Asserting the name would pass either way: the generic fallback leaves
// whatever os-release said. Container images are what break.
func TestGoogleCOSIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-google-cos.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.NotEqual(t, defaultLinux, leaf, "cos must not be left to the generic linux resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf),
		"a container image claimed only by the generic resolver is reported as scratch")
}

func TestGoogleCOSIsInPlatformCatalog(t *testing.T) {
	assert.Equal(t, []string{"os", "unix", "linux"}, osTree["cos"],
		"cos must carry a family chain for policy filters to match on")
}

func TestElementaryOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-elementary.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "elementary", di.Name, "os name should be identified")
	assert.Equal(t, "elementary OS 7 Horus", di.Title, "os title should be identified")
	assert.Equal(t, "7", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestOpenEulerDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-openeuler.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "openeuler", di.Name, "os name should be identified")
	assert.Equal(t, "openEuler 24.03 (LTS-SP2)", di.Title, "os title should be identified")
	assert.Equal(t, "24.03", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"euler", "linux", "unix", "os"}, di.Family)
}

func TestMageiaDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-mageia-9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "mageia", di.Name, "os name should be identified")
	assert.Equal(t, "Mageia 9", di.Title, "os title should be identified")
	assert.Equal(t, "9", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestMXLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-mx.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "mx", di.Name, "os name should be identified")
	assert.Equal(t, "MX 23.2 Libretto", di.Title, "os title should be identified")
	assert.Equal(t, "23.2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestZorinLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-zorin.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "zorin", di.Name, "os name should be identified")
	assert.Equal(t, "Zorin OS 16", di.Title, "os title should be identified")
	assert.Equal(t, "16", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestParrotLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-parrot.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "parrot", di.Name, "os name should be identified")
	assert.Equal(t, "Parrot OS 5.3 (Electro Ara)", di.Title, "os title should be identified")
	assert.Equal(t, "5.3", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestSteamOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-steamos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "steamos", di.Name, "os name should be identified")
	assert.Equal(t, "SteamOS", di.Title, "os title should be identified")
	assert.Equal(t, "3.7.16", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family)
}

func TestAzureLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-azurelinux.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "azurelinux", di.Name, "os name should be identified")
	assert.Equal(t, "Microsoft Azure Linux", di.Title, "os title should be identified")
	assert.Equal(t, "3.0", di.Version, "os version should be identified")
	assert.Equal(t, "3.0.20241005", di.Build, "os build should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// CBL-Mariner is Azure Linux under its pre-3.0 name and ships ID=mariner. It
// keeps reporting as "mariner" rather than being folded into "azurelinux",
// which would break anyone filtering on the name. Before it was wired into the
// azurelinux resolver it fell through to defaultLinux, which reads neither
// NAME nor VERSION, so title was the generic PRETTY_NAME and build was empty.
func TestMarinerDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-mariner.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "mariner", di.Name, "os name should be identified")
	assert.Equal(t, "Common Base Linux Mariner", di.Title, "os title should be identified")
	assert.Equal(t, "2.0", di.Version, "os version should be identified")
	assert.Equal(t, "2.0.20260304", di.Build, "os build should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestDetectorFlatcar(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-flatcar.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "flatcar", di.Name, "os name should be identified")
	assert.Equal(t, "Flatcar Container Linux by Kinvolk", di.Title, "os title should be identified")
	assert.Equal(t, "4459.0.0", di.Version, "os version should be identified")
	assert.Equal(t, "2025-09-12-2110", di.Build, "os build should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestDetectorTalos(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-talos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "talos", di.Name, "os name should be identified")
	assert.Equal(t, "Talos (v1.13.9)", di.Title, "os title should be identified")
	// VERSION_ID is v1.13.9 on this target; the vendor's "v" prefix is stripped
	// so version comparisons do not have to special-case Talos. The prefixed
	// string survives in Title, which is PRETTY_NAME verbatim.
	assert.Equal(t, "1.13.9", di.Version, "os version should have the v prefix stripped")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
	assert.Equal(t, map[string]string{"distro-id": "talos"}, di.Labels)
}

// Talos ships no shell, no package database and no sshd, so it is only ever
// reached as an image, a disk or a mounted filesystem. Nothing claimed
// ID=talos, so it fell to the generic resolver, and platform_resolver.go
// renames any container claimed only by that resolver to "scratch", which
// reports an empty package list with no error.
func TestTalosIsClaimedByItsOwnResolver(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/detect-talos.toml"))
	require.NoError(t, err)

	pf, leaf, resolved := OperatingSystems.resolvePlatform(&inventory.Platform{}, mockConn)
	require.True(t, resolved, "platform should resolve")
	require.NotNil(t, leaf)

	assert.Equal(t, talos, leaf, "Talos must be claimed by its own resolver")
	assert.False(t, isUnidentifiedPlatform(pf, leaf),
		"a container image claimed only by the generic resolver is reported as scratch")
}

// Anolis OS, OpenCloudOS, deepin and openKylin all set an ID no resolver
// claimed, so detection fell to the generic resolver and every one of their
// container images was reported as "scratch": no family, and so no package
// manager and no findings.
//
// Each lands in a different place, and the family is the point: it is what
// selects rpm or dpkg further down.

func TestAnolisDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-anolis-8.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "anolis", di.Name, "os name should be identified")
	assert.Equal(t, "Anolis OS 8.8", di.Title, "os title should be identified")
	assert.Equal(t, "8.8", di.Version, "os version should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

// OpenCloudOS ships no /etc/redhat-release, so the redhat family declines it
// before its children are consulted. It resolves as a platform of its own and
// packages.go names it to get the rpm package manager back.
func TestOpenCloudOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-opencloudos-9.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "opencloudos", di.Name, "os name should be identified")
	assert.Equal(t, "OpenCloudOS 9.0", di.Title, "os title should be identified")
	assert.Equal(t, "9.0", di.Version, "os version should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestDeepinDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-deepin-25.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "deepin", di.Name, "os name should be identified")
	assert.Equal(t, "Deepin 25", di.Title, "os title should be identified")
	assert.Equal(t, "25", di.Version, "os version should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestOpenKylinDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-openkylin-3.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "openkylin", di.Name, "os name should be identified")
	assert.Equal(t, "openKylin 3.0", di.Title, "os title should be identified")
	assert.Equal(t, "3.0", di.Version, "os version should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestEndeavourOSContainerDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-endeavouros.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "endeavouros", di.Name, "os name should be identified")
	assert.Equal(t, "EndeavourOS", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family)
}

func TestCumulusOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-cumulus.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "cumulus-linux", di.Name, "os name should be identified")
	assert.Equal(t, "Cumulus Linux", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
	assert.Equal(t, "5.12.1", di.Version)
	assert.Equal(t, "5.12.1.0026", di.Build)
}

func TestNobaraDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-nobara.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "nobara", di.Name, "os name should be identified")
	assert.Equal(t, "Nobara Linux 40 (KDE Plasma)", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestHCEDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-hce-2.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "hce", di.Name, "os name should be identified")
	assert.Equal(t, "Huawei Cloud EulerOS 2.0 (x86_64)", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"euler", "linux", "unix", "os"}, di.Family)
}

func TestEulerOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-euleros-2.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "euleros", di.Name, "os name should be identified")
	assert.Equal(t, "EulerOS 2.0 (SP9x86_64)", di.Title, "os title should be identified")
	assert.Equal(t, "2.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"euler", "linux", "unix", "os"}, di.Family)
}

// Verify /etc/euleros-release overrides the title from /etc/os-release
func TestEulerOSDetector_withdifferentversion(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-euleros-2_v2.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "euleros", di.Name, "os name should be identified")
	assert.Equal(t, "EulerOS 2.0 (SP9x86_64)", di.Title, "os title should be identified")
	assert.Equal(t, "2.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"euler", "linux", "unix", "os"}, di.Family)
}

func TestGardenLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-gardenlinux.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "gardenlinux", di.Name, "os name should be identified")
	assert.Equal(t, "Garden Linux 934.0", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
	assert.Equal(t, "934.0", di.Version, "os version should be identified")
}

func TestGardenLinuxDetector_1877(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-gardenlinux_1877.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "gardenlinux", di.Name, "os name should be identified")
	assert.Equal(t, "Garden Linux 1877.9", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
	assert.Equal(t, "1877.9", di.Version, "os version should be identified")
}

func TestElxrDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-elxr-12.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "elxr", di.Name, "os name should be identified")
	assert.Equal(t, "eLxr 12 (aria)", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
	assert.Equal(t, "12", di.Version, "os version should be identified")
}

func TestCachyOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-cachyos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "cachyos", di.Name, "os name should be identified")
	assert.Equal(t, "CachyOS", di.Title, "os title should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"arch", "linux", "unix", "os"}, di.Family)
}

func TestTailsDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-tails.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "tails", di.Name, "os name should be identified")
	assert.Equal(t, "Tails", di.Title, "os title should be identified")
	assert.Equal(t, "6.11", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestKDENeonDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-kdeneon.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "neon", di.Name, "os name should be identified")
	assert.Equal(t, "KDE neon 6.2", di.Title, "os title should be identified")
	assert.Equal(t, "22.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestWindriver7Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-windriver7.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "wrlinux", di.Name, "os name should be identified")
	assert.Equal(t, "Wind River Linux 7.0.0.2", di.Title, "os title should be identified")
	assert.Equal(t, "7.0.0.2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestQubesOSDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-qubes.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "qubes", di.Name, "os name should be identified")
	assert.Equal(t, "Qubes OS 4.2 (R4.2)", di.Title, "os title should be identified")
	assert.Equal(t, "4.2", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

// os-release does not require an ID field, and vendor firmware such as FRITZ!OS
// ships without one. The name is derived from NAME so the platform does not end
// up reported as "unknown".
func TestOSReleaseWithoutIDDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-fritzos.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "fritzos", di.Name, "os name should be derived from NAME")
	assert.Equal(t, "FRITZ!OS 8.03", di.Title, "os title should be identified")
	assert.Equal(t, "8.03", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// a linux system that carries no lsb or os-release information at all falls back
// to the generic-linux resolver name
func TestGenericLinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-generic-linux.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "generic-linux", di.Name, "os name should fall back to the generic name")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

// PRETTY_NAME is not used to derive a name, since it carries the version and
// would mint a new platform name for every release. Without an ID or a NAME the
// system falls back to generic-linux, keeping PRETTY_NAME as the title only.
func TestOSReleaseWithPrettyNameOnlyDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-linux-prettyname-only.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "generic-linux", di.Name, "os name should not be derived from PRETTY_NAME")
	assert.Equal(t, "Some Vendor Linux 1.2.3", di.Title, "os title should be identified")
	assert.Equal(t, "1.2.3", di.Version, "os version should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestSlugifyPlatformName(t *testing.T) {
	test := []struct {
		Val      string
		Expected string
	}{
		{Val: "FRITZ!OS", Expected: "fritzos"},
		{Val: "Buildroot", Expected: "buildroot"},
		{Val: "Generic Vendor Linux", Expected: "generic-vendor-linux"},
		{Val: "Debian GNU/Linux", Expected: "debian-gnulinux"},
		{Val: "", Expected: ""},
	}

	for i := range test {
		assert.Equal(t, test[i].Expected, slugifyPlatformName(test[i].Val), test[i].Val)
	}
}

// container images we cannot identify are reported as "scratch". The check keys
// off the resolver that matched, not the platform name, because a resolver does
// not always emit the name it is registered under.
func TestIsUnidentifiedPlatform(t *testing.T) {
	test := []struct {
		Name     string
		Leaf     *PlatformResolver
		Expected bool
	}{
		{Name: "", Leaf: nil, Expected: true},
		{Name: "generic-linux", Leaf: defaultLinux, Expected: true},
		// a name derived from os-release NAME still means we could not identify
		// the distribution, so container images stay "scratch"
		{Name: "fritzos", Leaf: defaultLinux, Expected: true},
		{Name: "ubuntu", Leaf: ubuntu, Expected: false},
		// the oracle resolver emits "oraclelinux", a name it is not registered
		// under. It must not be mistaken for an unidentified platform.
		{Name: "oraclelinux", Leaf: oracle, Expected: false},
		{Name: "alpine", Leaf: alpine, Expected: false},
	}

	for i := range test {
		pf := &inventory.Platform{Name: test[i].Name}
		assert.Equal(t, test[i].Expected, isUnidentifiedPlatform(pf, test[i].Leaf), test[i].Name)
	}
}

func TestRhel10Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-rhel-10.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "redhat", di.Name, "os name should be identified")
	assert.Equal(t, "Red Hat Enterprise Linux 10.0 (Coughlan)", di.Title, "os title should be identified")
	assert.Equal(t, "10.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}

func TestAmazon2023LinuxDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-amzn-2023.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "amazonlinux", di.Name, "os name should be identified")
	assert.Equal(t, "Amazon Linux 2023.12.20260817", di.Title, "os title should be identified")
	assert.Equal(t, "2023", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"linux", "unix", "os"}, di.Family)
}

func TestDebian11Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian11.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "debian", di.Name, "os name should be identified")
	assert.Equal(t, "Debian GNU/Linux 11 (bullseye)", di.Title, "os title should be identified")
	assert.Equal(t, "11.11", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestDebian12Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian12.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "debian", di.Name, "os name should be identified")
	assert.Equal(t, "Debian GNU/Linux 12 (bookworm)", di.Title, "os title should be identified")
	assert.Equal(t, "12.15", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestDebian13Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-debian13.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "debian", di.Name, "os name should be identified")
	assert.Equal(t, "Debian GNU/Linux 13 (trixie)", di.Title, "os title should be identified")
	assert.Equal(t, "13.6", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestUbuntu2404Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu2404.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu 24.04.4 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "24.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestUbuntu2604Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-ubuntu2604.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "ubuntu", di.Name, "os name should be identified")
	assert.Equal(t, "Ubuntu 26.04 LTS", di.Title, "os title should be identified")
	assert.Equal(t, "26.04", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"debian", "linux", "unix", "os"}, di.Family)
}

func TestSles16Detector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-suse-sles-16.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "sles", di.Name, "os name should be identified")
	assert.Equal(t, "SUSE Linux Enterprise Server 16.0", di.Title, "os title should be identified")
	assert.Equal(t, "16.0", di.Version, "os version should be identified")
	assert.Equal(t, "x86_64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"suse", "linux", "unix", "os"}, di.Family)
}

// Fedora ELN's /etc/redhat-release reads "Fedora ELN 11", with no "release"
// keyword. The redhat family resolver treats an unparseable release file as
// "not a redhat host", so before this was handled ELN skipped the whole redhat
// subtree and landed in defaultLinux as name "eln" with no redhat family,
// which killed every resource gated on IsFamily("redhat").
func TestFedoraELNDetector(t *testing.T) {
	di, err := detectPlatformFromMock("./testdata/detect-fedora-eln.toml")
	assert.Nil(t, err, "was able to create the provider")

	assert.Equal(t, "fedora", di.Name, "os name should be identified")
	assert.Equal(t, "Fedora ELN 11", di.Title, "os title should be identified")
	assert.Equal(t, "11", di.Version, "os version should be identified")
	assert.Equal(t, "aarch64", di.Arch, "os arch should be identified")
	assert.Equal(t, []string{"redhat", "linux", "unix", "os"}, di.Family)
}
