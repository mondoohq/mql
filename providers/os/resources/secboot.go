// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"debug/pe"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// The configuration secboot reads unless told otherwise.
const secbootDefaultConfigPath = "/etc/secboot/config.json"

// secbootDefaults mirrors the DEFAULTS table in secboot's main.py. The tool
// merges config.json over it, so a key missing from the file is not unset: it
// has the value below, and that is what the next image build uses.
var secbootDefaults = SecbootConfig{
	EfiPartition:         "/dev/disk/by-label/efi",
	EfiMountpoint:        "/boot/efi",
	EfiSubdir:            "/boot/efi/EFI/Linux",
	LuksPartition:        "/dev/disk/by-label/root",
	KernelParams:         "",
	InitramfsCompression: "lz4",
	DkmsFiles:            []string{},
	CertificateStorage:   "/etc/secboot",
	DracutParams:         []string{},
	KernelPriority:       []string{},
	MachineIdPath:        "/etc/machine-id",
	EfiStub:              "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
	FwupdBinary:          "/usr/lib/fwupd/efi/fwupdx64.efi",
	TpmDevice:            "auto",
	TpmPcrs:              "7",
}

// SecbootConfig is config.json, decoded over the tool's defaults.
type SecbootConfig struct {
	EfiPartition         string   `json:"efi-partition"`
	EfiMountpoint        string   `json:"efi-mountpoint"`
	EfiSubdir            string   `json:"efi-subdir"`
	LuksPartition        string   `json:"luks-partition"`
	KernelParams         string   `json:"kernel-params"`
	InitramfsCompression string   `json:"initramfs-compression"`
	DkmsFiles            []string `json:"dkms-files"`
	CertificateStorage   string   `json:"certificate-storage"`
	DracutParams         []string `json:"dracut-params"`
	KernelPriority       []string `json:"kernel-priority"`
	MachineIdPath        string   `json:"machine-id"`
	EfiStub              string   `json:"efi-stub"`
	FwupdBinary          string   `json:"fwupd-binary"`
	TpmDevice            string   `json:"tpm-device"`
	TpmPcrs              string   `json:"tpm-pcrs"`
}

// ParseSecbootConfig decodes config.json on top of the tool's defaults, so
// every field carries the value the next build will use rather than the zero
// value of whatever the file happens to omit.
func ParseSecbootConfig(r io.Reader) (SecbootConfig, error) {
	cfg := secbootDefaults
	// Copy the slices, so a decode that leaves one alone cannot hand the
	// caller the package-level default to write into.
	cfg.DkmsFiles = append([]string{}, secbootDefaults.DkmsFiles...)
	cfg.DracutParams = append([]string{}, secbootDefaults.DracutParams...)
	cfg.KernelPriority = append([]string{}, secbootDefaults.KernelPriority...)

	data, err := io.ReadAll(r)
	if err != nil {
		return cfg, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		// secboot treats an unreadable configuration as fatal, but an empty
		// file decodes to the defaults, which is what it would run with.
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// SecbootImage is one unified kernel image, read from the image rather than
// from any configuration file.
type SecbootImage struct {
	Path       string
	Kernel     string
	Cmdline    string
	Parameters map[string]string
	Flags      []string
	Signed     bool
}

// IMAGE_DIRECTORY_ENTRY_SECURITY, the certificate table that carries an
// Authenticode signature. It is a data directory rather than a section, so it
// does not appear among the image's sections.
const peCertificateTable = 4

// ReadUnifiedKernelImage reads what a unified kernel image boots with. The
// kernel command line and the kernel release are separate sections of the
// executable, per the Unified Kernel Image specification, so only the headers
// and those sections are read: the kernel itself is the bulk of the file and is
// never touched.
func ReadUnifiedKernelImage(r io.ReaderAt) (SecbootImage, error) {
	img := SecbootImage{}

	f, err := pe.NewFile(r)
	if err != nil {
		return img, err
	}
	defer f.Close()

	img.Cmdline = peSectionString(f, ".cmdline")
	img.Kernel = peSectionString(f, ".uname")
	img.Parameters, img.Flags = ParseCmdline(img.Cmdline)

	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		img.Signed = oh.DataDirectory[peCertificateTable].Size > 0
	case *pe.OptionalHeader32:
		img.Signed = oh.DataDirectory[peCertificateTable].Size > 0
	}

	return img, nil
}

// peSectionString returns a section's contents as text. A section is padded out
// to the file alignment, so it is cut to the length the header declares and
// then trimmed of the padding a shorter string leaves behind.
func peSectionString(f *pe.File, name string) string {
	section := f.Section(name)
	if section == nil {
		return ""
	}
	data, err := section.Data()
	if err != nil {
		return ""
	}
	if int(section.VirtualSize) < len(data) {
		data = data[:section.VirtualSize]
	}
	return string(bytes.Trim(data, "\x00\r\n \t"))
}

type mqlSecbootConfigInternal struct {
	lock           sync.Mutex
	fetched        bool
	cachedConfig   SecbootConfig
	imagesFetched  bool
	cachedImages   []SecbootImage
	cachedImagesOK bool
}

func initSecbootConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		if p, ok := x.Value.(string); ok && p != "" {
			return args, nil, nil
		}
	}
	args["path"] = llx.StringData(secbootDefaultConfigPath)
	return args, nil, nil
}

func (s *mqlSecbootConfig) id() (string, error) {
	return "secboot.config:" + s.Path.Data, nil
}

// fetch reads config.json once, so every setting shares a single read.
func (s *mqlSecbootConfig) fetch() error {
	if s.fetched {
		return nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.fetched {
		return nil
	}

	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("wrong connection type")
	}
	fs := conn.FileSystem()
	if fs == nil {
		return errors.New("filesystem not available")
	}

	s.cachedConfig = secbootDefaults
	f, err := fs.Open(s.Path.Data)
	if err != nil {
		// A host that does not run secboot has no configuration. The settings
		// report the defaults the tool would use, and images reports null
		// rather than describing a host that has none.
		s.fetched = true
		return nil
	}
	defer f.Close()

	cfg, err := ParseSecbootConfig(f)
	if err != nil {
		return err
	}
	s.cachedConfig = cfg
	s.fetched = true
	return nil
}

func (s *mqlSecbootConfig) kernelParams() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.KernelParams, nil
}

func (s *mqlSecbootConfig) parameters() (map[string]any, error) {
	if err := s.fetch(); err != nil {
		return nil, err
	}
	params, _ := ParseCmdline(s.cachedConfig.KernelParams)
	return convert.MapToInterfaceMap(params), nil
}

func (s *mqlSecbootConfig) flags() ([]any, error) {
	if err := s.fetch(); err != nil {
		return nil, err
	}
	_, flags := ParseCmdline(s.cachedConfig.KernelParams)
	return convert.SliceAnyToInterface(flags), nil
}

func (s *mqlSecbootConfig) efiPartition() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.EfiPartition, nil
}

func (s *mqlSecbootConfig) efiMountpoint() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.EfiMountpoint, nil
}

func (s *mqlSecbootConfig) efiSubdir() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.EfiSubdir, nil
}

func (s *mqlSecbootConfig) luksPartition() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.LuksPartition, nil
}

func (s *mqlSecbootConfig) efiStub() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.EfiStub, nil
}

func (s *mqlSecbootConfig) certificateStorage() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.CertificateStorage, nil
}

func (s *mqlSecbootConfig) machineIdPath() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.MachineIdPath, nil
}

func (s *mqlSecbootConfig) initramfsCompression() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.InitramfsCompression, nil
}

func (s *mqlSecbootConfig) dracutParams() ([]any, error) {
	if err := s.fetch(); err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(s.cachedConfig.DracutParams), nil
}

func (s *mqlSecbootConfig) kernelPriority() ([]any, error) {
	if err := s.fetch(); err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(s.cachedConfig.KernelPriority), nil
}

func (s *mqlSecbootConfig) dkmsFiles() ([]any, error) {
	if err := s.fetch(); err != nil {
		return nil, err
	}
	return convert.SliceAnyToInterface(s.cachedConfig.DkmsFiles), nil
}

func (s *mqlSecbootConfig) tpmDevice() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.TpmDevice, nil
}

func (s *mqlSecbootConfig) tpmPcrs() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.TpmPcrs, nil
}

func (s *mqlSecbootConfig) fwupdBinary() (string, error) {
	if err := s.fetch(); err != nil {
		return "", err
	}
	return s.cachedConfig.FwupdBinary, nil
}

// fetchImages reads every image under efiSubdir once, so images and drifted
// share one walk.
func (s *mqlSecbootConfig) fetchImages() error {
	if err := s.fetch(); err != nil {
		return err
	}
	if s.imagesFetched {
		return nil
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.imagesFetched {
		return nil
	}

	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return errors.New("wrong connection type")
	}
	fs := conn.FileSystem()
	if fs == nil {
		return errors.New("filesystem not available")
	}

	s.imagesFetched = true

	dir := s.cachedConfig.EfiSubdir
	if dir == "" {
		return nil
	}
	entries, err := afero.ReadDir(fs, dir)
	if err != nil {
		// The directory is absent on a host that does not run secboot, and is
		// unreadable on a scan that cannot see the EFI system partition.
		// Neither is a host with no images.
		return nil
	}

	names := []string{}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(path.Ext(e.Name()), ".efi") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)

	images := make([]SecbootImage, 0, len(names))
	for _, name := range names {
		p := path.Join(dir, name)
		f, err := fs.Open(p)
		if err != nil {
			log.Debug().Str("path", p).Err(err).Msg("cannot open unified kernel image")
			continue
		}
		img, err := ReadUnifiedKernelImage(f)
		f.Close()
		if err != nil {
			// A file with an .efi suffix that is not a unified kernel image,
			// such as the firmware updater secboot copies beside them, is not
			// an error: it is simply not one of the images.
			log.Debug().Str("path", p).Err(err).Msg("not a readable unified kernel image")
			continue
		}
		if img.Cmdline == "" {
			// An EFI binary with no command line section boots nothing this
			// resource can report on, such as the boot loader itself.
			continue
		}
		img.Path = p
		images = append(images, img)
	}

	s.cachedImages = images
	s.cachedImagesOK = len(images) > 0
	return nil
}

func (s *mqlSecbootConfig) images() ([]any, error) {
	if err := s.fetchImages(); err != nil {
		return nil, err
	}

	if !s.cachedImagesOK {
		// A host with no readable images has none to report. An empty list
		// would satisfy every assertion made over the images.
		s.Images.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	resources := make([]any, 0, len(s.cachedImages))
	for _, img := range s.cachedImages {
		resource, err := CreateResource(s.MqlRuntime, "secboot.image", map[string]*llx.RawData{
			"__id":       llx.StringData("secboot.image:" + img.Path),
			"path":       llx.StringData(img.Path),
			"kernel":     llx.StringData(img.Kernel),
			"cmdline":    llx.StringData(img.Cmdline),
			"parameters": llx.MapData(convert.MapToInterfaceMap(img.Parameters), types.String),
			"flags":      llx.ArrayData(convert.SliceAnyToInterface(img.Flags), types.String),
			"signed":     llx.BoolData(img.Signed),
		})
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func (i *mqlSecbootImage) id() (string, error) {
	return i.MqlID(), nil
}
