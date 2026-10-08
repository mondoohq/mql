// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// ctrImage is one row of `ctr images list`.
type ctrImage struct {
	name      string
	mediaType string
	digest    string
	platforms []string
	labels    map[string]string
}

// parseCtrImageList parses the table `ctr -n <ns> images list` prints. The
// columns are aligned to the header, and the SIZE column holds a space
// ("3.9 MiB"), so each cell is cut at the header's column offsets rather than
// at whitespace.
func parseCtrImageList(output string) []ctrImage {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) < 2 {
		return nil
	}
	cols := []string{"REF", "TYPE", "DIGEST", "SIZE", "PLATFORMS", "LABELS"}
	offsets := make([]int, len(cols))
	for i, col := range cols {
		idx := strings.Index(lines[0], col)
		if idx < 0 {
			return nil
		}
		offsets[i] = utf8.RuneCountInString(lines[0][:idx])
	}

	cell := func(row []rune, i int) string {
		start := offsets[i]
		if start >= len(row) {
			return ""
		}
		end := len(row)
		if i+1 < len(offsets) && offsets[i+1] < end {
			end = offsets[i+1]
		}
		return strings.TrimSpace(string(row[start:end]))
	}

	var res []ctrImage
	for _, line := range lines[1:] {
		row := []rune(line)
		name := cell(row, 0)
		if name == "" {
			continue
		}
		img := ctrImage{
			name:      name,
			mediaType: cell(row, 1),
			digest:    cell(row, 2),
			platforms: []string{},
			labels:    map[string]string{},
		}
		if p := cell(row, 4); p != "" && p != "-" {
			img.platforms = strings.Split(p, ",")
		}
		if l := cell(row, 5); l != "" && l != "-" {
			for _, kv := range strings.Split(l, ",") {
				k, v, _ := strings.Cut(kv, "=")
				img.labels[k] = v
			}
		}
		res = append(res, img)
	}
	return res
}

func (p *mqlContainerd) images() ([]any, error) {
	ctr, namespaces, err := p.listContainerdNamespaces()
	if err != nil {
		return nil, err
	}
	root := p.GetRoot()
	if root.Error != nil {
		return nil, root.Error
	}
	hostOS, hostArch, hostVariant := hostOCIPlatform(p.MqlRuntime)

	res := []any{}
	for _, ns := range namespaces {
		if ns == "" {
			continue
		}
		o, err := CreateResource(p.MqlRuntime, "command", map[string]*llx.RawData{
			"command": llx.StringData(ctrCommand(ctr, "-n", ns, "images", "list")),
		})
		if err != nil {
			return nil, err
		}
		cmd := o.(*mqlCommand)
		if exit := cmd.GetExitcode(); exit.Data != 0 {
			log.Debug().Str("namespace", ns).Str("stderr", cmd.Stderr.Data).Msg("skipping namespace, failed to list images")
			continue
		}

		for _, img := range parseCtrImageList(cmd.Stdout.Data) {
			labels := make(map[string]any, len(img.labels))
			for k, v := range img.labels {
				labels[k] = v
			}
			r, err := CreateResource(p.MqlRuntime, "containerd.image", map[string]*llx.RawData{
				"__id":      llx.StringData(ns + "/" + img.name),
				"name":      llx.StringData(img.name),
				"namespace": llx.StringData(ns),
				"digest":    llx.StringData(img.digest),
				"mediaType": llx.StringData(img.mediaType),
				"platforms": llx.ArrayData(convert.SliceAnyToInterface(img.platforms), types.String),
				"labels":    llx.MapData(labels, types.String),
			})
			if err != nil {
				return nil, err
			}
			ci := r.(*mqlContainerdImage)
			ci.contentRoot = root.Data
			ci.hostOS, ci.hostArch, ci.hostVariant = hostOS, hostArch, hostVariant
			res = append(res, ci)
		}
	}
	return res, nil
}

type mqlContainerdImageInternal struct {
	contentRoot string
	hostOS      string
	hostArch    string
	hostVariant string

	lock    sync.Mutex
	loaded  bool
	content *ociImageContent
	err     error
}

// ociImageContent is what the image's content says about the image built for
// one platform.
type ociImageContent struct {
	configDigest string
	// size is the configuration's and the compressed layers' size
	size   int64
	config ocispec.Image
}

// load reads the image's content once.
func (p *mqlContainerdImage) load() (*ociImageContent, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.loaded {
		read := func(digest string) ([]byte, bool) {
			blob, ok := containerdBlobPath(p.contentRoot, digest)
			if !ok {
				return nil, false
			}
			s, ok := readSmallRegularFile(p.MqlRuntime, blob, maxSmallFileSize)
			return []byte(s), ok
		}
		p.content, p.err = resolveOCIImage(read, p.Digest.Data, p.MediaType.Data, p.hostOS, p.hostArch, p.hostVariant)
		p.loaded = true
	}
	return p.content, p.err
}

var ociDigestRe = regexp.MustCompile(`^([a-z0-9]+):([a-f0-9]{32,128})$`)

// containerdBlobPath is where containerd's content store keeps a blob. The
// digest comes from ctr's output, so it is checked to name nothing but a file
// in the store.
func containerdBlobPath(root, digest string) (string, bool) {
	m := ociDigestRe.FindStringSubmatch(digest)
	if m == nil || root == "" {
		return "", false
	}
	return path.Join(root, "io.containerd.content.v1.content", "blobs", m[1], m[2]), true
}

// ociMediaTypeIsIndex reports whether a media type is a multi-platform index.
func ociMediaTypeIsIndex(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageIndex ||
		mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
}

// resolveOCIImage follows an image's manifest, or its index to the manifest
// for the host's platform, to the image configuration. Nil without an error
// when the content is not stored or there is no manifest for the host.
func resolveOCIImage(read func(digest string) ([]byte, bool), digest, mediaType, hostOS, hostArch, hostVariant string) (*ociImageContent, error) {
	for depth := 0; depth < 3 && ociMediaTypeIsIndex(mediaType); depth++ {
		raw, ok := read(digest)
		if !ok {
			return nil, nil
		}
		var index ocispec.Index
		if err := json.Unmarshal(raw, &index); err != nil {
			return nil, llx.MalformedData(fmt.Errorf("cannot parse image index %s: %w", digest, err))
		}
		desc, ok := selectPlatformManifest(index.Manifests, hostOS, hostArch, hostVariant, func(d string) bool {
			_, ok := read(d)
			return ok
		})
		if !ok {
			return nil, nil
		}
		digest, mediaType = desc.Digest.String(), desc.MediaType
	}
	if ociMediaTypeIsIndex(mediaType) {
		return nil, nil
	}

	raw, ok := read(digest)
	if !ok {
		return nil, nil
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse image manifest %s: %w", digest, err))
	}
	configDigest := manifest.Config.Digest.String()
	raw, ok = read(configDigest)
	if !ok {
		return nil, nil
	}
	res := &ociImageContent{configDigest: configDigest, size: manifest.Config.Size}
	if err := json.Unmarshal(raw, &res.config); err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse image configuration %s: %w", configDigest, err))
	}
	for _, l := range manifest.Layers {
		res.size += l.Size
	}
	return res, nil
}

// selectPlatformManifest picks the manifest an index has for the host's
// platform, the way containerd's default platform matcher does. Without a
// known host architecture it picks the first manifest whose content is
// stored, which on a host that pulled the image is the host's own.
func selectPlatformManifest(manifests []ocispec.Descriptor, hostOS, hostArch, hostVariant string, stored func(digest string) bool) (ocispec.Descriptor, bool) {
	for _, m := range manifests {
		if m.Platform == nil || m.Platform.OS == "unknown" || m.Platform.Architecture == "unknown" {
			continue
		}
		if hostArch == "" {
			if stored(m.Digest.String()) {
				return m, true
			}
			continue
		}
		if hostOS != "" && m.Platform.OS != hostOS {
			continue
		}
		if m.Platform.Architecture != hostArch {
			continue
		}
		if !ociVariantMatches(hostArch, hostVariant, m.Platform.Variant) {
			continue
		}
		return m, true
	}
	return ocispec.Descriptor{}, false
}

// ociVariantMatches compares architecture variants: arm64 without a variant is
// v8, and a host whose variant is unknown takes any.
func ociVariantMatches(arch, host, image string) bool {
	if arch == "arm64" {
		if host == "" {
			host = "v8"
		}
		if image == "" {
			image = "v8"
		}
	}
	return host == "" || image == "" || host == image
}

// hostOCIPlatform names the scanned host's platform as OCI images do.
func hostOCIPlatform(runtime *plugin.Runtime) (string, string, string) {
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok || conn.Asset() == nil || conn.Asset().Platform == nil {
		return "", "", ""
	}
	pf := conn.Asset().Platform
	osName := "linux"
	if pf.IsFamily("windows") {
		osName = "windows"
	}
	arch, variant := ociArch(pf.Arch)
	return osName, arch, variant
}

// ociArch maps a kernel's machine name (`uname -m`) to an OCI architecture
// and variant.
func ociArch(machine string) (string, string) {
	switch strings.ToLower(machine) {
	case "x86_64", "amd64", "x86-64":
		return "amd64", ""
	case "aarch64", "arm64":
		return "arm64", ""
	case "armv7l", "armv7", "armhf":
		return "arm", "v7"
	case "armv6l", "armv6", "armel":
		return "arm", "v6"
	case "i386", "i486", "i586", "i686", "386", "x86":
		return "386", ""
	case "ppc64le", "s390x", "riscv64", "mips64le", "loong64":
		return strings.ToLower(machine), ""
	}
	return "", ""
}

// ociImageField reads one field of an image's configuration, or marks it
// null when the image's content is not stored.
func ociImageField[T any](load func() (*ociImageContent, error), field *plugin.TValue[T], get func(*ociImageContent) T) (T, error) {
	var zero T
	c, err := load()
	if err != nil {
		return zero, err
	}
	if c == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return zero, nil
	}
	return get(c), nil
}

func (p *mqlContainerdImage) configDigest() (string, error) {
	return ociImageField(p.load, &p.ConfigDigest, func(c *ociImageContent) string { return c.configDigest })
}

func (p *mqlContainerdImage) size() (int64, error) {
	return ociImageField(p.load, &p.Size, func(c *ociImageContent) int64 { return c.size })
}

func (p *mqlContainerdImage) createdAt() (*time.Time, error) {
	t, err := ociImageField(p.load, &p.CreatedAt, func(c *ociImageContent) *time.Time { return c.config.Created })
	if err == nil && t == nil {
		p.CreatedAt.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return t, err
}

func (p *mqlContainerdImage) os() (string, error) {
	return ociImageField(p.load, &p.Os, func(c *ociImageContent) string { return c.config.OS })
}

func (p *mqlContainerdImage) architecture() (string, error) {
	return ociImageField(p.load, &p.Architecture, func(c *ociImageContent) string { return c.config.Architecture })
}

func (p *mqlContainerdImage) variant() (string, error) {
	return ociImageField(p.load, &p.Variant, func(c *ociImageContent) string { return c.config.Variant })
}

func (p *mqlContainerdImage) user() (string, error) {
	return ociImageField(p.load, &p.User, func(c *ociImageContent) string { return c.config.Config.User })
}

func (p *mqlContainerdImage) runsAsRoot() (bool, error) {
	return ociImageField(p.load, &p.RunsAsRoot, func(c *ociImageContent) bool { return imageUserIsRoot(c.config.Config.User) })
}

func (p *mqlContainerdImage) entrypoint() ([]any, error) {
	return ociImageField(p.load, &p.Entrypoint, func(c *ociImageContent) []any {
		return convert.SliceAnyToInterface(c.config.Config.Entrypoint)
	})
}

func (p *mqlContainerdImage) cmd() ([]any, error) {
	return ociImageField(p.load, &p.Cmd, func(c *ociImageContent) []any {
		return convert.SliceAnyToInterface(c.config.Config.Cmd)
	})
}

func (p *mqlContainerdImage) workingDir() (string, error) {
	return ociImageField(p.load, &p.WorkingDir, func(c *ociImageContent) string { return c.config.Config.WorkingDir })
}

func (p *mqlContainerdImage) exposedPorts() ([]any, error) {
	return ociImageField(p.load, &p.ExposedPorts, func(c *ociImageContent) []any {
		return sortedPorts(c.config.Config.ExposedPorts)
	})
}

func (p *mqlContainerdImage) layers() ([]any, error) {
	return ociImageField(p.load, &p.Layers, func(c *ociImageContent) []any {
		layers := make([]any, 0, len(c.config.RootFS.DiffIDs))
		for _, d := range c.config.RootFS.DiffIDs {
			layers = append(layers, d.String())
		}
		return layers
	})
}

// containers lists the containers in the image's namespace created from it.
func (p *mqlContainerdImage) containers() ([]any, error) {
	d, err := NewResource(p.MqlRuntime, "containerd", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := d.(*mqlContainerd).GetContainers()
	if all.Error != nil {
		return nil, all.Error
	}
	res := []any{}
	for _, x := range all.Data {
		if c, ok := x.(*mqlContainerdContainer); ok && c.Namespace.Data == p.Namespace.Data && c.Image.Data == p.Name.Data {
			res = append(res, c)
		}
	}
	return res, nil
}

// sourceImage resolves the container's image reference in its namespace,
// from the image list every container shares.
func (c *mqlContainerdContainer) sourceImage() (*mqlContainerdImage, error) {
	if c.Image.Data != "" {
		d, err := NewResource(c.MqlRuntime, "containerd", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}
		images := d.(*mqlContainerd).GetImages()
		if images.Error != nil {
			return nil, images.Error
		}
		for _, x := range images.Data {
			if img, ok := x.(*mqlContainerdImage); ok && img.Namespace.Data == c.Namespace.Data && img.Name.Data == c.Image.Data {
				return img, nil
			}
		}
	}
	c.SourceImage.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
