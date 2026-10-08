// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// maxStorageListSize bounds the containers/storage lists read whole
// (images.json, layers.json), a few KB per image or layer.
const maxStorageListSize = 32 << 20

// crioStorage returns containers/storage's root and graph driver as CRI-O
// uses them: crio.root and crio.storage_driver when CRI-O's configuration sets
// them, otherwise graphroot and driver from storage.conf, which CRI-O starts
// from.
func (c *mqlCrio) crioStorage() (string, string, error) {
	cfg := c.GetConfiguration()
	if cfg.Error != nil {
		return "", "", cfg.Error
	}
	data, _ := cfg.Data.(map[string]any)
	crioTable, _ := data["crio"].(map[string]any)
	root, _ := crioTable["root"].(string)
	driver, _ := crioTable["storage_driver"].(string)
	if root != "" && driver != "" {
		return root, driver, nil
	}

	raw, err := CreateResource(c.MqlRuntime, "containers.storage", map[string]*llx.RawData{})
	if err != nil {
		return "", "", err
	}
	storage := raw.(*mqlContainersStorage)
	if root == "" {
		graphRoot := storage.GetGraphRoot()
		if graphRoot.Error != nil {
			return "", "", graphRoot.Error
		}
		root = graphRoot.Data
	}
	if driver == "" {
		d := storage.GetDriver()
		if d.Error != nil {
			return "", "", d.Error
		}
		driver = d.Data
	}
	if driver == "" {
		driver = "overlay"
	}
	return root, driver, nil
}

// crioStorageImage is an entry of containers/storage's images.json.
type crioStorageImage struct {
	ID            string            `json:"id"`
	Digest        string            `json:"digest"`
	Digests       []string          `json:"digests"`
	Names         []string          `json:"names"`
	Layer         string            `json:"layer"`
	BigDataNames  []string          `json:"big-data-names"`
	BigDataSizes  map[string]int64  `json:"big-data-sizes"`
	BigDataDigest map[string]string `json:"big-data-digests"`
}

// crioStorageLayer is an entry of containers/storage's layers.json.
type crioStorageLayer struct {
	ID       string `json:"id"`
	Parent   string `json:"parent"`
	DiffSize int64  `json:"diff-size"`
}

var crioImageID = regexp.MustCompile(`^[0-9a-f]{64}$`)

func parseCrioStorageImages(content string) ([]crioStorageImage, error) {
	if strings.TrimSpace(content) == "" {
		return nil, nil
	}
	var res []crioStorageImage
	if err := json.Unmarshal([]byte(content), &res); err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse containers/storage images: %w", err))
	}
	return res, nil
}

func parseCrioStorageLayers(content string) (map[string]crioStorageLayer, error) {
	res := map[string]crioStorageLayer{}
	if strings.TrimSpace(content) == "" {
		return res, nil
	}
	var layers []crioStorageLayer
	if err := json.Unmarshal([]byte(content), &layers); err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse containers/storage layers: %w", err))
	}
	for _, l := range layers {
		res[l.ID] = l
	}
	return res, nil
}

// crioImageSize is the size containers/storage reports for an image, which is
// what crictl and the kubelet show: the uncompressed size of its layer chain
// and the size of its stored metadata (manifests, configuration).
func crioImageSize(img crioStorageImage, layers map[string]crioStorageLayer) int64 {
	var size int64
	seen := map[string]bool{}
	for id := img.Layer; id != "" && !seen[id]; {
		seen[id] = true
		l, ok := layers[id]
		if !ok {
			break
		}
		size += l.DiffSize
		id = l.Parent
	}
	for _, s := range img.BigDataSizes {
		size += s
	}
	return size
}

// crioBigDataFileName is the file containers/storage keeps an image's big data
// item in: the key itself when it is made of lowercase letters, digits and
// dots, otherwise "=" and the key in base64.
func crioBigDataFileName(key string) string {
	for _, ch := range key {
		if ch != '.' && (ch < '0' || ch > '9') && (ch < 'a' || ch > 'z') {
			return "=" + base64.StdEncoding.EncodeToString([]byte(key))
		}
	}
	return key
}

// crioImageConfigKey is the big data key of the image's configuration, the
// configuration's digest. It is the image ID for every image pulled from a
// registry.
func crioImageConfigKey(img crioStorageImage) string {
	want := "sha256:" + img.ID
	for _, k := range img.BigDataNames {
		if k == want {
			return k
		}
	}
	for _, k := range img.BigDataNames {
		if ociDigestRe.MatchString(k) {
			return k
		}
	}
	return ""
}

// crioRepoDigests lists the content-addressed references of an image: the
// repository of each of its names with each manifest digest it is stored
// under, as Podman reports them.
func crioRepoDigests(img crioStorageImage) []string {
	digests := []string{}
	seenDigest := map[string]bool{}
	add := func(d string) {
		if d != "" && !seenDigest[d] {
			seenDigest[d] = true
			digests = append(digests, d)
		}
	}
	add(img.Digest)
	for _, d := range img.Digests {
		add(d)
	}
	for _, k := range img.BigDataNames {
		if d, ok := strings.CutPrefix(k, "manifest-"); ok {
			add(d)
		}
	}

	res := []string{}
	seen := map[string]bool{}
	for _, name := range img.Names {
		repo := imageRepository(name)
		for _, d := range digests {
			ref := repo + "@" + d
			if !seen[ref] {
				seen[ref] = true
				res = append(res, ref)
			}
		}
	}
	sort.Strings(res)
	return res
}

// imageRepository strips the tag or digest from an image reference. A colon
// before the last slash belongs to a registry port.
func imageRepository(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	if i := strings.LastIndex(ref, ":"); i > slash {
		ref = ref[:i]
	}
	return ref
}

func (c *mqlCrio) images() ([]any, error) {
	root, driver, err := c.crioStorage()
	if err != nil {
		return nil, err
	}

	imagesFile := path.Join(root, driver+"-images", "images.json")
	content, ok := readSmallRegularFile(c.MqlRuntime, imagesFile, maxStorageListSize)
	if !ok {
		log.Debug().Str("path", imagesFile).Msg("crio> cannot read the image list")
		return []any{}, nil
	}
	images, err := parseCrioStorageImages(content)
	if err != nil {
		return nil, err
	}

	layers := map[string]crioStorageLayer{}
	for _, list := range []string{"layers.json", "volatile-layers.json"} {
		content, _ := readSmallRegularFile(c.MqlRuntime, path.Join(root, driver+"-layers", list), maxStorageListSize)
		parsed, err := parseCrioStorageLayers(content)
		if err != nil {
			return nil, err
		}
		for k, v := range parsed {
			layers[k] = v
		}
	}

	res := []any{}
	for _, img := range images {
		if !crioImageID.MatchString(img.ID) {
			continue
		}
		r, err := CreateResource(c.MqlRuntime, "crio.image", map[string]*llx.RawData{
			"id":          llx.StringData(img.ID),
			"names":       llx.ArrayData(convert.SliceAnyToInterface(img.Names), types.String),
			"repoDigests": llx.ArrayData(convert.SliceAnyToInterface(crioRepoDigests(img)), types.String),
			"digest":      llx.StringData(img.Digest),
			"size":        llx.IntData(crioImageSize(img, layers)),
		})
		if err != nil {
			return nil, err
		}
		ci := r.(*mqlCrioImage)
		if key := crioImageConfigKey(img); key != "" {
			ci.configPath = path.Join(root, driver+"-images", img.ID, crioBigDataFileName(key))
			ci.configDigest = key
		}
		res = append(res, ci)
	}
	return res, nil
}

type mqlCrioImageInternal struct {
	// configPath is the image's configuration in containers/storage
	configPath   string
	configDigest string

	lock    sync.Mutex
	loaded  bool
	content *ociImageContent
	err     error
}

// load reads the image's configuration once. Nil without an error when it is
// not stored.
func (p *mqlCrioImage) load() (*ociImageContent, error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	if !p.loaded {
		p.loaded = true
		if p.configPath == "" {
			return nil, nil
		}
		raw, ok := readSmallRegularFile(p.MqlRuntime, p.configPath, maxSmallFileSize)
		if !ok {
			return nil, nil
		}
		c := &ociImageContent{configDigest: p.configDigest, size: p.Size.Data}
		if err := json.Unmarshal([]byte(raw), &c.config); err != nil {
			p.err = llx.MalformedData(fmt.Errorf("cannot parse the configuration of image %s: %w", p.Id.Data, err))
		} else {
			p.content = c
		}
	}
	return p.content, p.err
}

func (p *mqlCrioImage) id() (string, error) {
	return p.Id.Data, nil
}

func (p *mqlCrioImage) labels() (map[string]any, error) {
	return ociImageField(p.load, &p.Labels, func(c *ociImageContent) map[string]any {
		res := make(map[string]any, len(c.config.Config.Labels))
		for k, v := range c.config.Config.Labels {
			res[k] = v
		}
		return res
	})
}

func (p *mqlCrioImage) createdAt() (*time.Time, error) {
	t, err := ociImageField(p.load, &p.CreatedAt, func(c *ociImageContent) *time.Time { return c.config.Created })
	if err == nil && t == nil {
		p.CreatedAt.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return t, err
}

func (p *mqlCrioImage) os() (string, error) {
	return ociImageField(p.load, &p.Os, func(c *ociImageContent) string { return c.config.OS })
}

func (p *mqlCrioImage) architecture() (string, error) {
	return ociImageField(p.load, &p.Architecture, func(c *ociImageContent) string { return c.config.Architecture })
}

func (p *mqlCrioImage) variant() (string, error) {
	return ociImageField(p.load, &p.Variant, func(c *ociImageContent) string { return c.config.Variant })
}

func (p *mqlCrioImage) user() (string, error) {
	return ociImageField(p.load, &p.User, func(c *ociImageContent) string { return c.config.Config.User })
}

func (p *mqlCrioImage) runsAsRoot() (bool, error) {
	return ociImageField(p.load, &p.RunsAsRoot, func(c *ociImageContent) bool { return imageUserIsRoot(c.config.Config.User) })
}

func (p *mqlCrioImage) entrypoint() ([]any, error) {
	return ociImageField(p.load, &p.Entrypoint, func(c *ociImageContent) []any {
		return convert.SliceAnyToInterface(c.config.Config.Entrypoint)
	})
}

func (p *mqlCrioImage) cmd() ([]any, error) {
	return ociImageField(p.load, &p.Cmd, func(c *ociImageContent) []any {
		return convert.SliceAnyToInterface(c.config.Config.Cmd)
	})
}

func (p *mqlCrioImage) workingDir() (string, error) {
	return ociImageField(p.load, &p.WorkingDir, func(c *ociImageContent) string { return c.config.Config.WorkingDir })
}

func (p *mqlCrioImage) exposedPorts() ([]any, error) {
	return ociImageField(p.load, &p.ExposedPorts, func(c *ociImageContent) []any {
		return sortedPorts(c.config.Config.ExposedPorts)
	})
}

func (p *mqlCrioImage) layers() ([]any, error) {
	return ociImageField(p.load, &p.Layers, func(c *ociImageContent) []any {
		layers := make([]any, 0, len(c.config.RootFS.DiffIDs))
		for _, d := range c.config.RootFS.DiffIDs {
			layers = append(layers, d.String())
		}
		return layers
	})
}

// containers lists CRI-O's containers created from the image.
func (p *mqlCrioImage) containers() ([]any, error) {
	d, err := NewResource(p.MqlRuntime, "crio", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := d.(*mqlCrio).GetContainers()
	if all.Error != nil {
		return nil, all.Error
	}
	res := []any{}
	for _, x := range all.Data {
		if c, ok := x.(*mqlCrioContainer); ok && c.imageID == p.Id.Data {
			res = append(res, c)
		}
	}
	return res, nil
}

// sourceImage resolves the image containers/storage records for the
// container, from the image list every container shares.
func (c *mqlCrioContainer) sourceImage() (*mqlCrioImage, error) {
	if c.imageID != "" {
		d, err := NewResource(c.MqlRuntime, "crio", map[string]*llx.RawData{})
		if err != nil {
			return nil, err
		}
		images := d.(*mqlCrio).GetImages()
		if images.Error != nil {
			return nil, images.Error
		}
		for _, x := range images.Data {
			if img, ok := x.(*mqlCrioImage); ok && img.Id.Data == c.imageID {
				return img, nil
			}
		}
	}
	c.SourceImage.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
