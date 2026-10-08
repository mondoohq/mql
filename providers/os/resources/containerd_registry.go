// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/types"
)

// containerdRegistryHost is a host of a registry namespace.
type containerdRegistryHost struct {
	Namespace    string
	URL          string
	Server       bool
	Capabilities []string
	SkipVerify   bool
	CACerts      []string
	ClientCerts  []string
	// File is the hosts.toml the host is read from, empty for one from the
	// deprecated inline settings
	File string
}

// containerdAllCapabilities are the operations a host is trusted with when
// its configuration names none.
var containerdAllCapabilities = []string{"pull", "resolve", "push"}

// containerdHostFile is the part of a hosts.toml, or of one of its
// [host."<url>"] tables, that applies to one host.
type containerdHostFile struct {
	Capabilities []string `toml:"capabilities"`
	CA           any      `toml:"ca"`
	Client       any      `toml:"client"`
	SkipVerify   *bool    `toml:"skip_verify"`
}

// parseContainerdHostsFile reads a hosts.toml: its hosts in the order they
// are listed, then the server, as containerd tries them.
func parseContainerdHostsFile(namespace, file, content string) ([]containerdRegistryHost, error) {
	var doc struct {
		containerdHostFile
		Server string                        `toml:"server"`
		Host   map[string]containerdHostFile `toml:"host"`
	}
	md, err := toml.Decode(content, &doc)
	if err != nil {
		return nil, err
	}
	dir := path.Dir(file)
	res := []containerdRegistryHost{}
	seen := map[string]bool{}
	for _, key := range md.Keys() {
		if len(key) != 2 || key[0] != "host" || seen[key[1]] {
			continue
		}
		seen[key[1]] = true
		h, err := newContainerdRegistryHost(namespace, key[1], dir, doc.Host[key[1]])
		if err != nil {
			return nil, err
		}
		h.File = file
		res = append(res, h)
	}
	// without a server, images come from the namespace's registry itself
	serverURL := doc.Server
	if serverURL == "" && namespace != "_default" {
		serverURL = containerdDefaultHost(namespace)
	}
	server, err := newContainerdRegistryHost(namespace, serverURL, dir, doc.containerdHostFile)
	if err != nil {
		return nil, err
	}
	server.Server = true
	server.File = file
	return append(res, server), nil
}

func newContainerdRegistryHost(namespace, u, dir string, cfg containerdHostFile) (containerdRegistryHost, error) {
	h := containerdRegistryHost{Namespace: namespace, URL: containerdHostURL(u)}
	h.Capabilities = containerdAllCapabilities
	if len(cfg.Capabilities) > 0 {
		h.Capabilities = cfg.Capabilities
	}
	if cfg.SkipVerify != nil {
		h.SkipVerify = *cfg.SkipVerify
	}
	var err error
	if h.CACerts, err = containerdCertPaths(cfg.CA, dir, false); err != nil {
		return h, fmt.Errorf("invalid ca: %w", err)
	}
	if h.ClientCerts, err = containerdCertPaths(cfg.Client, dir, true); err != nil {
		return h, fmt.Errorf("invalid client: %w", err)
	}
	return h, nil
}

// containerdHostURL completes a host the way containerd does: https unless
// the scheme says otherwise.
func containerdHostURL(u string) string {
	if u == "" || strings.HasPrefix(u, "http") {
		return u
	}
	return "https://" + u
}

// containerdCertPaths reads a `ca` or `client` setting: a path or a list of
// paths, and for `client` a list of certificate and key pairs, of which the
// certificate is returned. Relative paths are taken from the hosts.toml's
// directory.
func containerdCertPaths(v any, dir string, pairs bool) ([]string, error) {
	abs := func(p string) string {
		if p == "" || path.IsAbs(p) {
			return p
		}
		return path.Join(dir, p)
	}
	res := []string{}
	switch x := v.(type) {
	case nil:
	case string:
		res = append(res, abs(x))
	case []any:
		for _, item := range x {
			switch y := item.(type) {
			case string:
				res = append(res, abs(y))
			case []any:
				if !pairs || len(y) != 2 {
					return nil, fmt.Errorf("unexpected %v", y)
				}
				cert, ok := y[0].(string)
				if !ok {
					return nil, fmt.Errorf("unexpected %v", y)
				}
				res = append(res, abs(cert))
			default:
				return nil, fmt.Errorf("unexpected %T", item)
			}
		}
	default:
		return nil, fmt.Errorf("unexpected %T", v)
	}
	return res, nil
}

// containerdHostDirPort matches a host directory that holds a port, which
// containerd writes as host_port_.
var containerdHostDirPort = regexp.MustCompile(`^(.+)_([0-9]+)_$`)

// containerdNamespace returns the registry namespace a host directory
// configures ("registry.local_5000_" is "registry.local:5000").
func containerdNamespace(dir string) string {
	if m := containerdHostDirPort.FindStringSubmatch(dir); m != nil {
		return m[1] + ":" + m[2]
	}
	return dir
}

// containerdHostsFiles returns the hosts.toml files of the registry
// directories, each namespace from the first directory that configures it.
func containerdHostsFiles(fs afero.Fs, roots []string) [][2]string {
	res := [][2]string{}
	seen := map[string]bool{}
	for _, root := range roots {
		entries, err := afero.ReadDir(fs, root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			ns := containerdNamespace(e.Name())
			if seen[ns] {
				continue
			}
			file := path.Join(root, e.Name(), "hosts.toml")
			if _, err := fs.Stat(file); err != nil {
				continue
			}
			seen[ns] = true
			res = append(res, [2]string{ns, file})
		}
	}
	return res
}

// containerdInlineRegistryHosts reads the hosts of the deprecated
// registry.mirrors and registry.configs settings: every mirror endpoint of a
// namespace, then the namespace's registry itself, with the TLS settings
// configured for each endpoint's host.
func containerdInlineRegistryHosts(registry map[string]any, fold bool) []containerdRegistryHost {
	get := func(m map[string]any, key string) any {
		v, _ := containerdGet(m, key, fold)
		return v
	}
	mirrors, _ := get(registry, "mirrors").(map[string]any)
	configs, _ := get(registry, "configs").(map[string]any)

	tlsFor := func(h *containerdRegistryHost) {
		u, err := url.Parse(h.URL)
		if err != nil {
			return
		}
		cfg, _ := configs[u.Host].(map[string]any)
		tls, _ := get(cfg, "tls").(map[string]any)
		h.SkipVerify, _ = get(tls, "insecure_skip_verify").(bool)
		if ca, ok := get(tls, "ca_file").(string); ok && ca != "" {
			h.CACerts = []string{ca}
		}
		if cert, ok := get(tls, "cert_file").(string); ok && cert != "" {
			h.ClientCerts = []string{cert}
		}
	}

	res := []containerdRegistryHost{}
	covered := map[string]bool{}
	namespaces := make([]string, 0, len(mirrors))
	for ns := range mirrors {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)
	for _, ns := range namespaces {
		mirror, _ := mirrors[ns].(map[string]any)
		hasServer := false
		for _, e := range containerdStrings(get(mirror, "endpoint")) {
			h := containerdRegistryHost{Namespace: ns, URL: containerdHostURL(e), Capabilities: containerdAllCapabilities}
			if u, err := url.Parse(h.URL); err == nil {
				covered[u.Host] = true
				if u.Host == ns || u.Host == containerdDefaultHost(ns) {
					hasServer = true
					h.Server = true
				}
			}
			tlsFor(&h)
			res = append(res, h)
		}
		if !hasServer && ns != "*" {
			h := containerdRegistryHost{Namespace: ns, URL: "https://" + containerdDefaultHost(ns), Server: true, Capabilities: containerdAllCapabilities}
			covered[containerdDefaultHost(ns)] = true
			tlsFor(&h)
			res = append(res, h)
		}
	}

	hosts := make([]string, 0, len(configs))
	for host := range configs {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		if covered[host] {
			continue
		}
		h := containerdRegistryHost{Namespace: host, URL: "https://" + host, Server: true, Capabilities: containerdAllCapabilities}
		tlsFor(&h)
		res = append(res, h)
	}
	return res
}

// containerdDefaultHost is the host containerd pulls a namespace's images
// from: Docker Hub's registry for docker.io, the namespace itself otherwise.
func containerdDefaultHost(ns string) string {
	if ns == "docker.io" {
		return "registry-1.docker.io"
	}
	return ns
}

func (c *mqlContainerd) registryHosts() ([]any, error) {
	paths, ok, err := c.registryConfigPathList()
	if err != nil {
		return nil, err
	}
	var hosts []containerdRegistryHost
	if ok && len(paths) > 0 {
		fs := c.MqlRuntime.Connection.(shared.Connection).FileSystem()
		for _, f := range containerdHostsFiles(fs, paths) {
			data, err := afero.ReadFile(fs, f[1])
			if err != nil {
				log.Debug().Err(err).Str("file", f[1]).Msg("containerd> cannot read a hosts.toml")
				continue
			}
			parsed, err := parseContainerdHostsFile(f[0], f[1], string(data))
			if err != nil {
				return nil, llx.MalformedData(fmt.Errorf("cannot parse %s: %w", f[1], err))
			}
			hosts = append(hosts, parsed...)
		}
	} else {
		v, _, err := c.setting(containerdRegistry)
		if err != nil {
			return nil, err
		}
		registry, _ := v.(map[string]any)
		hosts = containerdInlineRegistryHosts(registry, c.major == 2)
	}

	res := []any{}
	for _, h := range hosts {
		r, err := c.newRegistryHost(h)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (c *mqlContainerd) fileResources(paths []string) ([]any, error) {
	res := []any{}
	for _, p := range paths {
		f, err := CreateResource(c.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return nil, err
		}
		res = append(res, f)
	}
	return res, nil
}

// containerdRegistryHostID identifies a host by where it is configured, its
// namespace and URL, and whether it is the namespace's server, which may
// share its URL with one of the hosts.
func containerdRegistryHostID(h containerdRegistryHost) string {
	src := h.File
	if src == "" {
		src = "config"
	}
	role := "host"
	if h.Server {
		role = "server"
	}
	return "containerd.registryHost/" + src + "/" + h.Namespace + "/" + role + "/" + h.URL
}

func (c *mqlContainerd) newRegistryHost(h containerdRegistryHost) (plugin.Resource, error) {
	caps := make([]any, 0, len(h.Capabilities))
	for _, s := range h.Capabilities {
		caps = append(caps, strings.ToLower(s))
	}
	ca, err := c.fileResources(h.CACerts)
	if err != nil {
		return nil, err
	}
	client, err := c.fileResources(h.ClientCerts)
	if err != nil {
		return nil, err
	}
	file := llx.NilData
	if h.File != "" {
		f, err := CreateResource(c.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(h.File)})
		if err != nil {
			return nil, err
		}
		file = llx.ResourceData(f, "file")
	}
	return CreateResource(c.MqlRuntime, "containerd.registryHost", map[string]*llx.RawData{
		"__id":         llx.StringData(containerdRegistryHostID(h)),
		"namespace":    llx.StringData(h.Namespace),
		"url":          llx.StringData(h.URL),
		"server":       llx.BoolData(h.Server),
		"capabilities": llx.ArrayData(caps, types.String),
		"skipVerify":   llx.BoolData(h.SkipVerify),
		"caCerts":      llx.ArrayData(ca, types.Resource("file")),
		"clientCerts":  llx.ArrayData(client, types.Resource("file")),
		"file":         file,
	})
}
