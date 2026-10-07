// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/pem"
	"path"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// defaultKubeletCertDir is where the kubelet keeps its certificates when
// --cert-dir is not set.
const defaultKubeletCertDir = "/var/lib/kubelet/pki"

func (m *mqlKubelet) flags() (map[string]any, error) {
	return kubeletFlags(m.MqlRuntime, m.Process.Data)
}

func (m *mqlKubelet) configDir() (string, error) {
	flags, err := m.flags()
	if err != nil {
		return "", err
	}
	dir, _ := flags["config-dir"].(string)
	return dir, nil
}

func (m *mqlKubelet) configDropIns() ([]any, error) {
	flags, err := m.flags()
	if err != nil {
		return nil, err
	}
	files := []any{}
	for _, p := range m.kubeletDropInPaths(flags) {
		f, err := CreateResource(m.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

func (m *mqlKubelet) kubeconfig() (*mqlFile, error) {
	flags, err := m.flags()
	if err != nil {
		return nil, err
	}
	p, _ := flags["kubeconfig"].(string)
	if p == "" {
		m.Kubeconfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	f, err := CreateResource(m.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

// kubeletServingCertPath returns the file the kubelet serves its HTTPS port
// with: tlsCertFile, or, when none is configured, the certificate it keeps in
// its certificate directory. With serverTLSBootstrap that is the one the API
// server issued; otherwise the kubelet generates a self-signed one at startup.
func kubeletServingCertPath(tlsCertFile string, serverTLSBootstrap bool, certDir string) string {
	if tlsCertFile != "" {
		return tlsCertFile
	}
	if certDir == "" {
		certDir = defaultKubeletCertDir
	}
	if serverTLSBootstrap {
		return path.Join(certDir, "kubelet-server-current.pem")
	}
	return path.Join(certDir, "kubelet.crt")
}

func (m *mqlKubelet) servingCertificates() ([]any, error) {
	tlsCertFile, err := m.configValue("tlsCertFile")
	if err != nil {
		return nil, err
	}
	bootstrap, err := m.configValue("serverTLSBootstrap")
	if err != nil {
		return nil, err
	}
	flags, err := m.flags()
	if err != nil {
		return nil, err
	}
	certDir, _ := flags["cert-dir"].(string)
	p := kubeletServingCertPath(kubeletString(tlsCertFile), kubeletBool(bootstrap), certDir)
	return kubeletCertificates(m.MqlRuntime, p)
}

func (m *mqlKubelet) clientCAs() ([]any, error) {
	p, err := m.configValue("authentication", "x509", "clientCAFile")
	if err != nil {
		return nil, err
	}
	if kubeletString(p) == "" {
		return []any{}, nil
	}
	return kubeletCertificates(m.MqlRuntime, kubeletString(p))
}

// kubeletCertificates parses the certificates in a PEM file on the target.
// kubelet-server-current.pem holds the serving certificate and its private
// key in one file, so only the CERTIFICATE blocks are handed on: the PEM
// becomes an argument of the certificates resource, and arguments are kept
// with the scan's data.
func kubeletCertificates(runtime *plugin.Runtime, p string) ([]any, error) {
	certs := pemCertificateBlocks(readKubeletFile(runtime, p))
	if certs == "" {
		return []any{}, nil
	}
	c, err := runtime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(certs),
	})
	if err != nil {
		return nil, err
	}
	list, err := runtime.GetSharedData("certificates", c.MqlID(), "list")
	if err != nil || list == nil {
		return []any{}, err
	}
	if v, ok := list.Value.([]any); ok {
		return v, nil
	}
	return []any{}, nil
}

func (m *mqlKubelet) webhookAuthenticationEnabled() (bool, error) {
	return m.configBool(&m.WebhookAuthenticationEnabled, "authentication", "webhook", "enabled")
}

func (m *mqlKubelet) staticPodPath() (string, error) {
	v, err := m.configValue("staticPodPath")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) staticPodManifests() ([]any, error) {
	dir, err := m.staticPodPath()
	if err != nil {
		return nil, err
	}
	if !path.IsAbs(dir) {
		return []any{}, nil
	}
	// The kubelet reads every file in the directory but hidden ones, or the
	// path itself when it is a file.
	out, ok := m.runQuiet("find " + shellQuote(dir) + " -maxdepth 1 -type f ! -name '.*'")
	if !ok {
		return []any{}, nil
	}
	files := []any{}
	for _, p := range staticPodManifestPaths(out) {
		f, err := CreateResource(m.MqlRuntime, "file", map[string]*llx.RawData{"path": llx.StringData(p)})
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

// staticPodManifestPaths returns the paths find printed, sorted.
func staticPodManifestPaths(out string) []string {
	paths := []string{}
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); path.IsAbs(line) {
			paths = append(paths, line)
		}
	}
	sort.Strings(paths)
	return paths
}

func (m *mqlKubelet) allowedUnsafeSysctls() ([]any, error) {
	v, err := m.configValue("allowedUnsafeSysctls")
	if err != nil {
		return nil, err
	}
	return kubeletList(v), nil
}

func (m *mqlKubelet) seccompDefault() (bool, error) {
	return m.configBool(&m.SeccompDefault, "seccompDefault")
}

func (m *mqlKubelet) podPidsLimit() (int64, error) {
	v, err := m.configValue("podPidsLimit")
	if err != nil {
		return 0, err
	}
	// the configuration has the kubelet's default (-1, unlimited) applied, so
	// only a configuration without the key at all lacks it
	if v == nil {
		m.PodPidsLimit.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return kubeletInt(v), nil
}

func (m *mqlKubelet) enableDebuggingHandlers() (bool, error) {
	return m.configBool(&m.EnableDebuggingHandlers, "enableDebuggingHandlers")
}

func (m *mqlKubelet) enableSystemLogHandler() (bool, error) {
	return m.configBool(&m.EnableSystemLogHandler, "enableSystemLogHandler")
}

func (m *mqlKubelet) enableSystemLogQuery() (bool, error) {
	return m.configBool(&m.EnableSystemLogQuery, "enableSystemLogQuery")
}

func (m *mqlKubelet) enableProfilingHandler() (bool, error) {
	return m.configBool(&m.EnableProfilingHandler, "enableProfilingHandler")
}

func (m *mqlKubelet) imagePullCredentialsVerificationPolicy() (string, error) {
	v, err := m.configValue("imagePullCredentialsVerificationPolicy")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) featureGates() (map[string]any, error) {
	v, err := m.configValue("featureGates")
	if err != nil {
		return nil, err
	}
	return kubeletFeatureGates(v), nil
}

// kubeletList returns a config list as a list of strings.
func kubeletList(v any) []any {
	res := []any{}
	list, _ := v.([]any)
	for _, item := range list {
		if s, ok := item.(string); ok {
			res = append(res, s)
		}
	}
	return res
}

// kubeletFeatureGates returns the feature gates of the config, which arrive
// as booleans from the config file and as strings from --feature-gates.
func kubeletFeatureGates(v any) map[string]any {
	res := map[string]any{}
	gates, _ := v.(map[string]any)
	for name, enabled := range gates {
		res[name] = kubeletBool(enabled)
	}
	return res
}

// pemCertificateBlocks returns only the CERTIFICATE blocks of a PEM file,
// re-encoded, and drops every other block (private keys) and any text
// between blocks.
func pemCertificateBlocks(content string) string {
	var out strings.Builder
	rest := []byte(content)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			_ = pem.Encode(&out, &pem.Block{Type: block.Type, Bytes: block.Bytes})
		}
	}
	return out.String()
}

// configBool reads a boolean of the kubelet's configuration, which has the
// kubelet's defaults applied, so a field the configuration file leaves unset
// reads its default (enableDebuggingHandlers: true). A key the configuration
// does not hold at all reads null rather than false, so that a missing value
// is never taken for an explicit false.
func (m *mqlKubelet) configBool(field *plugin.TValue[bool], keys ...string) (bool, error) {
	v, err := m.configValue(keys...)
	if err != nil {
		return false, err
	}
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return kubeletBool(v), nil
}
