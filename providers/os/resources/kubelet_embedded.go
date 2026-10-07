// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"sigs.k8s.io/yaml"
)

// kubeletHost is the kind of process the kubelet runs in. K3s and MicroK8s
// run it inside their own process, with no kubelet process and no kubelet
// command line to read.
type kubeletHost int

const (
	// kubeletStandalone is a kubelet process of its own.
	kubeletStandalone kubeletHost = iota
	// kubeletInK3s is the kubelet inside "k3s server" or "k3s agent", which
	// Linux names k3s-server and k3s-agent.
	kubeletInK3s
	// kubeletInKubelite is the kubelet inside MicroK8s's kubelite.
	kubeletInKubelite
)

// kubeletHostOf returns the kind of process an executable and its command
// line name. K3s renames its process k3s-server or k3s-agent, which
// /proc/<pid>/status reports, while a process list built from ps reports the
// binary, k3s, with the subcommand on the command line. "k3s kubectl" and the
// like are one-off commands, not a node.
func kubeletHostOf(executable string, command string) kubeletHost {
	switch path.Base(executable) {
	case "k3s-server", "k3s-agent":
		return kubeletInK3s
	case "k3s":
		if fields := strings.Fields(command); len(fields) > 1 && (fields[1] == "server" || fields[1] == "agent") {
			return kubeletInK3s
		}
		return kubeletStandalone
	case "kubelite":
		return kubeletInKubelite
	default:
		return kubeletStandalone
	}
}

// processKubeletHost returns the kind of kubelet host a process is.
func processKubeletHost(proc *mqlProcess) kubeletHost {
	exe := proc.GetExecutable()
	if exe.Error != nil {
		return kubeletStandalone
	}
	command := proc.GetCommand()
	if command.Error != nil {
		return kubeletHostOf(exe.Data, "")
	}
	return kubeletHostOf(exe.Data, command.Data)
}

// k3sDefaultDataDir is where K3s keeps its state when run as root.
const k3sDefaultDataDir = "/var/lib/rancher/k3s"

// k3sConfigFile is K3s's configuration file, which holds the same options as
// its command line.
const k3sConfigFile = "/etc/rancher/k3s/config.yaml"

// k3sKubeletFlags returns the kubelet flags K3s passes that a scan can read:
// --kubelet-arg from its command line and from its config file, and
// --config-dir, which K3s points at the drop-in directory it writes most of
// the kubelet's configuration to. A command-line value overrides the config
// file's, as in K3s.
func k3sKubeletFlags(command string, configFile string) map[string]any {
	// K3s passes --read-only-port=0 itself; a --kubelet-arg can override it.
	flags := map[string]any{"read-only-port": "0"}
	dataDir := k3sDefaultDataDir

	var fileConfig map[string]any
	if configFile != "" && yaml.Unmarshal([]byte(configFile), &fileConfig) == nil {
		if v, ok := fileConfig["data-dir"].(string); ok && v != "" {
			dataDir = v
		}
		for _, arg := range stringOrList(fileConfig["kubelet-arg"]) {
			addKeyValueFlag(flags, arg)
		}
	}

	args := strings.Fields(command)
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		switch name {
		case "--kubelet-arg", "--data-dir", "-d":
		default:
			continue
		}
		if !hasValue {
			if i+1 >= len(args) {
				continue
			}
			i++
			value = args[i]
		}
		if name == "--kubelet-arg" {
			addKeyValueFlag(flags, value)
		} else {
			dataDir = value
		}
	}

	if _, ok := flags["config-dir"]; !ok {
		flags["config-dir"] = path.Join(dataDir, "agent", "etc", "kubelet.conf.d")
	}
	return flags
}

// stringOrList reads a K3s config value that may be one string or a list.
func stringOrList(v any) []string {
	switch v := v.(type) {
	case string:
		return []string{v}
	case []any:
		res := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				res = append(res, s)
			}
		}
		return res
	}
	return nil
}

// addKeyValueFlag adds a "name=value" kubelet argument, with or without its
// leading dashes, to flags.
func addKeyValueFlag(flags map[string]any, arg string) {
	name, value, _ := strings.Cut(strings.TrimLeft(arg, "-"), "=")
	if name != "" {
		flags[strings.ToLower(name)] = value
	}
}

var snapVariable = regexp.MustCompile(`\$\{(SNAP|SNAP_DATA|SNAP_COMMON)\}`)

// microk8sKubeletFlags parses MicroK8s's kubelet arguments file, one
// "--name=value" per line, whose paths use the snap's ${SNAP}, ${SNAP_DATA}
// and ${SNAP_COMMON}. argsFile is that file's path
// (/var/snap/microk8s/<revision>/args/kubelet), from which the snap's
// directories follow.
func microk8sKubeletFlags(content string, argsFile string) map[string]any {
	snapData := path.Dir(path.Dir(argsFile))
	revision := path.Base(snapData)
	vars := map[string]string{
		"SNAP":        path.Join("/snap/microk8s", revision),
		"SNAP_DATA":   snapData,
		"SNAP_COMMON": path.Join(path.Dir(snapData), "common"),
	}

	flags := map[string]any{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-") {
			continue
		}
		name, value, _ := strings.Cut(strings.TrimLeft(line, "-"), "=")
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		value = snapVariable.ReplaceAllStringFunc(value, func(v string) string {
			return vars[v[2:len(v)-1]]
		})
		if name != "" {
			flags[strings.ToLower(name)] = value
		}
	}
	return flags
}

// microk8sSnapVersion returns the version in MicroK8s's snap.yaml, such as
// "v1.35.6". kubelite has no --version: run with it, it starts a second
// MicroK8s, so the version is read, never run.
func microk8sSnapVersion(snapYAML string) string {
	for _, line := range strings.Split(snapYAML, "\n") {
		if v, ok := strings.CutPrefix(line, "version:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// microk8sVersion reads the version of the MicroK8s whose kubelite runs the
// kubelet from the snap.yaml of that snap revision
// (/snap/microk8s/<revision>/meta/snap.yaml next to /snap/microk8s/<revision>/kubelite).
func (m *mqlKubelet) microk8sVersion(proc *mqlProcess) (string, error) {
	command := proc.GetCommand()
	if command.Error != nil {
		return "", command.Error
	}
	fields := strings.Fields(command.Data)
	if len(fields) == 0 {
		return "", nil
	}
	kubelite := path.Clean(fields[0])
	if !strings.HasPrefix(kubelite, "/snap/microk8s/") {
		return "", nil
	}
	snapYAML := path.Join(path.Dir(kubelite), "meta", "snap.yaml")
	return microk8sSnapVersion(readKubeletFile(m.MqlRuntime, snapYAML)), nil
}

// kubeletDropInFiles orders the files of a --config-dir as the kubelet reads
// them: only names ending in .conf, in lexical order, each overriding the
// ones before.
func kubeletDropInFiles(names []string) []string {
	res := []string{}
	for _, name := range names {
		if strings.HasSuffix(name, ".conf") {
			res = append(res, name)
		}
	}
	sort.Strings(res)
	return res
}

// readKubeletFile reads a file on the target through the file resource, so
// it uses sudo where the scan does. A missing or unreadable file reads as "".
func readKubeletFile(runtime *plugin.Runtime, p string) string {
	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(p),
	})
	if err != nil {
		return ""
	}
	content := f.(*mqlFile).GetContent()
	if content.Error != nil {
		return ""
	}
	return content.Data
}
