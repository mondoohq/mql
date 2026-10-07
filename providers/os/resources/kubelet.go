// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package resources

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
	"strconv"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"

	"sigs.k8s.io/yaml"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

const defaultKubeletConfig = "/var/lib/kubelet/config.yaml"

func initKubelet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	p, err := getKubeletProcess(runtime)
	if err != nil {
		return nil, nil, err
	}
	args["process"] = llx.ResourceData(p, "process")

	kubeletFlagsData := p.GetFlags()
	if kubeletFlagsData.Error != nil {
		return nil, nil, kubeletFlagsData.Error
	}
	kubeletFlags := kubeletFlagsData.Data

	// Check kubelet for "--config" flag and set path to config file accordingly
	configFilePath := defaultKubeletConfig
	if kubeletConfigFilePath, ok := kubeletFlags["config"]; ok {
		path, ok := kubeletConfigFilePath.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for value of '--config' flag, it must be a string")
		}
		configFilePath = path
	}

	f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
		"path": llx.StringData(configFilePath),
	})
	if err != nil {
		return nil, nil, err
	}
	mqlFile, ok := f.(*mqlFile)
	if !ok {
		return nil, nil, errors.New("kubelet config file resource has unexpected type")
	}
	args["configFile"] = llx.ResourceData(mqlFile, "file")

	return args, nil, nil
}

func (m *mqlKubelet) configuration() (map[string]any, error) {
	configFileData, err := kubeletConfigContent(m.ConfigFile.Data.GetContent())
	if err != nil {
		return nil, err
	}
	kubeletFlags := map[string]any{}
	if m.Process.Data.GetFlags() != nil {
		kubeletFlags = m.Process.Data.GetFlags().Data
	}
	// The defaults depend on the kubelet's version. Without one (the version
	// cannot be read), the oldest supported release's defaults apply.
	minor := 0
	if version := m.GetVersion(); version.Error == nil {
		minor = kubeletMinorVersion(version.Data)
	}
	// I cannot re-use "mqlFile" here, as it is not read at this point in time
	configuration, err := createConfiguration(kubeletFlags, configFileData, minor)
	if err != nil {
		return nil, err
	}
	return configuration, nil
}

// kubeletMinorVersion returns the minor version of a kubelet version such as
// "v1.36.4+k0s" (36), or 0 when it is not a Kubernetes 1.x version.
func kubeletMinorVersion(version string) int {
	rest, ok := strings.CutPrefix(strings.TrimPrefix(version, "v"), "1.")
	if !ok {
		return 0
	}
	digits := rest
	if i := strings.IndexFunc(rest, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
		digits = rest[:i]
	}
	minor, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return minor
}

// kubeletConfigContent returns the content of the kubelet config file. A file
// that is not there (AKS has none) reads as empty, and the kubelet defaults
// apply. A file the scan may not read (config.yaml is 0600, as CIS
// recommends, on a non-root scan) is a refusal: reading it as empty reported
// the defaults, so readOnlyPort == 0 passed on a kubelet serving 10255. That
// is returned only with structured errors on (ADR 046), since v13 reported
// the defaults.
func kubeletConfigContent(content *plugin.TValue[string]) (string, error) {
	if content == nil {
		return "", nil
	}
	if content.Error == nil {
		return content.Data, nil
	}
	if errors.Is(content.Error, fs.ErrNotExist) {
		return "", nil
	}
	if errors.Is(content.Error, fs.ErrPermission) {
		if !plugin.StructuredErrors() {
			return "", nil
		}
		return "", llx.Forbidden(content.Error)
	}
	return "", content.Error
}

// createConfiguration builds the running kubelet config the way the kubelet
// does: it decodes the config file, fills the fields the file leaves at their
// zero value with the defaults of the kubelet's minor version, and then
// merges the kubelet flags on top.
//
// The defaults come after the file, not before it. kubeadm writes explicit
// zero values such as "streamingConnectionIdleTimeout: 0s" and
// "syncFrequency: 0s", which the kubelet treats as unset and replaces with
// its defaults (4h and 1m). Decoding the file over the defaults reported
// those zeros instead. A map the file sets, such as evictionHard, likewise
// replaces the default map rather than being merged into it.
func createConfiguration(kubeletFlags map[string]any, configFileContent string, minor int) (map[string]any, error) {
	kubeletConfig := kubeletconfigv1beta1.KubeletConfiguration{}

	// AKS has no kubelet config file
	if configFileContent != "" {
		err := yaml.Unmarshal([]byte(configFileContent), &kubeletConfig)
		if err != nil {
			return nil, fmt.Errorf("error when converting file content into KubeletConfiguration: %v", err)
		}
	}
	SetDefaults_KubeletConfiguration(&kubeletConfig, minor)

	options, err := convert.JsonToDict(kubeletConfig)
	if err != nil {
		return nil, fmt.Errorf("error when converting KubeletConfig into dict: %v", err)
	}

	// JSON marshalling of KubeletConfiguration does not include fields with zero/null values
	// But "0" is an important value for the kubelet, so we need to add it manually
	if kubeletConfig.ReadOnlyPort == 0 {
		options["readOnlyPort"] = 0.0
	}

	err = mergeFlagsIntoConfig(options, kubeletFlags)
	if err != nil {
		return nil, fmt.Errorf("error applying precedence to KubeletConfig: %v", err)
	}

	err = mergeDeprecatedFlagsIntoConfig(options, kubeletFlags)
	if err != nil {
		return nil, fmt.Errorf("error applying precedence for deprecated flags to KubeletConfig: %v", err)
	}

	coerceToKubeletTypes(options, reflect.TypeOf(kubeletconfigv1beta1.KubeletConfiguration{}))
	return options, nil
}

var durationType = reflect.TypeOf(metav1.Duration{})

// coerceToKubeletTypes converts the string values that flags put into the
// config map to the types the config file uses for the same fields: a flag
// such as --anonymous-auth=false arrives as "false", where the config holds
// false, so a check for == false failed on a kubelet configured by flags
// (Canonical Kubernetes). Booleans, numbers and comma-separated lists
// (--cluster-dns) are converted; a value that does not parse is left as it
// is. Fields are matched by their JSON name, nested structs included.
func coerceToKubeletTypes(m map[string]any, t reflect.Type) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		v, ok := m[name]
		if !ok {
			continue
		}
		ft := field.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if sub, ok := v.(map[string]any); ok {
			if ft.Kind() == reflect.Struct && ft != durationType {
				coerceToKubeletTypes(sub, ft)
			}
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		switch ft.Kind() {
		case reflect.Bool:
			if b, err := strconv.ParseBool(s); err == nil {
				m[name] = b
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if n, err := strconv.ParseInt(s, 10, 64); err == nil {
				m[name] = float64(n)
			}
		case reflect.Float32, reflect.Float64:
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				m[name] = f
			}
		case reflect.Slice:
			if ft.Elem().Kind() == reflect.String {
				list := []any{}
				for _, item := range strings.Split(s, ",") {
					if item = strings.TrimSpace(item); item != "" {
						list = append(list, item)
					}
				}
				m[name] = list
			}
		}
	}
}

// configValue walks the merged kubelet configuration following the given keys
// and returns the value at that path, or nil if any segment is missing.
func (m *mqlKubelet) configValue(keys ...string) (any, error) {
	cfg := m.GetConfiguration()
	if cfg.Error != nil {
		return nil, cfg.Error
	}
	cur := cfg.Data
	for _, k := range keys {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return nil, nil
		}
		cur, ok = asMap[k]
		if !ok {
			return nil, nil
		}
	}
	return cur, nil
}

// kubelet config values come either from the config file/defaults (native Go
// types) or from CLI flags (always strings), so each accessor coerces both.
func kubeletBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		b, err := strconv.ParseBool(x)
		return err == nil && b
	}
	return false
}

func kubeletString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func kubeletInt(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case string:
		if n, err := strconv.ParseInt(x, 10, 64); err == nil {
			return n
		}
	}
	return 0
}

func (m *mqlKubelet) anonymousAuthEnabled() (bool, error) {
	v, err := m.configValue("authentication", "anonymous", "enabled")
	if err != nil {
		return false, err
	}
	return kubeletBool(v), nil
}

func (m *mqlKubelet) authorizationMode() (string, error) {
	v, err := m.configValue("authorization", "mode")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) clientCAFile() (string, error) {
	v, err := m.configValue("authentication", "x509", "clientCAFile")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) readOnlyPort() (int64, error) {
	v, err := m.configValue("readOnlyPort")
	if err != nil {
		return 0, err
	}
	return kubeletInt(v), nil
}

func (m *mqlKubelet) streamingConnectionIdleTimeout() (string, error) {
	v, err := m.configValue("streamingConnectionIdleTimeout")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) protectKernelDefaults() (bool, error) {
	v, err := m.configValue("protectKernelDefaults")
	if err != nil {
		return false, err
	}
	return kubeletBool(v), nil
}

func (m *mqlKubelet) makeIPTablesUtilChains() (bool, error) {
	v, err := m.configValue("makeIPTablesUtilChains")
	if err != nil {
		return false, err
	}
	return kubeletBool(v), nil
}

func (m *mqlKubelet) eventRecordQPS() (int64, error) {
	v, err := m.configValue("eventRecordQPS")
	if err != nil {
		return 0, err
	}
	return kubeletInt(v), nil
}

func (m *mqlKubelet) tlsCertFile() (string, error) {
	v, err := m.configValue("tlsCertFile")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) tlsPrivateKeyFile() (string, error) {
	v, err := m.configValue("tlsPrivateKeyFile")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) rotateCertificates() (bool, error) {
	v, err := m.configValue("rotateCertificates")
	if err != nil {
		return false, err
	}
	return kubeletBool(v), nil
}

func (m *mqlKubelet) serverTLSBootstrap() (bool, error) {
	v, err := m.configValue("serverTLSBootstrap")
	if err != nil {
		return false, err
	}
	return kubeletBool(v), nil
}

func (m *mqlKubelet) tlsMinVersion() (string, error) {
	v, err := m.configValue("tlsMinVersion")
	if err != nil {
		return "", err
	}
	return kubeletString(v), nil
}

func (m *mqlKubelet) tlsCipherSuites() ([]any, error) {
	v, err := m.configValue("tlsCipherSuites")
	if err != nil {
		return nil, err
	}
	suites, ok := v.([]any)
	if !ok {
		return []any{}, nil
	}
	return suites, nil
}

// parseKubeletVersion extracts the version from "kubelet --version" output,
// which has the form "Kubernetes v1.34.0".
func parseKubeletVersion(out string) string {
	out = strings.TrimSpace(out)
	out = strings.TrimPrefix(out, "Kubernetes ")
	return strings.TrimSpace(out)
}

func (m *mqlKubelet) version() (string, error) {
	proc := m.GetProcess()
	if proc.Error != nil {
		return "", proc.Error
	}
	if proc.Data == nil {
		return "", nil
	}
	exe := proc.Data.GetExecutable()
	if exe.Error != nil {
		return "", exe.Error
	}
	if exe.Data == "" {
		return "", nil
	}
	exePath := resolveKubeletExecutable(exe.Data, m.kubeletBinaryProbe(proc.Data))

	// Single-quote the executable path so paths with spaces or shell
	// metacharacters are passed through unchanged; embedded single quotes
	// are escaped the POSIX way ('\'').
	quotedExe := "'" + strings.ReplaceAll(exePath, "'", `'\''`) + "'"
	o, err := CreateResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(quotedExe + " --version"),
	})
	if err != nil {
		return "", err
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil {
		return "", exit.Error
	} else if exit.Data != 0 {
		return "", errors.New("failed to determine kubelet version: " + cmd.GetStderr().Data)
	}
	return parseKubeletVersion(cmd.GetStdout().Data), nil
}

// kubeletInstallPaths are kubelet binaries that are off PATH, in directories
// only root can write. RKE2 keeps kubelet in /var/lib/rancher/rke2/bin.
var kubeletInstallPaths = []string{"/var/lib/rancher/rke2/bin/kubelet"}

// kubeletBinaryProbe answers what resolveKubeletExecutable needs to know about
// the kubelet process and the files on the target.
type kubeletBinaryProbe struct {
	// rootExe is the binary /proc/<pid>/exe links to, and is "" unless one
	// snapshot of the process shows root running it in the mount namespace of
	// the system's init (see parseKubeletProcSnapshot).
	rootExe func() string
	// argv0 is the first word of the process's command line.
	argv0 func() string
	// resolve returns the file a path names, with every link followed, or ""
	// when it cannot.
	resolve func(path string) string
	// trustedBinary reports whether path is a file owned by root that neither
	// its group nor others may write.
	trustedBinary func(path string) bool
}

// resolveKubeletExecutable returns the path to run for kubelet --version. On
// Linux the process list reports the bare name from /proc/<pid>/status, which
// only runs when kubelet is on PATH. k0s (/var/lib/k0s/bin), minikube
// (/var/lib/minikube/binaries/<version>), Canonical Kubernetes (its snap),
// RKE2 and NixOS (/nix/store) all keep kubelet elsewhere.
//
// The kubelet process is matched by name, and any user can start a process
// named kubelet, so a path from the process is used only when root runs it in
// the system's own mount namespace and the path is the very file
// /proc/<pid>/exe says root is running: running that file with --version gives
// no one anything root does not already run. argv[0] goes first because
// Canonical Kubernetes's kubelet is a link to a multi-call binary that acts as
// kubelet only when invoked as kubelet. A path resolve cannot follow comes back
// "" and so never matches. Otherwise kubeletInstallPaths, root's alone to
// change, are tried, and the bare name is kept.
func resolveKubeletExecutable(exe string, probe kubeletBinaryProbe) string {
	if path.IsAbs(exe) {
		return exe
	}
	if running := probe.rootExe(); running != "" {
		for _, p := range []string{probe.argv0(), running} {
			if path.IsAbs(p) && probe.resolve(p) == running {
				return p
			}
		}
	}
	for _, p := range kubeletInstallPaths {
		if probe.trustedBinary(p) {
			return p
		}
	}
	return exe
}

// kubeletProcSnapshotCommand reads, in one go, what parseKubeletProcSnapshot
// needs about a process: its Uid line, its binary, its mount namespace, the
// mount namespace of the system's init, and its Uid line again.
func kubeletProcSnapshotCommand(pid int64) string {
	p := "/proc/" + strconv.FormatInt(pid, 10)
	return "grep '^Uid:' " + p + "/status && readlink " + p + "/exe && readlink " + p +
		"/ns/mnt && readlink /proc/1/ns/mnt && grep '^Uid:' " + p + "/status"
}

// parseKubeletProcSnapshot returns the binary of the process that
// kubeletProcSnapshotCommand read, or "" when it is not one to run:
//
//   - root is not the real user, on either read. A process another user
//     started is refused, and so is a pid that a non-root process took over
//     between the reads.
//   - it runs in another mount namespace than the system's init, such as a
//     container. Its link names a file in that namespace, and the same path
//     on the system can be a different, user-writable file.
//   - the binary was deleted or replaced on disk since it started.
func parseKubeletProcSnapshot(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 5 {
		return ""
	}
	for _, uidLine := range []string{lines[0], lines[4]} {
		uid, ok := parseProcStatusRealUID(uidLine)
		if !ok || uid != 0 {
			return ""
		}
	}
	exe, mountNS, initMountNS := lines[1], lines[2], lines[3]
	if mountNS == "" || mountNS != initMountNS {
		return ""
	}
	if !path.IsAbs(exe) || strings.HasSuffix(exe, " (deleted)") {
		return ""
	}
	return exe
}

// kubeletBinaryProbe reads the facts resolveKubeletExecutable needs from the
// target. Each read is a command, so it runs with sudo where the scan does:
// /proc/<pid>/exe of a root process is not readable by others.
func (m *mqlKubelet) kubeletBinaryProbe(proc *mqlProcess) kubeletBinaryProbe {
	pid := proc.GetPid()
	return kubeletBinaryProbe{
		rootExe: func() string {
			if pid.Error != nil {
				return ""
			}
			out, ok := m.runQuiet(kubeletProcSnapshotCommand(pid.Data))
			if !ok {
				return ""
			}
			return parseKubeletProcSnapshot(out)
		},
		argv0: func() string {
			command := proc.GetCommand()
			if command.Error != nil {
				return ""
			}
			fields := strings.Fields(command.Data)
			if len(fields) == 0 {
				return ""
			}
			return fields[0]
		},
		resolve: func(p string) string {
			out, _ := m.runQuiet("readlink -f -- " + shellQuote(p))
			return strings.TrimSpace(out)
		},
		trustedBinary: func(p string) bool {
			out, ok := m.runQuiet("stat -L -c '%u %a' -- " + shellQuote(p))
			if !ok {
				return false
			}
			uid, mode, ok := parseStatOwnerMode(out)
			return ok && isRootOnlyWritable(uid, mode)
		},
	}
}

// runQuiet runs a command on the target and returns its output when it
// succeeds.
func (m *mqlKubelet) runQuiet(command string) (string, bool) {
	o, err := CreateResource(m.MqlRuntime, "command", map[string]*llx.RawData{
		"command": llx.StringData(command),
	})
	if err != nil {
		return "", false
	}
	cmd := o.(*mqlCommand)
	if exit := cmd.GetExitcode(); exit.Error != nil || exit.Data != 0 {
		return "", false
	}
	return cmd.GetStdout().Data, true
}

// parseProcStatusRealUID returns the real user id from /proc/<pid>/status,
// the first of the four ids on its Uid line.
func parseProcStatusRealUID(status string) (int64, bool) {
	for _, line := range strings.Split(status, "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			return 0, false
		}
		uid, err := strconv.ParseInt(fields[0], 10, 64)
		return uid, err == nil
	}
	return 0, false
}

// parseStatOwnerMode parses the output of stat -c '%u %a': the owner's user id
// and the octal permission bits.
func parseStatOwnerMode(out string) (int64, uint32, bool) {
	fields := strings.Fields(out)
	if len(fields) != 2 {
		return 0, 0, false
	}
	uid, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return 0, 0, false
	}
	mode, err := strconv.ParseUint(fields[1], 8, 32)
	if err != nil {
		return 0, 0, false
	}
	return uid, uint32(mode), true
}

// isRootOnlyWritable reports whether a file owned by uid with these permission
// bits can be changed by root alone.
func isRootOnlyWritable(uid int64, mode uint32) bool {
	return uid == 0 && mode&0o022 == 0
}

func getKubeletProcess(runtime *plugin.Runtime) (*mqlProcess, error) {
	obj, err := CreateResource(runtime, "processes", nil)
	if err != nil {
		return nil, err
	}
	processes := obj.(*mqlProcesses)

	data := processes.GetList()
	if data.Error != nil {
		return nil, data.Error
	}
	for _, process := range data.Data {
		mqlProcess := process.(*mqlProcess)
		exec := mqlProcess.Executable
		if exec.Error != nil {
			continue
		}
		if strings.HasSuffix(exec.Data, "kubelet") {
			return mqlProcess, nil
		}
	}
	return nil, errors.New("no kubelet process found")
}
