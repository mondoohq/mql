// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
)

// podmanPsEntry is one record of "podman ps --format json".
type podmanPsEntry struct {
	ID        string            `json:"Id"`
	Names     []string          `json:"Names"`
	Image     string            `json:"Image"`
	ImageID   string            `json:"ImageID"`
	Command   []string          `json:"Command"`
	State     string            `json:"State"`
	Status    string            `json:"Status"`
	Labels    map[string]string `json:"Labels"`
	IsInfra   bool              `json:"IsInfra"`
	ExitCode  int64             `json:"ExitCode"`
	Created   int64             `json:"Created"`
	Pod       string            `json:"Pod"`
	PodName   string            `json:"PodName"`
	Networks  []string          `json:"Networks"`
	Ports     []podmanPort      `json:"Ports"`
	Namespace string            `json:"Namespace"`
}

type podmanPort struct {
	HostIP        string
	ContainerPort int64
	HostPort      int64
	Range         int64
	Protocol      string
	// hasContainerPort is false for a record without a container port in
	// either spelling, which maps nothing
	hasContainerPort bool
}

// UnmarshalJSON reads a port mapping in both spellings podman has used:
// snake_case with a range from podman 4 on, and the camelCase
// hostIP/hostPort/containerPort of podman 3, which lists one port per record.
func (p *podmanPort) UnmarshalJSON(data []byte) error {
	var raw struct {
		HostIP        *string `json:"host_ip"`
		ContainerPort *int64  `json:"container_port"`
		HostPort      *int64  `json:"host_port"`
		Range         *int64  `json:"range"`
		Protocol      string  `json:"protocol"`

		V3HostIP        *string `json:"hostIP"`
		V3ContainerPort *int64  `json:"containerPort"`
		V3HostPort      *int64  `json:"hostPort"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*p = podmanPort{Protocol: raw.Protocol, Range: 1}
	if raw.Range != nil {
		p.Range = *raw.Range
	}
	if v := firstNonNil(raw.HostIP, raw.V3HostIP); v != nil {
		p.HostIP = *v
	}
	if v := firstNonNil(raw.HostPort, raw.V3HostPort); v != nil {
		p.HostPort = *v
	}
	if v := firstNonNil(raw.ContainerPort, raw.V3ContainerPort); v != nil {
		p.ContainerPort = *v
		p.hasContainerPort = true
	}
	return nil
}

func firstNonNil[T any](values ...*T) *T {
	for _, v := range values {
		if v != nil {
			return v
		}
	}
	return nil
}

// podmanInspectEntry is one record of "podman inspect --format json", limited to
// the fields describing what the container may reach. The mount, device and
// health check records have the shape Docker's have, so they decode into the
// Docker API types.
type podmanInspectEntry struct {
	ID              string                 `json:"Id"`
	EffectiveCaps   []string               `json:"EffectiveCaps"`
	BoundingCaps    []string               `json:"BoundingCaps"`
	AppArmorProfile string                 `json:"AppArmorProfile"`
	OCIConfigPath   string                 `json:"OCIConfigPath"`
	Mounts          []container.MountPoint `json:"Mounts"`
	State           struct {
		Status string        `json:"Status"`
		Health *podmanHealth `json:"Health"`
		// Healthcheck is the name podman 4.3 and older use for Health
		Healthcheck *podmanHealth `json:"Healthcheck"`
	} `json:"State"`
	Config struct {
		User        string                  `json:"User"`
		Healthcheck *container.HealthConfig `json:"Healthcheck"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool                      `json:"Privileged"`
		CapAdd         []string                  `json:"CapAdd"`
		CapDrop        []string                  `json:"CapDrop"`
		SecurityOpt    []string                  `json:"SecurityOpt"`
		ReadonlyRootfs bool                      `json:"ReadonlyRootfs"`
		NetworkMode    string                    `json:"NetworkMode"`
		PidMode        string                    `json:"PidMode"`
		IpcMode        string                    `json:"IpcMode"`
		UTSMode        string                    `json:"UTSMode"`
		UsernsMode     string                    `json:"UsernsMode"`
		CgroupMode     string                    `json:"CgroupMode"`
		Memory         int64                     `json:"Memory"`
		NanoCpus       int64                     `json:"NanoCpus"`
		CPUShares      int64                     `json:"CpuShares"`
		PidsLimit      int64                     `json:"PidsLimit"`
		Ulimits        []podmanUlimit            `json:"Ulimits"`
		Devices        []container.DeviceMapping `json:"Devices"`
		Tmpfs          map[string]string         `json:"Tmpfs"`
		RestartPolicy  struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
	} `json:"HostConfig"`
}

type podmanHealth struct {
	Status string `json:"Status"`
}

// healthStatus returns the status of the container's health check, empty
// when it has none or the container is not running. Podman keeps the last
// status of a stopped container.
func (e *podmanInspectEntry) healthStatus() string {
	if e.State.Status != "running" || !healthcheckDefined(e.Config.Healthcheck) {
		return ""
	}
	if h := e.State.Health; h != nil && h.Status != "" {
		return h.Status
	}
	if h := e.State.Healthcheck; h != nil {
		return h.Status
	}
	return ""
}

// podmanUlimit is a resource limit as podman inspect lists it, named by its
// rlimit constant (RLIMIT_NOFILE).
type podmanUlimit struct {
	Name string `json:"Name"`
	Soft int64  `json:"Soft"`
	Hard int64  `json:"Hard"`
}

// podmanUlimitName returns the name Docker and the --ulimit flag use for a
// limit (nofile for RLIMIT_NOFILE).
func podmanUlimitName(name string) string {
	return strings.ToLower(strings.TrimPrefix(name, "RLIMIT_"))
}

// podmanDefaultSeccompProfiles are where the packages install the seccomp
// profile Podman applies by default.
var podmanDefaultSeccompProfiles = map[string]struct{}{
	"/usr/share/containers/seccomp.json": {},
	"/etc/containers/seccomp.json":       {},
}

// isPodmanDefaultSeccompProfile reports whether a profile setting names the
// profile Podman ships.
func isPodmanDefaultSeccompProfile(profile string) bool {
	_, ok := podmanDefaultSeccompProfiles[profile]
	return ok || profile == "" || profile == "default"
}

// podmanSeccompProfile reports the seccomp profile a container effectively
// runs with: default, unconfined or custom. A privileged container is not
// filtered.
//
// The container's OCI spec, when it can be read, embeds the filter it was
// created with, so it alone decides whether any system call is filtered, and
// no profile file is read: a filtered container is custom when it, or the
// engine, names a profile other than the packaged one.
//
// Without the spec, the profile is the one the container names, by path, or
// else the engine's from `podman info`, which is the one a container created
// now gets. readProfile reads a named profile, so one that allows every
// system call is reported as unconfined.
func podmanSeccompProfile(privileged bool, securityOpt []string, spec *ociSpec, engine *podmanInfoSecurity, readProfile func(string) string) string {
	if privileged {
		return "unconfined"
	}
	named := ""
	for _, opt := range securityOpt {
		key, value, ok := splitSecurityOpt(opt)
		if ok && key == "seccomp" && value != "" {
			named = value
		}
	}

	if spec != nil {
		if spec.seccompUnconfined() {
			return "unconfined"
		}
		if named != "" && named != "unconfined" && !isPodmanDefaultSeccompProfile(named) {
			return "custom"
		}
		if named == "" && engine != nil && engine.SeccompProfilePath != "unconfined" && !isPodmanDefaultSeccompProfile(engine.SeccompProfilePath) {
			return "custom"
		}
		return "default"
	}

	if engine != nil && !engine.SeccompEnabled {
		return "unconfined"
	}
	profile := named
	if profile == "" && engine != nil {
		profile = engine.SeccompProfilePath
	}
	if isPodmanDefaultSeccompProfile(profile) {
		return "default"
	}
	if profile == "unconfined" || seccompAllowsAll(readProfile(profile)) {
		return "unconfined"
	}
	return "custom"
}

// podmanStoragePath reports whether a path lies under one of podman's storage
// roots (store.graphRoot, store.runRoot), where podman writes a container's
// config.json.
func podmanStoragePath(p string, roots ...string) bool {
	if !path.IsAbs(p) {
		return false
	}
	p = path.Clean(p)
	for _, root := range roots {
		if root == "" || !path.IsAbs(root) {
			continue
		}
		if strings.HasPrefix(p, path.Clean(root)+"/") {
			return true
		}
	}
	return false
}

// podmanImageEntry is one record of "podman images --format json".
type podmanImageEntry struct {
	ID           string            `json:"Id"`
	Names        []string          `json:"Names"`
	Repository   string            `json:"Repository"`
	Tag          string            `json:"Tag"`
	RepoDigests  []string          `json:"RepoDigests"`
	Digest       string            `json:"Digest"`
	Size         int64             `json:"Size"`
	Labels       map[string]string `json:"Labels"`
	Os           string            `json:"Os"`
	Architecture string            `json:"Arch"`
	Created      int64             `json:"Created"`
}

// podmanImageInspectEntry is the part of one "podman image inspect" record that
// "podman images" leaves out. Podman 5 and older list no platform at all, and
// podman 3 lists repo digests without the repository they belong to. Inspect
// spells the architecture key "Architecture", where the podman 6 list says "Arch".
type podmanImageInspectEntry struct {
	ID           string   `json:"Id"`
	RepoDigests  []string `json:"RepoDigests"`
	Os           string   `json:"Os"`
	Architecture string   `json:"Architecture"`
}

// podmanPodEntry is one record of "podman pod ps --format json".
type podmanPodEntry struct {
	ID      string            `json:"Id"`
	Name    string            `json:"Name"`
	Status  string            `json:"Status"`
	Created string            `json:"Created"`
	InfraID string            `json:"InfraId"`
	Labels  map[string]string `json:"Labels"`
}

// podmanVolumeEntry is one record of "podman volume ls --format json".
type podmanVolumeEntry struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	CreatedAt  string            `json:"CreatedAt"`
	Labels     map[string]string `json:"Labels"`
	Options    map[string]string `json:"Options"`
	Scope      string            `json:"Scope"`
	Anonymous  bool              `json:"Anonymous"`
}

// podmanNetworkEntry is one record of "podman network ls --format json". The
// network API uses snake_case where the others use PascalCase.
type podmanNetworkEntry struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	Driver           string              `json:"driver"`
	NetworkInterface string              `json:"network_interface"`
	Created          string              `json:"created"`
	Subnets          []podmanNetworkNet  `json:"subnets"`
	IPv6Enabled      bool                `json:"ipv6_enabled"`
	Internal         bool                `json:"internal"`
	DNSEnabled       bool                `json:"dns_enabled"`
	IPAMOptions      map[string]string   `json:"ipam_options"`
	Options          map[string]string   `json:"options"`
	Labels           map[string]string   `json:"labels"`
	Routes           []map[string]string `json:"routes"`
}

type podmanNetworkNet struct {
	Subnet  string `json:"subnet"`
	Gateway string `json:"gateway"`
}

// podmanInfo is the subset of "podman info --format json" describing the engine
// and the confinement it can apply.
type podmanInfo struct {
	Host struct {
		CgroupManager  string `json:"cgroupManager"`
		CgroupVersion  string `json:"cgroupVersion"`
		NetworkBackend string `json:"networkBackend"`
		OciRuntime     struct {
			Name string `json:"name"`
		} `json:"ociRuntime"`
		// Security is absent before podman 2.0, which reports none of these
		// settings, so a missing block must not read as all of them disabled.
		Security *podmanInfoSecurity `json:"security"`
	} `json:"host"`
	Store struct {
		GraphDriverName string `json:"graphDriverName"`
		GraphRoot       string `json:"graphRoot"`
		RunRoot         string `json:"runRoot"`
	} `json:"store"`
	Version struct {
		Version string `json:"Version"`
	} `json:"version"`
}

type podmanInfoSecurity struct {
	Rootless           bool   `json:"rootless"`
	SeccompEnabled     bool   `json:"seccompEnabled"`
	SeccompProfilePath string `json:"seccompProfilePath"`
	ApparmorEnabled    bool   `json:"apparmorEnabled"`
	SelinuxEnabled     bool   `json:"selinuxEnabled"`
}

func parsePodmanPs(data string) ([]podmanPsEntry, error) {
	res := []podmanPsEntry{}
	if err := unmarshalPodmanList(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func parsePodmanImages(data string) ([]podmanImageEntry, error) {
	res := []podmanImageEntry{}
	if err := unmarshalPodmanList(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func parsePodmanImageInspect(data string) ([]podmanImageInspectEntry, error) {
	res := []podmanImageInspectEntry{}
	if err := unmarshalPodmanList(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

// podmanUniqueImages drops the repeated records "podman images" prints for an
// image with more than one tag. Every repeat carries the same ID and names.
func podmanUniqueImages(entries []podmanImageEntry) []podmanImageEntry {
	seen := make(map[string]struct{}, len(entries))
	res := make([]podmanImageEntry, 0, len(entries))
	for _, entry := range entries {
		if _, ok := seen[entry.ID]; ok {
			continue
		}
		seen[entry.ID] = struct{}{}
		res = append(res, entry)
	}
	return res
}

// podmanImageNeedsInspect reports whether "podman images" left out something
// only "podman image inspect" reports: the platform, or the repository of a
// repo digest.
func podmanImageNeedsInspect(entry podmanImageEntry) bool {
	if entry.Os == "" || entry.Architecture == "" {
		return true
	}
	for _, digest := range entry.RepoDigests {
		if !strings.Contains(digest, "@") {
			return true
		}
	}
	return false
}

// podmanMergeImageInspect fills an image list record with what inspect reports.
// A repo digest the list prints without its repository is no reference an image
// can be pulled by, so only repository-qualified digests are kept, preferring
// those inspect reports.
func podmanMergeImageInspect(entry *podmanImageEntry, inspect podmanImageInspectEntry) {
	if len(inspect.RepoDigests) > 0 {
		entry.RepoDigests = inspect.RepoDigests
	} else {
		qualified := []string{}
		for _, digest := range entry.RepoDigests {
			if strings.Contains(digest, "@") {
				qualified = append(qualified, digest)
			}
		}
		entry.RepoDigests = qualified
	}
	if inspect.Os != "" {
		entry.Os = inspect.Os
	}
	if inspect.Architecture != "" {
		entry.Architecture = inspect.Architecture
	}
}

func parsePodmanPods(data string) ([]podmanPodEntry, error) {
	res := []podmanPodEntry{}
	if err := unmarshalPodmanList(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func parsePodmanVolumes(data string) ([]podmanVolumeEntry, error) {
	res := []podmanVolumeEntry{}
	if err := unmarshalPodmanList(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func parsePodmanNetworks(data string) ([]podmanNetworkEntry, error) {
	res := []podmanNetworkEntry{}
	if err := unmarshalPodmanList(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func parsePodmanInspect(data string) ([]podmanInspectEntry, error) {
	res := []podmanInspectEntry{}
	if err := unmarshalPodmanList(data, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func parsePodmanInfo(data string) (*podmanInfo, error) {
	info := &podmanInfo{}
	if err := json.Unmarshal([]byte(strings.TrimSpace(data)), info); err != nil {
		return nil, err
	}
	return info, nil
}

// unmarshalPodmanList decodes a podman list response. Empty output means no
// objects rather than malformed output, since some subcommands print nothing at
// all when there is nothing to list.
func unmarshalPodmanList(data string, target any) error {
	trimmed := strings.TrimSpace(data)
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	return json.Unmarshal([]byte(trimmed), target)
}

// podmanPrimaryName returns the name a container is usually referred to by.
func podmanPrimaryName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

// podmanNone is what podman prints in place of a value it has none of. It is a
// display sentinel, so it never reaches a field a query can read.
const podmanNone = "<none>"

// podmanImageRepoTag resolves the repository and tag of an image. Podman reports
// an untagged image as the "<none>" sentinel rather than as an empty field, and
// omits both fields entirely on some versions, in which case the first reference
// the image is tagged with carries the same information.
func podmanImageRepoTag(entry podmanImageEntry) (repository string, tag string) {
	repository = entry.Repository
	tag = entry.Tag
	if repository == podmanNone {
		repository = ""
	}
	if tag == podmanNone {
		tag = ""
	}

	if repository == "" && len(entry.Names) > 0 {
		repository, tag = podmanSplitReference(entry.Names[0])
	}
	return repository, tag
}

// podmanSplitReference splits an image reference into its repository and tag.
// A reference pinned by digest has no tag, and the digest stays with the
// repository so the reference can still be matched as written.
func podmanSplitReference(reference string) (repository string, tag string) {
	reference = strings.TrimSpace(reference)
	if reference == "" {
		return "", ""
	}

	if idx := strings.LastIndex(reference, "@"); idx >= 0 {
		return reference, ""
	}

	idx := strings.LastIndex(reference, ":")
	if idx < 0 {
		return reference, ""
	}

	// a colon before the last slash belongs to a registry port, not a tag
	if slash := strings.LastIndex(reference, "/"); slash > idx {
		return reference, ""
	}

	return reference[:idx], reference[idx+1:]
}

// podmanUnixTime converts a podman timestamp in seconds. Podman leaves the
// field at zero, or at its own sentinel for "never", when there is no time to
// report, and neither should surface as a date in 1970.
func podmanUnixTime(seconds int64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	t := time.Unix(seconds, 0).UTC()
	return &t
}

// podmanParseTime reads one of the RFC 3339 timestamps podman uses for pods,
// volumes, and networks.
func podmanParseTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999999Z0700"} {
		if t, err := time.Parse(layout, value); err == nil {
			utc := t.UTC()
			return &utc
		}
	}
	return nil
}

// podmanAllInterfaces is the address a port published on every host interface
// is reported with. Podman leaves the host IP empty for such a port.
const podmanAllInterfaces = "0.0.0.0"

// podmanPortDicts converts the port mappings of a container listing.
func podmanPortDicts(ports []podmanPort) []any {
	res := make([]any, 0, len(ports))
	for _, port := range ports {
		hostIP := strings.TrimSpace(port.HostIP)
		if hostIP == "" && port.hasContainerPort {
			hostIP = podmanAllInterfaces
		}
		res = append(res, map[string]any{
			"hostIp":        hostIP,
			"hostPort":      port.HostPort,
			"containerPort": port.ContainerPort,
			"protocol":      port.Protocol,
			"range":         port.Range,
			"allInterfaces": hostIP == podmanAllInterfaces || hostIP == "::",
		})
	}
	return res
}

// parsePodmanVersionOutput reads the release from "podman --version", which
// prints "podman version 1.6.4".
func parsePodmanVersionOutput(out string) string {
	fields := strings.Fields(strings.TrimSpace(out))
	for i, field := range fields {
		if field == "version" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// podmanMajorVersion returns the major release of a podman version string. The
// second result is false when the version cannot be read.
func podmanMajorVersion(version string) (int, bool) {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	major, _, _ := strings.Cut(version, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0, false
	}
	return n, true
}

// podmanMinSupportedMajor is the first podman release whose JSON output the
// podman resources decode. Podman 1.x prints different shapes for info, ps,
// images, pods, volumes, and networks.
const podmanMinSupportedMajor = 2

// podmanCheckSupported returns an error for a podman release older than 2.0,
// and nil for any newer or unreadable version.
func podmanCheckSupported(version string) error {
	major, ok := podmanMajorVersion(version)
	if !ok || major >= podmanMinSupportedMajor {
		return nil
	}
	return fmt.Errorf("podman %s is not supported, podman < %d.0 reports a different format", version, podmanMinSupportedMajor)
}
