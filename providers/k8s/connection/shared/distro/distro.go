// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package distro detects which Kubernetes distribution serves a cluster, such
// as AKS, EKS, GKE or OpenShift, and the cluster's identity in its cloud.
//
// Detection runs a fixed list of probes, from signals every client can read
// (the API server's version and TLS certificate, the kubeconfig) to signals
// that need RBAC (nodes) or run only inside the cluster (cloud metadata). The
// first probe that names a distribution decides; the others are kept as
// evidence. A probe that fails is recorded and never fails detection.
package distro

import (
	"context"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

// Distribution names.
const (
	Unknown   = "unknown"
	AKS       = "aks"
	EKS       = "eks"
	EKSD      = "eks-d"
	GKE       = "gke"
	OpenShift = "openshift"
	K3s       = "k3s"
	RKE2      = "rke2"
	K0s       = "k0s"
	Kind      = "kind"
	Minikube  = "minikube"
)

// Probe names, in the order in which they decide.
const (
	ProbeVersion     = "version"
	ProbeCertificate = "certificate"
	ProbeHost        = "host"
	ProbeAPIGroups   = "apiGroups"
	ProbeNodes       = "nodes"
	ProbeAuth        = "auth"
	ProbeMetadata    = "metadata"
	ProbeKubeconfig  = "kubeconfig"
	// ProbeManagedMode records what decided the managed mode. It never
	// decides the distribution.
	ProbeManagedMode = "managedMode"
)

// Managed modes, in which the cloud provider operates the nodes.
const (
	// ModeGKEAutopilot is a GKE Autopilot cluster.
	ModeGKEAutopilot = "autopilot"
	// ModeEKSAutoMode is an EKS cluster with EKS Auto Mode enabled.
	ModeEKSAutoMode = "auto-mode"
)

// Platform metadata keys under which the cluster asset records the result.
const (
	MetadataDistribution       = "k8s.mondoo.com/distribution"
	MetadataDistributionSource = "k8s.mondoo.com/distribution-source"
	// MetadataManagedMode is set only when a managed mode was detected.
	MetadataManagedMode = "k8s.mondoo.com/managed-mode"
)

// Evidence is what one probe saw.
type Evidence struct {
	// Distro is the distribution the probe points to, empty if none.
	Distro string
	// Value is the observed value the decision rests on, for example the
	// version string or the matching certificate name.
	Value string
	// Error is set when the probe could not run, for example when listing
	// nodes is forbidden.
	Error string
}

// Identity is the cluster's identity in its cloud, best effort.
type Identity struct {
	ClusterName string
	// Region is the cloud region, or for GKE the cluster's location (a region
	// or a zone).
	Region string
	// Account is the AWS account ID, the GCP project ID or the Azure
	// subscription ID.
	Account string
	// Source names where the identity came from, for example "kubeconfig".
	Source string
}

// Result is the detected distribution.
type Result struct {
	Name   string
	Source string
	// ManagedMode is ModeGKEAutopilot or ModeEKSAutoMode when the cluster
	// runs in that mode, empty when no signal showed one.
	ManagedMode string
	Identity    Identity
	// Evidence holds one entry per probe that ran, keyed by probe name.
	Evidence map[string]Evidence
}

// AssetAnnotations returns the annotations the cluster's cloud identity puts
// on the cluster asset and on everything discovered in it: the AWS account id
// (inventory.AnnotationAwsAccountId) for a cluster that runs in AWS. It is nil
// when the cloud is not AWS or the account is unknown, so callers can add it
// unconditionally.
func (r *Result) AssetAnnotations() map[string]string {
	if r == nil || CloudOf(r.Name) != "aws" || r.Identity.Account == "" {
		return nil
	}
	return map[string]string{inventory.AnnotationAwsAccountId: r.Identity.Account}
}

// PlatformMetadata returns the platform metadata the result puts on the
// cluster asset and the assets discovered in it. The managed mode is only
// included when one was detected.
func (r *Result) PlatformMetadata() map[string]string {
	if r == nil {
		return map[string]string{}
	}
	res := map[string]string{
		MetadataDistribution:       r.Name,
		MetadataDistributionSource: r.Source,
	}
	if r.ManagedMode != "" {
		res[MetadataManagedMode] = r.ManagedMode
	}
	return res
}

// Node is the part of a node the nodes probe reads.
type Node struct {
	Name       string
	ProviderID string
	Labels     map[string]string
}

// Kubeconfig is what the connection's kubeconfig says about the cluster, read
// before any authentication helper rewrites it.
type Kubeconfig struct {
	// ClusterEntry is the name of the current context's cluster entry.
	ClusterEntry string
	// ExecCommand and ExecArgs are the exec credential plugin, if any.
	ExecCommand string
	ExecArgs    []string
	// AuthProvider is the name of a legacy auth provider plugin (azure, gcp).
	AuthProvider string
	// Kubelogin is set when the connection was asked to use the kubelogin
	// flow.
	Kubelogin bool
}

// MetadataResult is what the cloud metadata service of the node says.
type MetadataResult struct {
	Distro   string
	Value    string
	Identity Identity
}

// Probes are the inputs to detection. Any nil function is skipped.
type Probes struct {
	// Version returns the API server's gitVersion.
	Version func(ctx context.Context) (string, error)
	// Certificate returns the DNS names of the API server's certificate.
	Certificate func(ctx context.Context) ([]string, error)
	// Host is the API server URL the connection uses.
	Host string
	// Kubeconfig is nil for in-cluster connections.
	Kubeconfig *Kubeconfig
	// APIGroups returns the API groups the server advertises.
	APIGroups func(ctx context.Context) ([]string, error)
	// Nodes returns a few of the cluster's nodes.
	Nodes func(ctx context.Context) ([]Node, error)
	// GroupResources returns the resource names (plural, without
	// subresources) the server serves in one API group, across its versions.
	// It is only asked for groups that APIGroups returned.
	GroupResources func(ctx context.Context, group string) ([]string, error)
	// Metadata asks the cloud metadata service. It is only set for in-cluster
	// connections and only runs when no other probe decided.
	Metadata func(ctx context.Context) (*MetadataResult, error)
}

var (
	// -eks-<commit> on EKS, -eks-<major>-<minor>-<build> on EKS Distro
	// (EKS Anywhere and other EKS-D based clusters).
	eksdVersion = regexp.MustCompile(`-eks-\d+-\d+-\d+`)
	eksVersion  = regexp.MustCompile(`-eks-[0-9a-f]+`)
)

// FromVersion maps an API server gitVersion to a distribution.
func FromVersion(gitVersion string) string {
	v := strings.ToLower(gitVersion)
	switch {
	case eksdVersion.MatchString(v):
		return EKSD
	case eksVersion.MatchString(v):
		return EKS
	case strings.Contains(v, "-gke."):
		return GKE
	case strings.Contains(v, "+k3s"):
		return K3s
	case strings.Contains(v, "+rke2"):
		return RKE2
	case strings.Contains(v, "+k0s"):
		return K0s
	}
	return ""
}

// managed control planes serve their API under these DNS suffixes, both in the
// endpoint URL and in the API server certificate
var hostSuffixes = []struct {
	suffix string
	distro string
}{
	{".azmk8s.io", AKS},
	{".eks.amazonaws.com.cn", EKS},
	{".eks.amazonaws.com", EKS},
	{".gke.goog", GKE},
	{".aroapp.io", OpenShift},
	{".openshiftapps.com", OpenShift},
}

// FromHostname maps an API server DNS name to a distribution.
func FromHostname(name string) string {
	n := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	n = strings.TrimPrefix(n, "*")
	for _, s := range hostSuffixes {
		if strings.HasSuffix(n, s.suffix) {
			return s.distro
		}
	}
	return ""
}

// hostname returns the host part of an API server URL.
func hostname(host string) string {
	if host == "" {
		return ""
	}
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	u, err := url.Parse(host)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// API groups that only the distribution's control plane serves.
var apiGroups = map[string]string{
	"config.openshift.io":         OpenShift,
	"vpcresources.k8s.aws":        EKS,
	"nodemanagement.gke.io":       GKE,
	"networking.gke.io":           GKE,
	"auto.gke.io":                 GKE,
	"internal.autoscaling.gke.io": GKE,
}

// FromAPIGroups maps the advertised API groups to a distribution. It returns
// the distribution and the group that decided.
func FromAPIGroups(groups []string) (string, string) {
	// OpenShift first: it also runs on the clouds (ROSA, ARO)
	for _, g := range groups {
		if apiGroups[g] == OpenShift {
			return OpenShift, g
		}
	}
	for _, g := range groups {
		if d, ok := apiGroups[g]; ok {
			return d, g
		}
	}
	return "", ""
}

// node labels that only the distribution sets
var nodeLabels = []struct {
	label  string
	distro string
}{
	{"node.openshift.io/os_id", OpenShift},
	{"kubernetes.azure.com/cluster", AKS},
	{"eks.amazonaws.com/nodegroup", EKS},
	{"eks.amazonaws.com/compute-type", EKS},
	{"cloud.google.com/gke-nodepool", GKE},
	{"minikube.k8s.io/name", Minikube},
}

// FromNodes maps node labels and provider IDs to a distribution.
func FromNodes(nodes []Node) (string, string) {
	for _, l := range nodeLabels {
		for _, n := range nodes {
			if _, ok := n.Labels[l.label]; ok {
				return l.distro, l.label
			}
		}
	}
	for _, n := range nodes {
		switch {
		case strings.HasPrefix(n.ProviderID, "kind://"):
			return Kind, "providerID kind://"
		case strings.HasPrefix(n.ProviderID, "k3s://"):
			return K3s, "providerID k3s://"
		}
		if n.Labels["node.kubernetes.io/instance-type"] == "k3s" {
			return K3s, "node.kubernetes.io/instance-type=k3s"
		}
	}
	return "", ""
}

// FromKubeconfigAuth maps the kubeconfig's credential plugin to a
// distribution. It is a weak signal (kubelogin also serves Azure Arc), so it
// decides only when the server itself said nothing.
func FromKubeconfigAuth(k *Kubeconfig) (string, string) {
	if k == nil {
		return "", ""
	}
	if k.Kubelogin {
		return AKS, "kubelogin option"
	}
	cmd := k.ExecCommand
	if i := strings.LastIndexAny(cmd, `/\`); i >= 0 {
		cmd = cmd[i+1:]
	}
	cmd = strings.TrimSuffix(strings.ToLower(cmd), ".exe")
	switch cmd {
	case "kubelogin":
		return AKS, cmd
	case "gke-gcloud-auth-plugin":
		return GKE, cmd
	case "aws-iam-authenticator":
		return EKS, cmd
	case "aws":
		if contains(k.ExecArgs, "eks") && contains(k.ExecArgs, "get-token") {
			return EKS, "aws eks get-token"
		}
	}
	switch k.AuthProvider {
	case "azure":
		return AKS, "auth-provider azure"
	case "gcp":
		return GKE, "auth-provider gcp"
	}
	return "", ""
}

func contains(list []string, s string) bool {
	return slices.Contains(list, s)
}

// Detect runs the probes and decides the distribution.
func Detect(ctx context.Context, p Probes) *Result {
	res := &Result{Name: Unknown, Evidence: map[string]Evidence{}}
	decide := func(probe string, ev Evidence) {
		res.Evidence[probe] = ev
		if res.Source == "" && ev.Distro != "" {
			res.Name = ev.Distro
			res.Source = probe
		}
	}

	if p.Version != nil {
		v, err := p.Version(ctx)
		ev := Evidence{Value: v, Distro: FromVersion(v)}
		if err != nil {
			ev.Error = err.Error()
		}
		decide(ProbeVersion, ev)
	}

	if p.Certificate != nil {
		names, err := p.Certificate(ctx)
		ev := Evidence{}
		if err != nil {
			ev.Error = err.Error()
		}
		for _, n := range names {
			if d := FromHostname(n); d != "" {
				ev.Distro, ev.Value = d, n
				break
			}
		}
		if ev.Value == "" && len(names) > 0 {
			ev.Value = strings.Join(names, ",")
		}
		decide(ProbeCertificate, ev)
	}

	if h := hostname(p.Host); h != "" {
		decide(ProbeHost, Evidence{Value: h, Distro: FromHostname(h)})
	}

	var groups []string
	if p.APIGroups != nil {
		var err error
		groups, err = p.APIGroups(ctx)
		ev := Evidence{}
		if err != nil {
			ev.Error = err.Error()
		}
		ev.Distro, ev.Value = FromAPIGroups(groups)
		decide(ProbeAPIGroups, ev)
	}

	var nodes []Node
	if p.Nodes != nil {
		var err error
		nodes, err = p.Nodes(ctx)
		ev := Evidence{}
		if err != nil {
			ev.Error = err.Error()
		}
		ev.Distro, ev.Value = FromNodes(nodes)
		decide(ProbeNodes, ev)
	}

	if p.Kubeconfig != nil {
		d, v := FromKubeconfigAuth(p.Kubeconfig)
		if d != "" || v != "" {
			decide(ProbeAuth, Evidence{Distro: d, Value: v})
		}
	}

	certName := ""
	if ev, ok := res.Evidence[ProbeCertificate]; ok && ev.Distro != "" {
		certName = ev.Value
	}

	// The metadata service decides only when nothing else did. In the
	// cluster, where there is no kubeconfig, it also names a managed cluster
	// that the other signals identified but could not name.
	var md *MetadataResult
	if p.Metadata != nil {
		undecided := res.Source == ""
		unnamed := cloudOf[res.Name] != "" &&
			identify(res.Name, p.Host, certName, p.Kubeconfig, nodes, nil).ClusterName == ""
		if undecided || unnamed {
			var err error
			md, err = p.Metadata(ctx)
			ev := Evidence{}
			if err != nil {
				ev.Error = err.Error()
			}
			if md != nil {
				ev.Distro, ev.Value = md.Distro, md.Value
			}
			decide(ProbeMetadata, ev)
		}
	}

	res.Identity = identify(res.Name, p.Host, certName, p.Kubeconfig, nodes, md)

	groupResources := func(group string) ([]string, error) {
		if p.GroupResources == nil || !contains(groups, group) {
			return nil, nil
		}
		return p.GroupResources(ctx, group)
	}
	if mode, ev := managedMode(res.Name, groupResources, nodes); ev != nil {
		res.ManagedMode = mode
		res.Evidence[ProbeManagedMode] = *ev
	}
	return res
}

// API resources that only a managed mode's control plane serves.
var managedModeResources = []struct {
	distro   string
	group    string
	resource string
	mode     string
}{
	// AllowlistedWorkload, the Autopilot allowlist for privileged partner
	// workloads. Standard clusters serve auto.gke.io too, but not this type.
	{GKE, "auto.gke.io", "allowlistedworkloads", ModeGKEAutopilot},
	// NodeClass of EKS Auto Mode, referenced by its NodePools.
	{EKS, "eks.amazonaws.com", "nodeclasses", ModeEKSAutoMode},
}

// managedMode detects whether a GKE or EKS cluster runs in its managed mode
// (GKE Autopilot, EKS Auto Mode). It first asks API discovery, which needs no
// permission, then the nodes. It returns the mode and the evidence for it, or
// no evidence when no signal was seen.
func managedMode(name string, groupResources func(group string) ([]string, error), nodes []Node) (string, *Evidence) {
	var errs []string
	for _, r := range managedModeResources {
		if r.distro != name {
			continue
		}
		resources, err := groupResources(r.group)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if contains(resources, r.resource) {
			return r.mode, &Evidence{Distro: name, Value: r.resource + "." + r.group}
		}
	}

	if mode, value := ManagedModeFromNodes(name, nodes); mode != "" {
		return mode, &Evidence{Distro: name, Value: value}
	}
	if len(errs) > 0 {
		return "", &Evidence{Error: strings.Join(errs, "; ")}
	}
	return "", nil
}

// ManagedModeFromNodes detects the managed mode of a GKE or EKS cluster from
// its nodes. EKS labels the nodes it runs in Auto Mode with
// eks.amazonaws.com/compute-type=auto, so one such node is enough. GKE names
// the nodes Autopilot manages gk3-*; a Standard cluster can run some
// Autopilot nodes for workloads that ask for an Autopilot compute class, so
// every node has to be one.
func ManagedModeFromNodes(name string, nodes []Node) (string, string) {
	if len(nodes) == 0 {
		return "", ""
	}
	switch name {
	case EKS:
		for _, n := range nodes {
			if n.Labels["eks.amazonaws.com/compute-type"] == "auto" {
				return ModeEKSAutoMode, "eks.amazonaws.com/compute-type=auto"
			}
		}
	case GKE:
		for _, n := range nodes {
			if !strings.HasPrefix(n.Name, "gk3-") {
				return "", ""
			}
		}
		return ModeGKEAutopilot, "node name prefix gk3-"
	}
	return "", ""
}
