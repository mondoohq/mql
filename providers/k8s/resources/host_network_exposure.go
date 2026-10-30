// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	corev1 "k8s.io/api/core/v1"
)

// escapesNetworkPolicy reports whether the pod uses host networking, in which
// case Kubernetes NetworkPolicy (both ingress and egress) does not apply to its
// traffic. Such pods are a coverage gap for any default-deny posture.
func (k *mqlK8sPod) escapesNetworkPolicy() (bool, error) {
	spec, err := k.podSpecTyped()
	if err != nil {
		return false, err
	}
	return spec.HostNetwork, nil
}

// nodePublicAddressesByName maps each node name to its public external
// addresses, so a pod bound to a node can be classified as internet-reachable
// when that specific node has a public address.
func (k *mqlK8s) nodePublicAddressesByName() (map[string][]string, error) {
	nodes := k.GetNodes()
	if nodes.Error != nil {
		return nil, nodes.Error
	}
	out := map[string][]string{}
	for _, item := range nodes.Data {
		node, ok := item.(*mqlK8sNode)
		if !ok || node.obj == nil {
			continue
		}
		var addrs []string
		for _, addr := range node.obj.Status.Addresses {
			if (addr.Type == corev1.NodeExternalIP || addr.Type == corev1.NodeExternalDNS) && addressIsPublicNodeAddress(addr.Address) {
				addrs = append(addrs, addr.Address)
			}
		}
		if len(addrs) > 0 {
			out[node.obj.Name] = sortedUniqueStrings(addrs)
		}
	}
	return out, nil
}

// hostExposurePorts collects the node-reachable ports of a pod: explicit
// hostPorts on any container, plus every containerPort when the pod runs on the
// host network (where the container port is reachable on the node directly). It
// returns the port dicts, the distinct protocols, and whether any explicit
// hostPort was found.
func hostExposurePorts(spec *corev1.PodSpec) ([]any, []string, bool) {
	ports := []any{}
	protocols := map[string]struct{}{}
	hasHostPort := false

	add := func(p corev1.ContainerPort) {
		host := p.HostPort
		if spec.HostNetwork && host == 0 {
			host = p.ContainerPort
		}
		if host == 0 {
			return
		}
		if p.HostPort != 0 {
			hasHostPort = true
		}
		proto := string(p.Protocol)
		if proto == "" {
			proto = string(corev1.ProtocolTCP)
		}
		ports = append(ports, map[string]any{
			"name":          p.Name,
			"port":          int64(host),
			"containerPort": int64(p.ContainerPort),
			"hostPort":      int64(p.HostPort),
			"protocol":      proto,
			"hostIP":        p.HostIP,
		})
		protocols[proto] = struct{}{}
	}

	for i := range spec.Containers {
		for _, p := range spec.Containers[i].Ports {
			add(p)
		}
	}
	for i := range spec.InitContainers {
		for _, p := range spec.InitContainers[i].Ports {
			add(p)
		}
	}

	protoList := make([]string, 0, len(protocols))
	for p := range protocols {
		protoList = append(protoList, p)
	}
	return ports, sortedUniqueStrings(protoList), hasHostPort
}

// podHostExposureArgs builds a network exposure for a pod that binds directly to
// the node network, the ingress vector that bypasses Services, Ingresses, and
// Gateways. A pod is host-exposed when it runs on the host network or declares
// any hostPort. Reachability mirrors the NodePort model: the pod is
// internet-exposed when the node it runs on has a public address.
func podHostExposureArgs(pod *corev1.Pod, nodePublicAddrs map[string][]string) []map[string]*llx.RawData {
	if pod == nil {
		return nil
	}
	spec := &pod.Spec
	ports, protocols, hasHostPort := hostExposurePorts(spec)
	if !spec.HostNetwork && !hasHostPort {
		return nil
	}

	mechanism := "hostPort"
	if spec.HostNetwork {
		mechanism = "hostNetwork"
	}

	pubAddrs := nodePublicAddrs[spec.NodeName]
	internetExposed := len(pubAddrs) > 0

	var addresses []string
	var classifications []string
	exposureReason := ""
	confidence := "high"
	switch {
	case internetExposed:
		addresses = pubAddrs
		exposureReason = mechanism + "PublicNode"
		classifications = classifyAddresses(addresses)
	case spec.NodeName == "":
		// Unscheduled pod: the config is exposure-capable but the node, and so
		// its addresses, are not yet known. Classifying an empty address set as
		// "internalOnly" would be misleading, so report it as unknown.
		exposureReason = mechanism + "NodeUnknown"
		confidence = "medium"
		classifications = []string{"unknown"}
	default:
		exposureReason = mechanism + "PrivateNode"
		if pod.Status.HostIP != "" {
			addresses = []string{pod.Status.HostIP}
		}
		classifications = classifyAddresses(addresses)
	}

	in := networkExposureInput{
		id:                     fmt.Sprintf("pod:%s:%s", pod.Namespace, pod.Name),
		sourceKind:             "Pod",
		sourceRef:              networkSourceRef("Pod", pod.Namespace, pod.Name),
		namespace:              pod.Namespace,
		name:                   pod.Name,
		addresses:              sortedUniqueStrings(addresses),
		ports:                  ports,
		protocols:              protocols,
		internetExposed:        internetExposed,
		exposureReason:         exposureReason,
		networkClassifications: classifications,
		confidence:             confidence,
	}
	return []map[string]*llx.RawData{networkExposureArgs(networkExposureInputWithMetadata(pod, in))}
}
