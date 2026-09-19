// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/types"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

var nonPublicAddressPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var optionalNetworkPolicyCoverageKinds = []string{
	"adminnetworkpolicies.v1alpha1.policy.networking.k8s.io",
	"baselineadminnetworkpolicies.v1alpha1.policy.networking.k8s.io",
	"multi-networkpolicies.v1beta1.k8s.cni.cncf.io",
	"multi-networkpolicies.v1beta2.k8s.cni.cncf.io",
	"multinetworkpolicies.v1beta1.k8s.cni.cncf.io",
	"multinetworkpolicies.v1beta2.k8s.cni.cncf.io",
	"networkpolicies.v1.crd.projectcalico.org",
	"globalnetworkpolicies.v1.crd.projectcalico.org",
	"ciliumnetworkpolicies.v2.cilium.io",
	"ciliumclusterwidenetworkpolicies.v2.cilium.io",
}

var optionalGatewayRouteExposureKinds = []string{
	"httproutes.v1.gateway.networking.k8s.io",
	"httproutes.v1beta1.gateway.networking.k8s.io",
	"grpcroutes.v1.gateway.networking.k8s.io",
	"grpcroutes.v1beta1.gateway.networking.k8s.io",
	"grpcroutes.v1alpha2.gateway.networking.k8s.io",
	"tlsroutes.v1.gateway.networking.k8s.io",
	"tlsroutes.v1beta1.gateway.networking.k8s.io",
	"tlsroutes.v1alpha2.gateway.networking.k8s.io",
	"tcproutes.v1.gateway.networking.k8s.io",
	"tcproutes.v1beta1.gateway.networking.k8s.io",
	"tcproutes.v1alpha2.gateway.networking.k8s.io",
	"udproutes.v1.gateway.networking.k8s.io",
	"udproutes.v1beta1.gateway.networking.k8s.io",
	"udproutes.v1alpha2.gateway.networking.k8s.io",
}

var optionalGatewayExposureKinds = []string{
	"gateways.v1.gateway.networking.k8s.io",
	"gateways.v1beta1.gateway.networking.k8s.io",
}

var optionalHBNNetworkExposureKinds = []string{
	"inbounds.v1alpha1.network.t-caas.telekom.com",
	"inbounds.v1alpha1.networking.t-caas.telekom.com",
	"inbounds.v1alpha1.hbn.t-caas.telekom.com",
	"inbounds.v1alpha1.network-connector.sylvaproject.org",
}

var optionalHBNStableEgressKinds = []string{
	"vrfs.v1alpha1.network.t-caas.telekom.com",
	"networks.v1alpha1.network.t-caas.telekom.com",
	"destinations.v1alpha1.network.t-caas.telekom.com",
	"outbounds.v1alpha1.network.t-caas.telekom.com",
	"layer2attachments.v1alpha1.network.t-caas.telekom.com",
	"podnetworks.v1alpha1.network.t-caas.telekom.com",
	"collectors.v1alpha1.network.t-caas.telekom.com",
	"trafficmirrors.v1alpha1.network.t-caas.telekom.com",
	"networkconnectors.v1alpha1.network-connector.sylvaproject.org",
	"networkconnectorconfigs.v1alpha1.network-connector.sylvaproject.org",
}

func (k *mqlK8s) networkExposures() ([]any, error) {
	settings := networkInventorySettingsFromRuntime(k.MqlRuntime)
	out := []any{}
	gatewayContexts := map[string]networkExposureContext{}

	services := k.GetServices()
	if services.Error != nil {
		return nil, services.Error
	}
	nodeAddresses, err := k.publicNodeAddresses()
	if err != nil {
		nodeAddresses = nil
	}
	for _, item := range services.Data {
		svc, ok := item.(*mqlK8sService)
		if !ok {
			continue
		}
		exposures, err := svc.networkExposuresWithNodeAddresses(nodeAddresses)
		if err != nil {
			return nil, err
		}
		out = append(out, exposures...)
	}

	ingresses := k.GetIngresses()
	if ingresses.Error != nil {
		return nil, ingresses.Error
	}
	for _, item := range ingresses.Data {
		ing, ok := item.(*mqlK8sIngress)
		if !ok {
			continue
		}
		exposures, err := ing.networkExposures()
		if err != nil {
			return nil, err
		}
		out = append(out, exposures...)
	}

	// Gateway API is optional; keep the normalized view available in clusters
	// that do not have the Gateway API CRDs installed.
	gateways := k.GetGateways()
	if gateways.Error == nil {
		for _, item := range gateways.Data {
			gw, ok := item.(*mqlK8sGateway)
			if !ok {
				continue
			}
			exposures, err := gw.networkExposures()
			if err != nil {
				return nil, err
			}
			out = append(out, exposures...)
			if gw.obj != nil {
				gatewayContexts[networkSourceRef("Gateway", gw.obj.Namespace, gw.obj.Name)] = gatewayNetworkExposureContext(gw.obj)
			}
		}
	}
	gatewayObjects, err := optionalK8sResources(k.MqlRuntime, optionalGatewayExposureKinds...)
	if err != nil {
		return nil, err
	}
	for _, object := range gatewayObjects {
		gw := gatewayFromUnstructured(asUnstructured(object))
		if gw == nil {
			continue
		}
		ref := networkSourceRef("Gateway", gw.Namespace, gw.Name)
		if _, ok := gatewayContexts[ref]; ok {
			continue
		}
		gatewayContexts[ref] = gatewayNetworkExposureContext(gw)
		for _, args := range gatewayNetworkExposureArgs(gw) {
			exposure, err := CreateResource(k.MqlRuntime, "k8s.networkExposure", args)
			if err != nil {
				return nil, err
			}
			out = append(out, exposure)
		}
	}

	routeObjects, err := optionalK8sResources(k.MqlRuntime, optionalGatewayRouteExposureKinds...)
	if err != nil {
		return nil, err
	}
	for _, object := range routeObjects {
		u := asUnstructured(object)
		if u == nil {
			continue
		}
		for _, args := range gatewayRouteNetworkExposureArgs(u, gatewayContexts) {
			exposure, err := CreateResource(k.MqlRuntime, "k8s.networkExposure", args)
			if err != nil {
				return nil, err
			}
			out = append(out, exposure)
		}
	}

	// Pods that bind directly to the node network (hostNetwork or hostPort)
	// are an ingress vector that bypasses Services, Ingresses, and Gateways.
	nodePublicAddrs, err := k.nodePublicAddressesByName()
	if err != nil {
		return nil, err
	}
	pods := k.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}
	for _, item := range pods.Data {
		pod, ok := item.(*mqlK8sPod)
		if !ok {
			continue
		}
		p, err := pod.getPod()
		if err != nil {
			return nil, err
		}
		for _, args := range podHostExposureArgs(p, nodePublicAddrs) {
			exposure, err := CreateResource(k.MqlRuntime, "k8s.networkExposure", args)
			if err != nil {
				return nil, err
			}
			out = append(out, exposure)
		}
	}

	if hbnKinds := enabledHBNOptionalKinds(settings, optionalHBNNetworkExposureKinds); len(hbnKinds) > 0 {
		hbnObjects, err := optionalK8sResources(k.MqlRuntime, hbnKinds...)
		if err != nil {
			return nil, err
		}
		for _, object := range hbnObjects {
			u := asUnstructured(object)
			if u == nil {
				continue
			}
			for _, args := range hbnNetworkExposureArgs(u) {
				exposure, err := CreateResource(k.MqlRuntime, "k8s.networkExposure", args)
				if err != nil {
					return nil, err
				}
				out = append(out, exposure)
			}
		}
	}

	return out, nil
}

func (k *mqlK8s) egressRoutes() ([]any, error) {
	settings := networkInventorySettingsFromRuntime(k.MqlRuntime)
	egressKinds := []string{
		"egresses.v2.coil.cybozu.com",
	}
	if settings.hbnEnabled && settings.hbnIncludeLegacyResources {
		egressKinds = append(egressKinds,
			"vrfrouteconfigurations.v1alpha1.network.t-caas.telekom.com",
			"bgppeerings.v1alpha1.network.t-caas.telekom.com",
			"nodenetworkconfigs.v1alpha1.network.t-caas.telekom.com",
			"networkconfigrevisions.v1alpha1.network.t-caas.telekom.com",
		)
	}
	objects, err := optionalK8sResources(k.MqlRuntime, egressKinds...)
	if err != nil {
		return nil, err
	}

	inputs := []egressRouteInput{}
	for _, object := range objects {
		u := asUnstructured(object)
		if u == nil {
			continue
		}
		inputs = append(inputs, egressRouteInputsFromUnstructured(u, settings)...)
	}

	if hbnKinds := enabledHBNOptionalKinds(settings, optionalHBNStableEgressKinds); len(hbnKinds) > 0 {
		stableObjects, err := optionalK8sResources(k.MqlRuntime, hbnKinds...)
		if err != nil {
			return nil, err
		}
		for _, object := range stableObjects {
			u := asUnstructured(object)
			if u == nil {
				continue
			}
			inputs = append(inputs, hbnStableEgressRouteInputs(u, settings)...)
		}
	}

	out := make([]any, 0, len(inputs))
	for _, input := range inputs {
		route, err := CreateResource(k.MqlRuntime, "k8s.egressRoute", egressRouteArgs(input))
		if err != nil {
			return nil, err
		}
		out = append(out, route)
	}
	return out, nil
}

func (k *mqlK8s) egressNats() ([]any, error) {
	settings := networkInventorySettingsFromRuntime(k.MqlRuntime)
	objects, err := optionalK8sResources(k.MqlRuntime,
		"egresses.v2.coil.cybozu.com",
		"ippools.v3.crd.projectcalico.org",
	)
	if err != nil {
		return nil, err
	}

	inputs := []egressNatInput{}
	for _, object := range objects {
		u := asUnstructured(object)
		if u == nil {
			continue
		}
		inputs = append(inputs, egressNatInputsFromUnstructured(u, settings)...)
	}

	if hbnKinds := enabledHBNOptionalKinds(settings, optionalHBNStableEgressKinds); len(hbnKinds) > 0 {
		stableObjects, err := optionalK8sResources(k.MqlRuntime, hbnKinds...)
		if err != nil {
			return nil, err
		}
		for _, object := range stableObjects {
			u := asUnstructured(object)
			if u == nil {
				continue
			}
			inputs = append(inputs, hbnStableEgressNatInputs(u, settings)...)
		}
	}

	out := make([]any, 0, len(inputs))
	for _, input := range inputs {
		nat, err := CreateResource(k.MqlRuntime, "k8s.egressNat", egressNatArgs(input))
		if err != nil {
			return nil, err
		}
		out = append(out, nat)
	}
	return out, nil
}

func (k *mqlK8s) networkPolicyCoverages() ([]any, error) {
	settings := networkInventorySettingsFromRuntime(k.MqlRuntime)
	policies := k.GetNetworkPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}

	out := make([]any, 0, len(policies.Data))
	nativeCoverageArgs, err := networkPolicyCoverageArgsFromPolicies(policies.Data)
	if err != nil {
		return nil, err
	}
	for _, args := range nativeCoverageArgs {
		coverage, err := CreateResource(k.MqlRuntime, "k8s.networkPolicyCoverage", args)
		if err != nil {
			return nil, err
		}
		out = append(out, coverage)
	}

	objects, err := optionalK8sResources(k.MqlRuntime, enabledNetworkPolicyCoverageKinds(settings)...)
	if err != nil {
		return nil, err
	}
	optionalCoverageArgs := []map[string]*llx.RawData{}
	for _, object := range objects {
		u := asUnstructured(object)
		if u == nil {
			continue
		}
		for _, args := range networkPolicyCoverageArgsFromUnstructured(u) {
			optionalCoverageArgs = append(optionalCoverageArgs, args)
			coverage, err := CreateResource(k.MqlRuntime, "k8s.networkPolicyCoverage", args)
			if err != nil {
				return nil, err
			}
			out = append(out, coverage)
		}
	}
	pods := k.GetPods()
	if pods.Error != nil {
		return nil, pods.Error
	}
	for _, args := range secondaryInterfaceCoverageArgsFromPods(pods.Data, optionalCoverageArgs) {
		coverage, err := CreateResource(k.MqlRuntime, "k8s.networkPolicyCoverage", args)
		if err != nil {
			return nil, err
		}
		out = append(out, coverage)
	}
	namespaceLabels := namespaceLabelsByName(k.GetNamespaces().Data)
	serviceAccountLabels := map[string]map[string]string{}
	if serviceAccounts := k.GetServiceaccounts(); serviceAccounts.Error == nil {
		serviceAccountLabels = serviceAccountLabelsByPodKey(serviceAccounts.Data)
	}
	for _, args := range primaryInterfaceCoverageArgsFromPods(pods.Data, append(nativeCoverageArgs, optionalCoverageArgs...), namespaceLabels, serviceAccountLabels) {
		coverage, err := CreateResource(k.MqlRuntime, "k8s.networkPolicyCoverage", args)
		if err != nil {
			return nil, err
		}
		out = append(out, coverage)
	}
	return out, nil
}

func (k *mqlK8sNamespace) networkExposures() ([]any, error) {
	return filterNetworkObjectsByNamespace(k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] {
		return c.GetNetworkExposures()
	})
}

func (k *mqlK8sNamespace) networkPolicyCoverages() ([]any, error) {
	return filterNetworkObjectsByNamespace(k.MqlRuntime, k.Name.Data, func(c *mqlK8s) *plugin.TValue[[]any] {
		return c.GetNetworkPolicyCoverages()
	})
}

func (k *mqlK8sService) networkExposures() ([]any, error) {
	o, err := CreateResource(k.MqlRuntime, "k8s", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	nodeAddresses, err := o.(*mqlK8s).publicNodeAddresses()
	if err != nil {
		nodeAddresses = nil
	}
	return k.networkExposuresWithNodeAddresses(nodeAddresses)
}

func (k *mqlK8sService) networkExposuresWithNodeAddresses(publicNodeAddresses []string) ([]any, error) {
	svc, err := k.getService()
	if err != nil {
		return nil, err
	}

	args := serviceNetworkExposureArgs(svc, publicNodeAddresses)
	return createNetworkExposures(k.MqlRuntime, args)
}

func (k *mqlK8sIngress) networkExposures() ([]any, error) {
	ing, err := k.getIngress()
	if err != nil {
		return nil, err
	}

	args := ingressNetworkExposureArgs(ing)
	return createNetworkExposures(k.MqlRuntime, args)
}

func (k *mqlK8sGateway) networkExposures() ([]any, error) {
	args := gatewayNetworkExposureArgs(k.obj)
	return createNetworkExposures(k.MqlRuntime, args)
}

func (k *mqlK8sNetworkpolicy) coverage() (*mqlK8sNetworkPolicyCoverage, error) {
	args, err := networkPolicyCoverageArgs(k.obj)
	if err != nil {
		return nil, err
	}
	coverage, err := CreateResource(k.MqlRuntime, "k8s.networkPolicyCoverage", args)
	if err != nil {
		return nil, err
	}
	return coverage.(*mqlK8sNetworkPolicyCoverage), nil
}

// These synthetic resources have no public id field; their deterministic
// identity is the __id set at construction. The generated __id fallback still
// references id(), so keep a trivial accessor returning the internal id.
func (k *mqlK8sNetworkExposure) id() (string, error)       { return k.__id, nil }
func (k *mqlK8sEgressRoute) id() (string, error)           { return k.__id, nil }
func (k *mqlK8sEgressNat) id() (string, error)             { return k.__id, nil }
func (k *mqlK8sNetworkPolicyCoverage) id() (string, error) { return k.__id, nil }

func (k *mqlK8s) publicNodeAddresses() ([]string, error) {
	nodes := k.GetNodes()
	if nodes.Error != nil {
		return nil, nodes.Error
	}

	addresses := []string{}
	for _, item := range nodes.Data {
		node, ok := item.(*mqlK8sNode)
		if !ok {
			continue
		}
		for _, addr := range node.obj.Status.Addresses {
			if (addr.Type == corev1.NodeExternalIP || addr.Type == corev1.NodeExternalDNS) && addressIsPublicNodeAddress(addr.Address) {
				addresses = append(addresses, addr.Address)
			}
		}
	}
	return sortedUniqueStrings(addresses), nil
}

func addressIsPublicNodeAddress(address string) bool {
	switch classifyAddress(address) {
	case "internet", "hostname":
		return true
	default:
		return false
	}
}

func serviceNetworkExposureArgs(svc *corev1.Service, publicNodeAddresses []string) []map[string]*llx.RawData {
	if svc == nil {
		return nil
	}

	sourceRef := networkSourceRef("Service", svc.Namespace, svc.Name)
	addresses := serviceExposureAddresses(svc)
	ports := servicePortDicts(svc.Spec.Ports)
	protocols := serviceProtocols(svc.Spec.Ports)
	classifications := classifyAddresses(addresses)
	internetExposed := contains(classifications, "internet") || contains(classifications, "hostname")
	exposureReason := "internalOnly"
	confidence := "high"

	switch svc.Spec.Type {
	case corev1.ServiceTypeLoadBalancer:
		sourceRangeClassifications := classifyCIDRs(svc.Spec.LoadBalancerSourceRanges)
		if len(addresses) == 0 {
			exposureReason = "loadBalancerPending"
			confidence = "low"
		} else if internetExposed && hasInternalLoadBalancerAnnotation(svc.Annotations) {
			// The declared scheme wins over the published address. An internal AWS
			// NLB's DNS name looks exactly like an internet-facing one, so without
			// this the address classification reports it as internet-reachable.
			internetExposed = false
			exposureReason = "internalLoadBalancerScheme"
		} else if internetExposed && len(svc.Spec.LoadBalancerSourceRanges) > 0 && !contains(sourceRangeClassifications, "publicSourceRange") {
			internetExposed = false
			exposureReason = "restrictedLoadBalancerSourceRange"
		} else if internetExposed {
			exposureReason = "publicLoadBalancerAddress"
		} else {
			exposureReason = "privateLoadBalancerAddress"
		}
		classifications = append(classifications, sourceRangeClassifications...)
	case corev1.ServiceTypeNodePort:
		addresses = sortedUniqueStrings(append(addresses, publicNodeAddresses...))
		classifications = classifyAddresses(addresses)
		internetExposed = len(publicNodeAddresses) > 0 || contains(classifications, "internet") || contains(classifications, "hostname")
		if len(publicNodeAddresses) > 0 {
			exposureReason = "nodePortPublicNode"
		} else if internetExposed {
			exposureReason = "nodePortPublicExternalIP"
		} else {
			exposureReason = "nodePortNoPublicNodeObserved"
			confidence = "medium"
		}
	case corev1.ServiceTypeExternalName:
		addresses = sortedUniqueStrings(append(addresses, svc.Spec.ExternalName))
		classifications = classifyAddresses(addresses)
		internetExposed = false
		exposureReason = "externalName"
		confidence = "low"
	case corev1.ServiceTypeClusterIP:
		if len(addresses) == 0 {
			return nil
		}
		if internetExposed {
			exposureReason = "externalIP"
			confidence = "medium"
		}
	default:
		if len(addresses) == 0 {
			return nil
		}
		exposureReason = "unknown"
		confidence = "low"
	}

	return []map[string]*llx.RawData{networkExposureArgs(networkExposureInputWithMetadata(svc, networkExposureInput{
		id:                     fmt.Sprintf("service:%s:%s", svc.Namespace, svc.Name),
		sourceKind:             "Service",
		sourceRef:              sourceRef,
		namespace:              svc.Namespace,
		name:                   svc.Name,
		addresses:              addresses,
		ports:                  ports,
		protocols:              protocols,
		internetExposed:        internetExposed,
		exposureReason:         exposureReason,
		networkClassifications: sortedUniqueStrings(classifications),
		confidence:             confidence,
	}))}
}

func ingressNetworkExposureArgs(ing *networkingv1.Ingress) []map[string]*llx.RawData {
	if ing == nil {
		return nil
	}

	statusAddresses := ingressStatusAddresses(ing)
	specHostnames := ingressSpecHostnames(ing)
	addresses := ingressExposureAddresses(ing)
	classifications := classifyAddresses(addresses)

	// Reachability follows the address the controller actually published, not the
	// rule hostnames. A rule host only matches the Host header of a request that
	// already reached the load balancer, so an internal load balancer fronting
	// public-looking names stays reachable only inside the VPC. The rule hostnames
	// are consulted solely while no address has been published, where they are the
	// one available signal of what the Ingress intends to serve.
	reachabilityAddresses := statusAddresses
	if len(reachabilityAddresses) == 0 {
		reachabilityAddresses = specHostnames
	}
	reachability := classifyAddresses(reachabilityAddresses)
	internetExposed := contains(reachability, "internet") || contains(reachability, "hostname")

	exposureReason := "ingressNoPublishedAddress"
	confidence := "low"
	if hasInternalLoadBalancerAnnotation(ing.Annotations) {
		// A declared scheme is authoritative and is reported as the reason in its own
		// right: the controller provisions the load balancer from it, so it settles
		// reachability whatever the published address or rule hostnames suggest.
		internetExposed = false
		exposureReason = "internalLoadBalancerScheme"
		confidence = "high"
	} else if internetExposed && len(statusAddresses) > 0 {
		exposureReason = "publicIngressAddress"
		confidence = "high"
	} else if internetExposed && len(specHostnames) > 0 {
		exposureReason = "publicIngressHostname"
		confidence = "medium"
	} else if len(statusAddresses) > 0 {
		exposureReason = "privateIngressAddress"
		confidence = "high"
	} else if len(specHostnames) > 0 {
		// A rule hostname is a statement of intent, not a published address, so
		// it carries the same lower confidence as its public counterpart above.
		exposureReason = "privateIngressHostname"
		confidence = "medium"
	}

	return []map[string]*llx.RawData{networkExposureArgs(networkExposureInputWithMetadata(ing, networkExposureInput{
		id:                     fmt.Sprintf("ingress:%s:%s", ing.Namespace, ing.Name),
		sourceKind:             "Ingress",
		sourceRef:              networkSourceRef("Ingress", ing.Namespace, ing.Name),
		namespace:              ing.Namespace,
		name:                   ing.Name,
		addresses:              addresses,
		ports:                  ingressPortDicts(ing),
		protocols:              ingressProtocols(ing),
		internetExposed:        internetExposed,
		exposureReason:         exposureReason,
		networkClassifications: sortedUniqueStrings(classifications),
		confidence:             confidence,
	}))}
}

func gatewayNetworkExposureArgs(gw *gatewayv1.Gateway) []map[string]*llx.RawData {
	if gw == nil {
		return nil
	}

	ctx := gatewayNetworkExposureContext(gw)
	return []map[string]*llx.RawData{networkExposureArgs(networkExposureInputWithMetadata(gw, networkExposureInput{
		id:                     fmt.Sprintf("gateway:%s:%s", gw.Namespace, gw.Name),
		sourceKind:             "Gateway",
		sourceRef:              networkSourceRef("Gateway", gw.Namespace, gw.Name),
		namespace:              gw.Namespace,
		name:                   gw.Name,
		addresses:              ctx.addresses,
		ports:                  gatewayPortDicts(gw),
		protocols:              gatewayProtocols(gw),
		internetExposed:        ctx.internetExposed,
		exposureReason:         ctx.exposureReason,
		networkClassifications: ctx.classifications,
		confidence:             ctx.confidence,
	}))}
}

type networkExposureContext struct {
	addresses       []string
	classifications []string
	internetExposed bool
	exposureReason  string
	confidence      string
}

func gatewayNetworkExposureContext(gw *gatewayv1.Gateway) networkExposureContext {
	addresses := gatewayExposureAddresses(gw)
	classifications := classifyAddresses(addresses)
	internetExposed := contains(classifications, "internet") || contains(classifications, "hostname")
	exposureReason := "gatewayNoPublishedAddress"
	confidence := "low"
	if internetExposed {
		exposureReason = "gatewayPublicAddress"
		confidence = "high"
	} else if len(addresses) > 0 {
		exposureReason = "gatewayPrivateAddress"
		confidence = "high"
	}

	return networkExposureContext{
		addresses:       addresses,
		classifications: sortedUniqueStrings(classifications),
		internetExposed: internetExposed,
		exposureReason:  exposureReason,
		confidence:      confidence,
	}
}

func gatewayRouteNetworkExposureArgs(u *unstructured.Unstructured, gatewayContexts map[string]networkExposureContext) []map[string]*llx.RawData {
	if u == nil || u.GroupVersionKind().Group != "gateway.networking.k8s.io" {
		return nil
	}

	protocols := gatewayRouteProtocols(u.GetKind())
	if len(protocols) == 0 {
		return nil
	}

	spec := nestedMap(u.Object, "spec")
	routeHostnames := stringSlice(spec["hostnames"])
	parentRefs := gatewayRouteParentRefs(u.GetNamespace(), nestedSlice(spec, "parentRefs"))
	effectiveParentRefs := parentRefs
	if acceptedParents, observed := gatewayRouteAcceptedParentRefs(u, parentRefs); observed {
		effectiveParentRefs = filterAcceptedGatewayRouteParentRefs(parentRefs, acceptedParents)
	}
	parentObserved, parentInternetExposed := gatewayRouteParentExposure(effectiveParentRefs, gatewayContexts)
	addresses := sortedUniqueStrings(append(routeHostnames, gatewayRouteParentAddresses(effectiveParentRefs, gatewayContexts)...))
	classifications := classifyAddresses(addresses)
	hostnameClassifications := classifyAddresses(routeHostnames)
	hostnameExposed := len(routeHostnames) > 0 && (contains(hostnameClassifications, "internet") || contains(hostnameClassifications, "hostname"))
	internetExposed := parentInternetExposed || (!parentObserved && hostnameExposed)
	exposureReason := gatewayRouteExposureReason(routeHostnames, effectiveParentRefs, gatewayContexts, classifications, internetExposed)
	confidence := "medium"
	if len(routeHostnames) == 0 && len(addresses) == 0 {
		confidence = "low"
	}
	if len(effectiveParentRefs) == 0 {
		internetExposed = false
		exposureReason = "gatewayRouteNoParentRef"
		confidence = "low"
	}
	if accepted, observed := gatewayRouteAccepted(u); observed && !accepted {
		internetExposed = false
		exposureReason = "gatewayRouteNotAccepted"
		confidence = "low"
	}

	return []map[string]*llx.RawData{networkExposureArgs(networkExposureInputWithObjectMetadata(u, networkExposureInput{
		id:                     fmt.Sprintf("%s:%s:%s", strings.ToLower(u.GetKind()), u.GetNamespace(), u.GetName()),
		sourceKind:             u.GetKind(),
		sourceRef:              unstructuredSourceRef(u),
		namespace:              u.GetNamespace(),
		name:                   u.GetName(),
		addresses:              addresses,
		ports:                  gatewayRoutePortDicts(spec),
		protocols:              protocols,
		internetExposed:        internetExposed,
		exposureReason:         exposureReason,
		networkClassifications: classifications,
		routes:                 effectiveParentRefs,
		confidence:             confidence,
	}))}
}

func networkPolicyCoverageArgs(policy *networkingv1.NetworkPolicy) (map[string]*llx.RawData, error) {
	if policy == nil {
		return networkPolicyCoverageRawArgs("", "", "", nil, nil, false, false, nil), nil
	}

	selector, err := convert.JsonToDict(policy.Spec.PodSelector)
	if err != nil {
		return nil, err
	}

	policyTypes := effectiveNetworkPolicyTypes(policy)
	ingressIsolated := contains(policyTypes, string(networkingv1.PolicyTypeIngress))
	egressIsolated := contains(policyTypes, string(networkingv1.PolicyTypeEgress))
	defaultDenyIngress := ingressIsolated && !networkPolicyIngressAllowsAll(policy.Spec.Ingress)
	defaultDenyEgress := egressIsolated && !networkPolicyEgressAllowsAll(policy.Spec.Egress)
	gaps := []string{}
	if !ingressIsolated {
		gaps = append(gaps, "primary ingress is not isolated by this policy")
	} else if !defaultDenyIngress {
		gaps = append(gaps, "primary ingress allows all traffic")
	}
	if !egressIsolated {
		gaps = append(gaps, "primary egress is not isolated by this policy")
	} else if !defaultDenyEgress {
		gaps = append(gaps, "primary egress allows all traffic")
	}
	gaps = append(gaps, "secondary interface coverage requires MultiNetworkPolicy or CNI-specific policy inventory")

	ref := networkSourceRef("NetworkPolicy", policy.Namespace, policy.Name)
	return networkPolicyCoverageRawArgs(
		fmt.Sprintf("networkpolicy:%s:%s", policy.Namespace, policy.Name),
		policy.Namespace,
		ref,
		selector,
		[]string{ref},
		defaultDenyIngress,
		defaultDenyEgress,
		gaps,
	), nil
}

type nativeNetworkPolicyCoverageAggregate struct {
	namespace          string
	selector           map[string]any
	nativePolicies     []string
	ingressIsolated    bool
	egressIsolated     bool
	ingressAllowsAll   bool
	egressAllowsAll    bool
	defaultDenyIngress bool
	defaultDenyEgress  bool
}

func networkPolicyCoverageArgsFromPolicies(items []any) ([]map[string]*llx.RawData, error) {
	groups := map[string]*nativeNetworkPolicyCoverageAggregate{}
	keys := []string{}

	for _, item := range items {
		policy, ok := item.(*mqlK8sNetworkpolicy)
		if !ok || policy.obj == nil {
			continue
		}
		selector, err := convert.JsonToDict(policy.obj.Spec.PodSelector)
		if err != nil {
			return nil, err
		}
		key, err := nativeNetworkPolicyCoverageKey(policy.obj.Namespace, selector)
		if err != nil {
			return nil, err
		}
		group, ok := groups[key]
		if !ok {
			group = &nativeNetworkPolicyCoverageAggregate{
				namespace: policy.obj.Namespace,
				selector:  selector,
			}
			groups[key] = group
			keys = append(keys, key)
		}

		ref := networkSourceRef("NetworkPolicy", policy.obj.Namespace, policy.obj.Name)
		group.nativePolicies = append(group.nativePolicies, ref)
		policyTypes := effectiveNetworkPolicyTypes(policy.obj)
		if contains(policyTypes, string(networkingv1.PolicyTypeIngress)) {
			group.ingressIsolated = true
			group.ingressAllowsAll = group.ingressAllowsAll || networkPolicyIngressAllowsAll(policy.obj.Spec.Ingress)
		}
		if contains(policyTypes, string(networkingv1.PolicyTypeEgress)) {
			group.egressIsolated = true
			group.egressAllowsAll = group.egressAllowsAll || networkPolicyEgressAllowsAll(policy.obj.Spec.Egress)
		}
	}

	for _, key := range keys {
		group := groups[key]
		group.defaultDenyIngress = group.ingressIsolated && !group.ingressAllowsAll
		group.defaultDenyEgress = group.egressIsolated && !group.egressAllowsAll
	}
	foldBroaderNativeNetworkPolicyCoverage(groups)

	sort.Strings(keys)
	out := make([]map[string]*llx.RawData, 0, len(keys))
	for _, key := range keys {
		group := groups[key]
		gaps := []string{}
		if !group.ingressIsolated {
			gaps = append(gaps, "primary ingress is not isolated by selected policies")
		} else if !group.defaultDenyIngress {
			gaps = append(gaps, "primary ingress allows all traffic")
		}
		if !group.egressIsolated {
			gaps = append(gaps, "primary egress is not isolated by selected policies")
		} else if !group.defaultDenyEgress {
			gaps = append(gaps, "primary egress allows all traffic")
		}
		gaps = append(gaps, "secondary interface coverage requires MultiNetworkPolicy or CNI-specific policy inventory")
		group.nativePolicies = sortedUniqueStrings(group.nativePolicies)

		out = append(out, networkPolicyCoverageRawArgs(
			fmt.Sprintf("networkpolicy:%s:%s", group.namespace, shortHashString(key)),
			group.namespace,
			strings.Join(group.nativePolicies, ","),
			group.selector,
			group.nativePolicies,
			group.defaultDenyIngress,
			group.defaultDenyEgress,
			gaps,
		))
	}
	return out, nil
}

func foldBroaderNativeNetworkPolicyCoverage(groups map[string]*nativeNetworkPolicyCoverageAggregate) {
	for _, group := range groups {
		for _, candidate := range groups {
			if group == candidate || group.namespace != candidate.namespace {
				continue
			}
			if !nativeNetworkPolicySelectorCovers(candidate.selector, group.selector) {
				continue
			}
			if candidate.defaultDenyIngress && !group.defaultDenyIngress && !group.ingressAllowsAll {
				group.ingressIsolated = true
				group.defaultDenyIngress = true
				group.nativePolicies = append(group.nativePolicies, candidate.nativePolicies...)
			}
			if candidate.defaultDenyEgress && !group.defaultDenyEgress && !group.egressAllowsAll {
				group.egressIsolated = true
				group.defaultDenyEgress = true
				group.nativePolicies = append(group.nativePolicies, candidate.nativePolicies...)
			}
		}
	}
}

func nativeNetworkPolicySelectorCovers(candidate, target map[string]any) bool {
	if selectorIsEmpty(candidate) {
		return true
	}
	if selectorIsEmpty(target) {
		return false
	}
	candidateLabels := selectorMatchLabels(candidate)
	targetLabels := selectorMatchLabels(target)
	if len(candidateLabels) == 0 {
		return false
	}
	for key, value := range candidateLabels {
		if targetLabels[key] != value {
			return false
		}
	}
	return true
}

func selectorMatchLabels(selector map[string]any) map[string]string {
	out := map[string]string{}
	for key, value := range nestedMap(selector, "matchLabels") {
		// Preserve genuine empty-string label values (matchLabels: {role: ""}
		// legitimately selects pods whose label is the empty string); only skip
		// non-string values. Using stringValue here would conflate the two.
		switch v := value.(type) {
		case string:
			out[key] = strings.TrimSpace(v)
		case *string:
			if v != nil {
				out[key] = strings.TrimSpace(*v)
			}
		}
	}
	return out
}

func nativeNetworkPolicyCoverageKey(namespace string, selector map[string]any) (string, error) {
	raw, err := json.Marshal(selector)
	if err != nil {
		return "", err
	}
	return namespace + "\x00" + string(raw), nil
}

func shortHashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func networkPolicyCoverageRawArgs(id, namespace, policyRef string, selector map[string]any, nativePolicies []string, defaultDenyIngress, defaultDenyEgress bool, gaps []string) map[string]*llx.RawData {
	if selector == nil {
		selector = map[string]any{}
	}
	return map[string]*llx.RawData{
		"__id":                             llx.StringData(id),
		"workloadRef":                      llx.StringData(""),
		"policyRef":                        llx.StringData(policyRef),
		"namespace":                        llx.StringData(namespace),
		"podSelector":                      llx.DictData(selector),
		"interfaces":                       stringArrayData([]string{"primary"}),
		"nativeNetworkPolicies":            stringArrayData(nativePolicies),
		"adminNetworkPolicies":             stringArrayData(nil),
		"multiNetworkPolicies":             stringArrayData(nil),
		"calicoPolicies":                   stringArrayData(nil),
		"ciliumPolicies":                   stringArrayData(nil),
		"defaultDenyIngress":               llx.BoolData(defaultDenyIngress),
		"defaultDenyEgress":                llx.BoolData(defaultDenyEgress),
		"adminDefaultDenyIngress":          llx.BoolData(false),
		"adminDefaultDenyEgress":           llx.BoolData(false),
		"secondaryInterfaceIngressCovered": llx.BoolData(false),
		"secondaryInterfaceEgressCovered":  llx.BoolData(false),
		"coverageGaps":                     stringArrayData(gaps),
	}
}

type networkInventorySettings struct {
	hbnEnabled                bool
	hbnIncludeLegacyResources bool
	multiNetworkPolicyEnabled bool
	publicCIDRs               map[string]struct{}
	privateCIDRs              map[string]struct{}
	trustedEgressCIDRs        map[string]struct{}
}

type networkInventoryOption struct {
	HBN struct {
		Enabled                *bool `json:"enabled"`
		IncludeLegacyResources *bool `json:"includeLegacyResources"`
	} `json:"hbn"`
	MultiNetworkPolicy struct {
		Enabled *bool `json:"enabled"`
	} `json:"multiNetworkPolicy"`
	Classifications struct {
		PublicCIDRs        []string `json:"publicCidrs"`
		PrivateCIDRs       []string `json:"privateCidrs"`
		TrustedEgressCIDRs []string `json:"trustedEgressCidrs"`
	} `json:"classifications"`
}

type egressRouteInput struct {
	id                     string
	sourceRef              string
	vrf                    string
	network                string
	destinations           []string
	cidrs                  []string
	publicCidrs            []string
	nat                    bool
	nodeStatuses           []string
	bgpPeerings            []string
	classification         string
	metadataClassification string
	owner                  string
	confidence             string
}

type egressNatInput struct {
	id                     string
	sourceRef              string
	vrf                    string
	network                string
	addresses              []string
	cidrs                  []string
	publicCidrs            []string
	nodeStatuses           []string
	classification         string
	metadataClassification string
	owner                  string
}

func networkInventorySettingsFromRuntime(rt *plugin.Runtime) networkInventorySettings {
	settings := networkInventorySettings{
		hbnEnabled:                true,
		hbnIncludeLegacyResources: true,
		multiNetworkPolicyEnabled: true,
		publicCIDRs:               map[string]struct{}{},
		privateCIDRs:              map[string]struct{}{},
		trustedEgressCIDRs:        map[string]struct{}{},
	}
	conn, ok := rt.Connection.(shared.Connection)
	if !ok || conn.InventoryConfig() == nil || conn.InventoryConfig().Options == nil {
		return settings
	}
	raw := conn.InventoryConfig().Options["kubernetesNetworkInventory"]
	if strings.TrimSpace(raw) == "" {
		return settings
	}

	var option networkInventoryOption
	if err := yaml.Unmarshal([]byte(raw), &option); err != nil {
		log.Debug().Err(err).Str("option", "kubernetesNetworkInventory").Msg("failed to parse Kubernetes network inventory options")
		return settings
	}
	if option.HBN.Enabled != nil {
		settings.hbnEnabled = *option.HBN.Enabled
	}
	if option.HBN.IncludeLegacyResources != nil {
		settings.hbnIncludeLegacyResources = *option.HBN.IncludeLegacyResources
	}
	if option.MultiNetworkPolicy.Enabled != nil {
		settings.multiNetworkPolicyEnabled = *option.MultiNetworkPolicy.Enabled
	}
	settings.publicCIDRs = stringSet(option.Classifications.PublicCIDRs)
	settings.privateCIDRs = stringSet(option.Classifications.PrivateCIDRs)
	settings.trustedEgressCIDRs = stringSet(option.Classifications.TrustedEgressCIDRs)
	return settings
}

func enabledHBNOptionalKinds(settings networkInventorySettings, kinds []string) []string {
	if !settings.hbnEnabled {
		return nil
	}
	out := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		if !settings.hbnIncludeLegacyResources && isLegacyHBNKind(kind) {
			continue
		}
		out = append(out, kind)
	}
	return out
}

func enabledNetworkPolicyCoverageKinds(settings networkInventorySettings) []string {
	out := make([]string, 0, len(optionalNetworkPolicyCoverageKinds))
	for _, kind := range optionalNetworkPolicyCoverageKinds {
		if !settings.multiNetworkPolicyEnabled && isMultiNetworkPolicyKind(kind) {
			continue
		}
		out = append(out, kind)
	}
	return out
}

func isLegacyHBNKind(kind string) bool {
	return strings.Contains(kind, ".network.t-caas.telekom.com") ||
		strings.Contains(kind, ".networking.t-caas.telekom.com") ||
		strings.Contains(kind, ".hbn.t-caas.telekom.com")
}

func isMultiNetworkPolicyKind(kind string) bool {
	return strings.Contains(kind, "multi-networkpolicies") || strings.Contains(kind, "multinetworkpolicies")
}

func optionalK8sResources(rt *plugin.Runtime, kinds ...string) ([]runtime.Object, error) {
	kt, err := k8sProvider(rt.Connection)
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	out := []runtime.Object{}
	for _, kind := range kinds {
		result, err := kt.Resources(kind, "", "")
		if err != nil {
			if optionalResourceUnavailable(err) {
				log.Debug().Err(err).Str("kind", kind).Msg("skipping optional Kubernetes resource")
				continue
			}
			return nil, err
		}
		for _, object := range result.Resources {
			u := asUnstructured(object)
			key := kind
			if u != nil {
				gvk := u.GroupVersionKind()
				key = strings.Join([]string{gvk.Group, gvk.Kind, u.GetNamespace(), u.GetName()}, "/")
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, object)
		}
	}
	return out, nil
}

func optionalResourceNotFound(err error) bool {
	return err != nil && (apierrors.IsNotFound(err) || strings.Contains(err.Error(), "could not find api kind"))
}

func optionalResourceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	return optionalResourceNotFound(err) || apierrors.IsForbidden(err) || strings.Contains(strings.ToLower(err.Error()), "forbidden")
}

func asUnstructured(object runtime.Object) *unstructured.Unstructured {
	if object == nil {
		return nil
	}
	if u, ok := object.(*unstructured.Unstructured); ok {
		return u
	}
	raw, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return nil
	}
	return &unstructured.Unstructured{Object: raw}
}

func gatewayFromUnstructured(u *unstructured.Unstructured) *gatewayv1.Gateway {
	if u == nil || !strings.EqualFold(u.GetKind(), "Gateway") {
		return nil
	}
	var gw gatewayv1.Gateway
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(u.Object, &gw); err != nil {
		return nil
	}
	return &gw
}

func egressRouteInputsFromUnstructured(u *unstructured.Unstructured, settings networkInventorySettings) []egressRouteInput {
	switch u.GetKind() {
	case "VRFRouteConfiguration":
		return vrfRouteConfigurationInputs(u, settings)
	case "BGPPeering":
		return bgpPeeringRouteInputs(u, settings)
	case "NodeNetworkConfig":
		return nodeNetworkConfigRouteInputs(u, settings)
	case "NetworkConfigRevision":
		return networkConfigRevisionRouteInputs(u, settings)
	case "Egress":
		return coilEgressRouteInputs(u, settings)
	default:
		return nil
	}
}

func vrfRouteConfigurationInputs(u *unstructured.Unstructured, settings networkInventorySettings) []egressRouteInput {
	spec := nestedMap(u.Object, "spec")
	cidrs := append(prefixItemsCIDRs(nestedSlice(spec, "import")), prefixItemsCIDRs(nestedSlice(spec, "export"))...)
	cidrs = append(cidrs, stringSlice(spec["aggregate"])...)
	cidrs = append(cidrs, stringSlice(spec["sbrPrefixes"])...)
	cidrs = sortedUniqueStrings(cidrs)

	return []egressRouteInput{newEgressRouteInput(egressRouteInputWithObjectMetadata(u, egressRouteInput{
		id:           fmt.Sprintf("hbn-vrf:%s", u.GetName()),
		sourceRef:    unstructuredSourceRef(u),
		vrf:          stringValue(spec["vrf"]),
		network:      stringValue(spec["routeTarget"]),
		destinations: cidrs,
		cidrs:        cidrs,
		confidence:   "high",
	}), settings)}
}

func bgpPeeringRouteInputs(u *unstructured.Unstructured, settings networkInventorySettings) []egressRouteInput {
	spec := nestedMap(u.Object, "spec")
	cidrs := append(prefixItemsCIDRs(nestedSlice(spec, "import")), prefixItemsCIDRs(nestedSlice(spec, "export"))...)
	network := nestedString(spec, "peeringVlan", "name")
	if network == "" && nestedMap(spec, "loopbackPeer") != nil {
		network = "loopback"
	}

	return []egressRouteInput{newEgressRouteInput(egressRouteInputWithObjectMetadata(u, egressRouteInput{
		id:           fmt.Sprintf("hbn-bgp:%s", u.GetName()),
		sourceRef:    unstructuredSourceRef(u),
		network:      network,
		destinations: cidrs,
		cidrs:        cidrs,
		bgpPeerings:  []string{unstructuredSourceRef(u)},
		confidence:   "high",
	}), settings)}
}

func nodeNetworkConfigRouteInputs(u *unstructured.Unstructured, settings networkInventorySettings) []egressRouteInput {
	spec := nestedMap(u.Object, "spec")
	out := []egressRouteInput{}
	if clusterVRF := nestedMap(spec, "clusterVRF"); clusterVRF != nil {
		out = append(out, vrfMapRouteInput(u, "cluster", "cluster", clusterVRF, settings))
	}
	for name, value := range nestedMap(spec, "fabricVRFs") {
		if vrf, ok := value.(map[string]any); ok {
			out = append(out, vrfMapRouteInput(u, "fabric", name, vrf, settings))
		}
	}
	for name, value := range nestedMap(spec, "localVRFs") {
		if vrf, ok := value.(map[string]any); ok {
			out = append(out, vrfMapRouteInput(u, "local", name, vrf, settings))
		}
	}
	return out
}

func networkConfigRevisionRouteInputs(u *unstructured.Unstructured, settings networkInventorySettings) []egressRouteInput {
	spec := nestedMap(u.Object, "spec")
	out := []egressRouteInput{}
	for _, item := range nestedSlice(spec, "vrf") {
		vrf, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := stringValue(vrf["name"])
		if name == "" {
			name = stringValue(vrf["vrf"])
		}
		cidrs := append(prefixItemsCIDRs(nestedSlice(vrf, "import")), prefixItemsCIDRs(nestedSlice(vrf, "export"))...)
		cidrs = append(cidrs, stringSlice(vrf["aggregate"])...)
		cidrs = append(cidrs, stringSlice(vrf["sbrPrefixes"])...)
		out = append(out, newEgressRouteInput(egressRouteInputWithObjectMetadata(u, egressRouteInput{
			id:           fmt.Sprintf("hbn-revision-vrf:%s:%s", u.GetName(), name),
			sourceRef:    unstructuredSourceRef(u),
			vrf:          stringValue(vrf["vrf"]),
			network:      stringValue(vrf["routeTarget"]),
			destinations: cidrs,
			cidrs:        cidrs,
			confidence:   revisionConfidence(u),
		}), settings))
	}
	for _, item := range nestedSlice(spec, "bgp") {
		bgp, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name := stringValue(bgp["name"])
		cidrs := append(prefixItemsCIDRs(nestedSlice(bgp, "import")), prefixItemsCIDRs(nestedSlice(bgp, "export"))...)
		out = append(out, newEgressRouteInput(egressRouteInputWithObjectMetadata(u, egressRouteInput{
			id:           fmt.Sprintf("hbn-revision-bgp:%s:%s", u.GetName(), name),
			sourceRef:    unstructuredSourceRef(u),
			network:      nestedString(bgp, "peeringVlan", "name"),
			destinations: cidrs,
			cidrs:        cidrs,
			bgpPeerings:  []string{fmt.Sprintf("%s#bgp/%s", unstructuredSourceRef(u), name)},
			confidence:   revisionConfidence(u),
		}), settings))
	}
	return out
}

func coilEgressRouteInputs(u *unstructured.Unstructured, settings networkInventorySettings) []egressRouteInput {
	destinations := stringSlice(nestedMap(u.Object, "spec")["destinations"])
	return []egressRouteInput{newEgressRouteInput(egressRouteInputWithObjectMetadata(u, egressRouteInput{
		id:           fmt.Sprintf("coil-egress:%s:%s", u.GetNamespace(), u.GetName()),
		sourceRef:    unstructuredSourceRef(u),
		network:      u.GetNamespace(),
		destinations: destinations,
		cidrs:        destinations,
		nat:          true,
		confidence:   "medium",
	}), settings)}
}

func vrfMapRouteInput(u *unstructured.Unstructured, group, name string, vrf map[string]any, settings networkInventorySettings) egressRouteInput {
	cidrs := []string{}
	for _, item := range nestedSlice(vrf, "staticRoutes") {
		if route, ok := item.(map[string]any); ok {
			cidrs = append(cidrs, stringValue(route["prefix"]))
		}
	}
	for _, item := range nestedSlice(vrf, "policyRoutes") {
		route, ok := item.(map[string]any)
		if !ok {
			continue
		}
		cidrs = append(cidrs, nestedString(route, "trafficMatch", "dstPrefix"))
		cidrs = append(cidrs, nestedString(route, "trafficMatch", "srcPrefix"))
	}
	bgpPeerings := []string{}
	for _, item := range nestedSlice(vrf, "bgpPeers") {
		peer, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if address := stringValue(peer["address"]); address != "" {
			bgpPeerings = append(bgpPeerings, address)
		}
		if listenRange := stringValue(peer["listenRange"]); listenRange != "" {
			bgpPeerings = append(bgpPeerings, listenRange)
		}
	}

	return newEgressRouteInput(egressRouteInputWithObjectMetadata(u, egressRouteInput{
		id:           fmt.Sprintf("hbn-node:%s:%s:%s", u.GetName(), group, name),
		sourceRef:    unstructuredSourceRef(u),
		vrf:          name,
		network:      group,
		destinations: cidrs,
		cidrs:        cidrs,
		nodeStatuses: []string{unstructuredSourceRef(u)},
		bgpPeerings:  bgpPeerings,
		confidence:   nodeNetworkConfigConfidence(u),
	}), settings)
}

func egressNatInputsFromUnstructured(u *unstructured.Unstructured, settings networkInventorySettings) []egressNatInput {
	switch u.GetKind() {
	case "Egress":
		spec := nestedMap(u.Object, "spec")
		cidrs := stringSlice(spec["destinations"])
		return []egressNatInput{newEgressNatInput(egressNatInputWithObjectMetadata(u, egressNatInput{
			id:        fmt.Sprintf("coil-egress:%s:%s", u.GetNamespace(), u.GetName()),
			sourceRef: unstructuredSourceRef(u),
			network:   u.GetNamespace(),
			cidrs:     cidrs,
			addresses: coilEgressPoolAnnotations(spec),
		}), settings)}
	case "IPPool":
		spec := nestedMap(u.Object, "spec")
		cidr := stringValue(spec["cidr"])
		if !boolValue(spec["natOutgoing"]) {
			return nil
		}
		return []egressNatInput{newEgressNatInput(egressNatInputWithObjectMetadata(u, egressNatInput{
			id:        fmt.Sprintf("calico-ippool:%s", u.GetName()),
			sourceRef: unstructuredSourceRef(u),
			network:   u.GetName(),
			cidrs:     []string{cidr},
		}), settings)}
	default:
		return nil
	}
}

func hbnNetworkExposureArgs(u *unstructured.Unstructured) []map[string]*llx.RawData {
	spec := nestedMap(u.Object, "spec")
	addresses := collectNetworkStrings(spec, []string{
		"address", "addresses", "ip", "ips", "publicIP", "publicIPs",
		"destination", "destinations", "cidr", "cidrs", "prefix", "prefixes",
	})
	classifications := classifyAddresses(addresses)
	internetExposed := contains(classifications, "internet") || contains(classifications, "hostname") || contains(classifyCIDRs(addresses), "publicSourceRange")
	exposureReason := "hbnInboundNoPublishedDestination"
	confidence := "low"
	if internetExposed {
		exposureReason = "hbnInboundPublicDestination"
		confidence = "medium"
	} else if len(addresses) > 0 {
		exposureReason = "hbnInboundPrivateDestination"
		confidence = "medium"
	}

	return []map[string]*llx.RawData{networkExposureArgs(networkExposureInputWithObjectMetadata(u, networkExposureInput{
		id:                     fmt.Sprintf("hbn-%s:%s:%s", strings.ToLower(u.GetKind()), u.GetNamespace(), u.GetName()),
		sourceKind:             u.GetKind(),
		sourceRef:              unstructuredSourceRef(u),
		namespace:              u.GetNamespace(),
		name:                   u.GetName(),
		addresses:              addresses,
		ports:                  hbnPortDicts(spec),
		protocols:              collectNetworkStrings(spec, []string{"protocol", "protocols"}),
		internetExposed:        internetExposed,
		exposureReason:         exposureReason,
		networkClassifications: sortedUniqueStrings(append(classifications, classifyCIDRs(addresses)...)),
		vrf:                    firstNetworkString(spec, []string{"vrf", "vrfRef", "vrfName"}),
		network:                firstNetworkString(spec, []string{"network", "networkRef", "networkName"}),
		routes:                 collectNetworkStrings(spec, []string{"backend", "backends", "service", "services", "workload", "workloads", "destinationRef", "networkRef"}),
		confidence:             confidence,
	}))}
}

func hbnStableEgressRouteInputs(u *unstructured.Unstructured, settings networkInventorySettings) []egressRouteInput {
	spec := nestedMap(u.Object, "spec")
	cidrs := collectNetworkStrings(spec, []string{
		"cidr", "cidrs", "prefix", "prefixes", "subnet", "subnets", "destination",
		"destinations", "aggregate", "aggregates", "sbrPrefix", "sbrPrefixes",
	})
	if len(cidrs) == 0 {
		return nil
	}

	network := firstNetworkString(spec, []string{"network", "networkRef", "networkName", "podNetwork", "podNetworkRef"})
	if network == "" {
		network = u.GetName()
	}
	in := egressRouteInput{
		id:           fmt.Sprintf("hbn-%s:%s:%s", strings.ToLower(u.GetKind()), u.GetNamespace(), u.GetName()),
		sourceRef:    unstructuredSourceRef(u),
		vrf:          firstNetworkString(spec, []string{"vrf", "vrfRef", "vrfName"}),
		network:      network,
		destinations: cidrs,
		cidrs:        cidrs,
		nodeStatuses: collectNetworkStrings(nestedMap(u.Object, "status"), []string{"node", "nodes", "nodeName", "nodeNames"}),
		bgpPeerings:  collectNetworkStrings(spec, []string{"bgpPeer", "bgpPeers", "peer", "peers", "peerAddress", "peerAddresses"}),
		confidence:   "medium",
	}
	if strings.EqualFold(u.GetKind(), "Outbound") || strings.EqualFold(u.GetKind(), "NetworkConnector") {
		in.nat = boolValue(spec["nat"]) || boolValue(spec["masquerade"]) || len(collectNetworkStrings(spec, []string{"nat", "natPool", "natPools", "egressIP", "egressIPs"})) > 0
	}
	return []egressRouteInput{newEgressRouteInput(egressRouteInputWithObjectMetadata(u, in), settings)}
}

func hbnStableEgressNatInputs(u *unstructured.Unstructured, settings networkInventorySettings) []egressNatInput {
	if !strings.EqualFold(u.GetKind(), "Outbound") && !strings.EqualFold(u.GetKind(), "NetworkConnector") {
		return nil
	}
	spec := nestedMap(u.Object, "spec")
	cidrs := collectNetworkStrings(spec, []string{
		"cidr", "cidrs", "prefix", "prefixes", "subnet", "subnets", "destination",
		"destinations", "aggregate", "aggregates", "sbrPrefix", "sbrPrefixes",
	})
	addresses := collectNetworkStrings(spec, []string{"nat", "natPool", "natPools", "egressIP", "egressIPs", "snatIP", "snatIPs"})
	if !boolValue(spec["nat"]) && !boolValue(spec["masquerade"]) && len(addresses) == 0 {
		return nil
	}
	if len(cidrs) == 0 {
		return nil
	}

	network := firstNetworkString(spec, []string{"network", "networkRef", "networkName", "podNetwork", "podNetworkRef"})
	if network == "" {
		network = u.GetName()
	}
	return []egressNatInput{newEgressNatInput(egressNatInputWithObjectMetadata(u, egressNatInput{
		id:           fmt.Sprintf("hbn-nat-%s:%s:%s", strings.ToLower(u.GetKind()), u.GetNamespace(), u.GetName()),
		sourceRef:    unstructuredSourceRef(u),
		vrf:          firstNetworkString(spec, []string{"vrf", "vrfRef", "vrfName"}),
		network:      network,
		addresses:    addresses,
		cidrs:        cidrs,
		nodeStatuses: collectNetworkStrings(nestedMap(u.Object, "status"), []string{"node", "nodes", "nodeName", "nodeNames"}),
	}), settings)}
}

func networkPolicyCoverageArgsFromUnstructured(u *unstructured.Unstructured) []map[string]*llx.RawData {
	spec := nestedMap(u.Object, "spec")
	switch u.GetKind() {
	case "AdminNetworkPolicy", "BaselineAdminNetworkPolicy":
		if u.GroupVersionKind().Group != "policy.networking.k8s.io" {
			return nil
		}
		return []map[string]*llx.RawData{adminNetworkPolicyCoverageArgs(u)}
	case "MultiNetworkPolicy":
		policyTypes := effectiveUnstructuredPolicyTypes(spec)
		ingressObserved := contains(policyTypes, string(networkingv1.PolicyTypeIngress))
		egressObserved := contains(policyTypes, string(networkingv1.PolicyTypeEgress))
		ingressAllowsAll := ingressObserved && unstructuredNetworkPolicyRulesAllowAll(nestedSlice(spec, "ingress"))
		egressAllowsAll := egressObserved && unstructuredNetworkPolicyRulesAllowAll(nestedSlice(spec, "egress"))
		ingressCovered := ingressObserved && !ingressAllowsAll
		egressCovered := egressObserved && !egressAllowsAll
		gaps := []string{}
		if !ingressObserved {
			gaps = append(gaps, "secondary ingress policy was not observed")
		} else if ingressAllowsAll {
			gaps = append(gaps, "secondary ingress allows all traffic")
		}
		if !egressObserved {
			gaps = append(gaps, "secondary egress policy was not observed")
		} else if egressAllowsAll {
			gaps = append(gaps, "secondary egress allows all traffic")
		}
		policyFor := u.GetAnnotations()["k8s.v1.cni.cncf.io/policy-for"]
		interfaces := []string{"secondary"}
		if policyFor != "" {
			interfaces = append(interfaces, policyFor)
		}
		return []map[string]*llx.RawData{networkPolicyCoverageRawArgsWithSources(
			fmt.Sprintf("multinetworkpolicy:%s:%s", u.GetNamespace(), u.GetName()),
			u.GetNamespace(),
			unstructuredSourceRef(u),
			nestedMap(spec, "podSelector"),
			interfaces,
			nil,
			nil,
			[]string{unstructuredSourceRef(u)},
			nil,
			nil,
			false,
			false,
			false,
			false,
			ingressCovered,
			egressCovered,
			gaps,
		)}
	case "NetworkPolicy", "GlobalNetworkPolicy":
		if u.GroupVersionKind().Group != "crd.projectcalico.org" {
			return nil
		}
		return []map[string]*llx.RawData{cniPolicyCoverageArgs(u, "calico")}
	case "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy":
		return []map[string]*llx.RawData{cniPolicyCoverageArgs(u, "cilium")}
	default:
		return nil
	}
}

func adminNetworkPolicyCoverageArgs(u *unstructured.Unstructured) map[string]*llx.RawData {
	spec := nestedMap(u.Object, "spec")
	ingressRules := nestedSlice(spec, "ingress")
	egressRules := nestedSlice(spec, "egress")
	ingressCovered := len(ingressRules) > 0
	egressCovered := len(egressRules) > 0
	defaultDenyIngress := adminNetworkPolicyHasCatchAllDenyAction(ingressRules, "from")
	defaultDenyEgress := adminNetworkPolicyHasCatchAllDenyAction(egressRules, "to")
	gaps := []string{}
	if !ingressCovered {
		gaps = append(gaps, "admin network policy ingress was not observed")
	} else if !defaultDenyIngress {
		gaps = append(gaps, "admin network policy ingress does not define catch-all deny traffic")
	}
	if !egressCovered {
		gaps = append(gaps, "admin network policy egress was not observed")
	} else if !defaultDenyEgress {
		gaps = append(gaps, "admin network policy egress does not define catch-all deny traffic")
	}

	return networkPolicyCoverageRawArgsWithSources(
		fmt.Sprintf("%s:%s", strings.ToLower(u.GetKind()), u.GetName()),
		u.GetNamespace(),
		unstructuredSourceRef(u),
		nestedMap(spec, "subject"),
		[]string{"primary"},
		nil,
		[]string{unstructuredSourceRef(u)},
		nil,
		nil,
		nil,
		defaultDenyIngress,
		defaultDenyEgress,
		defaultDenyIngress,
		defaultDenyEgress,
		false,
		false,
		gaps,
	)
}

func adminNetworkPolicyHasCatchAllDenyAction(rules []any, peerField string) bool {
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if len(nestedSlice(rule, "ports")) > 0 {
			continue
		}
		if !adminNetworkPolicyRuleHasCatchAllPeers(rule, peerField) {
			continue
		}
		switch {
		case strings.EqualFold(stringValue(rule["action"]), "Deny"):
			return true
		case strings.EqualFold(stringValue(rule["action"]), "Allow"),
			strings.EqualFold(stringValue(rule["action"]), "Pass"):
			return false
		}
	}
	return false
}

func adminNetworkPolicyRuleHasCatchAllPeers(rule map[string]any, peerField string) bool {
	peers := nestedSlice(rule, peerField)
	if len(peers) == 0 {
		return true
	}
	for _, peer := range peers {
		if adminNetworkPolicyPeerIsCatchAll(peer) {
			return true
		}
	}
	return false
}

func adminNetworkPolicyPeerIsCatchAll(peer any) bool {
	peerMap, ok := peer.(map[string]any)
	if !ok {
		return false
	}
	for _, field := range []string{"namespaces", "pods", "nodes"} {
		selector := nestedMap(peerMap, field)
		if selector == nil {
			continue
		}
		if len(selector) == 0 || selectorIsEmpty(selector) {
			return true
		}
	}
	for _, cidr := range stringSlice(peerMap["networks"]) {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return true
		}
	}
	return false
}

func cniPolicyCoverageArgs(u *unstructured.Unstructured, source string) map[string]*llx.RawData {
	spec := nestedMap(u.Object, "spec")
	ingressCovered := cniPolicyDirectionCovered(spec, source, "ingress")
	egressCovered := cniPolicyDirectionCovered(spec, source, "egress")
	defaultDenyIngress := cniPolicyDefaultDeny(spec, source, "ingress")
	defaultDenyEgress := cniPolicyDefaultDeny(spec, source, "egress")
	gaps := []string{}
	if !ingressCovered {
		gaps = append(gaps, source+" ingress policy was not observed")
	} else if !defaultDenyIngress {
		gaps = append(gaps, source+" ingress default-deny was not observed")
	}
	if !egressCovered {
		gaps = append(gaps, source+" egress policy was not observed")
	} else if !defaultDenyEgress {
		gaps = append(gaps, source+" egress default-deny was not observed")
	}
	calicoPolicies := []string{}
	ciliumPolicies := []string{}
	if source == "calico" {
		calicoPolicies = []string{unstructuredSourceRef(u)}
	} else {
		ciliumPolicies = []string{unstructuredSourceRef(u)}
	}
	return networkPolicyCoverageRawArgsWithSources(
		fmt.Sprintf("%s:%s:%s", strings.ToLower(u.GetKind()), u.GetNamespace(), u.GetName()),
		u.GetNamespace(),
		unstructuredSourceRef(u),
		selectorFromCniPolicy(spec),
		[]string{"primary"},
		nil,
		nil,
		nil,
		calicoPolicies,
		ciliumPolicies,
		defaultDenyIngress,
		defaultDenyEgress,
		false,
		false,
		false,
		false,
		gaps,
	)
}

func cniPolicyDirectionCovered(spec map[string]any, source, direction string) bool {
	if len(nestedSlice(spec, direction)) > 0 || len(nestedSlice(spec, direction+"Deny")) > 0 {
		return true
	}
	return source == "calico" && calicoPolicyTypesInclude(spec, direction)
}

func cniPolicyDefaultDeny(spec map[string]any, source, direction string) bool {
	if source == "cilium" {
		hasRules := len(nestedSlice(spec, direction)) > 0 || len(nestedSlice(spec, direction+"Deny")) > 0
		if !hasRules {
			return false
		}
		if enableDefaultDeny := nestedMap(spec, "enableDefaultDeny"); enableDefaultDeny != nil {
			if v, ok := enableDefaultDeny[direction].(bool); ok {
				if !v {
					return false
				}
			}
		}
		for _, item := range nestedSlice(spec, direction+"Deny") {
			rule, ok := item.(map[string]any)
			if ok && cniRuleIsCatchAllDeny(rule, source, direction) {
				return true
			}
		}
		for _, item := range nestedSlice(spec, direction) {
			rule, ok := item.(map[string]any)
			if ok && cniAllowRuleAllowsAll(rule, source, direction) {
				return false
			}
		}
		return len(nestedSlice(spec, direction)) > 0
	}
	if calicoPolicyTypesInclude(spec, direction) && len(nestedSlice(spec, direction)) == 0 {
		return true
	}
	for _, item := range nestedSlice(spec, direction) {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if !cniRuleIsCatchAllDeny(rule, source, direction) {
			continue
		}
		switch strings.ToLower(stringValue(rule["action"])) {
		case "deny":
			return true
		case "allow", "pass":
			return false
		}
	}
	return false
}

func calicoPolicyTypesInclude(spec map[string]any, direction string) bool {
	want := strings.ToLower(direction)
	for _, policyType := range stringSlice(spec["types"]) {
		if strings.ToLower(policyType) == want {
			return true
		}
	}
	return false
}

func cniRuleIsCatchAllDeny(rule map[string]any, source, direction string) bool {
	if len(rule) == 0 {
		return true
	}
	ignored := map[string]struct{}{"action": {}, "description": {}, "metadata": {}, "name": {}}
	for key, value := range rule {
		if _, ok := ignored[key]; ok {
			continue
		}
		if cniRuleFieldConstrainDeny(key, value, source, direction) {
			return false
		}
	}
	return true
}

func cniAllowRuleAllowsAll(rule map[string]any, source, direction string) bool {
	if len(rule) == 0 {
		return true
	}
	return cniRuleIsCatchAllDeny(rule, source, direction)
}

func cniRuleFieldConstrainDeny(key string, value any, source, direction string) bool {
	switch key {
	case "protocol", "notProtocol", "ipVersion", "icmp", "http", "ports", "notPorts", "source", "destination",
		"srcSelector", "dstSelector", "selector", "namespaceSelector", "serviceAccountSelector",
		"nets", "notNets", "toPorts", "fromPorts", "toEndpoints", "fromEndpoints", "toCIDR", "fromCIDR",
		"toCIDRSet", "fromCIDRSet", "toFQDNs", "toServices", "fromRequires", "toRequires":
		return !fieldIsEmpty(value)
	case "toEntities", "fromEntities":
		values := stringSlice(value)
		if len(values) == 0 {
			return false
		}
		for _, entity := range values {
			if entity == "all" || entity == "world" {
				continue
			}
			return true
		}
		return false
	default:
		return !fieldIsEmpty(value)
	}
}

func networkPolicyCoverageRawArgsWithSources(id, namespace, policyRef string, selector map[string]any, interfaces, nativePolicies, adminPolicies, multiPolicies, calicoPolicies, ciliumPolicies []string, defaultDenyIngress, defaultDenyEgress, adminDefaultDenyIngress, adminDefaultDenyEgress, secondaryIngress, secondaryEgress bool, gaps []string) map[string]*llx.RawData {
	args := networkPolicyCoverageRawArgs(id, namespace, policyRef, selector, nativePolicies, defaultDenyIngress, defaultDenyEgress, gaps)
	args["interfaces"] = stringArrayData(interfaces)
	args["adminNetworkPolicies"] = stringArrayData(adminPolicies)
	args["multiNetworkPolicies"] = stringArrayData(multiPolicies)
	args["calicoPolicies"] = stringArrayData(calicoPolicies)
	args["ciliumPolicies"] = stringArrayData(ciliumPolicies)
	args["adminDefaultDenyIngress"] = llx.BoolData(adminDefaultDenyIngress)
	args["adminDefaultDenyEgress"] = llx.BoolData(adminDefaultDenyEgress)
	args["secondaryInterfaceIngressCovered"] = llx.BoolData(secondaryIngress)
	args["secondaryInterfaceEgressCovered"] = llx.BoolData(secondaryEgress)
	return args
}

func primaryInterfaceCoverageArgsFromPods(pods []any, policyCoverage []map[string]*llx.RawData, namespaceLabels, serviceAccountLabels map[string]map[string]string) []map[string]*llx.RawData {
	out := []map[string]*llx.RawData{}
	for _, item := range pods {
		podResource, ok := item.(*mqlK8sPod)
		if !ok {
			continue
		}
		pod, err := podResource.getPod()
		if err != nil {
			continue
		}
		out = append(out, primaryInterfaceCoverageArgsForPodWithSelectorContext(pod, policyCoverage, namespaceLabels, serviceAccountLabels))
	}
	return out
}

func primaryInterfaceCoverageArgsForPod(pod *corev1.Pod, policyCoverage []map[string]*llx.RawData) map[string]*llx.RawData {
	return primaryInterfaceCoverageArgsForPodWithNamespaceLabels(pod, policyCoverage, nil)
}

func primaryInterfaceCoverageArgsForPodWithNamespaceLabels(pod *corev1.Pod, policyCoverage []map[string]*llx.RawData, namespaceLabels map[string]map[string]string) map[string]*llx.RawData {
	return primaryInterfaceCoverageArgsForPodWithSelectorContext(pod, policyCoverage, namespaceLabels, nil)
}

func primaryInterfaceCoverageArgsForPodWithSelectorContext(pod *corev1.Pod, policyCoverage []map[string]*llx.RawData, namespaceLabels, serviceAccountLabels map[string]map[string]string) map[string]*llx.RawData {
	if pod == nil {
		return nil
	}
	defaultDenyIngress := false
	defaultDenyEgress := false
	adminDefaultDenyIngress := false
	adminDefaultDenyEgress := false
	unsafeIngress := false
	unsafeEgress := false
	policyRefs := []string{}
	nativePolicies := []string{}
	adminPolicies := []string{}
	calicoPolicies := []string{}
	ciliumPolicies := []string{}
	for _, policy := range policyCoverage {
		if !primaryPolicyCoversPodWithServiceAccount(policy, pod, namespaceLabels[pod.Namespace], serviceAccountLabels[podServiceAccountKey(pod)]) {
			continue
		}
		// policyRef is itself a comma-joined list, so it has to be split before
		// dedup: sortedUniqueStrings compares whole strings, and "a,b" and "b"
		// are distinct to it even though b is already covered.
		policyRefs = append(policyRefs, splitPolicyRefs(rawStringData(policy, "policyRef"))...)
		nativePolicies = append(nativePolicies, rawStringArrayData(policy, "nativeNetworkPolicies")...)
		adminPolicies = append(adminPolicies, rawStringArrayData(policy, "adminNetworkPolicies")...)
		calicoPolicies = append(calicoPolicies, rawStringArrayData(policy, "calicoPolicies")...)
		ciliumPolicies = append(ciliumPolicies, rawStringArrayData(policy, "ciliumPolicies")...)
		defaultDenyIngress = defaultDenyIngress || rawBoolData(policy, "defaultDenyIngress")
		defaultDenyEgress = defaultDenyEgress || rawBoolData(policy, "defaultDenyEgress")
		adminDefaultDenyIngress = adminDefaultDenyIngress || rawBoolData(policy, "adminDefaultDenyIngress")
		adminDefaultDenyEgress = adminDefaultDenyEgress || rawBoolData(policy, "adminDefaultDenyEgress")
		unsafeIngress = unsafeIngress || coverageGapMarksDirectionUnsafe(policy, "primary", "ingress")
		unsafeEgress = unsafeEgress || coverageGapMarksDirectionUnsafe(policy, "primary", "egress")
	}
	if unsafeIngress {
		defaultDenyIngress = false
	}
	if unsafeEgress {
		defaultDenyEgress = false
	}

	gaps := []string{}
	// NetworkPolicy is enforced on the pod network namespace, so it does not
	// apply to a host-network pod whatever selector matched it. Reporting such
	// a pod as default-denied contradicts k8s.pod.escapesNetworkPolicy and
	// hides the gap that matters most.
	if pod.Spec.HostNetwork {
		defaultDenyIngress = false
		defaultDenyEgress = false
		gaps = append(gaps, "pod "+pod.Namespace+"/"+pod.Name+" uses host networking, which NetworkPolicy does not cover")
	}
	if !defaultDenyIngress {
		gaps = append(gaps, "primary ingress is not default-deny for pod "+pod.Namespace+"/"+pod.Name)
	}
	if !defaultDenyEgress {
		gaps = append(gaps, "primary egress is not default-deny for pod "+pod.Namespace+"/"+pod.Name)
	}
	args := networkPolicyCoverageRawArgsWithSources(
		fmt.Sprintf("primary-interface:%s:%s", pod.Namespace, pod.Name),
		pod.Namespace,
		strings.Join(sortedUniqueStrings(policyRefs), ","),
		podLabelSelectorArgs(pod.Labels),
		[]string{"primary"},
		sortedUniqueStrings(nativePolicies),
		sortedUniqueStrings(adminPolicies),
		nil,
		sortedUniqueStrings(calicoPolicies),
		sortedUniqueStrings(ciliumPolicies),
		defaultDenyIngress,
		defaultDenyEgress,
		adminDefaultDenyIngress,
		adminDefaultDenyEgress,
		false,
		false,
		gaps,
	)
	args["workloadRef"] = llx.StringData(networkSourceRef("Pod", pod.Namespace, pod.Name))
	return args
}

func primaryPolicyCoversPod(policy map[string]*llx.RawData, pod *corev1.Pod, namespaceLabels map[string]string) bool {
	return primaryPolicyCoversPodWithServiceAccount(policy, pod, namespaceLabels, nil)
}

func primaryPolicyCoversPodWithServiceAccount(policy map[string]*llx.RawData, pod *corev1.Pod, namespaceLabels, serviceAccountLabels map[string]string) bool {
	if pod == nil {
		return false
	}
	namespace := rawStringData(policy, "namespace")
	if namespace != "" && namespace != pod.Namespace {
		return false
	}
	if !contains(rawStringArrayData(policy, "interfaces"), "primary") {
		return false
	}
	return selectorOrSubjectMatchesPod(rawMapData(policy, "podSelector"), pod, namespaceLabels, serviceAccountLabels)
}

const (
	multusNetworksAnnotation      = "k8s.v1.cni.cncf.io/networks"
	multusNetworkStatusAnnotation = "k8s.v1.cni.cncf.io/network-status"
)

type secondaryInterfaceAttachment struct {
	network       string
	name          string
	interfaceName string
}

func secondaryInterfaceCoverageArgsFromPods(pods []any, policyCoverage []map[string]*llx.RawData) []map[string]*llx.RawData {
	out := []map[string]*llx.RawData{}
	for _, item := range pods {
		podResource, ok := item.(*mqlK8sPod)
		if !ok {
			continue
		}
		pod, err := podResource.getPod()
		if err != nil {
			continue
		}
		out = append(out, secondaryInterfaceCoverageArgsForPod(pod, policyCoverage)...)
	}
	return out
}

func secondaryInterfaceCoverageArgsForPod(pod *corev1.Pod, policyCoverage []map[string]*llx.RawData) []map[string]*llx.RawData {
	if pod == nil {
		return nil
	}
	attachments := secondaryInterfaceAttachments(pod)
	out := make([]map[string]*llx.RawData, 0, len(attachments))
	for _, attachment := range attachments {
		ingressCovered := false
		egressCovered := false
		unsafeIngress := false
		unsafeEgress := false
		policyRefs := []string{}
		multiPolicies := []string{}
		calicoPolicies := []string{}
		ciliumPolicies := []string{}
		for _, policy := range policyCoverage {
			if !secondaryPolicyCoversAttachment(policy, pod, attachment) {
				continue
			}
			policyRefs = append(policyRefs, splitPolicyRefs(rawStringData(policy, "policyRef"))...)
			multiPolicies = append(multiPolicies, rawStringArrayData(policy, "multiNetworkPolicies")...)
			calicoPolicies = append(calicoPolicies, rawStringArrayData(policy, "calicoPolicies")...)
			ciliumPolicies = append(ciliumPolicies, rawStringArrayData(policy, "ciliumPolicies")...)
			ingressCovered = ingressCovered || rawBoolData(policy, "secondaryInterfaceIngressCovered")
			egressCovered = egressCovered || rawBoolData(policy, "secondaryInterfaceEgressCovered")
			unsafeIngress = unsafeIngress || coverageGapMarksDirectionUnsafe(policy, "secondary", "ingress")
			unsafeEgress = unsafeEgress || coverageGapMarksDirectionUnsafe(policy, "secondary", "egress")
		}
		if unsafeIngress {
			ingressCovered = false
		}
		if unsafeEgress {
			egressCovered = false
		}

		gaps := []string{}
		if !ingressCovered {
			gaps = append(gaps, "secondary ingress is not covered for network attachment "+attachment.network)
		}
		if !egressCovered {
			gaps = append(gaps, "secondary egress is not covered for network attachment "+attachment.network)
		}
		interfaces := []string{"secondary", attachment.network, attachment.name, attachment.interfaceName}
		args := networkPolicyCoverageRawArgsWithSources(
			fmt.Sprintf("secondary-interface:%s:%s:%s", pod.Namespace, pod.Name, shortHashString(attachment.network+"\x00"+attachment.interfaceName)),
			pod.Namespace,
			strings.Join(sortedUniqueStrings(policyRefs), ","),
			podLabelSelectorArgs(pod.Labels),
			interfaces,
			nil,
			nil,
			sortedUniqueStrings(multiPolicies),
			sortedUniqueStrings(calicoPolicies),
			sortedUniqueStrings(ciliumPolicies),
			false,
			false,
			false,
			false,
			ingressCovered,
			egressCovered,
			gaps,
		)
		args["workloadRef"] = llx.StringData(networkSourceRef("Pod", pod.Namespace, pod.Name))
		out = append(out, args)
	}
	return out
}

func secondaryPolicyCoversAttachment(policy map[string]*llx.RawData, pod *corev1.Pod, attachment secondaryInterfaceAttachment) bool {
	if pod == nil {
		return false
	}
	namespace := rawStringData(policy, "namespace")
	if namespace != "" && namespace != pod.Namespace {
		return false
	}
	interfaces := rawStringArrayData(policy, "interfaces")
	if !contains(interfaces, "secondary") {
		return false
	}
	if !secondaryPolicyInterfacesMatchAttachment(interfaces, attachment) {
		return false
	}
	return selectorMatchesPodLabels(rawMapData(policy, "podSelector"), pod.Labels)
}

func secondaryPolicyInterfacesMatchAttachment(interfaces []string, attachment secondaryInterfaceAttachment) bool {
	specificInterfaces := []string{}
	for _, item := range interfaces {
		if item == "secondary" {
			continue
		}
		specificInterfaces = append(specificInterfaces, item)
	}
	if len(specificInterfaces) == 0 {
		return true
	}
	for _, item := range specificInterfaces {
		if secondaryInterfaceTokenMatchesAttachment(item, attachment) {
			return true
		}
	}
	return false
}

func secondaryInterfaceTokenMatchesAttachment(token string, attachment secondaryInterfaceAttachment) bool {
	token = strings.TrimSpace(token)
	if token == "" {
		return false
	}
	if strings.Contains(token, "/") {
		return token == attachment.network
	}
	switch token {
	case attachment.name, attachment.interfaceName:
		return true
	default:
		return false
	}
}

func selectorMatchesPodLabels(selector map[string]any, podLabels map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	if !selectorHasLabelSelectorFields(selector) {
		return false
	}
	if selectorIsEmpty(selector) {
		return true
	}
	raw, err := json.Marshal(selector)
	if err != nil {
		return false
	}
	labelSelector := metav1.LabelSelector{}
	if err := json.Unmarshal(raw, &labelSelector); err != nil {
		return false
	}
	compiled, err := metav1.LabelSelectorAsSelector(&labelSelector)
	if err != nil {
		return false
	}
	return compiled.Matches(labels.Set(podLabels))
}

func selectorOrSubjectMatchesPod(selector map[string]any, pod *corev1.Pod, namespaceLabels, serviceAccountLabels map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	if pod == nil {
		return false
	}
	if adminNetworkPolicySubjectLooksLikeSelector(selector) {
		return adminNetworkPolicySubjectMatchesPod(selector, pod.Labels, namespaceLabels)
	}
	if cniPolicySelectorLooksLikeSelector(selector) {
		return cniPolicySelectorMatchesPod(selector, pod, namespaceLabels, serviceAccountLabels)
	}
	return selectorMatchesPodLabels(selector, pod.Labels)
}

func adminNetworkPolicySubjectLooksLikeSelector(subject map[string]any) bool {
	for _, field := range []string{"namespaces", "pods"} {
		if _, ok := subject[field]; ok {
			return true
		}
	}
	return false
}

func cniPolicySelectorLooksLikeSelector(selector map[string]any) bool {
	for _, field := range []string{"selector", "namespaceSelector", "serviceAccountSelector"} {
		if _, ok := selector[field]; ok {
			return true
		}
	}
	return false
}

func cniPolicySelectorMatchesPod(selector map[string]any, pod *corev1.Pod, namespaceLabels, serviceAccountLabels map[string]string) bool {
	podSelector := stringValue(selector["selector"])
	if podSelector != "" && !calicoSelectorMatchesLabels(podSelector, labelsWithNamespace(pod.Labels, pod.Namespace)) {
		return false
	}
	namespaceSelector := stringValue(selector["namespaceSelector"])
	if namespaceSelector != "" && !calicoSelectorMatchesLabels(namespaceSelector, labelsWithNamespace(namespaceLabels, pod.Namespace)) {
		return false
	}
	serviceAccountSelector := stringValue(selector["serviceAccountSelector"])
	if serviceAccountSelector != "" && !calicoSelectorMatchesLabels(serviceAccountSelector, serviceAccountLabels) {
		return false
	}
	return true
}

func serviceAccountLabelsByPodKey(items []any) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, item := range items {
		serviceAccount, ok := item.(*mqlK8sServiceaccount)
		if !ok || serviceAccount.obj == nil {
			continue
		}
		out[namespacedNameKey(serviceAccount.obj.Namespace, serviceAccount.obj.Name)] = serviceAccount.obj.Labels
	}
	return out
}

func podServiceAccountKey(pod *corev1.Pod) string {
	if pod == nil {
		return ""
	}
	name := pod.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	return namespacedNameKey(pod.Namespace, name)
}

func namespacedNameKey(namespace, name string) string {
	return namespace + "/" + name
}

func labelsWithNamespace(in map[string]string, namespace string) map[string]string {
	out := make(map[string]string, len(in)+1)
	for key, value := range in {
		out[key] = value
	}
	if namespace != "" {
		out["projectcalico.org/namespace"] = namespace
	}
	return out
}

func calicoSelectorMatchesLabels(selector string, values map[string]string) bool {
	return evalCalicoSelector(strings.TrimSpace(selector), values)
}

func evalCalicoSelector(expr string, values map[string]string) bool {
	expr = trimCalicoSelectorParens(strings.TrimSpace(expr))
	if expr == "" || expr == "all()" {
		return true
	}
	if expr == "global()" {
		return false
	}
	if parts := splitCalicoSelector(expr, "||"); len(parts) > 1 {
		for _, part := range parts {
			if evalCalicoSelector(part, values) {
				return true
			}
		}
		return false
	}
	if parts := splitCalicoSelector(expr, "&&"); len(parts) > 1 {
		for _, part := range parts {
			if !evalCalicoSelector(part, values) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(expr, "!") && !strings.HasPrefix(expr, "!=") {
		return !evalCalicoSelector(strings.TrimSpace(strings.TrimPrefix(expr, "!")), values)
	}
	return evalCalicoSelectorTerm(expr, values)
}

func evalCalicoSelectorTerm(expr string, values map[string]string) bool {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "has(") && strings.HasSuffix(expr, ")") {
		key := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "has("), ")"))
		_, ok := values[key]
		return ok
	}
	if strings.HasPrefix(expr, "!has(") && strings.HasSuffix(expr, ")") {
		key := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(expr, "!has("), ")"))
		_, ok := values[key]
		return !ok
	}
	if key, rawValues, ok := splitCalicoSetExpression(expr, " not in "); ok {
		return !contains(parseCalicoSetValues(rawValues), values[strings.TrimSpace(key)])
	}
	if key, rawValues, ok := splitCalicoSetExpression(expr, " in "); ok {
		return contains(parseCalicoSetValues(rawValues), values[strings.TrimSpace(key)])
	}
	if key, rawValue, ok := splitCalicoComparison(expr, "!="); ok {
		return values[strings.TrimSpace(key)] != trimCalicoSelectorValue(rawValue)
	}
	if key, rawValue, ok := splitCalicoComparison(expr, "=="); ok {
		return values[strings.TrimSpace(key)] == trimCalicoSelectorValue(rawValue)
	}
	return false
}

func splitCalicoComparison(expr, op string) (string, string, bool) {
	idx := strings.Index(expr, op)
	if idx < 0 {
		return "", "", false
	}
	return expr[:idx], expr[idx+len(op):], true
}

func splitCalicoSetExpression(expr, op string) (string, string, bool) {
	idx := strings.Index(expr, op)
	if idx < 0 {
		return "", "", false
	}
	return expr[:idx], expr[idx+len(op):], true
}

func parseCalicoSetValues(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "{")
	raw = strings.TrimSuffix(raw, "}")
	parts := splitCalicoSelector(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := trimCalicoSelectorValue(part)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func trimCalicoSelectorValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `'"`)
	return value
}

func trimCalicoSelectorParens(expr string) string {
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") && calicoSelectorOuterParensWrap(expr) {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}
	return expr
}

func calicoSelectorOuterParensWrap(expr string) bool {
	depth := 0
	inSingleQuote := false
	inDoubleQuote := false
	for i, r := range expr {
		switch r {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '(':
			if !inSingleQuote && !inDoubleQuote {
				depth++
			}
		case ')':
			if !inSingleQuote && !inDoubleQuote {
				depth--
				if depth == 0 && i != len(expr)-1 {
					return false
				}
			}
		}
	}
	return depth == 0
}

func splitCalicoSelector(expr, sep string) []string {
	parts := []string{}
	start := 0
	parenDepth := 0
	braceDepth := 0
	inSingleQuote := false
	inDoubleQuote := false
	for i := 0; i <= len(expr)-len(sep); i++ {
		switch expr[i] {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '(':
			if !inSingleQuote && !inDoubleQuote {
				parenDepth++
			}
		case ')':
			if !inSingleQuote && !inDoubleQuote && parenDepth > 0 {
				parenDepth--
			}
		case '{':
			if !inSingleQuote && !inDoubleQuote {
				braceDepth++
			}
		case '}':
			if !inSingleQuote && !inDoubleQuote && braceDepth > 0 {
				braceDepth--
			}
		}
		if inSingleQuote || inDoubleQuote || parenDepth != 0 || braceDepth != 0 {
			continue
		}
		if strings.HasPrefix(expr[i:], sep) {
			parts = append(parts, strings.TrimSpace(expr[start:i]))
			start = i + len(sep)
			i = start - 1
		}
	}
	if len(parts) == 0 {
		return []string{expr}
	}
	parts = append(parts, strings.TrimSpace(expr[start:]))
	return parts
}

func adminNetworkPolicySubjectMatchesPod(subject map[string]any, podLabels, namespaceLabels map[string]string) bool {
	if namespaceSelector := nestedMap(subject, "namespaces"); namespaceSelector != nil {
		if !selectorMatchesPodLabels(namespaceSelector, namespaceLabels) {
			return false
		}
	}
	if podSelector := nestedMap(subject, "pods"); podSelector != nil {
		return selectorMatchesPodLabels(podSelector, podLabels)
	}
	return true
}

func selectorHasLabelSelectorFields(selector map[string]any) bool {
	_, hasMatchLabels := selector["matchLabels"]
	_, hasMatchExpressions := selector["matchExpressions"]
	return hasMatchLabels || hasMatchExpressions
}

func coverageGapMarksDirectionUnsafe(policy map[string]*llx.RawData, scope, direction string) bool {
	for _, item := range rawStringArrayData(policy, "coverageGaps") {
		gap := strings.ToLower(item)
		if strings.Contains(gap, scope+" "+direction+" allows all traffic") {
			return true
		}
		if strings.Contains(gap, direction+" does not define catch-all deny traffic") {
			return true
		}
	}
	return false
}

func podLabelSelectorArgs(podLabels map[string]string) map[string]any {
	if len(podLabels) == 0 {
		return map[string]any{}
	}
	matchLabels := map[string]any{}
	for key, value := range podLabels {
		matchLabels[key] = value
	}
	return map[string]any{"matchLabels": matchLabels}
}

func secondaryInterfaceAttachments(pod *corev1.Pod) []secondaryInterfaceAttachment {
	if pod == nil {
		return nil
	}
	annotations := pod.GetAnnotations()
	attachments := []secondaryInterfaceAttachment{}
	attachments = append(attachments, parseNetworkSelectionAnnotation(annotations[multusNetworksAnnotation], pod.Namespace)...)
	attachments = append(attachments, parseNetworkStatusAnnotation(annotations[multusNetworkStatusAnnotation], pod.Namespace)...)
	return sortedUniqueSecondaryAttachments(attachments)
}

func parseNetworkSelectionAnnotation(value, defaultNamespace string) []secondaryInterfaceAttachment {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "[") || strings.HasPrefix(value, "{") {
		if attachments := parseNetworkSelectionJSON(value, defaultNamespace); len(attachments) > 0 {
			return attachments
		}
	}
	out := []secondaryInterfaceAttachment{}
	for _, item := range strings.Split(value, ",") {
		if attachment, ok := newSecondaryInterfaceAttachment(item, "", "", defaultNamespace); ok {
			out = append(out, attachment)
		}
	}
	return out
}

func parseNetworkSelectionJSON(value, defaultNamespace string) []secondaryInterfaceAttachment {
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(value), &items); err != nil {
		item := map[string]any{}
		if err := json.Unmarshal([]byte(value), &item); err != nil {
			return nil
		}
		items = append(items, item)
	}
	out := []secondaryInterfaceAttachment{}
	for _, item := range items {
		name := firstNonEmptyString(item, "name", "network", "networkName")
		namespace := firstNonEmptyString(item, "namespace")
		interfaceName := firstNonEmptyString(item, "interface", "interfaceName")
		if attachment, ok := newSecondaryInterfaceAttachment(name, namespace, interfaceName, defaultNamespace); ok {
			out = append(out, attachment)
		}
	}
	return out
}

func parseNetworkStatusAnnotation(value, defaultNamespace string) []secondaryInterfaceAttachment {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	items := []map[string]any{}
	if err := json.Unmarshal([]byte(value), &items); err != nil {
		return nil
	}
	out := []secondaryInterfaceAttachment{}
	for _, item := range items {
		if boolValue(item["default"]) {
			continue
		}
		name := firstNonEmptyString(item, "name", "network", "networkName")
		interfaceName := firstNonEmptyString(item, "interface", "interfaceName")
		if attachment, ok := newSecondaryInterfaceAttachment(name, "", interfaceName, defaultNamespace); ok {
			out = append(out, attachment)
		}
	}
	return out
}

func newSecondaryInterfaceAttachment(networkName, networkNamespace, interfaceName, defaultNamespace string) (secondaryInterfaceAttachment, bool) {
	networkName = strings.TrimSpace(networkName)
	networkNamespace = strings.TrimSpace(networkNamespace)
	interfaceName = strings.TrimSpace(interfaceName)
	if before, after, found := strings.Cut(networkName, "@"); found {
		networkName = strings.TrimSpace(before)
		if interfaceName == "" {
			interfaceName = strings.TrimSpace(after)
		}
	}
	if networkName == "" {
		return secondaryInterfaceAttachment{}, false
	}
	if strings.Contains(networkName, "/") {
		parts := strings.SplitN(networkName, "/", 2)
		networkNamespace = strings.TrimSpace(parts[0])
		networkName = strings.TrimSpace(parts[1])
	}
	if networkNamespace == "" {
		networkNamespace = defaultNamespace
	}
	network := networkName
	if networkNamespace != "" {
		network = networkNamespace + "/" + networkName
	}
	return secondaryInterfaceAttachment{
		network:       network,
		name:          networkName,
		interfaceName: interfaceName,
	}, true
}

func sortedUniqueSecondaryAttachments(in []secondaryInterfaceAttachment) []secondaryInterfaceAttachment {
	seen := map[string]secondaryInterfaceAttachment{}
	hasNamedInterface := map[string]bool{}
	for _, attachment := range in {
		if attachment.network != "" && attachment.interfaceName != "" {
			hasNamedInterface[attachment.network] = true
		}
	}
	keys := []string{}
	for _, attachment := range in {
		if attachment.network == "" {
			continue
		}
		if attachment.interfaceName == "" && hasNamedInterface[attachment.network] {
			continue
		}
		key := attachment.network + "\x00" + attachment.interfaceName
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = attachment
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]secondaryInterfaceAttachment, 0, len(keys))
	for _, key := range keys {
		out = append(out, seen[key])
	}
	return out
}

func firstNonEmptyString(in map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(in[key]); value != "" {
			return value
		}
	}
	return ""
}

func rawStringData(args map[string]*llx.RawData, key string) string {
	if args == nil || args[key] == nil {
		return ""
	}
	return stringValue(args[key].Value)
}

func rawStringArrayData(args map[string]*llx.RawData, key string) []string {
	if args == nil || args[key] == nil {
		return nil
	}
	return stringSlice(args[key].Value)
}

func rawBoolData(args map[string]*llx.RawData, key string) bool {
	if args == nil || args[key] == nil {
		return false
	}
	if value, ok := args[key].Value.(bool); ok {
		return value
	}
	return false
}

func rawMapData(args map[string]*llx.RawData, key string) map[string]any {
	if args == nil || args[key] == nil {
		return nil
	}
	if value, ok := args[key].Value.(map[string]any); ok {
		return value
	}
	return nil
}

func namespaceLabelsByName(items []any) map[string]map[string]string {
	out := map[string]map[string]string{}
	for _, item := range items {
		ns, ok := item.(*mqlK8sNamespace)
		if !ok || ns.obj == nil {
			continue
		}
		out[ns.obj.GetName()] = ns.obj.GetLabels()
	}
	return out
}

type networkExposureInput struct {
	id                     string
	sourceKind             string
	sourceRef              string
	namespace              string
	name                   string
	addresses              []string
	ports                  []any
	protocols              []string
	internetExposed        bool
	exposureReason         string
	networkClassifications []string
	metadataClassification string
	owner                  string
	vrf                    string
	network                string
	routes                 []string
	policyCoverage         []string
	confidence             string
}

func networkExposureArgs(in networkExposureInput) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData(in.id),
		"sourceKind":             llx.StringData(in.sourceKind),
		"sourceRef":              llx.StringData(in.sourceRef),
		"namespace":              llx.StringData(in.namespace),
		"name":                   llx.StringData(in.name),
		"addresses":              stringArrayData(in.addresses),
		"ports":                  llx.ArrayData(in.ports, types.Dict),
		"protocols":              stringArrayData(in.protocols),
		"internetExposed":        llx.BoolData(in.internetExposed),
		"exposureReason":         llx.StringData(in.exposureReason),
		"networkClassifications": stringArrayData(in.networkClassifications),
		"metadataClassification": llx.StringData(in.metadataClassification),
		"owner":                  llx.StringData(in.owner),
		"vrf":                    llx.StringData(in.vrf),
		"network":                llx.StringData(in.network),
		"routes":                 stringArrayData(in.routes),
		"policyCoverage":         stringArrayData(in.policyCoverage),
		"confidence":             llx.StringData(in.confidence),
	}
}

func egressRouteArgs(in egressRouteInput) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData(in.id),
		"sourceRef":              llx.StringData(in.sourceRef),
		"vrf":                    llx.StringData(in.vrf),
		"network":                llx.StringData(in.network),
		"destinations":           stringArrayData(in.destinations),
		"cidrs":                  stringArrayData(in.cidrs),
		"publicCidrs":            stringArrayData(in.publicCidrs),
		"nat":                    llx.BoolData(in.nat),
		"nodeStatuses":           stringArrayData(in.nodeStatuses),
		"bgpPeerings":            stringArrayData(in.bgpPeerings),
		"classification":         llx.StringData(in.classification),
		"metadataClassification": llx.StringData(in.metadataClassification),
		"owner":                  llx.StringData(in.owner),
		"confidence":             llx.StringData(in.confidence),
	}
}

func egressNatArgs(in egressNatInput) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                   llx.StringData(in.id),
		"sourceRef":              llx.StringData(in.sourceRef),
		"vrf":                    llx.StringData(in.vrf),
		"network":                llx.StringData(in.network),
		"addresses":              stringArrayData(in.addresses),
		"cidrs":                  stringArrayData(in.cidrs),
		"publicCidrs":            stringArrayData(in.publicCidrs),
		"nodeStatuses":           stringArrayData(in.nodeStatuses),
		"classification":         llx.StringData(in.classification),
		"metadataClassification": llx.StringData(in.metadataClassification),
		"owner":                  llx.StringData(in.owner),
	}
}

func networkExposureInputWithMetadata(obj metav1.Object, in networkExposureInput) networkExposureInput {
	if obj == nil {
		return in
	}
	in.metadataClassification = metadataValue(obj.GetAnnotations(), obj.GetLabels(), "network.mondoo.com/classification", "mondoo.com/classification")
	in.owner = metadataValue(obj.GetAnnotations(), obj.GetLabels(), "mondoo.com/owner", "network.mondoo.com/owner")
	return in
}

func networkExposureInputWithObjectMetadata(u *unstructured.Unstructured, in networkExposureInput) networkExposureInput {
	if u == nil {
		return in
	}
	in.metadataClassification = objectMetadataValue(u, "network.mondoo.com/classification", "mondoo.com/classification")
	in.owner = objectMetadataValue(u, "mondoo.com/owner", "network.mondoo.com/owner")
	return in
}

func newEgressRouteInput(in egressRouteInput, settings networkInventorySettings) egressRouteInput {
	in.cidrs = sortedUniqueStrings(in.cidrs)
	in.destinations = sortedUniqueStrings(append(in.destinations, in.cidrs...))
	in.publicCidrs = publicCIDRs(in.cidrs, settings)
	if in.classification == "" {
		in.classification = egressClassification(in.cidrs, settings)
	}
	if in.confidence == "" {
		in.confidence = "medium"
	}
	return in
}

func newEgressNatInput(in egressNatInput, settings networkInventorySettings) egressNatInput {
	in.cidrs = sortedUniqueStrings(in.cidrs)
	in.addresses = sortedUniqueStrings(in.addresses)
	in.publicCidrs = publicCIDRs(in.cidrs, settings)
	if in.classification == "" {
		in.classification = egressClassification(in.cidrs, settings)
	}
	return in
}

func egressRouteInputWithObjectMetadata(u *unstructured.Unstructured, in egressRouteInput) egressRouteInput {
	in.metadataClassification = objectMetadataValue(u, "network.mondoo.com/classification", "mondoo.com/classification")
	in.owner = objectMetadataValue(u, "mondoo.com/owner", "network.mondoo.com/owner")
	return in
}

func egressNatInputWithObjectMetadata(u *unstructured.Unstructured, in egressNatInput) egressNatInput {
	in.metadataClassification = objectMetadataValue(u, "network.mondoo.com/classification", "mondoo.com/classification")
	in.owner = objectMetadataValue(u, "mondoo.com/owner", "network.mondoo.com/owner")
	return in
}

func objectMetadataValue(u *unstructured.Unstructured, keys ...string) string {
	if u == nil {
		return ""
	}
	return metadataValue(u.GetAnnotations(), u.GetLabels(), keys...)
}

func metadataValue(annotations map[string]string, labels map[string]string, keys ...string) string {
	for _, source := range []map[string]string{annotations, labels} {
		for _, key := range keys {
			if value := strings.TrimSpace(source[key]); value != "" {
				return value
			}
		}
	}
	return ""
}

func createNetworkExposures(runtime *plugin.Runtime, args []map[string]*llx.RawData) ([]any, error) {
	out := make([]any, 0, len(args))
	for _, item := range args {
		exposure, err := CreateResource(runtime, "k8s.networkExposure", item)
		if err != nil {
			return nil, err
		}
		out = append(out, exposure)
	}
	return out, nil
}

func serviceExposureAddresses(svc *corev1.Service) []string {
	addresses := []string{}
	for _, ingress := range svc.Status.LoadBalancer.Ingress {
		addresses = append(addresses, ingress.IP, ingress.Hostname)
	}
	addresses = append(addresses, svc.Spec.ExternalIPs...)
	if svc.Spec.LoadBalancerIP != "" {
		addresses = append(addresses, svc.Spec.LoadBalancerIP)
	}
	return sortedUniqueStrings(addresses)
}

func ingressExposureAddresses(ing *networkingv1.Ingress) []string {
	return sortedUniqueStrings(append(ingressStatusAddresses(ing), ingressSpecHostnames(ing)...))
}

func gatewayExposureAddresses(gw *gatewayv1.Gateway) []string {
	addresses := []string{}
	for _, address := range gw.Status.Addresses {
		addresses = append(addresses, string(address.Value))
	}
	for _, address := range gw.Spec.Addresses {
		addresses = append(addresses, string(address.Value))
	}
	return sortedUniqueStrings(addresses)
}

func ingressStatusAddresses(ing *networkingv1.Ingress) []string {
	addresses := []string{}
	for _, ingress := range ing.Status.LoadBalancer.Ingress {
		addresses = append(addresses, ingress.IP, ingress.Hostname)
	}
	return sortedUniqueStrings(addresses)
}

func ingressSpecHostnames(ing *networkingv1.Ingress) []string {
	hostnames := []string{}
	for _, rule := range ing.Spec.Rules {
		hostnames = append(hostnames, rule.Host)
	}
	for _, tls := range ing.Spec.TLS {
		hostnames = append(hostnames, tls.Hosts...)
	}
	return sortedUniqueStrings(hostnames)
}

func gatewayRouteProtocols(kind string) []string {
	switch kind {
	case "HTTPRoute":
		return []string{"HTTP"}
	case "GRPCRoute":
		return []string{"GRPC"}
	case "TLSRoute":
		return []string{"TLS"}
	case "TCPRoute":
		return []string{"TCP"}
	case "UDPRoute":
		return []string{"UDP"}
	default:
		return nil
	}
}

func gatewayRouteParentRefs(routeNamespace string, refs []any) []string {
	out := []string{}
	for _, item := range refs {
		ref, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if refString := gatewayRouteParentRefString(routeNamespace, ref); refString != "" {
			out = append(out, refString)
		}
	}
	return sortedUniqueStrings(out)
}

func gatewayRouteParentRefString(routeNamespace string, ref map[string]any) string {
	name := stringValue(ref["name"])
	if name == "" {
		return ""
	}
	kind := stringValue(ref["kind"])
	if kind == "" {
		kind = "Gateway"
	}
	namespace := stringValue(ref["namespace"])
	if namespace == "" {
		namespace = routeNamespace
	}
	refString := networkSourceRef(kind, namespace, name)
	if sectionName := stringValue(ref["sectionName"]); sectionName != "" {
		refString += "#section/" + sectionName
	}
	if port, ok := int64Value(ref["port"]); ok {
		refString += fmt.Sprintf("#port/%d", port)
	}
	return refString
}

func gatewayRouteParentAddresses(parentRefs []string, gatewayContexts map[string]networkExposureContext) []string {
	out := []string{}
	for _, ref := range parentRefs {
		baseRef := strings.Split(ref, "#")[0]
		ctx, ok := gatewayContexts[baseRef]
		if !ok {
			continue
		}
		out = append(out, ctx.addresses...)
	}
	return sortedUniqueStrings(out)
}

func gatewayRouteExposureReason(routeHostnames, parentRefs []string, gatewayContexts map[string]networkExposureContext, classifications []string, internetExposed bool) string {
	if internetExposed {
		if len(routeHostnames) > 0 {
			return "gatewayRoutePublicHostname"
		}
		return "gatewayRoutePublicParent"
	}
	for _, ref := range parentRefs {
		baseRef := strings.Split(ref, "#")[0]
		if ctx, ok := gatewayContexts[baseRef]; ok && len(ctx.addresses) > 0 {
			return "gatewayRoutePrivateParent"
		}
	}
	if len(routeHostnames) > 0 {
		if contains(classifications, "internet") || contains(classifications, "hostname") {
			return "gatewayRoutePrivateParent"
		}
		return "gatewayRouteInternalHostname"
	}
	return "gatewayRouteNoHostname"
}

func gatewayRouteParentExposure(parentRefs []string, gatewayContexts map[string]networkExposureContext) (bool, bool) {
	observed := false
	internetExposed := false
	for _, ref := range parentRefs {
		baseRef := strings.Split(ref, "#")[0]
		ctx, ok := gatewayContexts[baseRef]
		if !ok {
			continue
		}
		observed = true
		internetExposed = internetExposed || ctx.internetExposed || contains(ctx.classifications, "internet")
	}
	return observed, internetExposed
}

func gatewayRoutePortDicts(spec map[string]any) []any {
	out := []any{}
	for _, item := range nestedSlice(spec, "parentRefs") {
		ref, ok := item.(map[string]any)
		if !ok {
			continue
		}
		port, ok := int64Value(ref["port"])
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"port":     port,
			"protocol": "Gateway",
			"source":   "parentRef",
		})
	}
	for _, item := range nestedSlice(spec, "rules") {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, backendRef := range nestedSlice(rule, "backendRefs") {
			ref, ok := backendRef.(map[string]any)
			if !ok {
				continue
			}
			port, ok := int64Value(ref["port"])
			if !ok {
				continue
			}
			out = append(out, map[string]any{
				"port":     port,
				"protocol": "Service",
				"source":   "backendRef",
			})
		}
	}
	return out
}

func gatewayRouteAccepted(u *unstructured.Unstructured) (bool, bool) {
	parents := gatewayRouteParentRefs(u.GetNamespace(), nestedSlice(nestedMap(u.Object, "spec"), "parentRefs"))
	accepted, observed := gatewayRouteAcceptedParentRefs(u, parents)
	return len(accepted) > 0, observed
}

func gatewayRouteAcceptedParentRefs(u *unstructured.Unstructured, specParentRefs []string) (map[string]struct{}, bool) {
	status := nestedMap(u.Object, "status")
	parents := nestedSlice(status, "parents")
	if len(parents) == 0 {
		return nil, false
	}

	specRefs := stringSet(specParentRefs)
	observed := false
	accepted := map[string]struct{}{}
	for _, item := range parents {
		parent, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ref := gatewayRouteParentRefString(u.GetNamespace(), nestedMap(parent, "parentRef"))
		baseRef := strings.Split(ref, "#")[0]
		for _, conditionItem := range nestedSlice(parent, "conditions") {
			condition, ok := conditionItem.(map[string]any)
			if !ok || stringValue(condition["type"]) != "Accepted" {
				continue
			}
			observed = true
			if strings.EqualFold(stringValue(condition["status"]), "True") {
				if _, ok := specRefs[ref]; ok {
					accepted[ref] = struct{}{}
				} else if _, ok := specRefs[baseRef]; ok {
					accepted[baseRef] = struct{}{}
				}
			}
		}
	}
	return accepted, observed
}

func filterAcceptedGatewayRouteParentRefs(parentRefs []string, accepted map[string]struct{}) []string {
	out := []string{}
	for _, ref := range parentRefs {
		if _, ok := accepted[ref]; ok {
			out = append(out, ref)
			continue
		}
		if _, ok := accepted[strings.Split(ref, "#")[0]]; ok {
			out = append(out, ref)
		}
	}
	return sortedUniqueStrings(out)
}

func hbnPortDicts(spec map[string]any) []any {
	out := []any{}
	for _, value := range collectNetworkValues(spec, []string{"port", "ports", "targetPort", "targetPorts"}) {
		if values, ok := value.([]any); ok {
			for _, nested := range values {
				out = appendHBNPortDict(out, nested)
			}
			continue
		}
		out = appendHBNPortDict(out, value)
	}
	return out
}

func appendHBNPortDict(out []any, value any) []any {
	if port, ok := int64Value(value); ok {
		return append(out, map[string]any{"port": port})
	}
	for _, portString := range stringSlice(value) {
		if port, ok := parseInt64(portString); ok {
			out = append(out, map[string]any{"port": port})
		}
	}
	return out
}

func servicePortDicts(ports []corev1.ServicePort) []any {
	out := make([]any, 0, len(ports))
	for _, port := range ports {
		entry := map[string]any{
			"name":       port.Name,
			"port":       int64(port.Port),
			"targetPort": port.TargetPort.String(),
			"nodePort":   int64(port.NodePort),
			"protocol":   string(port.Protocol),
		}
		if port.AppProtocol != nil {
			entry["appProtocol"] = *port.AppProtocol
		}
		out = append(out, entry)
	}
	return out
}

func ingressPortDicts(ing *networkingv1.Ingress) []any {
	ports := []any{map[string]any{"port": int64(80), "protocol": "HTTP"}}
	if len(ing.Spec.TLS) > 0 {
		ports = append(ports, map[string]any{"port": int64(443), "protocol": "HTTPS"})
	}
	return ports
}

func gatewayPortDicts(gw *gatewayv1.Gateway) []any {
	ports := make([]any, 0, len(gw.Spec.Listeners))
	for _, listener := range gw.Spec.Listeners {
		ports = append(ports, map[string]any{
			"name":     string(listener.Name),
			"port":     int64(listener.Port),
			"protocol": string(listener.Protocol),
			"hostname": stringPtrValue(listener.Hostname),
		})
	}
	return ports
}

func serviceProtocols(ports []corev1.ServicePort) []string {
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, string(port.Protocol))
	}
	return sortedUniqueStrings(out)
}

func ingressProtocols(ing *networkingv1.Ingress) []string {
	protocols := []string{"HTTP"}
	if len(ing.Spec.TLS) > 0 {
		protocols = append(protocols, "HTTPS")
	}
	return sortedUniqueStrings(protocols)
}

func gatewayProtocols(gw *gatewayv1.Gateway) []string {
	out := make([]string, 0, len(gw.Spec.Listeners))
	for _, listener := range gw.Spec.Listeners {
		out = append(out, string(listener.Protocol))
	}
	return sortedUniqueStrings(out)
}

func effectiveNetworkPolicyTypes(policy *networkingv1.NetworkPolicy) []string {
	if len(policy.Spec.PolicyTypes) > 0 {
		out := make([]string, 0, len(policy.Spec.PolicyTypes))
		for _, policyType := range policy.Spec.PolicyTypes {
			out = append(out, string(policyType))
		}
		return sortedUniqueStrings(out)
	}

	out := []string{string(networkingv1.PolicyTypeIngress)}
	if len(policy.Spec.Egress) > 0 {
		out = append(out, string(networkingv1.PolicyTypeEgress))
	}
	return out
}

func networkPolicyIngressAllowsAll(rules []networkingv1.NetworkPolicyIngressRule) bool {
	for _, rule := range rules {
		if len(rule.Ports) == 0 && len(rule.From) == 0 {
			return true
		}
	}
	return false
}

func networkPolicyEgressAllowsAll(rules []networkingv1.NetworkPolicyEgressRule) bool {
	for _, rule := range rules {
		if len(rule.Ports) == 0 && len(rule.To) == 0 {
			return true
		}
	}
	return false
}

func unstructuredNetworkPolicyRulesAllowAll(rules []any) bool {
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if len(rule) == 0 {
			return true
		}
		allowAll := true
		for _, value := range rule {
			if !fieldIsEmpty(value) {
				allowAll = false
				break
			}
		}
		if allowAll {
			return true
		}
	}
	return false
}

func classifyAddresses(addresses []string) []string {
	if len(addresses) == 0 {
		return []string{"internalOnly"}
	}

	out := []string{}
	for _, address := range addresses {
		out = append(out, classifyAddress(address))
	}
	return sortedUniqueStrings(out)
}

func classifyAddress(address string) string {
	address = strings.TrimSpace(address)
	if address == "" {
		return "unknown"
	}

	addr, err := netip.ParseAddr(address)
	if err == nil {
		if isPublicAddr(addr) {
			return "internet"
		}
		if addr.IsPrivate() {
			return "private"
		}
		return "internal"
	}

	if isInternalHostname(address) {
		return "internalHostname"
	}
	return "hostname"
}

func classifyCIDRs(cidrs []string) []string {
	out := []string{}
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		if prefixContainsPublicAddress(prefix) {
			out = append(out, "publicSourceRange")
		} else {
			out = append(out, "restrictedSourceRange")
		}
	}
	return sortedUniqueStrings(out)
}

func isPublicAddr(addr netip.Addr) bool {
	return addr.IsValid() &&
		addr.IsGlobalUnicast() &&
		!isNonPublicAddr(addr)
}

func isNonPublicAddr(addr netip.Addr) bool {
	for _, prefix := range nonPublicAddressPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func prefixContainsPublicAddress(prefix netip.Prefix) bool {
	prefix = prefix.Masked()
	if !prefix.Addr().IsValid() {
		return false
	}
	return !prefixWhollyContainedBy(prefix, nonPublicAddressPrefixes)
}

func prefixWhollyContainedBy(prefix netip.Prefix, containers []netip.Prefix) bool {
	prefix = prefix.Masked()
	for _, container := range containers {
		container = container.Masked()
		if container.Addr().Is4() != prefix.Addr().Is4() {
			continue
		}
		if container.Bits() <= prefix.Bits() && container.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
}

func prefixWhollyContainedBySet(prefix netip.Prefix, cidrs map[string]struct{}) bool {
	containers := make([]netip.Prefix, 0, len(cidrs))
	for cidr := range cidrs {
		container, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		containers = append(containers, container)
	}
	return prefixWhollyContainedBy(prefix, containers)
}

func isInternalHostname(hostname string) bool {
	hostname = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
	if hostname == "" {
		return false
	}
	return strings.HasSuffix(hostname, ".svc") ||
		strings.HasSuffix(hostname, ".svc.cluster.local") ||
		strings.HasSuffix(hostname, ".cluster.local") ||
		strings.HasSuffix(hostname, ".local") ||
		strings.HasSuffix(hostname, ".internal") ||
		strings.Contains(hostname, ".svc.") ||
		isInternalCloudLoadBalancerHostname(hostname)
}

// isInternalCloudLoadBalancerHostname reports whether a cloud load balancer's DNS
// name identifies it as internal (reachable only inside the VPC) rather than
// internet-facing.
//
// A Service or Ingress usually publishes its load balancer as a hostname, not an
// IP, and an unrecognized hostname is otherwise classified as internet-reachable.
// That is the safe default for an arbitrary name, but it misreads AWS load
// balancer DNS: an internal Application or Classic Load Balancer is always named
// internal-<name>-<id>.<region>.elb.amazonaws.com, and AWS never applies that
// prefix to an internet-facing one, so treating the prefix as internal removes a
// large class of false positives without risking a false negative.
//
// Network Load Balancers carry no equivalent marker in their DNS name, so an
// internal NLB is not detectable here; those are classified from the load
// balancer scheme annotation instead (see hasInternalLoadBalancerAnnotation).
func isInternalCloudLoadBalancerHostname(hostname string) bool {
	return strings.HasPrefix(hostname, "internal-") &&
		strings.HasSuffix(hostname, ".amazonaws.com") &&
		strings.Contains(hostname, ".elb.")
}

// internalLoadBalancerAnnotations maps the cloud controller annotations that
// explicitly request an internal load balancer to the value that means internal.
// The AWS NLB case is the reason this exists: unlike an ALB, an internal NLB's DNS
// name is indistinguishable from an internet-facing one, so the declared scheme is
// the only signal available.
var internalLoadBalancerAnnotations = map[string]string{
	// AWS Load Balancer Controller, Ingress (ALB) and Service (NLB)
	"alb.ingress.kubernetes.io/scheme":                      "internal",
	"service.beta.kubernetes.io/aws-load-balancer-scheme":   "internal",
	"service.beta.kubernetes.io/aws-load-balancer-internal": "true",
	// Azure cloud provider
	"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
	// GKE, current and legacy annotation
	"networking.gke.io/load-balancer-type": "internal",
	"cloud.google.com/load-balancer-type":  "internal",
}

// hasInternalLoadBalancerAnnotation reports whether the object explicitly requests
// an internal load balancer through a cloud controller annotation. A declared
// scheme is authoritative: the controller provisions the load balancer from it, so
// it outranks any inference drawn from the published address.
func hasInternalLoadBalancerAnnotation(annotations map[string]string) bool {
	for key, internalValue := range internalLoadBalancerAnnotations {
		if value, ok := annotations[key]; ok {
			if strings.EqualFold(strings.TrimSpace(value), internalValue) {
				return true
			}
		}
	}
	return false
}

func filterNetworkObjectsByNamespace(runtime *plugin.Runtime, namespace string, list func(k8s *mqlK8s) *plugin.TValue[[]any]) ([]any, error) {
	obj, err := CreateResource(runtime, "k8s", nil)
	if err != nil {
		return nil, err
	}
	resources := list(obj.(*mqlK8s))
	if resources.Error != nil {
		return nil, resources.Error
	}

	out := []any{}
	for _, item := range resources.Data {
		if networkObjectVisibleInNamespace(item, namespace) {
			out = append(out, item)
		}
	}
	return out, nil
}

func networkObjectVisibleInNamespace(item any, namespace string) bool {
	ns, ok := item.(interface {
		GetNamespace() *plugin.TValue[string]
	})
	if !ok {
		return false
	}
	itemNamespace := ns.GetNamespace().Data
	return itemNamespace == namespace || itemNamespace == ""
}

func networkSourceRef(kind, namespace, name string) string {
	if namespace == "" {
		return fmt.Sprintf("%s:%s", kind, name)
	}
	return fmt.Sprintf("%s:%s:%s", kind, namespace, name)
}

func stringArrayData(in []string) *llx.RawData {
	return llx.ArrayData(stringsToAny(sortedUniqueStrings(in)), types.String)
}

func stringsToAny(in []string) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

// splitPolicyRefs expands a comma-joined policyRef into its members so they can
// be deduplicated individually. sortedUniqueStrings compares whole strings, so
// without this a pod matched by both a broad and a narrow policy reports the
// broad one twice.
func splitPolicyRefs(joined string) []string {
	if joined == "" {
		return nil
	}
	return strings.Split(joined, ",")
}

func sortedUniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func publicCIDRs(cidrs []string, settings networkInventorySettings) []string {
	out := []string{}
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if _, ok := settings.privateCIDRs[cidr]; ok {
			continue
		}
		if _, ok := settings.trustedEgressCIDRs[cidr]; ok {
			continue
		}
		if _, ok := settings.publicCIDRs[cidr]; ok {
			out = append(out, cidr)
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if prefixWhollyContainedBySet(prefix, settings.privateCIDRs) || prefixWhollyContainedBySet(prefix, settings.trustedEgressCIDRs) {
			continue
		}
		if prefixWhollyContainedBySet(prefix, settings.publicCIDRs) || prefixContainsPublicAddress(prefix) {
			out = append(out, cidr)
		}
	}
	return sortedUniqueStrings(out)
}

func egressClassification(cidrs []string, settings networkInventorySettings) string {
	if len(cidrs) == 0 {
		return "unknown"
	}
	if len(publicCIDRs(cidrs, settings)) > 0 {
		return "publicEgress"
	}
	for _, cidr := range cidrs {
		if _, ok := settings.trustedEgressCIDRs[cidr]; ok {
			return "trustedEgress"
		}
	}
	return "privateEgress"
}

func prefixItemsCIDRs(items []any) []string {
	out := []string{}
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, stringValue(m["cidr"]))
	}
	return out
}

func effectiveUnstructuredPolicyTypes(spec map[string]any) []string {
	policyTypes := stringSlice(spec["policyTypes"])
	if len(policyTypes) > 0 {
		return sortedUniqueStrings(policyTypes)
	}
	out := []string{string(networkingv1.PolicyTypeIngress)}
	if len(nestedSlice(spec, "egress")) > 0 {
		out = append(out, string(networkingv1.PolicyTypeEgress))
	}
	return out
}

func selectorFromCniPolicy(spec map[string]any) map[string]any {
	for _, field := range []string{"podSelector", "endpointSelector"} {
		if selector := nestedMap(spec, field); selector != nil {
			return selector
		}
	}
	out := map[string]any{}
	for _, field := range []string{"selector", "namespaceSelector", "serviceAccountSelector"} {
		if value := stringValue(spec[field]); value != "" {
			out[field] = value
		}
	}
	if len(out) > 0 {
		return out
	}
	return map[string]any{}
}

func selectorIsEmpty(selector map[string]any) bool {
	for _, field := range []string{"matchLabels", "matchExpressions"} {
		value, ok := selector[field]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case map[string]any:
			if len(v) > 0 {
				return false
			}
		case []any:
			if len(v) > 0 {
				return false
			}
		default:
			if stringValue(v) != "" {
				return false
			}
		}
	}
	return true
}

func coilEgressPoolAnnotations(spec map[string]any) []string {
	annotations := nestedMap(spec, "template", "metadata", "annotations")
	return append(
		stringSlice(annotations["cni.projectcalico.org/ipv4pools"]),
		stringSlice(annotations["cni.projectcalico.org/ipv6pools"])...,
	)
}

func revisionConfidence(u *unstructured.Unstructured) string {
	if boolValue(nestedMap(u.Object, "status")["isInvalid"]) {
		return "low"
	}
	return "medium"
}

func nodeNetworkConfigConfidence(u *unstructured.Unstructured) string {
	if strings.EqualFold(stringValue(nestedMap(u.Object, "status")["configStatus"]), "provisioned") {
		return "high"
	}
	return "medium"
}

func unstructuredSourceRef(u *unstructured.Unstructured) string {
	return networkSourceRef(u.GetKind(), u.GetNamespace(), u.GetName())
}

func nestedMap(in map[string]any, fields ...string) map[string]any {
	if len(fields) == 0 {
		return in
	}
	value, ok, _ := unstructured.NestedMap(in, fields...)
	if ok {
		return value
	}
	return nil
}

func nestedSlice(in map[string]any, fields ...string) []any {
	value, ok, _ := unstructured.NestedSlice(in, fields...)
	if ok {
		return value
	}
	return nil
}

func nestedString(in map[string]any, fields ...string) string {
	value, ok, _ := unstructured.NestedString(in, fields...)
	if ok {
		return value
	}
	return ""
}

func stringSlice(value any) []string {
	switch v := value.(type) {
	case []string:
		return sortedUniqueStrings(v)
	case []any:
		out := []string{}
		for _, item := range v {
			out = append(out, stringValue(item))
		}
		return sortedUniqueStrings(out)
	case string:
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
			var parsed []string
			if err := yaml.Unmarshal([]byte(v), &parsed); err == nil {
				return sortedUniqueStrings(parsed)
			}
		}
		if v == "" {
			return nil
		}
		return []string{v}
	default:
		return nil
	}
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case *string:
		if v == nil {
			return ""
		}
		return strings.TrimSpace(*v)
	default:
		return ""
	}
}

func collectNetworkStrings(in map[string]any, keys []string) []string {
	values := collectNetworkValues(in, keys)
	out := []string{}
	for _, value := range values {
		out = append(out, stringSlice(value)...)
		if s := stringValue(value); s != "" {
			out = append(out, s)
		}
	}
	return sortedUniqueStrings(out)
}

func firstNetworkString(in map[string]any, keys []string) string {
	values := collectNetworkStrings(in, keys)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func collectNetworkValues(in map[string]any, keys []string) []any {
	if len(in) == 0 {
		return nil
	}
	want := stringSet(keys)
	out := []any{}
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			for key, nested := range v {
				if _, ok := want[key]; ok {
					out = append(out, nested)
				}
				walk(nested)
			}
		case []any:
			for _, nested := range v {
				walk(nested)
			}
		}
	}
	walk(in)
	return out
}

func int64Value(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	default:
		return 0, false
	}
}

func parseInt64(value string) (int64, bool) {
	out, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return out, err == nil
}

func boolValue(value any) bool {
	v, ok := value.(bool)
	return ok && v
}

func fieldIsEmpty(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []any:
		return len(v) == 0
	case []string:
		return len(v) == 0
	case map[string]any:
		return len(v) == 0
	default:
		return false
	}
}

func stringSet(in []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, value := range in {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		out[value] = struct{}{}
	}
	return out
}

func stringPtrValue[T ~string](value *T) string {
	if value == nil {
		return ""
	}
	return string(*value)
}
