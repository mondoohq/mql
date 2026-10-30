// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestServiceNetworkExposureArgsLoadBalancerPublic(t *testing.T) {
	svc := &corev1.Service{
		Name:      "web",
		Namespace: "prod",
		Annotations: map[string]string{
			"network.mondoo.com/classification": "internet-facing",
			"mondoo.com/owner":                  "team-edge",
		},
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeLoadBalancer,
			LoadBalancerSourceRanges: []string{"0.0.0.0/0"},
			Ports: []corev1.ServicePort{{
				Name:       "https",
				Port:       443,
				TargetPort: intstr.FromString("https"),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{IP: "8.8.8.8"}},
			},
		},
	}

	args := serviceNetworkExposureArgs(svc, nil)
	require.Len(t, args, 1)

	assert.Equal(t, "service:prod:web", args[0]["__id"].Value)
	assert.Equal(t, "Service:prod:web", args[0]["sourceRef"].Value)
	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "publicLoadBalancerAddress", args[0]["exposureReason"].Value)
	assert.Equal(t, "internet-facing", args[0]["metadataClassification"].Value)
	assert.Equal(t, "team-edge", args[0]["owner"].Value)
	assert.Equal(t, []any{"8.8.8.8"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"internet", "publicSourceRange"}, args[0]["networkClassifications"].Value)
	assert.Equal(t, []any{"TCP"}, args[0]["protocols"].Value)
	ports := args[0]["ports"].Value.([]any)
	require.Len(t, ports, 1)
	assert.Equal(t, int64(443), ports[0].(map[string]any)["port"])
	assert.Equal(t, "https", ports[0].(map[string]any)["targetPort"])
}

func TestServiceNetworkExposureArgsNodePortPublicNode(t *testing.T) {
	svc := &corev1.Service{
		Name: "api", Namespace: "prod",
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{{
				Port:     8080,
				NodePort: 30080,
				Protocol: corev1.ProtocolTCP,
			}},
		},
	}

	args := serviceNetworkExposureArgs(svc, []string{"1.2.3.4"})
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "nodePortPublicNode", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"1.2.3.4"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"internet"}, args[0]["networkClassifications"].Value)
}

func TestServiceNetworkExposureArgsNodePortPublicExternalIP(t *testing.T) {
	svc := &corev1.Service{
		Name: "api", Namespace: "prod",
		Spec: corev1.ServiceSpec{
			Type:        corev1.ServiceTypeNodePort,
			ExternalIPs: []string{"8.8.8.8"},
			Ports: []corev1.ServicePort{{
				Port:     8080,
				NodePort: 30080,
				Protocol: corev1.ProtocolTCP,
			}},
		},
	}

	args := serviceNetworkExposureArgs(svc, nil)
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "nodePortPublicExternalIP", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"8.8.8.8"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"internet"}, args[0]["networkClassifications"].Value)
}

func TestAddressIsPublicNodeAddressRejectsPrivateExternalIP(t *testing.T) {
	assert.True(t, addressIsPublicNodeAddress("8.8.8.8"))
	assert.True(t, addressIsPublicNodeAddress("node-a.example.com"))
	assert.False(t, addressIsPublicNodeAddress("10.0.0.10"))
	assert.False(t, addressIsPublicNodeAddress("192.168.10.10"))
	assert.False(t, addressIsPublicNodeAddress("node-a.cluster.local"))
}

func TestServiceNetworkExposureArgsPrivateLoadBalancer(t *testing.T) {
	svc := &corev1.Service{
		Name: "db", Namespace: "prod",
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{
				Port:     5432,
				Protocol: corev1.ProtocolTCP,
			}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{IP: "10.0.0.5"}},
			},
		},
	}

	args := serviceNetworkExposureArgs(svc, nil)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "privateLoadBalancerAddress", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"private"}, args[0]["networkClassifications"].Value)
}

func TestServiceNetworkExposureArgsRestrictedLoadBalancerSourceRange(t *testing.T) {
	svc := &corev1.Service{
		Name: "admin", Namespace: "prod",
		Spec: corev1.ServiceSpec{
			Type:                     corev1.ServiceTypeLoadBalancer,
			LoadBalancerSourceRanges: []string{"10.0.0.0/8"},
			Ports: []corev1.ServicePort{{
				Port:     8443,
				Protocol: corev1.ProtocolTCP,
			}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{IP: "8.8.8.8"}},
			},
		},
	}

	args := serviceNetworkExposureArgs(svc, nil)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "restrictedLoadBalancerSourceRange", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"internet", "restrictedSourceRange"}, args[0]["networkClassifications"].Value)
}

func TestIngressNetworkExposureArgsPublicHostname(t *testing.T) {
	ing := &networkingv1.Ingress{
		Name: "web", Namespace: "prod",
		Spec: networkingv1.IngressSpec{
			TLS: []networkingv1.IngressTLS{{Hosts: []string{"web.example.com"}}},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{{Hostname: "lb.example.com"}},
			},
		},
	}

	args := ingressNetworkExposureArgs(ing)
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "publicIngressAddress", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"lb.example.com", "web.example.com"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"HTTP", "HTTPS"}, args[0]["protocols"].Value)
}

func TestIngressNetworkExposureArgsConfiguredHostWithoutStatus(t *testing.T) {
	ing := &networkingv1.Ingress{
		Name: "web", Namespace: "prod",
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "web.example.com"}},
		},
	}

	args := ingressNetworkExposureArgs(ing)
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "publicIngressHostname", args[0]["exposureReason"].Value)
	assert.Equal(t, "medium", args[0]["confidence"].Value)
	assert.Equal(t, []any{"web.example.com"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"hostname"}, args[0]["networkClassifications"].Value)
}

func TestGatewayNetworkExposureArgs(t *testing.T) {
	hostname := gatewayv1.Hostname("gw.example.com")
	gw := &gatewayv1.Gateway{
		Name: "edge", Namespace: "prod",
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{{
				Name:     "https",
				Port:     443,
				Protocol: gatewayv1.HTTPSProtocolType,
				Hostname: &hostname,
			}},
		},
		Status: gatewayv1.GatewayStatus{
			Addresses: []gatewayv1.GatewayStatusAddress{{Value: "8.8.4.4"}},
		},
	}

	args := gatewayNetworkExposureArgs(gw)
	require.Len(t, args, 1)

	assert.Equal(t, "Gateway:prod:edge", args[0]["sourceRef"].Value)
	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayPublicAddress", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"HTTPS"}, args[0]["protocols"].Value)
	ports := args[0]["ports"].Value.([]any)
	require.Len(t, ports, 1)
	assert.Equal(t, "https", ports[0].(map[string]any)["name"])
	assert.Equal(t, "gw.example.com", ports[0].(map[string]any)["hostname"])
}

func TestGatewayRouteNetworkExposureArgsHTTPRoutePublicHostname(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1", "HTTPRoute", "prod", "web", map[string]any{
		"hostnames": []any{"web.example.com"},
		"parentRefs": []any{map[string]any{
			"name":        "edge",
			"sectionName": "https",
			"port":        int64(443),
		}},
		"rules": []any{map[string]any{
			"backendRefs": []any{map[string]any{"name": "web", "port": int64(8080)}},
		}},
	})

	args := gatewayRouteNetworkExposureArgs(route, map[string]networkExposureContext{
		"Gateway:prod:edge": {addresses: []string{"8.8.8.8"}, classifications: []string{"internet"}, internetExposed: true},
	})
	require.Len(t, args, 1)

	assert.Equal(t, "httproute:prod:web", args[0]["__id"].Value)
	assert.Equal(t, "HTTPRoute", args[0]["sourceKind"].Value)
	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayRoutePublicHostname", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"8.8.8.8", "web.example.com"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"hostname", "internet"}, args[0]["networkClassifications"].Value)
	assert.Equal(t, []any{"HTTP"}, args[0]["protocols"].Value)
	assert.Equal(t, []any{"Gateway:prod:edge#section/https#port/443"}, args[0]["routes"].Value)
	ports := args[0]["ports"].Value.([]any)
	require.Len(t, ports, 2)
	assert.Equal(t, int64(443), ports[0].(map[string]any)["port"])
	assert.Equal(t, "parentRef", ports[0].(map[string]any)["source"])
	assert.Equal(t, int64(8080), ports[1].(map[string]any)["port"])
	assert.Equal(t, "backendRef", ports[1].(map[string]any)["source"])
}

func TestGatewayRouteNetworkExposureArgsPrivateParentWithPublicHostnameIsNotInternetExposed(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1", "HTTPRoute", "prod", "web", map[string]any{
		"hostnames":  []any{"web.example.com"},
		"parentRefs": []any{map[string]any{"name": "internal"}},
	})

	args := gatewayRouteNetworkExposureArgs(route, map[string]networkExposureContext{
		"Gateway:prod:internal": {addresses: []string{"10.0.0.10"}, classifications: []string{"private"}, internetExposed: false},
	})
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayRoutePrivateParent", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"10.0.0.10", "web.example.com"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"Gateway:prod:internal"}, args[0]["routes"].Value)
}

func TestGatewayRouteNetworkExposureArgsTCPRouteUsesPublicParent(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1alpha2", "TCPRoute", "prod", "tcp-api", map[string]any{
		"parentRefs": []any{map[string]any{"name": "edge"}},
	})

	args := gatewayRouteNetworkExposureArgs(route, map[string]networkExposureContext{
		"Gateway:prod:edge": {addresses: []string{"8.8.4.4"}, classifications: []string{"internet"}, internetExposed: true},
	})
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayRoutePublicParent", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"8.8.4.4"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"TCP"}, args[0]["protocols"].Value)
}

func TestGatewayRouteNetworkExposureArgsInternalTLSHostname(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1alpha2", "TLSRoute", "prod", "internal", map[string]any{
		"hostnames":  []any{"api.default.svc.cluster.local"},
		"parentRefs": []any{map[string]any{"name": "mesh"}},
	})

	args := gatewayRouteNetworkExposureArgs(route, nil)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayRouteInternalHostname", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"internalHostname"}, args[0]["networkClassifications"].Value)
	assert.Equal(t, []any{"TLS"}, args[0]["protocols"].Value)
}

func TestGatewayRouteNetworkExposureArgsGRPCRoute(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1", "GRPCRoute", "prod", "grpc", map[string]any{
		"hostnames":  []any{"grpc.example.com"},
		"parentRefs": []any{map[string]any{"name": "edge"}},
	})

	args := gatewayRouteNetworkExposureArgs(route, nil)
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, []any{"GRPC"}, args[0]["protocols"].Value)
}

func TestGatewayRouteNetworkExposureArgsUDPRoute(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1alpha2", "UDPRoute", "prod", "dns", map[string]any{
		"parentRefs": []any{map[string]any{"name": "edge", "port": int64(53)}},
	})

	args := gatewayRouteNetworkExposureArgs(route, map[string]networkExposureContext{
		"Gateway:prod:edge#port/53": {addresses: []string{"8.8.4.4"}, classifications: []string{"internet"}, internetExposed: true},
		"Gateway:prod:edge":         {addresses: []string{"8.8.4.4"}, classifications: []string{"internet"}, internetExposed: true},
	})
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, []any{"UDP"}, args[0]["protocols"].Value)
}

func TestGatewayRouteNetworkExposureArgsNotAccepted(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1", "HTTPRoute", "prod", "web", map[string]any{
		"hostnames":  []any{"web.example.com"},
		"parentRefs": []any{map[string]any{"name": "edge"}},
	})
	route.Object["status"] = map[string]any{
		"parents": []any{map[string]any{
			"conditions": []any{map[string]any{"type": "Accepted", "status": "False"}},
		}},
	}

	args := gatewayRouteNetworkExposureArgs(route, map[string]networkExposureContext{
		"Gateway:prod:edge": {addresses: []string{"8.8.8.8"}, classifications: []string{"internet"}, internetExposed: true},
	})
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayRouteNotAccepted", args[0]["exposureReason"].Value)
	assert.Equal(t, "low", args[0]["confidence"].Value)
	assert.Equal(t, []any{"web.example.com"}, args[0]["addresses"].Value)
}

func TestGatewayRouteNetworkExposureArgsDetachedHostnameIsNotInternetExposed(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1", "HTTPRoute", "prod", "web", map[string]any{
		"hostnames": []any{"web.example.com"},
	})

	args := gatewayRouteNetworkExposureArgs(route, nil)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayRouteNoParentRef", args[0]["exposureReason"].Value)
	assert.Equal(t, "low", args[0]["confidence"].Value)
	assert.Equal(t, []any{"web.example.com"}, args[0]["addresses"].Value)
	assert.Empty(t, args[0]["routes"].Value)
}

func TestGatewayRouteNetworkExposureArgsUsesOnlyAcceptedParentAddresses(t *testing.T) {
	route := newUnstructured("gateway.networking.k8s.io/v1", "HTTPRoute", "prod", "web", map[string]any{
		"parentRefs": []any{
			map[string]any{"name": "public"},
			map[string]any{"name": "private"},
		},
	})
	route.Object["status"] = map[string]any{
		"parents": []any{
			map[string]any{
				"parentRef":  map[string]any{"name": "public"},
				"conditions": []any{map[string]any{"type": "Accepted", "status": "False"}},
			},
			map[string]any{
				"parentRef":  map[string]any{"name": "private"},
				"conditions": []any{map[string]any{"type": "Accepted", "status": "True"}},
			},
		},
	}

	args := gatewayRouteNetworkExposureArgs(route, map[string]networkExposureContext{
		"Gateway:prod:public":  {addresses: []string{"8.8.8.8"}, classifications: []string{"internet"}, internetExposed: true},
		"Gateway:prod:private": {addresses: []string{"10.0.0.1"}, classifications: []string{"private"}, internetExposed: false},
	})
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "gatewayRoutePrivateParent", args[0]["exposureReason"].Value)
	assert.Equal(t, []any{"10.0.0.1"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"Gateway:prod:private"}, args[0]["routes"].Value)
}

func TestNetworkPolicyCoverageArgsDoesNotTreatAllowAllEgressAsDefaultDeny(t *testing.T) {
	policy := &networkingv1.NetworkPolicy{
		Name: "allow-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}

	args, err := networkPolicyCoverageArgs(policy)
	require.NoError(t, err)

	assert.Equal(t, "networkpolicy:prod:allow-egress", args["__id"].Value)
	assert.Equal(t, "NetworkPolicy:prod:allow-egress", args["policyRef"].Value)
	assert.Equal(t, true, args["defaultDenyIngress"].Value)
	assert.Equal(t, false, args["defaultDenyEgress"].Value)
	assert.Equal(t, []any{"primary"}, args["interfaces"].Value)
	assert.Equal(t, []any{"NetworkPolicy:prod:allow-egress"}, args["nativeNetworkPolicies"].Value)
	assert.Equal(t, []any{
		"primary egress allows all traffic",
		"secondary interface coverage requires MultiNetworkPolicy or CNI-specific policy inventory",
	}, args["coverageGaps"].Value)
}

func TestNetworkPolicyCoverageArgsDefaultDenyEgress(t *testing.T) {
	policy := &networkingv1.NetworkPolicy{
		Name: "deny-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	}

	args, err := networkPolicyCoverageArgs(policy)
	require.NoError(t, err)

	assert.Equal(t, false, args["defaultDenyIngress"].Value)
	assert.Equal(t, true, args["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"primary ingress is not isolated by this policy",
		"secondary interface coverage requires MultiNetworkPolicy or CNI-specific policy inventory",
	}, args["coverageGaps"].Value)
}

func TestNetworkPolicyCoverageArgsIngressOnlyGap(t *testing.T) {
	policy := &networkingv1.NetworkPolicy{
		Name: "ingress-only", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}

	args, err := networkPolicyCoverageArgs(policy)
	require.NoError(t, err)

	assert.Equal(t, true, args["defaultDenyIngress"].Value)
	assert.Equal(t, false, args["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"primary egress is not isolated by this policy",
		"secondary interface coverage requires MultiNetworkPolicy or CNI-specific policy inventory",
	}, args["coverageGaps"].Value)
}

func TestNetworkPolicyCoverageArgsFromPoliciesAggregatesSameSelector(t *testing.T) {
	selector := metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	ingressPolicy := &networkingv1.NetworkPolicy{
		Name: "deny-ingress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selector,
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}
	egressPolicy := &networkingv1.NetworkPolicy{
		Name: "deny-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: selector,
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	}

	args, err := networkPolicyCoverageArgsFromPolicies([]any{
		&mqlK8sNetworkpolicy{obj: ingressPolicy},
		&mqlK8sNetworkpolicy{obj: egressPolicy},
	})
	require.NoError(t, err)
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, true, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"NetworkPolicy:prod:deny-egress",
		"NetworkPolicy:prod:deny-ingress",
	}, args[0]["nativeNetworkPolicies"].Value)
	assert.Equal(t, []any{
		"secondary interface coverage requires MultiNetworkPolicy or CNI-specific policy inventory",
	}, args[0]["coverageGaps"].Value)
}

func TestNetworkPolicyCoverageArgsFromPoliciesFoldsBroaderDefaultDenyEgress(t *testing.T) {
	namespaceDefaultDeny := &networkingv1.NetworkPolicy{
		Name: "deny-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	}
	workloadIngress := &networkingv1.NetworkPolicy{
		Name: "api-ingress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
			},
		},
	}

	args, err := networkPolicyCoverageArgsFromPolicies([]any{
		&mqlK8sNetworkpolicy{obj: namespaceDefaultDeny},
		&mqlK8sNetworkpolicy{obj: workloadIngress},
	})
	require.NoError(t, err)
	require.Len(t, args, 2)

	apiCoverage := coverageArgsWithPolicyRef(t, args, "NetworkPolicy:prod:api-ingress,NetworkPolicy:prod:deny-egress")
	assert.Equal(t, true, apiCoverage["defaultDenyIngress"].Value)
	assert.Equal(t, true, apiCoverage["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"NetworkPolicy:prod:api-ingress",
		"NetworkPolicy:prod:deny-egress",
	}, apiCoverage["nativeNetworkPolicies"].Value)
	assert.Equal(t, []any{
		"secondary interface coverage requires MultiNetworkPolicy or CNI-specific policy inventory",
	}, apiCoverage["coverageGaps"].Value)
}

func TestNetworkPolicyCoverageArgsFromPoliciesPreservesNarrowAllowAllEgress(t *testing.T) {
	namespaceDefaultDeny := &networkingv1.NetworkPolicy{
		Name: "deny-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
		},
	}
	workloadAllowAll := &networkingv1.NetworkPolicy{
		Name: "api-allow-all-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeEgress,
			},
			Egress: []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}

	args, err := networkPolicyCoverageArgsFromPolicies([]any{
		&mqlK8sNetworkpolicy{obj: namespaceDefaultDeny},
		&mqlK8sNetworkpolicy{obj: workloadAllowAll},
	})
	require.NoError(t, err)
	require.Len(t, args, 2)

	apiCoverage := coverageArgsWithPolicyRef(t, args, "NetworkPolicy:prod:api-allow-all-egress")
	assert.Equal(t, false, apiCoverage["defaultDenyEgress"].Value)
	assert.Equal(t, []any{"NetworkPolicy:prod:api-allow-all-egress"}, apiCoverage["nativeNetworkPolicies"].Value)
	assert.Contains(t, apiCoverage["coverageGaps"].Value, "primary egress allows all traffic")
}

func TestPrimaryInterfaceCoverageArgsForPodCoveredByDefaultDenyPolicy(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}
	defaultDenyEgress := &networkingv1.NetworkPolicy{
		Name: "deny-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
	policyCoverage, err := networkPolicyCoverageArgsFromPolicies([]any{
		&mqlK8sNetworkpolicy{obj: defaultDenyEgress},
	})
	require.NoError(t, err)

	args := primaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	assert.Equal(t, "primary-interface:prod:api-0", args["__id"].Value)
	assert.Equal(t, "Pod:prod:api-0", args["workloadRef"].Value)
	assert.Equal(t, []any{"primary"}, args["interfaces"].Value)
	assert.Equal(t, true, args["defaultDenyEgress"].Value)
	assert.Contains(t, args["nativeNetworkPolicies"].Value, "NetworkPolicy:prod:deny-egress")
}

func TestPrimaryInterfaceCoverageArgsForPodDoesNotHideAllowAllPolicy(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}
	namespaceDefaultDeny := &networkingv1.NetworkPolicy{
		Name: "deny-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
		},
	}
	workloadAllowAll := &networkingv1.NetworkPolicy{
		Name: "api-allow-all-egress", Namespace: "prod",
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress:      []networkingv1.NetworkPolicyEgressRule{{}},
		},
	}
	policyCoverage, err := networkPolicyCoverageArgsFromPolicies([]any{
		&mqlK8sNetworkpolicy{obj: namespaceDefaultDeny},
		&mqlK8sNetworkpolicy{obj: workloadAllowAll},
	})
	require.NoError(t, err)

	args := primaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	assert.Equal(t, false, args["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"NetworkPolicy:prod:api-allow-all-egress",
		"NetworkPolicy:prod:deny-egress",
	}, args["nativeNetworkPolicies"].Value)
	assert.Contains(t, args["coverageGaps"].Value, "primary egress is not default-deny for pod prod/api-0")
}

func TestPrimaryInterfaceCoverageArgsForPodReportsUncoveredPod(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}

	args := primaryInterfaceCoverageArgsForPod(pod, nil)

	assert.Equal(t, "primary-interface:prod:api-0", args["__id"].Value)
	assert.Equal(t, false, args["defaultDenyIngress"].Value)
	assert.Equal(t, false, args["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"primary egress is not default-deny for pod prod/api-0",
		"primary ingress is not default-deny for pod prod/api-0",
	}, args["coverageGaps"].Value)
}

func TestPrimaryInterfaceCoverageArgsForPodAppliesAdminNetworkPolicySubject(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}
	policy := newUnstructured("policy.networking.k8s.io/v1alpha1", "AdminNetworkPolicy", "", "cluster-guardrails", map[string]any{
		"subject": map[string]any{
			"namespaces": map[string]any{"matchLabels": map[string]any{"team": "core"}},
			"pods":       map[string]any{"matchLabels": map[string]any{"app": "api"}},
		},
		"ingress": []any{map[string]any{"action": "Deny"}},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)

	args := primaryInterfaceCoverageArgsForPodWithNamespaceLabels(pod, policyCoverage, map[string]map[string]string{
		"prod": map[string]string{"team": "core"},
	})

	assert.Equal(t, []any{"AdminNetworkPolicy:cluster-guardrails"}, args["adminNetworkPolicies"].Value)
	assert.Equal(t, true, args["defaultDenyIngress"].Value)
	assert.Equal(t, false, args["defaultDenyEgress"].Value)
	assert.Equal(t, true, args["adminDefaultDenyIngress"].Value)
	assert.Equal(t, false, args["adminDefaultDenyEgress"].Value)
	assert.NotContains(t, args["coverageGaps"].Value, "primary ingress is not default-deny for pod prod/api-0")
}

func TestPrimaryInterfaceCoverageArgsForPodRejectsMismatchedAdminNetworkPolicySubject(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}
	policy := newUnstructured("policy.networking.k8s.io/v1alpha1", "AdminNetworkPolicy", "", "cluster-guardrails", map[string]any{
		"subject": map[string]any{
			"namespaces": map[string]any{"matchLabels": map[string]any{"team": "platform"}},
			"pods":       map[string]any{"matchLabels": map[string]any{"app": "api"}},
		},
		"ingress": []any{map[string]any{"action": "Deny"}},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)

	args := primaryInterfaceCoverageArgsForPodWithNamespaceLabels(pod, policyCoverage, map[string]map[string]string{
		"prod": map[string]string{"team": "core"},
	})

	assert.Empty(t, args["adminNetworkPolicies"].Value)
	assert.Equal(t, false, args["defaultDenyIngress"].Value)
	assert.Contains(t, args["coverageGaps"].Value, "primary ingress is not default-deny for pod prod/api-0")
}

func TestPrimaryInterfaceCoverageArgsForPodAppliesBaselineAdminNetworkPolicySubject(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}
	policy := newUnstructured("policy.networking.k8s.io/v1alpha1", "BaselineAdminNetworkPolicy", "", "default", map[string]any{
		"subject": map[string]any{
			"pods": map[string]any{"matchLabels": map[string]any{"app": "api"}},
		},
		"egress": []any{map[string]any{"action": "Deny"}},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)

	args := primaryInterfaceCoverageArgsForPodWithNamespaceLabels(pod, policyCoverage, nil)

	assert.Equal(t, []any{"BaselineAdminNetworkPolicy:default"}, args["adminNetworkPolicies"].Value)
	assert.Equal(t, true, args["defaultDenyEgress"].Value)
	assert.Equal(t, false, args["adminDefaultDenyIngress"].Value)
	assert.Equal(t, true, args["adminDefaultDenyEgress"].Value)
	assert.NotContains(t, args["coverageGaps"].Value, "primary egress is not default-deny for pod prod/api-0")
}

func TestClassifyAddress(t *testing.T) {
	assert.Equal(t, "internet", classifyAddress("8.8.8.8"))
	assert.Equal(t, "private", classifyAddress("10.0.0.1"))
	assert.Equal(t, "internal", classifyAddress("100.64.0.1"))
	assert.Equal(t, "internal", classifyAddress("203.0.113.10"))
	assert.Equal(t, "internalHostname", classifyAddress("api.default.svc.cluster.local"))
	assert.Equal(t, "hostname", classifyAddress("api.example.com"))
	assert.Equal(t, []string{"publicSourceRange", "restrictedSourceRange"}, classifyCIDRs([]string{"0.0.0.0/0", "10.0.0.0/8"}))
	assert.Equal(t, []string{"publicSourceRange"}, classifyCIDRs([]string{"0.0.0.0/1", "::/1", "192.0.0.0/8"}))
}

func TestVRFRouteConfigurationEgressRouteInputs(t *testing.T) {
	settings := networkInventorySettings{publicCIDRs: stringSet([]string{"203.0.113.0/24"})}
	vrf := newUnstructured("network.t-caas.telekom.com/v1alpha1", "VRFRouteConfiguration", "", "m2m", map[string]any{
		"vrf":         "s-m2m",
		"routeTarget": "65000:42",
		"import": []any{
			map[string]any{"cidr": "10.102.0.0/24", "action": "permit"},
		},
		"export": []any{
			map[string]any{"cidr": "203.0.113.0/24", "action": "permit"},
		},
		"sbrPrefixes": []any{"10.250.2.0/30"},
	})

	inputs := egressRouteInputsFromUnstructured(vrf, settings)

	require.Len(t, inputs, 1)
	assert.Equal(t, "hbn-vrf:m2m", inputs[0].id)
	assert.Equal(t, "VRFRouteConfiguration:m2m", inputs[0].sourceRef)
	assert.Equal(t, "s-m2m", inputs[0].vrf)
	assert.Equal(t, "65000:42", inputs[0].network)
	assert.Equal(t, []string{"10.102.0.0/24", "10.250.2.0/30", "203.0.113.0/24"}, inputs[0].cidrs)
	assert.Equal(t, []string{"203.0.113.0/24"}, inputs[0].publicCidrs)
	assert.Equal(t, "publicEgress", inputs[0].classification)
	assert.Equal(t, "high", inputs[0].confidence)
}

func TestBGPPeeringEgressRouteInputs(t *testing.T) {
	peering := newUnstructured("network.t-caas.telekom.com/v1alpha1", "BGPPeering", "", "m2m-peer", map[string]any{
		"peeringVlan": map[string]any{"name": "uplink-42"},
		"import": []any{
			map[string]any{"cidr": "10.42.0.0/16"},
		},
	})

	inputs := egressRouteInputsFromUnstructured(peering, networkInventorySettings{})

	require.Len(t, inputs, 1)
	assert.Equal(t, "hbn-bgp:m2m-peer", inputs[0].id)
	assert.Equal(t, "uplink-42", inputs[0].network)
	assert.Equal(t, []string{"10.42.0.0/16"}, inputs[0].cidrs)
	assert.Equal(t, []string{"BGPPeering:m2m-peer"}, inputs[0].bgpPeerings)
	assert.Equal(t, "privateEgress", inputs[0].classification)
}

func TestNodeNetworkConfigEgressRouteInputs(t *testing.T) {
	nodeConfig := newUnstructured("network.t-caas.telekom.com/v1alpha1", "NodeNetworkConfig", "", "node-a", map[string]any{
		"fabricVRFs": map[string]any{
			"edge": map[string]any{
				"staticRoutes": []any{
					map[string]any{"prefix": "0.0.0.0/0"},
				},
				"policyRoutes": []any{
					map[string]any{"trafficMatch": map[string]any{"dstPrefix": "198.51.100.0/24", "srcPrefix": "10.0.0.0/24"}},
				},
				"bgpPeers": []any{
					map[string]any{"address": "192.0.2.10"},
				},
			},
		},
	})
	nodeConfig.Object["status"] = map[string]any{"configStatus": "provisioned"}

	inputs := egressRouteInputsFromUnstructured(nodeConfig, networkInventorySettings{})

	require.Len(t, inputs, 1)
	assert.Equal(t, "hbn-node:node-a:fabric:edge", inputs[0].id)
	assert.Equal(t, "edge", inputs[0].vrf)
	assert.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/24", "198.51.100.0/24"}, inputs[0].cidrs)
	assert.Equal(t, []string{"0.0.0.0/0"}, inputs[0].publicCidrs)
	assert.Equal(t, []string{"NodeNetworkConfig:node-a"}, inputs[0].nodeStatuses)
	assert.Equal(t, []string{"192.0.2.10"}, inputs[0].bgpPeerings)
	assert.Equal(t, "high", inputs[0].confidence)
}

func TestNetworkConfigRevisionEgressRouteInputs(t *testing.T) {
	revision := newUnstructured("network.t-caas.telekom.com/v1alpha1", "NetworkConfigRevision", "", "rev-17", map[string]any{
		"vrf": []any{
			map[string]any{
				"name":        "edge",
				"vrf":         "s-edge",
				"routeTarget": "65000:17",
				"export": []any{
					map[string]any{"cidr": "0.0.0.0/0"},
				},
			},
		},
		"bgp": []any{
			map[string]any{
				"name":        "fabric",
				"peeringVlan": map[string]any{"name": "fabric-vlan"},
				"import": []any{
					map[string]any{"cidr": "10.0.0.0/8"},
				},
			},
		},
	})
	revision.Object["status"] = map[string]any{"isInvalid": true}

	inputs := egressRouteInputsFromUnstructured(revision, networkInventorySettings{})

	require.Len(t, inputs, 2)
	assert.Equal(t, "hbn-revision-vrf:rev-17:edge", inputs[0].id)
	assert.Equal(t, []string{"0.0.0.0/0"}, inputs[0].publicCidrs)
	assert.Equal(t, "low", inputs[0].confidence)
	assert.Equal(t, "hbn-revision-bgp:rev-17:fabric", inputs[1].id)
	assert.Equal(t, []string{"10.0.0.0/8"}, inputs[1].cidrs)
	assert.Equal(t, "low", inputs[1].confidence)
}

func TestCoilEgressNatInputs(t *testing.T) {
	egress := newUnstructured("coil.cybozu.com/v2", "Egress", "prod", "m2m-egress", map[string]any{
		"destinations": []any{"10.102.0.0/24", "2001:db8::/32"},
		"template": map[string]any{
			"metadata": map[string]any{
				"annotations": map[string]any{
					"cni.projectcalico.org/ipv4pools": `["m2m-egress-v4"]`,
				},
			},
		},
	})

	routes := egressRouteInputsFromUnstructured(egress, networkInventorySettings{})
	nats := egressNatInputsFromUnstructured(egress, networkInventorySettings{})

	require.Len(t, routes, 1)
	assert.True(t, routes[0].nat)
	assert.Equal(t, "coil-egress:prod:m2m-egress", routes[0].id)
	require.Len(t, nats, 1)
	assert.Empty(t, routes[0].owner)
	assert.Empty(t, routes[0].metadataClassification)
	assert.Empty(t, nats[0].owner)
	assert.Empty(t, nats[0].metadataClassification)
	assert.Equal(t, []string{"10.102.0.0/24", "2001:db8::/32"}, nats[0].cidrs)
	assert.Equal(t, []string{"m2m-egress-v4"}, nats[0].addresses)
}

func TestHBNNetworkExposureArgsPublicInbound(t *testing.T) {
	inbound := newUnstructured("network.t-caas.telekom.com/v1alpha1", "Inbound", "prod", "public-api", map[string]any{
		"publicIP":   "8.8.8.8",
		"ports":      []any{int64(443)},
		"protocol":   "TCP",
		"vrfRef":     "internet",
		"networkRef": "edge",
		"backend":    "Service:prod:api",
	})

	args := hbnNetworkExposureArgs(inbound)

	require.Len(t, args, 1)
	assert.Equal(t, "hbn-inbound:prod:public-api", args[0]["__id"].Value)
	assert.Equal(t, "hbnInboundPublicDestination", args[0]["exposureReason"].Value)
	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, []any{"8.8.8.8"}, args[0]["addresses"].Value)
	assert.Equal(t, []any{"internet"}, args[0]["networkClassifications"].Value)
	assert.Equal(t, "internet", args[0]["vrf"].Value)
	assert.Equal(t, "edge", args[0]["network"].Value)
	assert.Equal(t, []any{"Service:prod:api", "edge"}, args[0]["routes"].Value)
	ports := args[0]["ports"].Value.([]any)
	require.Len(t, ports, 1)
	assert.Equal(t, int64(443), ports[0].(map[string]any)["port"])
}

func TestHBNStableEgressRouteInputsOutbound(t *testing.T) {
	outbound := newUnstructured("network.t-caas.telekom.com/v1alpha1", "Outbound", "prod", "internet", map[string]any{
		"vrfRef":       "s-edge",
		"networkRef":   "edge",
		"destinations": []any{"0.0.0.0/0", "10.0.0.0/8"},
		"natPool":      "198.51.100.10",
		"bgpPeers":     []any{"192.0.2.10"},
	})
	outbound.SetAnnotations(map[string]string{
		"mondoo.com/owner": "platform-network",
	})
	outbound.SetLabels(map[string]string{
		"network.mondoo.com/classification": "approved-egress",
	})

	inputs := hbnStableEgressRouteInputs(outbound, networkInventorySettings{})
	nats := hbnStableEgressNatInputs(outbound, networkInventorySettings{})

	require.Len(t, inputs, 1)
	assert.Equal(t, "hbn-outbound:prod:internet", inputs[0].id)
	assert.Equal(t, "s-edge", inputs[0].vrf)
	assert.Equal(t, "edge", inputs[0].network)
	assert.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8"}, inputs[0].cidrs)
	assert.Equal(t, []string{"0.0.0.0/0"}, inputs[0].publicCidrs)
	assert.True(t, inputs[0].nat)
	assert.Equal(t, []string{"192.0.2.10"}, inputs[0].bgpPeerings)
	assert.Equal(t, "approved-egress", inputs[0].metadataClassification)
	assert.Equal(t, "platform-network", inputs[0].owner)
	require.Len(t, nats, 1)
	assert.Equal(t, "hbn-nat-outbound:prod:internet", nats[0].id)
	assert.Equal(t, "platform-network", nats[0].owner)
	assert.Equal(t, "approved-egress", nats[0].metadataClassification)
	assert.Equal(t, "s-edge", nats[0].vrf)
	assert.Equal(t, "edge", nats[0].network)
	assert.Equal(t, []string{"198.51.100.10"}, nats[0].addresses)
	assert.Equal(t, []string{"0.0.0.0/0", "10.0.0.0/8"}, nats[0].cidrs)
	assert.Equal(t, []string{"0.0.0.0/0"}, nats[0].publicCidrs)
}

func TestMultiNetworkPolicyCoverageArgs(t *testing.T) {
	policy := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "allow-db", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress", "Egress"},
		"ingress":     []any{map[string]any{}},
		"egress":      []any{map[string]any{}},
	})
	policy.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, "multinetworkpolicy:prod:allow-db", args[0]["__id"].Value)
	assert.Equal(t, "MultiNetworkPolicy:prod:allow-db", args[0]["policyRef"].Value)
	assert.Equal(t, []any{"prod/macvlan1", "secondary"}, args[0]["interfaces"].Value)
	assert.Equal(t, []any{"MultiNetworkPolicy:prod:allow-db"}, args[0]["multiNetworkPolicies"].Value)
	assert.Equal(t, false, args[0]["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, false, args[0]["secondaryInterfaceEgressCovered"].Value)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"secondary egress allows all traffic",
		"secondary ingress allows all traffic",
	}, args[0]["coverageGaps"].Value)
}

func TestMultiNetworkPolicyCoverageArgsDefaultDenyWhenDirectionHasNoAllowAllRules(t *testing.T) {
	policy := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "deny-db", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress", "Egress"},
	})
	policy.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, true, args[0]["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, true, args[0]["secondaryInterfaceEgressCovered"].Value)
	assert.Empty(t, args[0]["coverageGaps"].Value)
}

func TestSecondaryInterfaceCoverageArgsForPodUncoveredStringAnnotation(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
		Annotations: map[string]string{
			multusNetworksAnnotation: "macvlan1@net1, other/net2",
		},
	}

	args := secondaryInterfaceCoverageArgsForPod(pod, nil)

	require.Len(t, args, 2)
	macvlanCoverage := coverageArgsWithInterface(t, args, "prod/macvlan1")
	assert.Contains(t, macvlanCoverage["__id"].Value, "secondary-interface:prod:api-0:")
	assert.Equal(t, "Pod:prod:api-0", macvlanCoverage["workloadRef"].Value)
	assert.Equal(t, "prod", macvlanCoverage["namespace"].Value)
	assert.Equal(t, []any{"macvlan1", "net1", "prod/macvlan1", "secondary"}, macvlanCoverage["interfaces"].Value)
	assert.Equal(t, false, macvlanCoverage["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, false, macvlanCoverage["secondaryInterfaceEgressCovered"].Value)
	assert.Equal(t, []any{
		"secondary egress is not covered for network attachment prod/macvlan1",
		"secondary ingress is not covered for network attachment prod/macvlan1",
	}, macvlanCoverage["coverageGaps"].Value)
	assert.Equal(t, []any{"net2", "other/net2", "secondary"}, coverageArgsWithInterface(t, args, "other/net2")["interfaces"].Value)
}

func TestSecondaryInterfaceCoverageArgsForPodCoveredByMatchingMultiNetworkPolicy(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "db-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "db"},
		Annotations: map[string]string{
			multusNetworksAnnotation: `[{"name":"macvlan1","namespace":"prod","interface":"net1"}]`,
		},
	}
	policy := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "allow-db", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress", "Egress"},
	})
	policy.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)

	args := secondaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	require.Len(t, args, 1)
	assert.Equal(t, "MultiNetworkPolicy:prod:allow-db", args[0]["policyRef"].Value)
	assert.Equal(t, []any{"MultiNetworkPolicy:prod:allow-db"}, args[0]["multiNetworkPolicies"].Value)
	assert.Equal(t, true, args[0]["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, true, args[0]["secondaryInterfaceEgressCovered"].Value)
	assert.Empty(t, args[0]["coverageGaps"].Value)
}

func TestSecondaryInterfaceCoverageArgsForPodCombinesSplitMultiNetworkPolicies(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "db-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "db"},
		Annotations: map[string]string{
			multusNetworksAnnotation: "prod/macvlan1",
		},
	}
	ingressPolicy := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "allow-db-ingress", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress"},
	})
	ingressPolicy.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})
	egressPolicy := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "allow-db-egress", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Egress"},
	})
	egressPolicy.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})
	policyCoverage := append(networkPolicyCoverageArgsFromUnstructured(ingressPolicy), networkPolicyCoverageArgsFromUnstructured(egressPolicy)...)

	args := secondaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	require.Len(t, args, 1)
	assert.Equal(t, true, args[0]["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, true, args[0]["secondaryInterfaceEgressCovered"].Value)
	assert.Empty(t, args[0]["coverageGaps"].Value)
	assert.Equal(t, []any{
		"MultiNetworkPolicy:prod:allow-db-egress",
		"MultiNetworkPolicy:prod:allow-db-ingress",
	}, args[0]["multiNetworkPolicies"].Value)
}

func TestSecondaryInterfaceCoverageArgsForPodDoesNotHideAllowAllPolicy(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "db-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "db"},
		Annotations: map[string]string{
			multusNetworksAnnotation: "prod/macvlan1",
		},
	}
	defaultDeny := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "deny-db", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress", "Egress"},
	})
	defaultDeny.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})
	allowAll := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "allow-db", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress", "Egress"},
		"ingress":     []any{map[string]any{}},
		"egress":      []any{map[string]any{}},
	})
	allowAll.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})
	policyCoverage := append(networkPolicyCoverageArgsFromUnstructured(defaultDeny), networkPolicyCoverageArgsFromUnstructured(allowAll)...)

	args := secondaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, false, args[0]["secondaryInterfaceEgressCovered"].Value)
	assert.Equal(t, []any{
		"MultiNetworkPolicy:prod:allow-db",
		"MultiNetworkPolicy:prod:deny-db",
	}, args[0]["multiNetworkPolicies"].Value)
	assert.Contains(t, args[0]["coverageGaps"].Value, "secondary ingress is not covered for network attachment prod/macvlan1")
	assert.Contains(t, args[0]["coverageGaps"].Value, "secondary egress is not covered for network attachment prod/macvlan1")
}

func TestSecondaryInterfaceCoverageArgsForPodDoesNotMatchPolicyForSameNameDifferentNamespace(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "db-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "db"},
		Annotations: map[string]string{
			multusNetworksAnnotation: "prod/macvlan1",
		},
	}
	policy := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "allow-db", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress", "Egress"},
		"ingress":     []any{map[string]any{}},
		"egress":      []any{map[string]any{}},
	})
	policy.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "other/macvlan1"})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)

	args := secondaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	require.Len(t, args, 1)
	assert.Empty(t, args[0]["policyRef"].Value)
	assert.Equal(t, false, args[0]["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, false, args[0]["secondaryInterfaceEgressCovered"].Value)
}

func TestSecondaryInterfaceCoverageArgsForPodSelectorMismatchRemainsUncovered(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
		Annotations: map[string]string{
			multusNetworksAnnotation: "prod/macvlan1",
		},
	}
	policy := newUnstructured("k8s.cni.cncf.io/v1beta1", "MultiNetworkPolicy", "prod", "allow-db", map[string]any{
		"podSelector": map[string]any{"matchLabels": map[string]any{"app": "db"}},
		"policyTypes": []any{"Ingress", "Egress"},
		"ingress":     []any{map[string]any{}},
		"egress":      []any{map[string]any{}},
	})
	policy.SetAnnotations(map[string]string{"k8s.v1.cni.cncf.io/policy-for": "prod/macvlan1"})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)

	args := secondaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	require.Len(t, args, 1)
	assert.Empty(t, args[0]["policyRef"].Value)
	assert.Equal(t, false, args[0]["secondaryInterfaceIngressCovered"].Value)
	assert.Equal(t, false, args[0]["secondaryInterfaceEgressCovered"].Value)
}

func TestSelectorMatchesPodLabelsRejectsNonLabelSelectorMaps(t *testing.T) {
	podLabels := map[string]string{"app": "api"}

	assert.True(t, selectorMatchesPodLabels(map[string]any{}, podLabels))
	assert.True(t, selectorMatchesPodLabels(map[string]any{"matchLabels": map[string]any{"app": "api"}}, podLabels))
	assert.False(t, selectorMatchesPodLabels(map[string]any{"subject": map[string]any{"namespaces": map[string]any{}}}, podLabels))
	assert.False(t, selectorMatchesPodLabels(map[string]any{"selector": "app == 'api'"}, podLabels))
}

func TestCalicoSelectorMatchesLabels(t *testing.T) {
	values := map[string]string{
		"app":                         "api",
		"tier":                        "frontend",
		"team":                        "core",
		"projectcalico.org/namespace": "prod",
	}

	assert.True(t, calicoSelectorMatchesLabels("all()", values))
	assert.True(t, calicoSelectorMatchesLabels("app == 'api'", values))
	assert.True(t, calicoSelectorMatchesLabels(`app == "api" && tier in {"frontend","edge"} && has(team)`, values))
	assert.True(t, calicoSelectorMatchesLabels("projectcalico.org/namespace == 'prod'", values))
	assert.True(t, calicoSelectorMatchesLabels("app != 'worker' && tier not in {'batch'}", values))
	assert.False(t, calicoSelectorMatchesLabels("global()", values))
	assert.False(t, calicoSelectorMatchesLabels("app == 'worker'", values))
	assert.False(t, calicoSelectorMatchesLabels("has(missing)", values))

	// Disjunction (||): true when any branch matches, false when none do.
	assert.True(t, calicoSelectorMatchesLabels("app == 'worker' || tier == 'frontend'", values))
	assert.False(t, calicoSelectorMatchesLabels("app == 'worker' || tier == 'batch'", values))

	// Negation, including !has().
	assert.True(t, calicoSelectorMatchesLabels("!(app == 'worker')", values))
	assert.False(t, calicoSelectorMatchesLabels("!(app == 'api')", values))
	assert.True(t, calicoSelectorMatchesLabels("!has(missing)", values))
	assert.False(t, calicoSelectorMatchesLabels("!has(app)", values))

	// Precedence: && binds tighter than ||, so this is (worker && frontend) || core.
	assert.True(t, calicoSelectorMatchesLabels("app == 'worker' && tier == 'frontend' || team == 'core'", values))
	assert.False(t, calicoSelectorMatchesLabels("app == 'worker' && (tier == 'frontend' || team == 'core')", values))

	// Parenthesized disjunction is not split at the top level by &&.
	assert.True(t, calicoSelectorMatchesLabels("(app == 'api' || app == 'web') && has(team)", values))
	assert.False(t, calicoSelectorMatchesLabels("(app == 'worker' || app == 'web') && has(team)", values))
}

func TestSelectorMatchLabelsPreservesEmptyValues(t *testing.T) {
	// A matchLabels value of "" is a real constraint (label must equal ""), not
	// an absent label; it must survive into the comparison set.
	got := selectorMatchLabels(map[string]any{
		"matchLabels": map[string]any{"role": "", "tier": "frontend"},
	})
	assert.Equal(t, map[string]string{"role": "", "tier": "frontend"}, got)

	// An empty-value selector covers a target that sets the same label to "".
	candidate := map[string]any{"matchLabels": map[string]any{"role": ""}}
	target := map[string]any{"matchLabels": map[string]any{"role": "", "tier": "frontend"}}
	assert.True(t, nativeNetworkPolicySelectorCovers(candidate, target))
	// ...but not one that sets it to a different value.
	mismatch := map[string]any{"matchLabels": map[string]any{"role": "admin"}}
	assert.False(t, nativeNetworkPolicySelectorCovers(candidate, mismatch))
}

func TestSecondaryInterfaceAttachmentsFromNetworkStatusIgnoreDefaultInterface(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Annotations: map[string]string{
			multusNetworkStatusAnnotation: `[
					{"name":"kindnet","interface":"eth0","default":true},
					{"name":"prod/macvlan1","interface":"net1","ips":["10.10.0.10"]}
				]`,
		},
	}

	attachments := secondaryInterfaceAttachments(pod)

	require.Len(t, attachments, 1)
	assert.Equal(t, "prod/macvlan1", attachments[0].network)
	assert.Equal(t, "macvlan1", attachments[0].name)
	assert.Equal(t, "net1", attachments[0].interfaceName)
}

func TestSecondaryInterfaceAttachmentsDedupeSelectionAnnotationAndNetworkStatus(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Annotations: map[string]string{
			multusNetworksAnnotation: "prod/macvlan1",
			multusNetworkStatusAnnotation: `[
					{"name":"prod/macvlan1","interface":"net1","ips":["10.10.0.10"]}
				]`,
		},
	}

	attachments := secondaryInterfaceAttachments(pod)

	require.Len(t, attachments, 1)
	assert.Equal(t, "prod/macvlan1", attachments[0].network)
	assert.Equal(t, "macvlan1", attachments[0].name)
	assert.Equal(t, "net1", attachments[0].interfaceName)
}

func TestAdminNetworkPolicyCoverageArgs(t *testing.T) {
	policy := newUnstructured("policy.networking.k8s.io/v1alpha1", "AdminNetworkPolicy", "", "cluster-guardrails", map[string]any{
		"subject": map[string]any{
			"namespaces": map[string]any{"matchLabels": map[string]any{"team": "core"}},
		},
		"ingress": []any{map[string]any{"action": "Deny"}},
		"egress":  []any{map[string]any{"action": "Allow"}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, "adminnetworkpolicy:cluster-guardrails", args[0]["__id"].Value)
	assert.Equal(t, "AdminNetworkPolicy:cluster-guardrails", args[0]["policyRef"].Value)
	assert.Equal(t, []any{"AdminNetworkPolicy:cluster-guardrails"}, args[0]["adminNetworkPolicies"].Value)
	assert.Equal(t, true, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, true, args[0]["adminDefaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["adminDefaultDenyEgress"].Value)
	assert.Equal(t, []any{"admin network policy egress does not define catch-all deny traffic"}, args[0]["coverageGaps"].Value)
}

func TestAdminNetworkPolicyCoverageArgsScopedDenyIsNotDefaultDeny(t *testing.T) {
	policy := newUnstructured("policy.networking.k8s.io/v1alpha1", "AdminNetworkPolicy", "", "scoped-guardrail", map[string]any{
		"subject": map[string]any{"namespaces": map[string]any{}},
		"ingress": []any{map[string]any{
			"action": "Deny",
			"from":   []any{map[string]any{"namespaces": map[string]any{"matchLabels": map[string]any{"team": "core"}}}},
		}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["adminDefaultDenyIngress"].Value)
	assert.Equal(t, []any{
		"admin network policy egress was not observed",
		"admin network policy ingress does not define catch-all deny traffic",
	}, args[0]["coverageGaps"].Value)
}

func TestAdminNetworkPolicyCoverageArgsAllowBeforeDenyIsNotDefaultDeny(t *testing.T) {
	policy := newUnstructured("policy.networking.k8s.io/v1alpha1", "AdminNetworkPolicy", "", "ordered-guardrail", map[string]any{
		"subject": map[string]any{"namespaces": map[string]any{}},
		"ingress": []any{
			map[string]any{"action": "Allow"},
			map[string]any{"action": "Deny"},
		},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["adminDefaultDenyIngress"].Value)
	assert.Equal(t, []any{
		"admin network policy egress was not observed",
		"admin network policy ingress does not define catch-all deny traffic",
	}, args[0]["coverageGaps"].Value)
}

func TestBaselineAdminNetworkPolicyCoverageArgsMissingEgress(t *testing.T) {
	policy := newUnstructured("policy.networking.k8s.io/v1alpha1", "BaselineAdminNetworkPolicy", "", "default", map[string]any{
		"subject": map[string]any{"pods": map[string]any{"matchLabels": map[string]any{"app": "api"}}},
		"ingress": []any{map[string]any{"action": "Deny"}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, "baselineadminnetworkpolicy:default", args[0]["__id"].Value)
	assert.Equal(t, []any{"BaselineAdminNetworkPolicy:default"}, args[0]["adminNetworkPolicies"].Value)
	assert.Equal(t, true, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, true, args[0]["adminDefaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["adminDefaultDenyEgress"].Value)
	assert.Equal(t, []any{"admin network policy egress was not observed"}, args[0]["coverageGaps"].Value)
}

func TestCalicoNetworkPolicyCoverageArgs(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "allow-api", map[string]any{
		"selector":               "app == 'api'",
		"namespaceSelector":      "team == 'core'",
		"serviceAccountSelector": "sa == 'api'",
		"ingress":                []any{map[string]any{}},
		"egress":                 []any{map[string]any{}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, []any{"NetworkPolicy:prod:allow-api"}, args[0]["calicoPolicies"].Value)
	assert.Equal(t, []any{"primary"}, args[0]["interfaces"].Value)
	assert.Equal(t, map[string]any{
		"namespaceSelector":      "team == 'core'",
		"selector":               "app == 'api'",
		"serviceAccountSelector": "sa == 'api'",
	}, args[0]["podSelector"].Value)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"calico egress default-deny was not observed",
		"calico ingress default-deny was not observed",
	}, args[0]["coverageGaps"].Value)
}

func TestCalicoEmptyTypedPolicyIsDefaultDeny(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "default-deny", map[string]any{
		"selector": "all()",
		"types":    []any{"Ingress", "Egress"},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, true, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, true, args[0]["defaultDenyEgress"].Value)
	assert.Empty(t, args[0]["coverageGaps"].Value)
}

func TestPrimaryInterfaceCoverageArgsForPodAppliesCalicoAllSelector(t *testing.T) {
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}
	policy := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "default-deny", map[string]any{
		"selector": "all()",
		"types":    []any{"Ingress", "Egress"},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)

	args := primaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	assert.Equal(t, []any{"NetworkPolicy:prod:default-deny"}, args["calicoPolicies"].Value)
	assert.Equal(t, true, args["defaultDenyIngress"].Value)
	assert.Equal(t, true, args["defaultDenyEgress"].Value)
	assert.NotContains(t, args["coverageGaps"].Value, "primary ingress is not default-deny for pod prod/api-0")
	assert.NotContains(t, args["coverageGaps"].Value, "primary egress is not default-deny for pod prod/api-0")
}

func TestPrimaryInterfaceCoverageArgsForPodAppliesCalicoSelectorToMatchingPodOnly(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "api-default-deny", map[string]any{
		"selector": "app == 'api' && tier in {'frontend','edge'} && has(team)",
		"types":    []any{"Ingress", "Egress"},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)
	matchingPod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api", "tier": "frontend", "team": "core"},
	}
	otherPod := &corev1.Pod{
		Name:      "worker-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "worker", "tier": "frontend", "team": "core"},
	}

	matchingArgs := primaryInterfaceCoverageArgsForPod(matchingPod, policyCoverage)
	otherArgs := primaryInterfaceCoverageArgsForPod(otherPod, policyCoverage)

	assert.Equal(t, []any{"NetworkPolicy:prod:api-default-deny"}, matchingArgs["calicoPolicies"].Value)
	assert.Equal(t, true, matchingArgs["defaultDenyIngress"].Value)
	assert.Equal(t, true, matchingArgs["defaultDenyEgress"].Value)
	assert.Empty(t, otherArgs["calicoPolicies"].Value)
	assert.Equal(t, false, otherArgs["defaultDenyIngress"].Value)
	assert.Equal(t, false, otherArgs["defaultDenyEgress"].Value)
}

func TestPrimaryInterfaceCoverageArgsForPodAppliesCalicoUnaryPrecedence(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "api-without-team-default-deny", map[string]any{
		"selector": "!has(team) && app == 'api'",
		"types":    []any{"Ingress", "Egress"},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)
	matchingPod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}
	teamPod := &corev1.Pod{
		Name:      "api-1",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api", "team": "core"},
	}

	matchingArgs := primaryInterfaceCoverageArgsForPod(matchingPod, policyCoverage)
	teamArgs := primaryInterfaceCoverageArgsForPod(teamPod, policyCoverage)

	assert.Equal(t, []any{"NetworkPolicy:prod:api-without-team-default-deny"}, matchingArgs["calicoPolicies"].Value)
	assert.Equal(t, true, matchingArgs["defaultDenyIngress"].Value)
	assert.Equal(t, true, matchingArgs["defaultDenyEgress"].Value)
	assert.Empty(t, teamArgs["calicoPolicies"].Value)
	assert.Equal(t, false, teamArgs["defaultDenyIngress"].Value)
	assert.Equal(t, false, teamArgs["defaultDenyEgress"].Value)
}

func TestPrimaryInterfaceCoverageArgsForPodAppliesCalicoNamespaceSelector(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "GlobalNetworkPolicy", "", "core-default-deny", map[string]any{
		"selector":          "app == 'api'",
		"namespaceSelector": "team == 'core'",
		"types":             []any{"Ingress", "Egress"},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}

	coreArgs := primaryInterfaceCoverageArgsForPodWithNamespaceLabels(pod, policyCoverage, map[string]map[string]string{
		"prod": map[string]string{"team": "core"},
	})
	platformArgs := primaryInterfaceCoverageArgsForPodWithNamespaceLabels(pod, policyCoverage, map[string]map[string]string{
		"prod": map[string]string{"team": "platform"},
	})

	assert.Equal(t, []any{"GlobalNetworkPolicy:core-default-deny"}, coreArgs["calicoPolicies"].Value)
	assert.Equal(t, true, coreArgs["defaultDenyIngress"].Value)
	assert.Equal(t, true, coreArgs["defaultDenyEgress"].Value)
	assert.Empty(t, platformArgs["calicoPolicies"].Value)
	assert.Equal(t, false, platformArgs["defaultDenyIngress"].Value)
	assert.Equal(t, false, platformArgs["defaultDenyEgress"].Value)
}

func TestPrimaryInterfaceCoverageArgsForPodAppliesCalicoServiceAccountSelector(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "api-serviceaccount-default-deny", map[string]any{
		"selector":               "all()",
		"serviceAccountSelector": "role == 'api'",
		"types":                  []any{"Ingress", "Egress"},
	})
	policyCoverage := networkPolicyCoverageArgsFromUnstructured(policy)
	apiPod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
		Spec:      corev1.PodSpec{ServiceAccountName: "api"},
	}
	workerPod := &corev1.Pod{
		Name:      "worker-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "worker"},
		Spec:      corev1.PodSpec{ServiceAccountName: "worker"},
	}
	serviceAccountLabels := serviceAccountLabelsByPodKey([]any{
		&mqlK8sServiceaccount{obj: &corev1.ServiceAccount{
			Name: "api", Namespace: "prod", Labels: map[string]string{"role": "api"},
		}},
		&mqlK8sServiceaccount{obj: &corev1.ServiceAccount{
			Name: "worker", Namespace: "prod", Labels: map[string]string{"role": "worker"},
		}},
	})

	apiArgs := primaryInterfaceCoverageArgsForPodWithSelectorContext(apiPod, policyCoverage, nil, serviceAccountLabels)
	workerArgs := primaryInterfaceCoverageArgsForPodWithSelectorContext(workerPod, policyCoverage, nil, serviceAccountLabels)
	missingLabelsArgs := primaryInterfaceCoverageArgsForPodWithSelectorContext(apiPod, policyCoverage, nil, nil)

	assert.Equal(t, []any{"NetworkPolicy:prod:api-serviceaccount-default-deny"}, apiArgs["calicoPolicies"].Value)
	assert.Equal(t, true, apiArgs["defaultDenyIngress"].Value)
	assert.Equal(t, true, apiArgs["defaultDenyEgress"].Value)
	assert.Empty(t, workerArgs["calicoPolicies"].Value)
	assert.Equal(t, false, workerArgs["defaultDenyIngress"].Value)
	assert.Equal(t, false, workerArgs["defaultDenyEgress"].Value)
	assert.Empty(t, missingLabelsArgs["calicoPolicies"].Value)
	assert.Equal(t, false, missingLabelsArgs["defaultDenyIngress"].Value)
	assert.Equal(t, false, missingLabelsArgs["defaultDenyEgress"].Value)
}

func TestPrimaryInterfaceCoverageArgsForPodKeepsDefaultDenyWithScopedCalicoPolicy(t *testing.T) {
	defaultDeny := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "default-deny", map[string]any{
		"selector": "all()",
		"types":    []any{"Egress"},
	})
	scopedDeny := newUnstructured("crd.projectcalico.org/v1", "NetworkPolicy", "prod", "deny-public-egress", map[string]any{
		"selector": "app == 'api'",
		"egress": []any{map[string]any{
			"action":      "Deny",
			"destination": map[string]any{"nets": []any{"203.0.113.0/24"}},
		}},
	})
	policyCoverage := append(networkPolicyCoverageArgsFromUnstructured(defaultDeny), networkPolicyCoverageArgsFromUnstructured(scopedDeny)...)
	pod := &corev1.Pod{
		Name:      "api-0",
		Namespace: "prod",
		Labels:    map[string]string{"app": "api"},
	}

	args := primaryInterfaceCoverageArgsForPod(pod, policyCoverage)

	assert.Equal(t, []any{
		"NetworkPolicy:prod:default-deny",
		"NetworkPolicy:prod:deny-public-egress",
	}, args["calicoPolicies"].Value)
	assert.Equal(t, true, args["defaultDenyEgress"].Value)
	assert.NotContains(t, args["coverageGaps"].Value, "primary egress is not default-deny for pod prod/api-0")
}

func TestCalicoGlobalNetworkPolicyCoverageArgs(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "GlobalNetworkPolicy", "", "deny-public-egress", map[string]any{
		"selector": "projectcalico.org/namespace == 'prod'",
		"egress":   []any{map[string]any{"action": "Deny"}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, "globalnetworkpolicy::deny-public-egress", args[0]["__id"].Value)
	assert.Equal(t, []any{"GlobalNetworkPolicy:deny-public-egress"}, args[0]["calicoPolicies"].Value)
	assert.Equal(t, true, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{"calico ingress policy was not observed"}, args[0]["coverageGaps"].Value)
}

func TestCalicoScopedDenyIsNotDefaultDeny(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "GlobalNetworkPolicy", "", "deny-api-egress", map[string]any{
		"selector": "projectcalico.org/namespace == 'prod'",
		"egress": []any{map[string]any{
			"action":      "Deny",
			"destination": map[string]any{"nets": []any{"203.0.113.0/24"}},
		}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"calico egress default-deny was not observed",
		"calico ingress policy was not observed",
	}, args[0]["coverageGaps"].Value)
}

func TestCalicoCatchAllAllowBeforeDenyIsNotDefaultDeny(t *testing.T) {
	policy := newUnstructured("crd.projectcalico.org/v1", "GlobalNetworkPolicy", "", "ordered-egress", map[string]any{
		"selector": "projectcalico.org/namespace == 'prod'",
		"egress": []any{
			map[string]any{"action": "Allow"},
			map[string]any{"action": "Deny"},
		},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"calico egress default-deny was not observed",
		"calico ingress policy was not observed",
	}, args[0]["coverageGaps"].Value)
}

func TestCiliumNetworkPolicyCoverageArgs(t *testing.T) {
	policy := newUnstructured("cilium.io/v2", "CiliumNetworkPolicy", "prod", "allow-web", map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
		"ingress":          []any{map[string]any{}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, []any{"CiliumNetworkPolicy:prod:allow-web"}, args[0]["ciliumPolicies"].Value)
	assert.Equal(t, map[string]any{"matchLabels": map[string]any{"app": "web"}}, args[0]["podSelector"].Value)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"cilium egress policy was not observed",
		"cilium ingress default-deny was not observed",
	}, args[0]["coverageGaps"].Value)
}

func TestCiliumScopedDenyIsNotDefaultDeny(t *testing.T) {
	policy := newUnstructured("cilium.io/v2", "CiliumNetworkPolicy", "prod", "deny-world", map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{"app": "web"}},
		"egressDeny": []any{map[string]any{
			"toCIDR": []any{"203.0.113.0/24"},
		}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"cilium egress default-deny was not observed",
		"cilium ingress policy was not observed",
	}, args[0]["coverageGaps"].Value)
}

func TestCiliumClusterwideNetworkPolicyCoverageArgs(t *testing.T) {
	policy := newUnstructured("cilium.io/v2", "CiliumClusterwideNetworkPolicy", "", "cluster-deny", map[string]any{
		"endpointSelector": map[string]any{"matchLabels": map[string]any{"role": "edge"}},
		"egressDeny":       []any{map[string]any{}},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, "ciliumclusterwidenetworkpolicy::cluster-deny", args[0]["__id"].Value)
	assert.Equal(t, []any{"CiliumClusterwideNetworkPolicy:cluster-deny"}, args[0]["ciliumPolicies"].Value)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, true, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{"cilium ingress policy was not observed"}, args[0]["coverageGaps"].Value)
}

func TestCiliumNetworkPolicyEnableDefaultDenyFalse(t *testing.T) {
	policy := newUnstructured("cilium.io/v2", "CiliumNetworkPolicy", "prod", "observe-only", map[string]any{
		"endpointSelector":  map[string]any{"matchLabels": map[string]any{"app": "web"}},
		"ingress":           []any{map[string]any{}},
		"enableDefaultDeny": map[string]any{"ingress": false},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, []any{
		"cilium egress policy was not observed",
		"cilium ingress default-deny was not observed",
	}, args[0]["coverageGaps"].Value)
}

func TestCiliumEnableDefaultDenyWithoutRulesDoesNotCoverDirection(t *testing.T) {
	policy := newUnstructured("cilium.io/v2", "CiliumNetworkPolicy", "prod", "metadata-only", map[string]any{
		"endpointSelector":  map[string]any{"matchLabels": map[string]any{"app": "web"}},
		"enableDefaultDeny": map[string]any{"ingress": true, "egress": true},
	})

	args := networkPolicyCoverageArgsFromUnstructured(policy)

	require.Len(t, args, 1)
	assert.Equal(t, false, args[0]["defaultDenyIngress"].Value)
	assert.Equal(t, false, args[0]["defaultDenyEgress"].Value)
	assert.Equal(t, []any{
		"cilium egress policy was not observed",
		"cilium ingress policy was not observed",
	}, args[0]["coverageGaps"].Value)
}

func TestOptionalResourceNotFound(t *testing.T) {
	assert.True(t, optionalResourceNotFound(errors.New(`could not find api kind "widgets.v1.example.com"`)))
	assert.True(t, optionalResourceNotFound(apierrors.NewNotFound(schema.GroupResource{Group: "example.com", Resource: "widgets"}, "example")))
	assert.False(t, optionalResourceNotFound(errors.New("widgets.v1.example.com is forbidden")))
	assert.True(t, optionalResourceUnavailable(errors.New(`could not find api kind "widgets.v1.example.com"`)))
	assert.True(t, optionalResourceUnavailable(apierrors.NewForbidden(schema.GroupResource{Group: "example.com", Resource: "widgets"}, "example", errors.New("denied"))))
	assert.True(t, optionalResourceUnavailable(errors.New("widgets.v1.example.com is forbidden")))
}

func TestOptionalNetworkPolicyCoverageKindsIncludeMultiNetworkPolicyVersions(t *testing.T) {
	assert.Contains(t, optionalNetworkPolicyCoverageKinds, "adminnetworkpolicies.v1alpha1.policy.networking.k8s.io")
	assert.Contains(t, optionalNetworkPolicyCoverageKinds, "baselineadminnetworkpolicies.v1alpha1.policy.networking.k8s.io")
	assert.Contains(t, optionalNetworkPolicyCoverageKinds, "multi-networkpolicies.v1beta1.k8s.cni.cncf.io")
	assert.Contains(t, optionalNetworkPolicyCoverageKinds, "multi-networkpolicies.v1beta2.k8s.cni.cncf.io")
}

func TestOptionalGatewayRouteExposureKindsIncludeAllGatewayRouteTypes(t *testing.T) {
	assert.Contains(t, optionalGatewayRouteExposureKinds, "httproutes.v1.gateway.networking.k8s.io")
	assert.Contains(t, optionalGatewayRouteExposureKinds, "grpcroutes.v1.gateway.networking.k8s.io")
	assert.Contains(t, optionalGatewayRouteExposureKinds, "tlsroutes.v1alpha2.gateway.networking.k8s.io")
	assert.Contains(t, optionalGatewayRouteExposureKinds, "tcproutes.v1alpha2.gateway.networking.k8s.io")
	assert.Contains(t, optionalGatewayRouteExposureKinds, "udproutes.v1alpha2.gateway.networking.k8s.io")
	assert.Contains(t, tlsRouteResourceKinds, "tlsroutes.v1.gateway.networking.k8s.io")
	assert.Contains(t, tlsRouteResourceKinds, "tlsroutes.v1beta1.gateway.networking.k8s.io")
	assert.Contains(t, tlsRouteResourceKinds, "tlsroutes.v1alpha2.gateway.networking.k8s.io")
	assert.Contains(t, tcpRouteResourceKinds, "tcproutes.v1.gateway.networking.k8s.io")
	assert.Contains(t, tcpRouteResourceKinds, "tcproutes.v1beta1.gateway.networking.k8s.io")
	assert.Contains(t, tcpRouteResourceKinds, "tcproutes.v1alpha2.gateway.networking.k8s.io")
	assert.Contains(t, udpRouteResourceKinds, "udproutes.v1.gateway.networking.k8s.io")
	assert.Contains(t, udpRouteResourceKinds, "udproutes.v1beta1.gateway.networking.k8s.io")
	assert.Contains(t, udpRouteResourceKinds, "udproutes.v1alpha2.gateway.networking.k8s.io")
}

func TestOptionalGatewayExposureKindsIncludeGatewayVersions(t *testing.T) {
	assert.Contains(t, optionalGatewayExposureKinds, "gateways.v1.gateway.networking.k8s.io")
	assert.Contains(t, optionalGatewayExposureKinds, "gateways.v1beta1.gateway.networking.k8s.io")
}

func TestGatewayFromUnstructuredV1Beta1(t *testing.T) {
	gw := newUnstructured("gateway.networking.k8s.io/v1beta1", "Gateway", "prod", "edge", map[string]any{
		"listeners": []any{map[string]any{
			"name":     "https",
			"port":     int64(443),
			"protocol": "HTTPS",
		}},
	})
	gw.Object["status"] = map[string]any{
		"addresses": []any{map[string]any{"value": "8.8.8.8"}},
	}

	converted := gatewayFromUnstructured(gw)

	require.NotNil(t, converted)
	assert.Equal(t, "prod", converted.Namespace)
	assert.Equal(t, "edge", converted.Name)
	assert.Equal(t, "8.8.8.8", converted.Status.Addresses[0].Value)
}

type fakeNamespacedNetworkObject struct {
	namespace string
}

func (f fakeNamespacedNetworkObject) GetNamespace() *plugin.TValue[string] {
	return &plugin.TValue[string]{Data: f.namespace}
}

func TestNetworkObjectVisibleInNamespaceIncludesClusterScoped(t *testing.T) {
	assert.True(t, networkObjectVisibleInNamespace(fakeNamespacedNetworkObject{namespace: "prod"}, "prod"))
	assert.True(t, networkObjectVisibleInNamespace(fakeNamespacedNetworkObject{}, "prod"))
	assert.False(t, networkObjectVisibleInNamespace(fakeNamespacedNetworkObject{namespace: "dev"}, "prod"))
	assert.False(t, networkObjectVisibleInNamespace(struct{}{}, "prod"))
}

func TestOptionalHBNKindsIncludeLegacyAndStableFamilies(t *testing.T) {
	assert.Contains(t, optionalHBNNetworkExposureKinds, "inbounds.v1alpha1.network.t-caas.telekom.com")
	assert.Contains(t, optionalHBNStableEgressKinds, "vrfs.v1alpha1.network.t-caas.telekom.com")
	assert.Contains(t, optionalHBNStableEgressKinds, "outbounds.v1alpha1.network.t-caas.telekom.com")
	assert.Contains(t, optionalHBNStableEgressKinds, "networkconnectors.v1alpha1.network-connector.sylvaproject.org")
}

func TestEnabledHBNOptionalKindsRespectOptions(t *testing.T) {
	settings := networkInventorySettings{hbnEnabled: false, hbnIncludeLegacyResources: true}
	assert.Empty(t, enabledHBNOptionalKinds(settings, optionalHBNNetworkExposureKinds))

	settings = networkInventorySettings{hbnEnabled: true, hbnIncludeLegacyResources: false}
	kinds := enabledHBNOptionalKinds(settings, optionalHBNNetworkExposureKinds)
	assert.Contains(t, kinds, "inbounds.v1alpha1.network-connector.sylvaproject.org")
	assert.NotContains(t, kinds, "inbounds.v1alpha1.network.t-caas.telekom.com")
	assert.NotContains(t, kinds, "inbounds.v1alpha1.networking.t-caas.telekom.com")
}

func TestEnabledNetworkPolicyCoverageKindsRespectMultiNetworkPolicyOption(t *testing.T) {
	settings := networkInventorySettings{multiNetworkPolicyEnabled: false}
	kinds := enabledNetworkPolicyCoverageKinds(settings)

	assert.NotContains(t, kinds, "multi-networkpolicies.v1beta1.k8s.cni.cncf.io")
	assert.NotContains(t, kinds, "multinetworkpolicies.v1beta1.k8s.cni.cncf.io")
	assert.Contains(t, kinds, "adminnetworkpolicies.v1alpha1.policy.networking.k8s.io")
	assert.Contains(t, kinds, "ciliumnetworkpolicies.v2.cilium.io")
}

func newUnstructured(apiVersion, kind, namespace, name string, spec map[string]any) *unstructured.Unstructured {
	u := &unstructured.Unstructured{Object: map[string]any{
		"spec": spec,
	}}
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		panic(err)
	}
	u.SetGroupVersionKind(gv.WithKind(kind))
	u.SetNamespace(namespace)
	u.SetName(name)
	return u
}

func coverageArgsWithInterface(t *testing.T, args []map[string]*llx.RawData, want string) map[string]*llx.RawData {
	t.Helper()
	for _, item := range args {
		for _, iface := range item["interfaces"].Value.([]any) {
			if iface == want {
				return item
			}
		}
	}
	require.Failf(t, "coverage interface not found", "wanted interface %q", want)
	return nil
}

func coverageArgsWithPolicyRef(t *testing.T, args []map[string]*llx.RawData, want string) map[string]*llx.RawData {
	t.Helper()
	for _, item := range args {
		if item["policyRef"].Value == want {
			return item
		}
	}
	require.Failf(t, "coverage policyRef not found", "wanted policyRef %q", want)
	return nil
}

func TestClassifyAddressInternalCloudLoadBalancerHostname(t *testing.T) {
	// AWS names an internal ALB/CLB with an internal- prefix and never applies it
	// to an internet-facing one, so the prefix is a safe negative signal.
	assert.Equal(t, "internalHostname",
		classifyAddress("internal-bba-prod-ptp-2120307359.eu-central-1.elb.amazonaws.com"))
	// An internet-facing load balancer of the same shape stays internet-reachable.
	assert.Equal(t, "hostname",
		classifyAddress("bba-prod-ptp-2120307359.eu-central-1.elb.amazonaws.com"))
	// NLB DNS layout puts the region after .elb.; the prefix rule still applies.
	assert.Equal(t, "internalHostname",
		classifyAddress("internal-sftpgo-sftp-e4600cc5.elb.eu-central-1.amazonaws.com"))
	// The prefix alone must not be enough outside AWS load balancer domains.
	assert.Equal(t, "hostname", classifyAddress("internal-tools.example.com"))
}

func TestServiceNetworkExposureArgsInternalSchemeAnnotation(t *testing.T) {
	// An internal NLB's DNS name is indistinguishable from an internet-facing one,
	// so only the declared scheme reveals that it is VPC-only.
	svc := &corev1.Service{
		Name:        "sftpgo-sftp",
		Namespace:   "sftpgo",
		Annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal"},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 22, Protocol: corev1.ProtocolTCP}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{
					Hostname: "sftpgo-sftp-e4600cc5a973d130.elb.eu-central-1.amazonaws.com",
				}},
			},
		},
	}

	args := serviceNetworkExposureArgs(svc, nil)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "internalLoadBalancerScheme", args[0]["exposureReason"].Value)
}

func TestServiceNetworkExposureArgsInternetFacingSchemeStaysExposed(t *testing.T) {
	// Guard against the annotation check over-reaching: an explicitly
	// internet-facing scheme must remain flagged.
	svc := &corev1.Service{
		Name:        "sftpgo-sftp",
		Namespace:   "sftpgo",
		Annotations: map[string]string{"service.beta.kubernetes.io/aws-load-balancer-scheme": "internet-facing"},
		Spec: corev1.ServiceSpec{
			Type:  corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{{Port: 22, Protocol: corev1.ProtocolTCP}},
		},
		Status: corev1.ServiceStatus{
			LoadBalancer: corev1.LoadBalancerStatus{
				Ingress: []corev1.LoadBalancerIngress{{
					Hostname: "sftpgo-sftp-e4600cc5a973d130.elb.eu-central-1.amazonaws.com",
				}},
			},
		},
	}

	args := serviceNetworkExposureArgs(svc, nil)
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "publicLoadBalancerAddress", args[0]["exposureReason"].Value)
}

func TestIngressNetworkExposureArgsInternalSchemeAnnotation(t *testing.T) {
	// The published address is an internal ALB and the rule host is an ordinary
	// public-looking name; the declared scheme must keep this off the exposed list.
	ing := &networkingv1.Ingress{
		Name:        "bba-prod-ptp",
		Namespace:   "bba-prod-ptp",
		Annotations: map[string]string{"alb.ingress.kubernetes.io/scheme": "internal"},
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "plan.example.com"}},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{{
					Hostname: "internal-bba-prod-ptp-2120307359.eu-central-1.elb.amazonaws.com",
				}},
			},
		},
	}

	args := ingressNetworkExposureArgs(ing)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "internalLoadBalancerScheme", args[0]["exposureReason"].Value)
}

func TestIngressNetworkExposureArgsUnannotatedInternalAlbNotExposed(t *testing.T) {
	// The AWS Load Balancer Controller defaults to an internal scheme, so an
	// unannotated Ingress on an internal- ALB must be classified from its address.
	// The rule host is a public-looking name on purpose: an Ingress essentially
	// always defines one, and it must not override the published internal address.
	ing := &networkingv1.Ingress{
		Name: "atp-prod-ptp", Namespace: "atp-prod-ptp",
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "plan.atp.example.com"}},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{{
					Hostname: "internal-atp-prod-ptp-1954117370.eu-central-1.elb.amazonaws.com",
				}},
			},
		},
	}

	args := ingressNetworkExposureArgs(ing)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "privateIngressAddress", args[0]["exposureReason"].Value)
	// The reported address set still unions both, so the evidence stays complete.
	assert.Equal(t, []any{
		"internal-atp-prod-ptp-1954117370.eu-central-1.elb.amazonaws.com",
		"plan.atp.example.com",
	}, args[0]["addresses"].Value)
}

func TestIngressNetworkExposureArgsPublicAlbWithRuleHostStaysExposed(t *testing.T) {
	// Mirror of the test above: a genuinely internet-facing ALB must remain flagged
	// once reachability is read from the published address instead of the rule host.
	ing := &networkingv1.Ingress{
		Name: "nbe-prod-public", Namespace: "nbe-prod-ptp",
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "plan.nbe.example.com"}},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{{
					Hostname: "nbe-prod-public-795082853.eu-central-1.elb.amazonaws.com",
				}},
			},
		},
	}

	args := ingressNetworkExposureArgs(ing)
	require.Len(t, args, 1)

	assert.Equal(t, true, args[0]["internetExposed"].Value)
	assert.Equal(t, "publicIngressAddress", args[0]["exposureReason"].Value)
}

func TestIngressNetworkExposureArgsPrivateIpWithPublicRuleHost(t *testing.T) {
	// Not AWS-specific: an Ingress published on a private IP is internal, however
	// public its rule hostnames look.
	ing := &networkingv1.Ingress{
		Name: "onprem", Namespace: "prod",
		Spec: networkingv1.IngressSpec{
			Rules: []networkingv1.IngressRule{{Host: "app.example.com"}},
		},
		Status: networkingv1.IngressStatus{
			LoadBalancer: networkingv1.IngressLoadBalancerStatus{
				Ingress: []networkingv1.IngressLoadBalancerIngress{{IP: "10.0.0.5"}},
			},
		},
	}

	args := ingressNetworkExposureArgs(ing)
	require.Len(t, args, 1)

	assert.Equal(t, false, args[0]["internetExposed"].Value)
	assert.Equal(t, "privateIngressAddress", args[0]["exposureReason"].Value)
}
