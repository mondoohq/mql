// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	kyvernoMappingAnnotationCheckUid = "mondoo.com/check-uid"
	kyvernoMappingAnnotationCheckMrn = "mondoo.com/check-mrn"
	kyvernoMappingAnnotationPolicy   = "mondoo.com/policy-uid"
	kyvernoMappingAnnotationReason   = "mondoo.com/mapping-reason"

	kyvernoValidUntilAnnotationMondoo = "exceptions.mondoo.com/valid-until"
	kyvernoValidUntilAnnotation       = "kyverno.io/valid-until"
	kyvernoJustificationMondoo        = "exceptions.mondoo.com/justification"
	kyvernoJustificationAnnotation    = "kyverno.io/exception-reason"
	kyvernoOwnerAnnotation            = "exceptions.mondoo.com/owner"
	kyvernoTicketAnnotation           = "exceptions.mondoo.com/ticket"

	kyvernoBuiltinMondooPolicyUid              = "mondoo-kubernetes-security"
	kyvernoBuiltinMondooBestPracticesPolicyUid = "mondoo-kubernetes-best-practices"
)

var (
	kyvernoDefaultMappingAnnotationCheckUids       = []string{kyvernoMappingAnnotationCheckUid}
	kyvernoDefaultMappingAnnotationCheckMrns       = []string{kyvernoMappingAnnotationCheckMrn}
	kyvernoDefaultMappingAnnotationPolicyUids      = []string{kyvernoMappingAnnotationPolicy}
	kyvernoDefaultMappingAnnotationReasons         = []string{kyvernoMappingAnnotationReason}
	kyvernoDefaultExceptionAnnotationValidUntil    = []string{kyvernoValidUntilAnnotationMondoo, kyvernoValidUntilAnnotation}
	kyvernoDefaultExceptionAnnotationJustification = []string{kyvernoJustificationMondoo, kyvernoJustificationAnnotation}
	kyvernoDefaultExceptionAnnotationOwners        = []string{kyvernoOwnerAnnotation}
	kyvernoDefaultExceptionAnnotationTickets       = []string{kyvernoTicketAnnotation}
)

type mqlK8sKyvernoInternal struct {
	lock                               sync.Mutex
	cachedPolicyExceptionObjects       []runtime.Object
	cachedPolicyExceptionObjectsLoaded bool
}

type mqlK8sKyvernoPolicyInternal struct {
	obj          metav1.Object
	manifestData map[string]any
	ruleData     []*kyvernoRuleData
}

type mqlK8sKyvernoRuleInternal struct {
	data *kyvernoRuleData
}

type mqlK8sKyvernoPolicyreportInternal struct {
	obj          metav1.Object
	manifestData map[string]any
	resultData   []*kyvernoResultData
}

type mqlK8sKyvernoResultInternal struct {
	data *kyvernoResultData
}

type mqlK8sKyvernoPolicyexceptionInternal struct {
	obj          metav1.Object
	manifestData map[string]any
	data         *kyvernoExceptionData
}

type mqlK8sKyvernoMappingInternal struct {
	data kyvernoMappingData
}

type kyvernoRuleData struct {
	id               string
	policyId         string
	policyApiVersion string
	policyKind       string
	policyNamespace  string
	policyName       string
	name             string
	ruleType         string
	matchKinds       []string
	match            map[string]any
	exclude          map[string]any
	conditions       []map[string]any
	manifest         map[string]any
}

type kyvernoResultData struct {
	id                   string
	reportId             string
	reportApiVersion     string
	reportKind           string
	reportNamespace      string
	reportName           string
	scopeApiVersion      string
	scopeKind            string
	scopeNamespace       string
	scopeName            string
	scopeUid             string
	scopeLabels          map[string]string
	scopeNamespaceLabels map[string]string
	policy               string
	rule                 string
	category             string
	severity             string
	source               string
	result               string
	scored               bool
	message              string
	timestamp            time.Time
	properties           map[string]string
	mappedCheckUids      []string
	mappedCheckMrns      []string
	mappedExceptionIds   []string
	manifest             map[string]any
}

type kyvernoExceptionData struct {
	namespace                string
	name                     string
	policyRefs               []string
	ruleNames                []string
	ruleNamesByPolicyRef     map[string][]string
	matchKinds               []string
	matchNamespaces          []string
	matchNames               []string
	matchLabelSelectors      []labels.Selector
	matchNamespaceSelectors  []labels.Selector
	matchScope               kyvernoMatchScope
	excludeScope             kyvernoMatchScope
	unsupportedScope         bool
	match                    map[string]any
	validUntil               string
	validUntilTime           *time.Time
	justification            string
	owner                    string
	ticket                   string
	computedStatus           string
	statusReasons            []string
	mappedMondooCheckUids    []string
	mappedMondooExceptionIds []string
}

type kyvernoMatchScope struct {
	directClauses []kyvernoMatchClause
	anyClauses    []kyvernoMatchClause
	allClauses    []kyvernoMatchClause
}

type kyvernoMatchClause struct {
	kinds             []string
	namespaces        []string
	names             []string
	labelSelector     labels.Selector
	namespaceSelector labels.Selector
	unsupported       bool
}

type kyvernoMappingData struct {
	id               string
	kyvernoKind      string
	kyvernoNamespace string
	kyvernoPolicy    string
	kyvernoRule      string
	mondooPolicyUid  string
	mondooCheckUid   string
	mondooCheckMrn   string
	source           string
	confidence       string
	reason           string
}

type kyvernoPolicyExceptionMatch struct {
	id        string
	policyRef string
	data      *kyvernoExceptionData
}

type kyvernoResourceKind struct {
	lookup string
}

var (
	kyvernoCELNamespaceEquals = []*regexp.Regexp{
		regexp.MustCompile(`(?:object|request)\.metadata\.namespace\s*==\s*['"]([^'"]+)['"]`),
		regexp.MustCompile(`request\.namespace\s*==\s*['"]([^'"]+)['"]`),
	}
	kyvernoCELNameEquals = []*regexp.Regexp{
		regexp.MustCompile(`(?:object|request)\.metadata\.name\s*==\s*['"]([^'"]+)['"]`),
	}
	kyvernoCELKindEquals = []*regexp.Regexp{
		regexp.MustCompile(`(?:object|request)\.kind\s*==\s*['"]([^'"]+)['"]`),
	}
	kyvernoK8sKindPluralAliases = map[string]string{
		"configmaps":               "configmap",
		"cronjobs":                 "cronjob",
		"daemonsets":               "daemonset",
		"deployments":              "deployment",
		"horizontalpodautoscalers": "horizontalpodautoscaler",
		"ingresses":                "ingress",
		"jobs":                     "job",
		"namespaces":               "namespace",
		"networkpolicies":          "networkpolicy",
		"persistentvolumeclaims":   "persistentvolumeclaim",
		"persistentvolumes":        "persistentvolume",
		"pods":                     "pod",
		"replicasets":              "replicaset",
		"secrets":                  "secret",
		"services":                 "service",
		"statefulsets":             "statefulset",
		"storageclasses":           "storageclass",
	}
)

var kyvernoPolicyKinds = []kyvernoResourceKind{
	{lookup: "clusterpolicies.v1.kyverno.io"},
	{lookup: "clusterpolicy.v1.kyverno.io"},
	{lookup: "policies.v1.kyverno.io"},
	{lookup: "policy.v1.kyverno.io"},
	{lookup: "validatingpolicies.v1.policies.kyverno.io"},
	{lookup: "validatingpolicy.v1.policies.kyverno.io"},
	{lookup: "validatingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "validatingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "validatingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "validatingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedvalidatingpolicies.v1.policies.kyverno.io"},
	{lookup: "namespacedvalidatingpolicy.v1.policies.kyverno.io"},
	{lookup: "namespacedvalidatingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedvalidatingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedvalidatingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedvalidatingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "imagevalidatingpolicies.v1.policies.kyverno.io"},
	{lookup: "imagevalidatingpolicy.v1.policies.kyverno.io"},
	{lookup: "imagevalidatingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "imagevalidatingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "imagevalidatingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "imagevalidatingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedimagevalidatingpolicies.v1.policies.kyverno.io"},
	{lookup: "namespacedimagevalidatingpolicy.v1.policies.kyverno.io"},
	{lookup: "namespacedimagevalidatingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedimagevalidatingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedimagevalidatingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedimagevalidatingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "mutatingpolicies.v1.policies.kyverno.io"},
	{lookup: "mutatingpolicy.v1.policies.kyverno.io"},
	{lookup: "mutatingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "mutatingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "mutatingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "mutatingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedmutatingpolicies.v1.policies.kyverno.io"},
	{lookup: "namespacedmutatingpolicy.v1.policies.kyverno.io"},
	{lookup: "namespacedmutatingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedmutatingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedmutatingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedmutatingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "generatingpolicies.v1.policies.kyverno.io"},
	{lookup: "generatingpolicy.v1.policies.kyverno.io"},
	{lookup: "generatingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "generatingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "generatingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "generatingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedgeneratingpolicies.v1.policies.kyverno.io"},
	{lookup: "namespacedgeneratingpolicy.v1.policies.kyverno.io"},
	{lookup: "namespacedgeneratingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedgeneratingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "namespacedgeneratingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "namespacedgeneratingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "deletingpolicies.v1.policies.kyverno.io"},
	{lookup: "deletingpolicy.v1.policies.kyverno.io"},
	{lookup: "deletingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "deletingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "deletingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "deletingpolicy.v1alpha1.policies.kyverno.io"},
	{lookup: "namespaceddeletingpolicies.v1.policies.kyverno.io"},
	{lookup: "namespaceddeletingpolicy.v1.policies.kyverno.io"},
	{lookup: "namespaceddeletingpolicies.v1beta1.policies.kyverno.io"},
	{lookup: "namespaceddeletingpolicy.v1beta1.policies.kyverno.io"},
	{lookup: "namespaceddeletingpolicies.v1alpha1.policies.kyverno.io"},
	{lookup: "namespaceddeletingpolicy.v1alpha1.policies.kyverno.io"},
}

var kyvernoPolicyExceptionKinds = []kyvernoResourceKind{
	{lookup: "policyexceptions.v2.kyverno.io"},
	{lookup: "policyexception.v2.kyverno.io"},
	{lookup: "policyexceptions.v2beta1.kyverno.io"},
	{lookup: "policyexception.v2beta1.kyverno.io"},
	{lookup: "policyexceptions.v2alpha1.kyverno.io"},
	{lookup: "policyexception.v2alpha1.kyverno.io"},
	{lookup: "policyexceptions.v1alpha2.kyverno.io"},
	{lookup: "policyexception.v1alpha2.kyverno.io"},
	{lookup: "policyexceptions.v1alpha1.kyverno.io"},
	{lookup: "policyexception.v1alpha1.kyverno.io"},
	{lookup: "policyexceptions.v1.policies.kyverno.io"},
	{lookup: "policyexception.v1.policies.kyverno.io"},
	{lookup: "policyexceptions.v1beta1.policies.kyverno.io"},
	{lookup: "policyexception.v1beta1.policies.kyverno.io"},
	{lookup: "policyexceptions.v1alpha1.policies.kyverno.io"},
	{lookup: "policyexception.v1alpha1.policies.kyverno.io"},
}

var kyvernoReportKinds = []kyvernoResourceKind{
	{lookup: "policyreports.v1alpha2.wgpolicyk8s.io"},
	{lookup: "policyreport.v1alpha2.wgpolicyk8s.io"},
	{lookup: "clusterpolicyreports.v1alpha2.wgpolicyk8s.io"},
	{lookup: "clusterpolicyreport.v1alpha2.wgpolicyk8s.io"},
	{lookup: "reports.v1alpha1.openreports.io"},
	{lookup: "report.v1alpha1.openreports.io"},
	{lookup: "clusterreports.v1alpha1.openreports.io"},
	{lookup: "clusterreport.v1alpha1.openreports.io"},
}

type kyvernoBuiltinPolicyMapping struct {
	policy          string
	rules           []string
	checks          []string
	mondooPolicyUid string
	confidence      string
	reason          string
}

var kyvernoBuiltinPolicyMappings = []kyvernoBuiltinPolicyMapping{
	{
		policy: "disallow-privileged-containers",
		rules:  []string{"privileged-containers", "validate-privileged", "autogen-privileged-containers"},
		checks: kyvernoWorkloadChecks("privilegedcontainer"),
	},
	{
		policy: "disallow-privilege-escalation",
		rules:  []string{"privilege-escalation", "autogen-privilege-escalation"},
		checks: kyvernoWorkloadChecks("allowprivilegeescalation"),
	},
	{
		policy: "block-ephemeral-containers",
		rules:  []string{"block-ephemeral-containers", "autogen-block-ephemeral-containers"},
		checks: []string{"mondoo-kubernetes-security-pod-no-ephemeral-containers"},
	},
	{
		policy: "require-run-as-non-root-user",
		rules:  []string{"run-as-non-root-user", "run-as-non-root", "autogen-run-as-non-root-user", "autogen-run-as-non-root"},
		checks: kyvernoWorkloadChecks("runasnonroot"),
	},
	{
		policy: "require-run-as-nonroot",
		rules:  []string{"run-as-non-root", "run-as-nonroot", "autogen-run-as-non-root", "autogen-run-as-nonroot"},
		checks: kyvernoWorkloadChecks("runasnonroot"),
	},
	{
		policy:     "require-run-as-containeruser",
		rules:      []string{"require-run-as-containeruser"},
		checks:     []string{"mondoo-kubernetes-security-pod-windows-runas-containeruser"},
		confidence: "high",
		reason:     "Official Kyverno policy requires Windows Pod and container runAsUserName values to be unset or ContainerUser; Mondoo checks the same Pod security-context values.",
	},
	{
		policy: "require-non-root-groups",
		rules:  []string{"check-runasgroup", "check-supplementalgroups", "check-fsgroup", "autogen-check-runasgroup", "autogen-check-supplementalgroups", "autogen-check-fsgroup"},
		checks: kyvernoWorkloadChecks("non-root-groups"),
	},
	{
		policy:     "service-mesh-require-run-as-nonroot",
		rules:      []string{"run-as-non-root-istio"},
		checks:     kyvernoWorkloadChecks("runasnonroot"),
		confidence: "medium",
		reason:     "Official Kyverno policy checks selected service mesh containers; Mondoo checks all workload containers.",
	},
	{
		policy: "disallow-host-namespaces",
		rules:  []string{"host-namespaces", "autogen-host-namespaces"},
		checks: kyvernoWorkloadChecks("hostipc", "hostnetwork", "hostpid"),
	},
	{
		policy: "disallow-host-ports",
		rules:  []string{"host-ports-none", "host-ports", "autogen-host-ports-none", "autogen-host-ports"},
		checks: kyvernoWorkloadChecks("ports-hostport"),
	},
	{
		policy:          "disallow-host-ports",
		rules:           []string{"host-ports-none", "host-ports", "autogen-host-ports-none", "autogen-host-ports"},
		checks:          kyvernoBestPracticeWorkloadChecks("ports-hostport"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		reason:          "Official Kyverno policy semantics match Mondoo Kubernetes best practices checks.",
	},
	{
		policy:     "disallow-host-ports-range",
		rules:      []string{"host-port-range", "autogen-host-port-range"},
		checks:     kyvernoWorkloadChecks("ports-hostport"),
		confidence: "medium",
		reason:     "Official Kyverno policy allows a configured hostPort range; Mondoo checks disallow hostPorts entirely.",
	},
	{
		policy:          "disallow-host-ports-range",
		rules:           []string{"host-port-range", "autogen-host-port-range"},
		checks:          kyvernoBestPracticeWorkloadChecks("ports-hostport"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy allows a configured hostPort range; Mondoo best practices checks disallow hostPorts entirely.",
	},
	{
		policy:     "disallow-host-path",
		rules:      []string{"host-path", "autogen-host-path"},
		checks:     kyvernoWorkloadChecks("hostpath-readonly"),
		confidence: "medium",
		reason:     "Official Kyverno policy forbids hostPath volumes; Mondoo checks that workload hostPath mounts are read-only.",
	},
	{
		policy: "disallow-host-process",
		rules:  []string{"host-process-containers", "autogen-host-process-containers"},
		checks: kyvernoWorkloadChecks("hostprocess"),
	},
	{
		policy:     "restrict-apparmor-profiles",
		rules:      []string{"app-armor"},
		checks:     []string{"mondoo-kubernetes-security-pod-apparmor-profile"},
		confidence: "high",
		reason:     "Official Kyverno policy allows Pod AppArmor annotations only when unset, runtime/default, or localhost/*; Mondoo checks the same Pod annotation values.",
	},
	{
		policy: "disallow-proc-mount",
		rules:  []string{"check-proc-mount", "autogen-check-proc-mount"},
		checks: kyvernoWorkloadChecks("proc-mount"),
	},
	{
		policy: "disallow-selinux",
		rules:  []string{"selinux-type", "autogen-selinux-type"},
		checks: kyvernoWorkloadChecks("selinux-type"),
	},
	{
		policy: "disallow-selinux",
		rules:  []string{"selinux-user-role", "autogen-selinux-user-role"},
		checks: kyvernoWorkloadChecks("selinux-user-role"),
	},
	{
		policy: "restrict-sysctls",
		rules:  []string{"check-sysctls", "autogen-check-sysctls"},
		checks: kyvernoWorkloadChecks("safe-sysctls"),
	},
	{
		policy:     "prevent-cr8escape",
		rules:      []string{"restrict-sysctls-cr8escape", "autogen-restrict-sysctls-cr8escape"},
		checks:     kyvernoWorkloadChecks("sysctls-no-cr8escape-values"),
		confidence: "high",
		reason:     "Official Kyverno policy forbids '+' and '=' characters in Pod sysctl values to prevent cr8escape; Mondoo checks the same sysctl value condition across workload resources.",
	},
	{
		policy: "restrict-seccomp",
		rules:  []string{"check-seccomp", "autogen-check-seccomp"},
		checks: kyvernoWorkloadChecks("seccomp-profile"),
	},
	{
		policy:     "restrict-seccomp-strict",
		rules:      []string{"check-seccomp-strict", "autogen-check-seccomp-strict"},
		checks:     kyvernoWorkloadChecks("seccomp-profile"),
		confidence: "medium",
		reason:     "Official Kyverno strict seccomp variants differ on whether unset profiles are allowed; Mondoo maps the common not-Unconfined seccomp posture.",
	},
	{
		policy: "require-ro-rootfs",
		rules:  []string{"validate-readOnlyRootFilesystem", "readonly-root-filesystem", "autogen-validate-readOnlyRootFilesystem", "autogen-readonly-root-filesystem"},
		checks: kyvernoWorkloadChecks("readonlyrootfilesystem"),
	},
	{
		policy: "require-readonly-root-filesystem",
		rules:  []string{"readonly-root-filesystem", "autogen-readonly-root-filesystem"},
		checks: kyvernoWorkloadChecks("readonlyrootfilesystem"),
	},
	{
		policy: "drop-all-capabilities",
		rules:  []string{"drop-all", "require-drop-all", "autogen-drop-all", "autogen-require-drop-all"},
		checks: kyvernoWorkloadChecks("capability-drop-all"),
	},
	{
		policy: "drop-cap-net-raw",
		rules:  []string{"require-drop-cap-net-raw", "drop-cap-net-raw", "autogen-require-drop-cap-net-raw", "autogen-drop-cap-net-raw"},
		checks: kyvernoWorkloadChecks("capability-net-raw"),
	},
	{
		policy: "disallow-capabilities-strict",
		rules:  []string{"require-drop-all", "autogen-require-drop-all"},
		checks: kyvernoWorkloadChecks("capability-drop-all"),
	},
	{
		policy:     "disallow-capabilities-strict",
		rules:      []string{"adding-capabilities-strict", "capabilities-strict", "autogen-adding-capabilities-strict", "autogen-capabilities-strict"},
		checks:     kyvernoWorkloadChecks("capability-net-raw", "capability-sys-admin"),
		confidence: "medium",
		reason:     "Official Kyverno policy blocks many added capabilities; Mondoo has checks for selected high-risk capabilities.",
	},
	{
		policy:     "disallow-capabilities",
		rules:      []string{"adding-capabilities", "autogen-adding-capabilities"},
		checks:     kyvernoWorkloadChecks("capability-net-raw", "capability-sys-admin"),
		confidence: "medium",
		reason:     "Official Kyverno policy blocks many added capabilities; Mondoo has checks for selected high-risk capabilities.",
	},
	{
		policy:     "psp-restrict-adding-capabilities",
		rules:      []string{"allowed-capabilities"},
		checks:     kyvernoWorkloadChecks("capability-net-raw", "capability-sys-admin"),
		confidence: "medium",
		reason:     "Official Kyverno PSP migration policy restricts added capabilities; Mondoo has checks for selected high-risk capabilities.",
	},
	{
		policy:     "service-mesh-disallow-capabilities",
		rules:      []string{"adding-capabilities-istio-linkerd", "autogen-adding-capabilities-istio-linkerd"},
		checks:     kyvernoWorkloadChecks("capability-net-raw", "capability-sys-admin"),
		confidence: "medium",
		reason:     "Official Kyverno service mesh variant restricts many added capabilities with mesh-specific exemptions; Mondoo has checks for selected high-risk capabilities.",
	},
	{
		policy:     "podsecurity-subrule-baseline",
		rules:      []string{"baseline", "autogen-baseline"},
		checks:     kyvernoPSSBaselineChecks(),
		confidence: "medium",
		reason:     "Official Kyverno podSecurity rule enforces the full Pod Security Standards baseline profile; Mondoo maps overlapping workload security checks.",
	},
	{
		policy:          "podsecurity-subrule-baseline",
		rules:           []string{"baseline", "autogen-baseline"},
		checks:          kyvernoBestPracticeWorkloadChecks("ports-hostport"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno podSecurity baseline profile includes hostPort controls; Mondoo best practices checks disallow hostPorts entirely.",
	},
	{
		policy:     "podsecurity-subrule-restricted",
		rules:      []string{"restricted", "autogen-restricted"},
		checks:     kyvernoPSSRestrictedChecks(),
		confidence: "medium",
		reason:     "Official Kyverno podSecurity rule enforces the full Pod Security Standards restricted profile; Mondoo maps overlapping workload security checks.",
	},
	{
		policy:          "podsecurity-subrule-restricted",
		rules:           []string{"restricted", "autogen-restricted"},
		checks:          kyvernoBestPracticeWorkloadChecks("ports-hostport"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno podSecurity restricted profile includes hostPort controls; Mondoo best practices checks disallow hostPorts entirely.",
	},
	{
		policy:     "podsecurity-subrule-restricted-capabilities",
		rules:      []string{"restricted-exempt-capabilities", "autogen-restricted-exempt-capabilities"},
		checks:     kyvernoPSSRestrictedWithoutCapabilitiesChecks(),
		confidence: "medium",
		reason:     "Official Kyverno podSecurity rule enforces the restricted profile while exempting the Capabilities control; Mondoo maps overlapping non-capability workload security checks.",
	},
	{
		policy:          "podsecurity-subrule-restricted-capabilities",
		rules:           []string{"restricted-exempt-capabilities", "autogen-restricted-exempt-capabilities"},
		checks:          kyvernoBestPracticeWorkloadChecks("ports-hostport"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno restricted profile with Capabilities exempted still includes hostPort controls; Mondoo best practices checks disallow hostPorts entirely.",
	},
	{
		policy:     "podsecurity-subrule-restricted-seccomp",
		rules:      []string{"restricted-exempt-seccomp", "autogen-restricted-exempt-seccomp"},
		checks:     kyvernoPSSRestrictedWithoutSeccompChecks(),
		confidence: "medium",
		reason:     "Official Kyverno podSecurity rule enforces the restricted profile while exempting the Seccomp control; Mondoo maps overlapping workload security checks.",
	},
	{
		policy:          "podsecurity-subrule-restricted-seccomp",
		rules:           []string{"restricted-exempt-seccomp", "autogen-restricted-exempt-seccomp"},
		checks:          kyvernoBestPracticeWorkloadChecks("ports-hostport"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno restricted profile with Seccomp exempted still includes hostPort controls; Mondoo best practices checks disallow hostPorts entirely.",
	},
	{
		policy:          "disallow-default-namespace",
		rules:           []string{"validate-namespace", "validate-podcontroller-namespace", "autogen-validate-namespace", "autogen-validate-podcontroller-namespace"},
		checks:          kyvernoBestPracticeChecks([]string{"pod", "daemonset", "deployment", "job", "statefulset"}, "default-namespace"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		reason:          "Official Kyverno policy semantics match Mondoo Kubernetes best practices checks.",
	},
	{
		policy:          "prevent-bare-pods",
		rules:           []string{"bare-pods"},
		checks:          kyvernoBestPracticeChecks([]string{"pod"}, "no-owner"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy blocks directly created Pods by requiring ownerReferences; Mondoo checks for non-empty Pod owner references.",
	},
	{
		policy:     "require-requests-limits",
		rules:      []string{"validate-resources", "require-requests-limits", "autogen-validate-resources", "autogen-require-requests-limits"},
		checks:     kyvernoWorkloadChecks("limitmemory"),
		confidence: "medium",
		reason:     "Official Kyverno policy requires memory limits and CPU/memory requests; Mondoo maps the memory-limit portion.",
	},
	{
		policy:          "require-requests-limits",
		rules:           []string{"validate-resources", "require-requests-limits", "autogen-validate-resources", "autogen-require-requests-limits"},
		checks:          kyvernoBestPracticeWorkloadChecks("requestcpu", "requestmemory"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy requires CPU and memory requests plus memory limits; Mondoo best practices checks cover the CPU and memory request portions.",
	},
	{
		policy:          "add-default-resources",
		rules:           []string{"add-default-requests", "autogen-add-default-requests"},
		checks:          kyvernoBestPracticeWorkloadChecks("requestcpu", "requestmemory"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno mutating policy adds default CPU and memory requests; Mondoo validates the resulting request posture.",
	},
	{
		policy:     "apply-pss-restricted-profile",
		rules:      []string{"add-pss-fields", "autogen-add-pss-fields"},
		checks:     kyvernoWorkloadChecks("privilegedcontainer", "capability-drop-all", "allowprivilegeescalation", "runasnonroot"),
		confidence: "medium",
		reason:     "Official Kyverno mutating policy sets selected Pod Security Standards restricted fields; Mondoo maps the overlapping workload security posture.",
	},
	{
		policy:     "add-psa-labels",
		rules:      []string{"add-baseline-enforce-restricted-warn"},
		checks:     []string{"mondoo-kubernetes-security-namespace-psa-enforce-warn-labels"},
		confidence: "high",
		reason:     "Official Kyverno policy adds Pod Security Admission enforce and warn Namespace labels when absent; Mondoo checks the same scanner-visible label postcondition.",
	},
	{
		policy:     "add-psa-namespace-reporting",
		rules:      []string{"check-namespace-labels"},
		checks:     []string{"mondoo-kubernetes-security-namespace-psa-labels"},
		confidence: "high",
		reason:     "Official Kyverno policy audits Namespaces for non-empty Pod Security Admission labels; Mondoo checks the same Namespace label condition.",
	},
	{
		policy:     "deny-privileged-profile",
		rules:      []string{"check-privileged"},
		checks:     []string{"mondoo-kubernetes-security-namespace-psa-enforce-not-privileged"},
		confidence: "medium",
		reason:     "Official Kyverno policy denies privileged PSA enforce labels for non-cluster-admin actors; Mondoo checks the scanner-visible privileged Namespace label state.",
	},
	{
		policy: "require-cpu-limits",
		rules:  []string{"check-cpu-limits", "autogen-check-cpu-limits"},
		checks: kyvernoWorkloadChecks("limitcpu"),
	},
	{
		policy:          "forbid-cpu-limits",
		rules:           []string{"check-cpu-limits", "autogen-check-cpu-limits"},
		checks:          kyvernoBestPracticeWorkloadChecks("no-cpu-limits"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy forbids CPU limits on regular Pod containers; Mondoo checks the same container resource field across Pods and standard workload Pod templates.",
	},
	{
		policy:          "require-qos-burstable",
		rules:           []string{"burstable"},
		checks:          []string{"mondoo-kubernetes-best-practices-pod-not-besteffort"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:     "require-qos-guaranteed",
		rules:      []string{"guaranteed", "autogen-guaranteed"},
		checks:     kyvernoWorkloadChecks("limitcpu", "limitmemory"),
		confidence: "medium",
		reason:     "Official Kyverno policy requires CPU and memory requests and limits with equal values; Mondoo maps the limit presence portion.",
	},
	{
		policy:          "require-qos-guaranteed",
		rules:           []string{"guaranteed", "autogen-guaranteed"},
		checks:          kyvernoBestPracticeWorkloadChecks("requestcpu", "requestmemory"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy requires CPU and memory requests and limits with equal values; Mondoo best practices checks cover the request presence portion.",
	},
	{
		policy:     "memory-requests-equal-limits",
		rules:      []string{"memory-requests-equal-limits", "autogen-memory-requests-equal-limits"},
		checks:     kyvernoWorkloadChecks("limitmemory"),
		confidence: "medium",
		reason:     "Official Kyverno policy requires memory requests and limits with equal values; Mondoo maps the memory limit presence portion.",
	},
	{
		policy:          "memory-requests-equal-limits",
		rules:           []string{"memory-requests-equal-limits", "autogen-memory-requests-equal-limits"},
		checks:          kyvernoBestPracticeWorkloadChecks("requestmemory"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy requires memory requests and limits with equal values; Mondoo best practices checks cover the memory request presence portion.",
	},
	{
		policy:     "imagepullpolicy-always",
		rules:      []string{"imagepullpolicy-always", "validate-imagepullpolicy", "autogen-imagepullpolicy-always", "autogen-validate-imagepullpolicy"},
		checks:     kyvernoWorkloadChecks("imagepull"),
		confidence: "medium",
		reason:     "Official Kyverno policy requires imagePullPolicy Always; Mondoo also checks immutable non-latest image tags.",
	},
	{
		policy:     "disallow-latest-tag",
		rules:      []string{"require-and-validate-image-tag", "require-image-tag", "validate-image-tag", "autogen-require-and-validate-image-tag", "autogen-require-image-tag", "autogen-validate-image-tag"},
		checks:     kyvernoWorkloadChecks("image-tag-not-latest"),
		confidence: "high",
		reason:     "Official Kyverno policy requires explicit image tags and rejects mutable latest tags; Mondoo checks enforce the same image reference conditions across workload resources.",
	},
	{
		policy:     "always-pull-images",
		rules:      []string{"always-pull-images"},
		checks:     kyvernoWorkloadChecks("imagepull"),
		confidence: "medium",
		reason:     "Official Kyverno mutating policy sets imagePullPolicy Always; Mondoo validates image pull policy and immutable tags.",
	},
	{
		policy:     "require-image-checksum",
		rules:      []string{"require-image-checksum", "autogen-require-image-checksum"},
		checks:     kyvernoWorkloadChecks("imagepull"),
		confidence: "medium",
		reason:     "Official Kyverno policy requires digest-based image references; Mondoo image-pull checks also require imagePullPolicy Always.",
	},
	{
		policy:     "require-imagepullsecrets",
		rules:      []string{"check-for-image-pull-secrets"},
		checks:     []string{"mondoo-kubernetes-security-pod-imagepullsecret-required-for-restricted-registries"},
		confidence: "high",
		reason:     "Official Kyverno policy requires imagePullSecrets when Pod regular container images are outside ghcr.io or quay.io; Mondoo checks the same predicate.",
	},
	{
		policy:     "resolve-image-to-digest",
		rules:      []string{"resolve-to-digest", "autogen-resolve-to-digest"},
		checks:     kyvernoWorkloadChecks("imagepull"),
		confidence: "medium",
		reason:     "Official Kyverno mutating policy resolves image tags to digests; Mondoo image-pull checks also require imagePullPolicy Always.",
	},
	{
		policy:          "require-pod-probes",
		rules:           []string{"validate-probes", "autogen-validate-probes"},
		checks:          kyvernoBestPracticeChecks([]string{"pod", "daemonset", "deployment", "statefulset"}, "livenessprobe", "readinessProbe"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy accepts liveness, readiness, or startup probes; Mondoo has separate liveness and readiness probe checks.",
	},
	{
		policy:          "validate-probes",
		rules:           []string{"validate-probes"},
		checks:          kyvernoBestPracticeChecks([]string{"daemonset", "deployment", "statefulset"}, "probes-different"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy: "deny-commands-in-exec-probe",
		rules:  []string{"check-commands", "autogen-check-commands"},
		checks: kyvernoWorkloadChecks("liveness-exec-probe-no-debug-commands"),
	},
	{
		policy:          "require-container-port-names",
		rules:           []string{"port-name", "autogen-port-name"},
		checks:          kyvernoBestPracticeWorkloadChecks("port-name"),
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy: "restrict-automount-sa-token",
		rules:  []string{"validate-automountServiceAccountToken", "automountserviceaccounttoken", "autogen-validate-automountServiceAccountToken", "autogen-automountserviceaccounttoken"},
		checks: kyvernoWorkloadChecks("serviceaccount"),
	},
	{
		policy:     "restrict-sa-automount-sa-token",
		rules:      []string{"validate-sa-automountServiceAccountToken"},
		checks:     kyvernoWorkloadChecks("serviceaccount"),
		confidence: "medium",
		reason:     "Official Kyverno policy checks ServiceAccount token automounting; Mondoo checks workload service account token exposure.",
	},
	{
		policy:     "disable-automountserviceaccounttoken",
		rules:      []string{"disable-automountserviceaccounttoken"},
		checks:     kyvernoWorkloadChecks("serviceaccount"),
		confidence: "medium",
		reason:     "Official Kyverno mutating policy disables service account token automounting; Mondoo validates workload service account token exposure.",
	},
	{
		policy: "check-serviceaccount-secrets",
		rules:  []string{"deny-secrets"},
		checks: []string{"mondoo-kubernetes-security-serviceaccount-no-long-lived-secrets"},
	},
	{
		policy: "deny-secret-service-account-token-type",
		rules:  []string{"deny-secret-service-account-token-type"},
		checks: []string{"mondoo-kubernetes-security-secret-no-service-account-token"},
	},
	{
		policy: "secrets-not-from-env-vars",
		rules:  []string{"secrets-not-from-env-vars", "secrets-not-from-envfrom", "autogen-secrets-not-from-env-vars", "autogen-secrets-not-from-envfrom"},
		checks: kyvernoWorkloadChecks("no-secret-env-vars"),
	},
	{
		policy: "no-secrets",
		rules: []string{
			"secrets-not-from-env",
			"secrets-not-from-envfrom",
			"secrets-not-from-env-envFrom-and-volumes",
			"autogen-secrets-not-from-env",
			"autogen-secrets-not-from-envfrom",
			"autogen-secrets-not-from-env-envFrom-and-volumes",
		},
		checks: kyvernoWorkloadChecks("no-secret-env-vars"),
	},
	{
		policy: "no-secrets",
		rules: []string{
			"secrets-not-from-volumes",
			"secrets-not-from-env-envFrom-and-volumes",
			"autogen-secrets-not-from-volumes",
			"autogen-secrets-not-from-env-envFrom-and-volumes",
		},
		checks: kyvernoWorkloadChecks("no-secret-volumes"),
	},
	{
		policy: "restrict-binding-clusteradmin",
		rules:  []string{"clusteradmin-bindings"},
		checks: []string{"mondoo-kubernetes-security-rbac-no-cluster-admin-bindings"},
	},
	{
		policy: "restrict-binding-system-groups",
		rules:  []string{"restrict-anonymous", "restrict-masters", "restrict-subject-groups", "restrict-unauthenticated"},
		checks: []string{"mondoo-kubernetes-security-rbac-no-system-group-bindings"},
	},
	{
		policy: "restrict-wildcard-verbs",
		rules:  []string{"wildcard-verbs"},
		checks: []string{"mondoo-kubernetes-security-rbac-no-wildcard-verbs"},
	},
	{
		policy: "restrict-wildcard-resources",
		rules:  []string{"wildcard-resources"},
		checks: []string{"mondoo-kubernetes-security-rbac-no-wildcard-resources"},
	},
	{
		policy: "restrict-secret-role-verbs",
		rules:  []string{"secret-verbs"},
		checks: []string{"mondoo-kubernetes-security-rbac-no-secret-read-verbs"},
	},
	{
		policy: "restrict-escalation-verbs-roles",
		rules:  []string{"escalate"},
		checks: []string{"mondoo-kubernetes-security-rbac-no-escalation-verbs"},
	},
	{
		policy: "restrict-clusterrole-nodesproxy",
		rules:  []string{"clusterrole-nodesproxy"},
		checks: []string{"mondoo-kubernetes-security-rbac-no-nodes-proxy"},
	},
	{
		policy:     "restrict-deprecated-registry",
		rules:      []string{"restrict-deprecated-registry"},
		checks:     []string{"mondoo-kubernetes-security-pod-no-deprecated-k8s-gcr-registry"},
		confidence: "high",
		reason:     "Official Kyverno policy blocks Pod container images from the deprecated k8s.gcr.io registry; Mondoo checks the same Pod image registry predicate.",
	},
	{
		policy: "ensure-readonly-hostpath",
		rules:  []string{"ensure-hostpaths-readonly", "autogen-ensure-hostpaths-readonly"},
		checks: kyvernoWorkloadChecks("hostpath-readonly"),
	},
	{
		policy:     "restrict-volume-types",
		rules:      []string{"restricted-volumes", "autogen-restricted-volumes"},
		checks:     kyvernoWorkloadChecks("hostpath-readonly"),
		confidence: "medium",
		reason:     "Official Kyverno policy blocks hostPath and other non-core volume types; Mondoo maps the hostPath volume overlap.",
	},
	{
		policy:     "limit-hostpath-type-pv",
		rules:      []string{"limit-hostpath-type-pv-to-slash-data"},
		checks:     []string{"mondoo-kubernetes-security-no-hostpath-persistent-volumes"},
		confidence: "medium",
		reason:     "Official Kyverno policy limits hostPath PersistentVolumes to selected paths; Mondoo disallows hostPath PersistentVolumes entirely.",
	},
	{
		policy: "disallow-container-sock-mounts",
		rules:  []string{"validate-docker-sock-mount", "autogen-validate-docker-sock-mount"},
		checks: kyvernoWorkloadChecks("docker-socket"),
	},
	{
		policy: "disallow-container-sock-mounts",
		rules:  []string{"validate-containerd-sock-mount", "autogen-validate-containerd-sock-mount"},
		checks: kyvernoWorkloadChecks("containerd-socket"),
	},
	{
		policy: "disallow-container-sock-mounts",
		rules:  []string{"validate-crio-sock-mount", "autogen-validate-crio-sock-mount"},
		checks: kyvernoWorkloadChecks("crio-socket"),
	},
	{
		policy:     "docker-socket-check",
		rules:      []string{"conditional-anchor-dockersock", "docker-socket-check", "autogen-conditional-anchor-dockersock", "autogen-docker-socket-check"},
		checks:     kyvernoWorkloadChecks("docker-socket"),
		confidence: "medium",
		reason:     "Official Kyverno policy allows Docker socket mounts only with an approved label; Mondoo flags Docker socket mounts.",
	},
	{
		policy: "disallow-helm-tiller",
		rules:  []string{"validate-helm-tiller", "autogen-validate-helm-tiller"},
		checks: []string{
			"mondoo-kubernetes-security-pod-tiller",
			"mondoo-kubernetes-security-deployment-tiller",
		},
	},
	{
		policy: "disallow-ingress-nginx-custom-snippets",
		rules:  []string{"check-config-map", "check-ingress-annotations"},
		checks: []string{
			"mondoo-kubernetes-security-configmap-ingress-nginx-snippet-annotations-disabled",
			"mondoo-kubernetes-security-ingress-nginx-no-custom-snippets",
		},
	},
	{
		policy: "restrict-ingress-paths",
		rules:  []string{"check-paths"},
		checks: []string{"mondoo-kubernetes-security-ingress-nginx-no-sensitive-paths"},
	},
	{
		policy:     "restrict-annotations",
		rules:      []string{"check-ingress"},
		checks:     []string{"mondoo-kubernetes-security-ingress-nginx-no-dangerous-annotation-values"},
		confidence: "high",
		reason:     "Official Kyverno check-ingress rule blocks dangerous ingress-nginx annotation values; Mondoo checks the same annotation-value denylist.",
	},
	{
		policy: "restrict-annotations",
		rules:  []string{"block-flux-v1"},
		checks: []string{
			"mondoo-kubernetes-security-pod-no-flux-v1-annotations",
			"mondoo-kubernetes-security-cronjob-no-flux-v1-annotations",
			"mondoo-kubernetes-security-job-no-flux-v1-annotations",
			"mondoo-kubernetes-security-daemonset-no-flux-v1-annotations",
			"mondoo-kubernetes-security-deployment-no-flux-v1-annotations",
			"mondoo-kubernetes-security-statefulset-no-flux-v1-annotations",
		},
		confidence: "high",
		reason:     "Official Kyverno block-flux-v1 rule blocks fluxcd.io/* annotations on Pods and selected workload controllers; Mondoo checks the same annotation key prefix on those resource types.",
	},
	{
		policy:     "restrict-jobs",
		rules:      []string{"restrict-job-from-cronjob"},
		checks:     []string{"mondoo-kubernetes-security-job-created-by-cronjob"},
		confidence: "high",
		reason:     "Official Kyverno policy allows Jobs only when their first owner reference is a CronJob; Mondoo checks the same Job owner-reference predicate.",
	},
	{
		policy:     "limit-hostpath-vols",
		rules:      []string{"limit-hostpath-to-slash-data", "autogen-limit-hostpath-to-slash-data"},
		checks:     kyvernoWorkloadChecks("hostpath-readonly"),
		confidence: "medium",
		reason:     "Official Kyverno policy limits hostPath mounts to selected paths; Mondoo checks that workload hostPath mounts are read-only.",
	},
	{
		policy:     "remove-hostpath-volumes",
		rules:      []string{"remove-hostpath-all"},
		checks:     kyvernoWorkloadChecks("hostpath-readonly"),
		confidence: "medium",
		reason:     "Official Kyverno mutating policy removes hostPath volumes; Mondoo validates remaining workload hostPath mounts as read-only.",
	},
	{
		policy:     "remove-serviceaccount-token",
		rules:      []string{"remove-vol-volmount"},
		checks:     kyvernoWorkloadChecks("serviceaccount"),
		confidence: "medium",
		reason:     "Official Kyverno mutating policy removes service account token volume mounts; Mondoo validates workload service account token exposure.",
	},
	{
		policy:     "add-default-securitycontext",
		rules:      []string{"add-default-securitycontext", "autogen-add-default-securitycontext"},
		checks:     kyvernoWorkloadChecks("runasnonroot"),
		confidence: "medium",
		reason:     "Official Kyverno mutating policy sets runAsNonRoot in the Pod securityContext; Mondoo validates workload runAsNonRoot posture.",
	},
	{
		policy:          "no-loadbalancer-service",
		rules:           []string{"no-LoadBalancer"},
		checks:          []string{"mondoo-kubernetes-best-practices-service-no-loadbalancer"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "no-localhost-service",
		rules:           []string{"no-localhost-service"},
		checks:          []string{"mondoo-kubernetes-best-practices-service-no-externalname-localhost"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "restrict-external-ips",
		rules:           []string{"check-ips"},
		checks:          []string{"mondoo-kubernetes-best-practices-service-no-external-ips"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "restrict-nodeport",
		rules:           []string{"validate-nodeport"},
		checks:          []string{"mondoo-kubernetes-best-practices-service-no-nodeport"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "restrict-service-port-range",
		rules:           []string{"restrict-port-range"},
		checks:          []string{"mondoo-kubernetes-best-practices-service-ports-approved-range"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "disallow-empty-ingress-host",
		rules:           []string{"disallow-empty-ingress-host"},
		checks:          []string{"mondoo-kubernetes-best-practices-ingress-hosts-not-empty"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "restrict-ingress-defaultbackend",
		rules:           []string{"restrict-ingress-defaultbackend"},
		checks:          []string{"mondoo-kubernetes-best-practices-ingress-no-default-backend"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "restrict-ingress-wildcard",
		rules:           []string{"block-ingress-wildcard"},
		checks:          []string{"mondoo-kubernetes-best-practices-ingress-hosts-no-wildcard"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "restrict-ingress-classes",
		rules:           []string{"validate-ingress"},
		checks:          []string{"mondoo-kubernetes-best-practices-ingress-approved-class-annotation"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "require-ingress-https",
		rules:           []string{"has-annotation", "has-tls"},
		checks:          []string{"mondoo-kubernetes-best-practices-ingress-require-https"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "ingress-host-match-tls",
		rules:           []string{"host-match-tls"},
		checks:          []string{"mondoo-kubernetes-best-practices-ingress-tls-hosts-match-rules"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "limit-containers-per-pod",
		rules:           []string{"limit-containers-per-pod"},
		checks:          []string{"mondoo-kubernetes-best-practices-pod-max-four-containers"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "deployment-has-multiple-replicas",
		rules:           []string{"deployment-has-multiple-replicas"},
		checks:          []string{"mondoo-kubernetes-best-practices-deployment-multiple-replicas"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "add-networkpolicy",
		rules:           []string{"default-deny"},
		checks:          []string{"mondoo-kubernetes-best-practices-namespace-default-deny-networkpolicy"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy generates a default-deny NetworkPolicy for each Namespace; Mondoo checks for the same default-deny NetworkPolicy postcondition.",
	},
	{
		policy:          "add-networkpolicy-dns",
		rules:           []string{"add-netpol-dns"},
		checks:          []string{"mondoo-kubernetes-best-practices-namespace-allow-dns-networkpolicy"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy generates an allow-dns NetworkPolicy for each Namespace; Mondoo checks for the same DNS egress NetworkPolicy postcondition.",
	},
	{
		policy:          "generate-networkpolicy-existing",
		rules:           []string{"generate-existing-networkpolicy"},
		checks:          []string{"mondoo-kubernetes-best-practices-namespace-egress-default-deny-networkpolicy"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy generates an egress-only default-deny NetworkPolicy for existing Namespaces; Mondoo checks for the same generated NetworkPolicy postcondition.",
	},
	{
		policy:          "namespace-inventory-check",
		rules:           []string{"resourcequotas"},
		checks:          []string{"mondoo-kubernetes-best-practices-namespace-resourcequota"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "add-ns-quota",
		rules:           []string{"generate-limitrange"},
		checks:          []string{"mondoo-kubernetes-best-practices-namespace-limitrange"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy generates a LimitRange for each Namespace; Mondoo checks the same Namespace LimitRange inventory postcondition.",
	},
	{
		policy:          "add-ns-quota",
		rules:           []string{"generate-resourcequota"},
		checks:          []string{"mondoo-kubernetes-best-practices-namespace-resourcequota"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy generates a ResourceQuota for each Namespace; Mondoo checks the same Namespace ResourceQuota inventory postcondition.",
	},
	{
		policy:          "namespace-inventory-check",
		rules:           []string{"networkpolicies"},
		checks:          []string{"mondoo-kubernetes-best-practices-namespace-networkpolicy"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "pdb-maxunavailable",
		rules:           []string{"pdb-maxunavailable"},
		checks:          []string{"mondoo-kubernetes-best-practices-pdb-maxunavailable-nonzero"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "pdb-maxunavailable-with-deployments",
		rules:           []string{"pdb-maxunavailable"},
		checks:          []string{"mondoo-kubernetes-best-practices-pdb-maxunavailable-nonzero"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy blocks zero maxUnavailable only when matching Deployments exist; Mondoo checks zero maxUnavailable across all PodDisruptionBudgets.",
	},
	{
		policy:          "prevent-duplicate-hpa",
		rules:           []string{"check-targetref-duplicates"},
		checks:          []string{"mondoo-kubernetes-best-practices-hpa-no-duplicate-targets"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "prevent-duplicate-hpa",
		rules:           []string{"verify-kind-name-duplicates"},
		checks:          []string{"mondoo-kubernetes-best-practices-hpa-scale-target-kind"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "check-hpa-exists",
		rules:           []string{"validate-hpa"},
		checks:          []string{"mondoo-kubernetes-best-practices-workloads-have-hpa"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "readwriteonce-pod",
		rules:           []string{"readwrite-pvc-single-pod"},
		checks:          []string{"mondoo-kubernetes-best-practices-pvc-readwriteoncepod"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "require-pod-priorityclassname",
		rules:           []string{"check-priorityclassname"},
		checks:          []string{"mondoo-kubernetes-best-practices-pod-priorityclassname"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "require-storageclass",
		rules:           []string{"pvc-storageclass"},
		checks:          []string{"mondoo-kubernetes-best-practices-pvc-storageclass"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "require-storageclass",
		rules:           []string{"ss-storageclass"},
		checks:          []string{"mondoo-kubernetes-best-practices-statefulset-storageclass"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "add-ttl-jobs",
		rules:           []string{"add-ttlSecondsAfterFinished"},
		checks:          []string{"mondoo-kubernetes-best-practices-job-ttl-after-finished"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy adds ttlSecondsAfterFinished to directly created Jobs without ownerReferences; Mondoo checks the same direct-Job TTL postcondition.",
	},
	{
		policy:          "add-emptydir-sizelimit",
		rules:           []string{"mutate-emptydir"},
		checks:          []string{"mondoo-kubernetes-best-practices-pod-emptydir-size-limit"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy ensures Pod emptyDir volumes have sizeLimit values; Mondoo checks the same emptyDir sizeLimit postcondition.",
	},
	{
		policy:          "require-emptydir-requests-and-limits",
		rules:           []string{"check-emptydir-requests-limits"},
		checks:          []string{"mondoo-kubernetes-best-practices-pod-emptydir-ephemeral-storage-resources"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy requires containers mounting emptyDir volumes without sizeLimit to define ephemeral-storage requests and limits; Mondoo checks the same Pod resource postcondition.",
	},
	{
		policy:          "restrict-storageclass",
		rules:           []string{"storageclass-delete"},
		checks:          []string{"mondoo-kubernetes-best-practices-storageclass-reclaim-policy-delete"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "high",
		reason:          "Official Kyverno policy requires StorageClasses to use reclaimPolicy Delete; Mondoo checks the same StorageClass reclaim policy.",
	},
	{
		policy:          "restrict-networkpolicy-empty-podselector",
		rules:           []string{"empty-podselector"},
		checks:          []string{"mondoo-kubernetes-best-practices-networkpolicy-podselector-not-empty"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
	{
		policy:          "restrict-node-selection",
		rules:           []string{"restrict-nodeselector"},
		checks:          []string{"mondoo-kubernetes-best-practices-pod-no-node-selector"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
		confidence:      "medium",
		reason:          "Official Kyverno policy blocks nodeSelector and nodeName on Pod CREATE; Mondoo maps the observable nodeSelector field and intentionally does not map nodeName because it is normally populated by the scheduler after admission.",
	},
	{
		policy:          "require-labels",
		rules:           []string{"check-for-labels"},
		checks:          []string{"mondoo-kubernetes-best-practices-pod-label-app-name"},
		mondooPolicyUid: kyvernoBuiltinMondooBestPracticesPolicyUid,
	},
}

func (k *mqlK8s) kyverno() (*mqlK8sKyverno, error) {
	r, err := CreateResource(k.MqlRuntime, "k8s.kyverno", nil)
	if err != nil {
		return nil, err
	}
	return r.(*mqlK8sKyverno), nil
}

func (k *mqlK8sKyverno) installed() (bool, error) {
	policies := k.GetPolicies()
	if policies.Error != nil {
		return false, policies.Error
	}
	if len(policies.Data) > 0 {
		return true, nil
	}
	exceptions := k.GetPolicyExceptions()
	if exceptions.Error != nil {
		return false, exceptions.Error
	}
	if len(exceptions.Data) > 0 {
		return true, nil
	}
	reports := k.GetPolicyReports()
	if reports.Error != nil {
		return false, reports.Error
	}
	return len(reports.Data) > 0, nil
}

func (k *mqlK8sKyverno) policyCount() (int64, error) {
	items := k.GetPolicies()
	if items.Error != nil {
		return 0, items.Error
	}
	return int64(len(items.Data)), nil
}

func (k *mqlK8sKyverno) exceptionCount() (int64, error) {
	items := k.GetPolicyExceptions()
	if items.Error != nil {
		return 0, items.Error
	}
	return int64(len(items.Data)), nil
}

func (k *mqlK8sKyverno) resultCount() (int64, error) {
	items := k.GetResults()
	if items.Error != nil {
		return 0, items.Error
	}
	return int64(len(items.Data)), nil
}

func (k *mqlK8sKyverno) mirrorPolicyExceptions() (bool, error) {
	return kyvernoOptionBool(k.MqlRuntime, shared.OPTION_KYVERNO_MIRROR_POLICY_EXCEPTIONS, false), nil
}

func (k *mqlK8sKyverno) mirroredExceptionApproval() (string, error) {
	return kyvernoOptionString(k.MqlRuntime, shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_APPROVAL, "externally-approved"), nil
}

func (k *mqlK8sKyverno) mirroredExceptionAction() (string, error) {
	return kyvernoOptionString(k.MqlRuntime, shared.OPTION_KYVERNO_MIRRORED_EXCEPTION_ACTION, "RISK_ACCEPTED"), nil
}

func (k *mqlK8sKyverno) failExpiredPolicyExceptions() (bool, error) {
	return kyvernoOptionBool(k.MqlRuntime, shared.OPTION_KYVERNO_FAIL_EXPIRED_POLICY_EXCEPTIONS, true), nil
}

func (k *mqlK8sKyverno) reportUnmappedPolicyExceptions() (bool, error) {
	return kyvernoOptionBool(k.MqlRuntime, shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_EXCEPTIONS, true), nil
}

func (k *mqlK8sKyverno) reportUnmappedPolicyResults() (bool, error) {
	return kyvernoOptionBool(k.MqlRuntime, shared.OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_RESULTS, true), nil
}

func (k *mqlK8sKyverno) policies() ([]any, error) {
	objects, err := k.collectObjects(kyvernoPolicyKinds)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(objects))
	for _, obj := range objects {
		metaObj, typeObj, manifest, err := objectParts(obj)
		if err != nil {
			return nil, err
		}
		rules := kyvernoRulesFromPolicy(metaObj, typeObj, manifest)
		if rules == nil {
			rules = []*kyvernoRuleData{}
		}
		annotations := metaObj.GetAnnotations()
		ts := metaObj.GetCreationTimestamp()
		res, err := CreateResource(k.MqlRuntime, "k8s.kyverno.policy", map[string]*llx.RawData{
			"id":                      llx.StringData(kyvernoObjectId("policy", typeObj.GetAPIVersion(), typeObj.GetKind(), metaObj.GetNamespace(), metaObj.GetName())),
			"uid":                     llx.StringData(string(metaObj.GetUID())),
			"apiVersion":              llx.StringData(typeObj.GetAPIVersion()),
			"kind":                    llx.StringData(typeObj.GetKind()),
			"namespace":               llx.StringData(metaObj.GetNamespace()),
			"name":                    llx.StringData(metaObj.GetName()),
			"created":                 llx.TimeData(ts.Time),
			"title":                   llx.StringData(firstAnnotation(annotations, "policies.kyverno.io/title")),
			"category":                llx.StringData(firstAnnotation(annotations, "policies.kyverno.io/category")),
			"severity":                llx.StringData(firstAnnotation(annotations, "policies.kyverno.io/severity")),
			"subject":                 llx.StringData(firstAnnotation(annotations, "policies.kyverno.io/subject")),
			"description":             llx.StringData(firstAnnotation(annotations, "policies.kyverno.io/description")),
			"background":              llx.BoolData(boolFromPath(manifest, true, "spec", "background")),
			"validationFailureAction": llx.StringData(validationAction(manifest)),
			"ruleCount":               llx.IntData(int64(len(rules))),
		})
		if err != nil {
			return nil, err
		}
		cast := res.(*mqlK8sKyvernoPolicy)
		cast.obj = metaObj
		cast.manifestData = manifest
		cast.ruleData = rules
		out = append(out, cast)
	}
	sortKyvernoPolicies(out)
	return out, nil
}

func (k *mqlK8sKyverno) rules() ([]any, error) {
	policies := k.GetPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	out := []any{}
	for _, item := range policies.Data {
		policy := item.(*mqlK8sKyvernoPolicy)
		rules := policy.GetRules()
		if rules.Error != nil {
			return nil, rules.Error
		}
		out = append(out, rules.Data...)
	}
	return out, nil
}

func (k *mqlK8sKyverno) policyReports() ([]any, error) {
	objects, err := k.collectObjects(kyvernoReportKinds)
	if err != nil {
		return nil, err
	}
	scopeResolver := newKyvernoScopeMetadataResolver(k.MqlRuntime)
	out := make([]any, 0, len(objects))
	for _, obj := range objects {
		metaObj, typeObj, manifest, err := objectParts(obj)
		if err != nil {
			return nil, err
		}
		results := kyvernoResultsFromReport(metaObj, typeObj, manifest)
		if results == nil {
			results = []*kyvernoResultData{}
		}
		scopeResolver.enrich(results)
		scope := mapFromPath(manifest, "scope")
		ts := metaObj.GetCreationTimestamp()
		res, err := CreateResource(k.MqlRuntime, "k8s.kyverno.policyreport", map[string]*llx.RawData{
			"id":             llx.StringData(kyvernoObjectId("policyreport", typeObj.GetAPIVersion(), typeObj.GetKind(), metaObj.GetNamespace(), metaObj.GetName())),
			"uid":            llx.StringData(string(metaObj.GetUID())),
			"apiVersion":     llx.StringData(typeObj.GetAPIVersion()),
			"kind":           llx.StringData(typeObj.GetKind()),
			"namespace":      llx.StringData(metaObj.GetNamespace()),
			"name":           llx.StringData(metaObj.GetName()),
			"created":        llx.TimeData(ts.Time),
			"scopeKind":      llx.StringData(stringFromMap(scope, "kind")),
			"scopeNamespace": llx.StringData(stringFromMap(scope, "namespace")),
			"scopeName":      llx.StringData(stringFromMap(scope, "name")),
			"scopeUid":       llx.StringData(stringFromMap(scope, "uid")),
			"resultCount":    llx.IntData(int64(len(results))),
		})
		if err != nil {
			return nil, err
		}
		cast := res.(*mqlK8sKyvernoPolicyreport)
		cast.obj = metaObj
		cast.manifestData = manifest
		cast.resultData = results
		out = append(out, cast)
	}
	sortKyvernoReports(out)
	return out, nil
}

func (k *mqlK8sKyverno) results() ([]any, error) {
	mappingIndex, err := k.mappingIndex()
	if err != nil {
		return nil, err
	}
	exceptionIndex, err := k.resultExceptionIndex()
	if err != nil {
		return nil, err
	}
	reports := k.GetPolicyReports()
	if reports.Error != nil {
		return nil, reports.Error
	}
	out := []any{}
	for _, item := range reports.Data {
		report := item.(*mqlK8sKyvernoPolicyreport)
		resultData, err := report.initializedResults()
		if err != nil {
			return nil, err
		}
		for _, data := range resultData {
			res, err := kyvernoResultResource(k.MqlRuntime, enrichedKyvernoResultData(data, mappingIndex, exceptionIndex))
			if err != nil {
				return nil, err
			}
			out = append(out, res)
		}
	}
	return out, nil
}

func (k *mqlK8sKyverno) policyExceptions() ([]any, error) {
	objects, err := k.policyExceptionObjects()
	if err != nil {
		return nil, err
	}

	policyIndex, ruleIndex, err := k.policyRuleIndexes()
	if err != nil {
		return nil, err
	}
	mappingIndex, err := k.mappingIndex()
	if err != nil {
		return nil, err
	}
	resultIndex, err := k.resultIndex()
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(objects))
	for _, obj := range objects {
		metaObj, typeObj, manifest, err := objectParts(obj)
		if err != nil {
			return nil, err
		}
		data := kyvernoPolicyExceptionData(k.MqlRuntime, metaObj, manifest, policyIndex, ruleIndex, mappingIndex, resultIndex)
		ts := metaObj.GetCreationTimestamp()
		res, err := CreateResource(k.MqlRuntime, "k8s.kyverno.policyexception", map[string]*llx.RawData{
			"id":             llx.StringData(kyvernoObjectId("policyexception", typeObj.GetAPIVersion(), typeObj.GetKind(), metaObj.GetNamespace(), metaObj.GetName())),
			"uid":            llx.StringData(string(metaObj.GetUID())),
			"apiVersion":     llx.StringData(typeObj.GetAPIVersion()),
			"kind":           llx.StringData(typeObj.GetKind()),
			"namespace":      llx.StringData(metaObj.GetNamespace()),
			"name":           llx.StringData(metaObj.GetName()),
			"created":        llx.TimeData(ts.Time),
			"validUntil":     llx.StringData(data.validUntil),
			"validUntilTime": llx.TimeDataPtr(data.validUntilTime),
			"justification":  llx.StringData(data.justification),
			"owner":          llx.StringData(data.owner),
			"ticket":         llx.StringData(data.ticket),
			"computedStatus": llx.StringData(data.computedStatus),
		})
		if err != nil {
			return nil, err
		}
		cast := res.(*mqlK8sKyvernoPolicyexception)
		cast.obj = metaObj
		cast.manifestData = manifest
		cast.data = data
		out = append(out, cast)
	}
	sortKyvernoExceptions(out)
	return out, nil
}

func (k *mqlK8sKyverno) mappings() ([]any, error) {
	policies := k.GetPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}

	mappingById := map[string]kyvernoMappingData{}
	for _, item := range policies.Data {
		policy := item.(*mqlK8sKyvernoPolicy)
		if kyvernoDefaultMappingsEnabled(k.MqlRuntime) {
			mappings, err := builtinMappingsForPolicy(policy)
			if err != nil {
				return nil, err
			}
			for _, mapping := range mappings {
				mappingById[mapping.id] = mapping
			}
		}
		mappings, err := annotationMappingsForPolicy(k.MqlRuntime, policy)
		if err != nil {
			return nil, err
		}
		for _, mapping := range mappings {
			mappingById[mapping.id] = mapping
		}
	}

	ids := make([]string, 0, len(mappingById))
	for id := range mappingById {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		data := mappingById[id]
		res, err := CreateResource(k.MqlRuntime, "k8s.kyverno.mapping", map[string]*llx.RawData{
			"id":               llx.StringData(data.id),
			"kyvernoKind":      llx.StringData(data.kyvernoKind),
			"kyvernoNamespace": llx.StringData(data.kyvernoNamespace),
			"kyvernoPolicy":    llx.StringData(data.kyvernoPolicy),
			"kyvernoRule":      llx.StringData(data.kyvernoRule),
			"mondooPolicyUid":  llx.StringData(data.mondooPolicyUid),
			"mondooCheckUid":   llx.StringData(data.mondooCheckUid),
			"mondooCheckMrn":   llx.StringData(data.mondooCheckMrn),
			"source":           llx.StringData(data.source),
			"confidence":       llx.StringData(data.confidence),
			"reason":           llx.StringData(data.reason),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlK8sKyvernoMapping).data = data
		out = append(out, res)
	}
	return out, nil
}

func (k *mqlK8sKyverno) collectObjects(kinds []kyvernoResourceKind) ([]runtime.Object, error) {
	kt, err := k8sProvider(k.MqlRuntime.Connection)
	if err != nil {
		return nil, err
	}

	out := []runtime.Object{}
	seen := map[string]struct{}{}
	for _, kind := range kinds {
		result, err := kt.Resources(kind.lookup, "", "")
		if err != nil {
			if strings.Contains(err.Error(), "could not find api kind") {
				continue
			}
			if strings.Contains(err.Error(), "ambiguous kind") {
				continue
			}
			return nil, err
		}
		for _, obj := range result.Resources {
			metaObj, typeObj, _, err := objectParts(obj)
			if err != nil {
				log.Debug().Err(err).Msg("could not parse kyverno resource")
				continue
			}
			id := kyvernoObjectId("object", typeObj.GetAPIVersion(), typeObj.GetKind(), metaObj.GetNamespace(), metaObj.GetName())
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, obj)
		}
	}
	return out, nil
}

func (k *mqlK8sKyverno) policyExceptionObjects() ([]runtime.Object, error) {
	k.lock.Lock()
	defer k.lock.Unlock()
	if k.cachedPolicyExceptionObjectsLoaded {
		return k.cachedPolicyExceptionObjects, nil
	}
	objs, err := k.collectObjects(kyvernoPolicyExceptionKinds)
	if err != nil {
		return nil, err
	}
	k.cachedPolicyExceptionObjects = objs
	k.cachedPolicyExceptionObjectsLoaded = true
	return k.cachedPolicyExceptionObjects, nil
}

func (k *mqlK8sKyvernoRule) initializedData() (*kyvernoRuleData, error) {
	if k.data == nil {
		return nil, fmt.Errorf("kyverno rule data not initialized")
	}
	return k.data, nil
}

func (k *mqlK8sKyvernoResult) initializedData() (*kyvernoResultData, error) {
	if k.data == nil {
		return nil, fmt.Errorf("kyverno result data not initialized")
	}
	return k.data, nil
}

func (k *mqlK8sKyvernoPolicyexception) initializedData() (*kyvernoExceptionData, error) {
	if k.data == nil {
		return nil, fmt.Errorf("kyverno policyexception data not initialized")
	}
	return k.data, nil
}

func (k *mqlK8sKyvernoPolicy) initializedObject() (metav1.Object, error) {
	if k.obj == nil {
		return nil, fmt.Errorf("kyverno policy data not initialized")
	}
	return k.obj, nil
}

func (k *mqlK8sKyvernoPolicy) initializedManifest() (map[string]any, error) {
	if k.manifestData == nil {
		return nil, fmt.Errorf("kyverno policy data not initialized")
	}
	return k.manifestData, nil
}

func (k *mqlK8sKyvernoPolicy) initializedRules() ([]*kyvernoRuleData, error) {
	if k.ruleData == nil {
		return nil, fmt.Errorf("kyverno policy data not initialized")
	}
	return k.ruleData, nil
}

func (k *mqlK8sKyvernoPolicyreport) initializedManifest() (map[string]any, error) {
	if k.manifestData == nil {
		return nil, fmt.Errorf("kyverno policyreport data not initialized")
	}
	return k.manifestData, nil
}

func (k *mqlK8sKyvernoPolicyreport) initializedResults() ([]*kyvernoResultData, error) {
	if k.resultData == nil {
		return nil, fmt.Errorf("kyverno policyreport data not initialized")
	}
	return k.resultData, nil
}

func (k *mqlK8sKyvernoPolicyexception) initializedObject() (metav1.Object, error) {
	if k.obj == nil {
		return nil, fmt.Errorf("kyverno policyexception data not initialized")
	}
	return k.obj, nil
}

func (k *mqlK8sKyvernoPolicyexception) initializedManifest() (map[string]any, error) {
	if k.manifestData == nil {
		return nil, fmt.Errorf("kyverno policyexception data not initialized")
	}
	return k.manifestData, nil
}

func (k *mqlK8sKyvernoPolicy) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sKyvernoPolicy) labels() (map[string]any, error) {
	obj, err := k.initializedObject()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(obj.GetLabels()), nil
}

func (k *mqlK8sKyvernoPolicy) annotations() (map[string]any, error) {
	obj, err := k.initializedObject()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(obj.GetAnnotations()), nil
}

func (k *mqlK8sKyvernoPolicy) manifest() (map[string]any, error) {
	return k.initializedManifest()
}

func (k *mqlK8sKyvernoPolicy) rules() ([]any, error) {
	ruleData, err := k.initializedRules()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(ruleData))
	for _, data := range ruleData {
		res, err := CreateResource(k.MqlRuntime, "k8s.kyverno.rule", map[string]*llx.RawData{
			"id":               llx.StringData(data.id),
			"policyId":         llx.StringData(data.policyId),
			"policyApiVersion": llx.StringData(data.policyApiVersion),
			"policyKind":       llx.StringData(data.policyKind),
			"policyNamespace":  llx.StringData(data.policyNamespace),
			"policyName":       llx.StringData(data.policyName),
			"name":             llx.StringData(data.name),
			"type":             llx.StringData(data.ruleType),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlK8sKyvernoRule).data = data
		out = append(out, res)
	}
	return out, nil
}

func (k *mqlK8sKyvernoPolicy) mappedMondooChecks() ([]any, error) {
	kyverno, err := kyvernoRoot(k.MqlRuntime)
	if err != nil {
		return nil, err
	}
	mappings := kyverno.GetMappings()
	if mappings.Error != nil {
		return nil, mappings.Error
	}
	out := []any{}
	for _, item := range mappings.Data {
		m := item.(*mqlK8sKyvernoMapping)
		if m.KyvernoPolicy.Data == k.Name.Data && m.KyvernoNamespace.Data == k.Namespace.Data && m.KyvernoKind.Data == k.Kind.Data {
			out = append(out, m)
		}
	}
	return out, nil
}

func (k *mqlK8sKyvernoRule) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sKyvernoRule) matchKinds() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.matchKinds), nil
}

func (k *mqlK8sKyvernoRule) match() (map[string]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return data.match, nil
}

func (k *mqlK8sKyvernoRule) exclude() (map[string]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return data.exclude, nil
}

func (k *mqlK8sKyvernoRule) conditions() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return mapsToAny(data.conditions), nil
}

func (k *mqlK8sKyvernoRule) manifest() (map[string]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return data.manifest, nil
}

func (k *mqlK8sKyvernoRule) mappedMondooChecks() ([]any, error) {
	kyverno, err := kyvernoRoot(k.MqlRuntime)
	if err != nil {
		return nil, err
	}
	mappings := kyverno.GetMappings()
	if mappings.Error != nil {
		return nil, mappings.Error
	}
	out := []any{}
	for _, item := range mappings.Data {
		m := item.(*mqlK8sKyvernoMapping)
		if m.KyvernoPolicy.Data == k.PolicyName.Data && m.KyvernoRule.Data == k.Name.Data &&
			m.KyvernoNamespace.Data == k.PolicyNamespace.Data && m.KyvernoKind.Data == k.PolicyKind.Data {
			out = append(out, m)
		}
	}
	return out, nil
}

func (k *mqlK8sKyvernoPolicyreport) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sKyvernoPolicyreport) manifest() (map[string]any, error) {
	return k.initializedManifest()
}

func (k *mqlK8sKyvernoPolicyreport) results() ([]any, error) {
	resultData, err := k.initializedResults()
	if err != nil {
		return nil, err
	}
	kyverno, err := kyvernoRoot(k.MqlRuntime)
	if err != nil {
		return nil, err
	}
	mappingIndex, err := kyverno.mappingIndex()
	if err != nil {
		return nil, err
	}
	exceptionIndex, err := kyverno.resultExceptionIndex()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(resultData))
	for _, data := range resultData {
		res, err := kyvernoResultResource(k.MqlRuntime, enrichedKyvernoResultData(data, mappingIndex, exceptionIndex))
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (k *mqlK8sKyvernoResult) properties() (map[string]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(data.properties), nil
}

func (k *mqlK8sKyvernoResult) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sKyvernoResult) mappedMondooCheckUids() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.mappedCheckUids), nil
}

func (k *mqlK8sKyvernoResult) mappedMondooCheckMrns() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.mappedCheckMrns), nil
}

func (k *mqlK8sKyvernoResult) mappedPolicyExceptionIds() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.mappedExceptionIds), nil
}

func (k *mqlK8sKyvernoResult) manifest() (map[string]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return data.manifest, nil
}

func (k *mqlK8sKyvernoPolicyexception) labels() (map[string]any, error) {
	obj, err := k.initializedObject()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(obj.GetLabels()), nil
}

func (k *mqlK8sKyvernoPolicyexception) annotations() (map[string]any, error) {
	obj, err := k.initializedObject()
	if err != nil {
		return nil, err
	}
	return convert.MapToInterfaceMap(obj.GetAnnotations()), nil
}

func (k *mqlK8sKyvernoPolicyexception) manifest() (map[string]any, error) {
	return k.initializedManifest()
}

func (k *mqlK8sKyvernoPolicyexception) id() (string, error) {
	return k.Id.Data, nil
}

func (k *mqlK8sKyvernoPolicyexception) policyRefs() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.policyRefs), nil
}

func (k *mqlK8sKyvernoPolicyexception) ruleNames() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.ruleNames), nil
}

func (k *mqlK8sKyvernoPolicyexception) matchKinds() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.matchKinds), nil
}

func (k *mqlK8sKyvernoPolicyexception) matchNamespaces() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.matchNamespaces), nil
}

func (k *mqlK8sKyvernoPolicyexception) matchNames() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.matchNames), nil
}

func (k *mqlK8sKyvernoPolicyexception) match() (map[string]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return data.match, nil
}

func (k *mqlK8sKyvernoPolicyexception) statusReasons() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.statusReasons), nil
}

func (k *mqlK8sKyvernoPolicyexception) mappedMondooCheckUids() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.mappedMondooCheckUids), nil
}

func (k *mqlK8sKyvernoPolicyexception) mappedMondooExceptionIds() ([]any, error) {
	data, err := k.initializedData()
	if err != nil {
		return nil, err
	}
	return kyvernoStringsToAny(data.mappedMondooExceptionIds), nil
}

func (k *mqlK8sKyvernoMapping) id() (string, error) {
	return k.Id.Data, nil
}

func kyvernoResultResource(runtime *plugin.Runtime, data *kyvernoResultData) (*mqlK8sKyvernoResult, error) {
	res, err := CreateResource(runtime, "k8s.kyverno.result", map[string]*llx.RawData{
		"id":               llx.StringData(data.id),
		"reportId":         llx.StringData(data.reportId),
		"reportApiVersion": llx.StringData(data.reportApiVersion),
		"reportKind":       llx.StringData(data.reportKind),
		"reportNamespace":  llx.StringData(data.reportNamespace),
		"reportName":       llx.StringData(data.reportName),
		"scopeKind":        llx.StringData(data.scopeKind),
		"scopeNamespace":   llx.StringData(data.scopeNamespace),
		"scopeName":        llx.StringData(data.scopeName),
		"scopeUid":         llx.StringData(data.scopeUid),
		"policy":           llx.StringData(data.policy),
		"rule":             llx.StringData(data.rule),
		"category":         llx.StringData(data.category),
		"severity":         llx.StringData(data.severity),
		"source":           llx.StringData(data.source),
		"result":           llx.StringData(data.result),
		"scored":           llx.BoolData(data.scored),
		"message":          llx.StringData(data.message),
		"timestamp":        llx.TimeData(data.timestamp),
	})
	if err != nil {
		return nil, err
	}
	cast := res.(*mqlK8sKyvernoResult)
	cast.data = data
	return cast, nil
}

func objectParts(obj runtime.Object) (metav1.Object, metav1.Type, map[string]any, error) {
	metaObj, err := meta.Accessor(obj)
	if err != nil {
		return nil, nil, nil, err
	}
	typeObj, err := meta.TypeAccessor(obj)
	if err != nil {
		return nil, nil, nil, err
	}
	manifest, err := convert.JsonToDict(obj)
	if err != nil {
		return nil, nil, nil, err
	}
	if typeObj.GetKind() == "" {
		if u, ok := obj.(*unstructured.Unstructured); ok {
			gvk := u.GroupVersionKind()
			typeObj.SetKind(gvk.Kind)
			typeObj.SetAPIVersion(gvk.GroupVersion().String())
		}
	}
	return metaObj, typeObj, manifest, nil
}

func kyvernoRulesFromPolicy(obj metav1.Object, objT metav1.Type, manifest map[string]any) []*kyvernoRuleData {
	policyId := kyvernoObjectId("policy", objT.GetAPIVersion(), objT.GetKind(), obj.GetNamespace(), obj.GetName())
	rules := []*kyvernoRuleData{}

	for _, rule := range sliceOfMapsFromPath(manifest, "spec", "rules") {
		name := stringFromMap(rule, "name")
		if name == "" {
			continue
		}
		match := mapFromAny(rule["match"])
		exclude := mapFromAny(rule["exclude"])
		conditions := make([]map[string]any, 0)
		conditions = append(conditions, sliceOfMapsFromAny(rule["preconditions"])...)
		conditions = append(conditions, sliceOfMapsFromAny(rule["matchConditions"])...)
		rules = append(rules, &kyvernoRuleData{
			id:               kyvernoRuleId(objT.GetKind(), obj.GetNamespace(), obj.GetName(), name),
			policyId:         policyId,
			policyApiVersion: objT.GetAPIVersion(),
			policyKind:       objT.GetKind(),
			policyNamespace:  obj.GetNamespace(),
			policyName:       obj.GetName(),
			name:             name,
			ruleType:         classicRuleType(rule),
			matchKinds:       matchKinds(match),
			match:            match,
			exclude:          exclude,
			conditions:       conditions,
			manifest:         rule,
		})
	}

	for _, validation := range sliceOfMapsFromPath(manifest, "spec", "validations") {
		rules = append(rules, celRuleData(policyId, obj, objT, "validation", validation))
	}
	for _, mutation := range sliceOfMapsFromPath(manifest, "spec", "mutations") {
		rules = append(rules, celRuleData(policyId, obj, objT, "mutation", mutation))
	}
	for _, generation := range sliceOfMapsFromPath(manifest, "spec", "generations") {
		rules = append(rules, celRuleData(policyId, obj, objT, "generation", generation))
	}
	for _, generation := range sliceOfMapsFromPath(manifest, "spec", "generate") {
		rules = append(rules, celRuleData(policyId, obj, objT, "generation", generation))
	}
	for _, deletion := range sliceOfMapsFromPath(manifest, "spec", "deletions") {
		rules = append(rules, celRuleData(policyId, obj, objT, "deletion", deletion))
	}
	for _, attestor := range sliceOfMapsFromPath(manifest, "spec", "attestors") {
		rules = append(rules, celRuleData(policyId, obj, objT, "attestor", attestor))
	}
	if len(rules) == 0 {
		rules = append(rules, &kyvernoRuleData{
			id:               kyvernoRuleId(objT.GetKind(), obj.GetNamespace(), obj.GetName(), obj.GetName()),
			policyId:         policyId,
			policyApiVersion: objT.GetAPIVersion(),
			policyKind:       objT.GetKind(),
			policyNamespace:  obj.GetNamespace(),
			policyName:       obj.GetName(),
			name:             obj.GetName(),
			ruleType:         strings.ToLower(objT.GetKind()),
			matchKinds:       matchKinds(mapFromPath(manifest, "spec", "matchConstraints")),
			match:            mapFromPath(manifest, "spec", "matchConstraints"),
			conditions:       sliceOfMapsFromPath(manifest, "spec", "matchConditions"),
			manifest:         mapFromPath(manifest, "spec"),
		})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].id < rules[j].id })
	return rules
}

func celRuleData(policyId string, obj metav1.Object, objT metav1.Type, ruleType string, manifest map[string]any) *kyvernoRuleData {
	name := stringFromMap(manifest, "name")
	if name == "" {
		name = stableHash(ruleType, fmt.Sprintf("%v", manifest))[:12]
	}
	match := mapFromPath(manifest, "matchConstraints")
	if len(match) == 0 {
		match = mapFromPath(manifest, "match")
	}
	return &kyvernoRuleData{
		id:               kyvernoRuleId(objT.GetKind(), obj.GetNamespace(), obj.GetName(), name),
		policyId:         policyId,
		policyApiVersion: objT.GetAPIVersion(),
		policyKind:       objT.GetKind(),
		policyNamespace:  obj.GetNamespace(),
		policyName:       obj.GetName(),
		name:             name,
		ruleType:         ruleType,
		matchKinds:       matchKinds(match),
		match:            match,
		conditions:       sliceOfMapsFromAny(manifest["matchConditions"]),
		manifest:         manifest,
	}
}

func kyvernoResultsFromReport(obj metav1.Object, objT metav1.Type, manifest map[string]any) []*kyvernoResultData {
	reportId := kyvernoObjectId("policyreport", objT.GetAPIVersion(), objT.GetKind(), obj.GetNamespace(), obj.GetName())
	reportScope := mapFromPath(manifest, "scope")
	results := []*kyvernoResultData{}
	for idx, entry := range sliceOfMapsFromPath(manifest, "results") {
		properties := stringMapFromAny(entry["properties"])
		policy := firstNonEmpty(stringFromMap(entry, "policy"), properties["policy"])
		rule := firstNonEmpty(stringFromMap(entry, "rule"), properties["rule"])
		source := firstNonEmpty(stringFromMap(entry, "source"), properties["source"])
		result := strings.ToLower(stringFromMap(entry, "result"))
		timestamp := timeFromAny(entry["timestamp"])
		if timestamp.IsZero() {
			timestamp = timeFromAny(entry["time"])
		}
		for scopeIdx, scope := range kyvernoResultScopes(entry, reportScope) {
			id := stableHash(reportId, fmt.Sprintf("%d", idx), fmt.Sprintf("%d", scopeIdx), policy, rule, result, stringFromMap(scope, "uid"), stringFromMap(scope, "name"), timestamp.String())
			results = append(results, &kyvernoResultData{
				id:               "kyverno-result:" + id,
				reportId:         reportId,
				reportApiVersion: objT.GetAPIVersion(),
				reportKind:       objT.GetKind(),
				reportNamespace:  obj.GetNamespace(),
				reportName:       obj.GetName(),
				scopeApiVersion:  stringFromMap(scope, "apiVersion"),
				scopeKind:        stringFromMap(scope, "kind"),
				scopeNamespace:   stringFromMap(scope, "namespace"),
				scopeName:        stringFromMap(scope, "name"),
				scopeUid:         firstNonEmpty(stringFromMap(scope, "uid"), stringFromMap(scope, "resourceUID")),
				scopeLabels:      kyvernoScopeLabelsFromProperties(properties),
				policy:           policy,
				rule:             rule,
				category:         firstNonEmpty(stringFromMap(entry, "category"), properties["category"]),
				severity:         firstNonEmpty(stringFromMap(entry, "severity"), properties["severity"]),
				source:           source,
				result:           result,
				scored:           boolFromAny(entry["scored"], true),
				message:          stringFromMap(entry, "message"),
				timestamp:        timestamp,
				properties:       properties,
				manifest:         entry,
			})
		}
	}
	return results
}

func kyvernoResultScopes(entry map[string]any, reportScope map[string]any) []map[string]any {
	resources := sliceOfMapsFromAny(entry["resources"])
	if len(resources) == 0 {
		if resource := mapFromAny(entry["resource"]); len(resource) > 0 {
			resources = []map[string]any{resource}
		}
	}
	if len(resources) == 0 {
		return []map[string]any{reportScope}
	}
	out := make([]map[string]any, 0, len(resources))
	for _, resource := range resources {
		out = append(out, resource)
	}
	return out
}

type kyvernoScopeMetadataResolver struct {
	connection     shared.Connection
	scopeLabels    map[string]map[string]string
	namespaceLabel map[string]map[string]string
}

func newKyvernoScopeMetadataResolver(runtime *plugin.Runtime) *kyvernoScopeMetadataResolver {
	resolver := &kyvernoScopeMetadataResolver{
		scopeLabels:    map[string]map[string]string{},
		namespaceLabel: map[string]map[string]string{},
	}
	if runtime == nil || runtime.Connection == nil {
		return resolver
	}
	conn, err := k8sProvider(runtime.Connection)
	if err != nil {
		log.Debug().Err(err).Msg("could not resolve Kyverno policy report scope metadata without k8s connection")
		return resolver
	}
	resolver.connection = conn
	return resolver
}

func (r *kyvernoScopeMetadataResolver) enrich(results []*kyvernoResultData) {
	if r == nil || r.connection == nil {
		return
	}
	for _, result := range results {
		if result == nil {
			continue
		}
		if labels, ok := r.labelsForScope(result); ok {
			result.scopeLabels = mergeStringMaps(result.scopeLabels, labels)
		}
		if labels, ok := r.labelsForNamespace(result.scopeNamespace); ok {
			result.scopeNamespaceLabels = mergeStringMaps(result.scopeNamespaceLabels, labels)
		}
	}
}

func (r *kyvernoScopeMetadataResolver) labelsForScope(result *kyvernoResultData) (map[string]string, bool) {
	if result == nil || result.scopeKind == "" || result.scopeName == "" {
		return nil, false
	}
	lookupKind := kyvernoScopeLookupKind(result)
	key := strings.Join([]string{lookupKind, result.scopeNamespace, result.scopeName}, "\x00")
	if cached, ok := r.scopeLabels[key]; ok {
		return cloneStringMap(cached), true
	}
	labels, ok := r.fetchObjectLabels(lookupKind, result.scopeName, result.scopeNamespace)
	if !ok {
		return nil, false
	}
	r.scopeLabels[key] = cloneStringMap(labels)
	return labels, true
}

func (r *kyvernoScopeMetadataResolver) labelsForNamespace(namespace string) (map[string]string, bool) {
	if namespace == "" {
		return nil, false
	}
	if cached, ok := r.namespaceLabel[namespace]; ok {
		return cloneStringMap(cached), true
	}
	labels, ok := r.fetchObjectLabels("namespace", namespace, "")
	if !ok {
		return nil, false
	}
	r.namespaceLabel[namespace] = cloneStringMap(labels)
	return labels, true
}

func (r *kyvernoScopeMetadataResolver) fetchObjectLabels(kind string, name string, namespace string) (map[string]string, bool) {
	if kind == "" || name == "" {
		return nil, false
	}
	result, err := r.connection.Resources(kind, name, namespace)
	if err != nil {
		log.Debug().Err(err).Str("kind", kind).Str("namespace", namespace).Str("name", name).Msg("could not resolve Kyverno policy report scope object")
		return nil, false
	}
	if result == nil || len(result.Resources) == 0 {
		return nil, false
	}
	obj, err := meta.Accessor(result.Resources[0])
	if err != nil {
		log.Debug().Err(err).Str("kind", kind).Str("namespace", namespace).Str("name", name).Msg("could not read Kyverno policy report scope object metadata")
		return nil, false
	}
	return cloneStringMap(obj.GetLabels()), true
}

func kyvernoScopeLookupKind(result *kyvernoResultData) string {
	kind := strings.ToLower(strings.TrimSpace(result.scopeKind))
	if kind == "" || result.scopeApiVersion == "" {
		return kind
	}
	gv, err := schema.ParseGroupVersion(result.scopeApiVersion)
	if err != nil {
		return kind
	}
	return strings.Join([]string{kind, gv.Version, gv.Group}, ".")
}

func kyvernoScopeLabelsFromProperties(properties map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range properties {
		if label, ok := strings.CutPrefix(key, "label."); ok && label != "" {
			out[label] = value
		}
		if label, ok := strings.CutPrefix(key, "labels."); ok && label != "" {
			out[label] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func kyvernoPolicyExceptionData(
	runtime *plugin.Runtime,
	obj metav1.Object,
	manifest map[string]any,
	policyIndex map[string]struct{},
	ruleIndex map[string]struct{},
	mappingIndex map[string][]kyvernoMappingData,
	resultIndex map[string][]*kyvernoResultData,
) *kyvernoExceptionData {
	annotations := obj.GetAnnotations()
	data := &kyvernoExceptionData{
		namespace:            obj.GetNamespace(),
		name:                 obj.GetName(),
		policyRefs:           []string{},
		ruleNames:            []string{},
		ruleNamesByPolicyRef: map[string][]string{},
		matchKinds:           []string{},
		matchNamespaces:      []string{},
		matchNames:           []string{},
		match:                map[string]any{},
		validUntil:           firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_VALID_UNTIL, kyvernoDefaultExceptionAnnotationValidUntil...)...),
		justification:        firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_JUSTIFICATIONS, kyvernoDefaultExceptionAnnotationJustification...)...),
		owner:                firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_OWNERS, kyvernoDefaultExceptionAnnotationOwners...)...),
		ticket:               firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_EXCEPTION_ANNOTATION_TICKETS, kyvernoDefaultExceptionAnnotationTickets...)...),
	}
	if validUntilTime := timeFromAny(data.validUntil); !validUntilTime.IsZero() {
		data.validUntilTime = &validUntilTime
	}

	for _, exception := range sliceOfMapsFromPath(manifest, "spec", "exceptions") {
		policyName := stringFromMap(exception, "policyName")
		rules := stringsFromAny(exception["ruleNames"])
		if policyName != "" {
			data.policyRefs = append(data.policyRefs, policyName)
			data.ruleNamesByPolicyRef[policyName] = append(data.ruleNamesByPolicyRef[policyName], rules...)
		}
		data.ruleNames = append(data.ruleNames, rules...)
	}
	for _, policyRef := range sliceOfMapsFromPath(manifest, "spec", "policyRefs") {
		ref := stringFromMap(policyRef, "name")
		kind := stringFromMap(policyRef, "kind")
		if ns := stringFromMap(policyRef, "namespace"); ns != "" && !strings.Contains(ref, "/") {
			ref = ns + "/" + ref
		} else if policyRefKindIsNamespaced(kind) && data.namespace != "" && !strings.Contains(ref, "/") {
			ref = data.namespace + "/" + ref
		}
		if kind != "" {
			ref = kind + ":" + ref
		}
		if ref != "" {
			data.policyRefs = append(data.policyRefs, ref)
		}
		refRules := []string{}
		refRules = append(refRules, stringsFromAny(policyRef["ruleNames"])...)
		refRules = append(refRules, stringsFromAny(policyRef["rules"])...)
		if ruleName := stringFromMap(policyRef, "ruleName"); ruleName != "" {
			refRules = append(refRules, ruleName)
		}
		data.ruleNames = append(data.ruleNames, refRules...)
		if ref != "" {
			data.ruleNamesByPolicyRef[ref] = append(data.ruleNamesByPolicyRef[ref], refRules...)
		}
	}
	if policyName := stringFromPath(manifest, "spec", "policyName"); policyName != "" {
		data.policyRefs = append(data.policyRefs, policyName)
		rules := stringsFromPath(manifest, "spec", "ruleNames")
		data.ruleNamesByPolicyRef[policyName] = append(data.ruleNamesByPolicyRef[policyName], rules...)
	}
	data.ruleNames = append(data.ruleNames, stringsFromPath(manifest, "spec", "ruleNames")...)
	data.policyRefs = uniqueStrings(data.policyRefs)
	data.ruleNames = uniqueStrings(data.ruleNames)
	for ref, rules := range data.ruleNamesByPolicyRef {
		data.ruleNamesByPolicyRef[ref] = uniqueStrings(rules)
	}

	match := kyvernoPolicyExceptionMatchFromSpec(mapFromPath(manifest, "spec"))
	data.match = match
	data.matchKinds = uniqueStrings(matchKinds(match))
	data.matchNamespaces = uniqueStrings(matchNamespaces(match))
	data.matchNames = uniqueStrings(matchNames(match))
	data.matchLabelSelectors = matchResourceLabelSelectors(match, "selector")
	data.matchNamespaceSelectors = matchResourceLabelSelectors(match, "namespaceSelector")
	data.matchScope = kyvernoMatchScopeFromMatch(match)
	data.excludeScope = kyvernoMatchScopeFromMatch(mapFromPath(manifest, "spec", "exclude"))
	data.unsupportedScope = kyvernoPolicyExceptionHasUnsupportedScope(manifest)

	reasons := []string{}
	status := "active"
	if len(data.policyRefs) == 0 {
		status = worseStatus(status, "invalid")
		reasons = append(reasons, "invalid: no referenced policies found")
	}
	if len(data.ruleNames) == 0 && !policyRefsUsePolicyLevelExceptions(data.policyRefs) {
		reasons = append(reasons, "broad: no explicit rule names found")
		status = worseStatus(status, "broad")
	}
	if isExpired(data.validUntil) {
		reasons = append(reasons, "expired: valid-until is in the past")
		status = worseStatus(status, "expired")
	}
	if isBroadException(data) {
		reasons = append(reasons, "broad: exception matches a wide resource or rule scope")
		status = worseStatus(status, "broad")
	}
	if data.unsupportedScope || data.matchScope.hasUnsupportedClauses() || data.excludeScope.hasUnsupportedClauses() {
		reasons = append(reasons, "invalid: PolicyException uses unsupported scope refinements")
		status = worseStatus(status, "invalid")
	}

	for _, policyRef := range data.policyRefs {
		policyLookupKey := preferredPolicyLookupKey(policyRef, policyIndex)
		reportPolicyName := policyReportName(policyRef)
		displayPolicyName := reportPolicyName
		if displayPolicyName == "" {
			displayPolicyName = normalizePolicyRef(policyRef)
		}
		if _, ok := policyIndex[policyLookupKey]; !ok {
			reasons = append(reasons, "orphaned: policy "+policyRef+" not found")
			status = worseStatus(status, "orphaned")
		}
		explicitRules := data.ruleNamesForPolicyRef(policyRef)
		rules := policyExceptionRulesForMapping(policyLookupKey, explicitRules, mappingIndex, ruleIndex)
		for _, rule := range rules {
			displayKey := displayPolicyName + "/" + rule
			if rule != "*" {
				if _, ok := ruleIndex[policyLookupKey+"/"+rule]; !ok {
					reasons = append(reasons, "orphaned: rule "+displayKey+" not found")
					status = worseStatus(status, "orphaned")
				}
			}
			mapped := false
			for _, mappingKey := range mappingKeysForExceptionRule(policyLookupKey, rule, mappingIndex) {
				mappings := preferredKyvernoMappings(mappingIndex[mappingKey])
				if len(mappings) == 0 {
					continue
				}
				mapped = true
				for _, mapping := range mappings {
					data.mappedMondooCheckUids = append(data.mappedMondooCheckUids, mapping.mondooCheckUid)
				}
				reasons = append(reasons, "mapped: "+displayMappingKey(displayPolicyName, policyLookupKey, mappingKey))
			}
			if !mapped && rule != "*" {
				reasons = append(reasons, "unmapped: "+displayKey)
				status = worseStatus(status, "unmapped")
			}
			resultRules := policyExceptionResultRules(policyRef, rule, explicitRules)
			if kyvernoExceptionHasMatchingResult(policyRef, policyLookupKey, reportPolicyName, resultRules, data, resultIndex) {
				reasons = append(reasons, "applied: matching exception skip result observed for "+displayPolicyName+"/"+strings.Join(resultRules, ","))
				status = worseStatus(status, "applied")
			} else {
				reasons = append(reasons, "notObserved: no matching exception skip result observed for "+displayPolicyName+"/"+strings.Join(resultRules, ","))
				status = worseStatus(status, "notObserved")
			}
		}
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "active: PolicyException parsed successfully")
	}
	data.mappedMondooCheckUids = uniqueStrings(data.mappedMondooCheckUids)
	data.mappedMondooExceptionIds = kyvernoMirroredExceptionIds(runtime, obj, manifest, data.mappedMondooCheckUids)
	if len(data.mappedMondooExceptionIds) > 0 {
		reasons = append(reasons, fmt.Sprintf("mirrored: %d Mondoo exception links generated", len(data.mappedMondooExceptionIds)))
	}
	data.computedStatus = status
	data.statusReasons = uniqueStrings(reasons)
	return data
}

func (k *mqlK8sKyverno) policyRuleIndexes() (map[string]struct{}, map[string]struct{}, error) {
	policies := k.GetPolicies()
	if policies.Error != nil {
		return nil, nil, policies.Error
	}
	policyIndex := map[string]struct{}{}
	ruleIndex := map[string]struct{}{}
	for _, item := range policies.Data {
		policy := item.(*mqlK8sKyvernoPolicy)
		key := policyKey(policy.Kind.Data, policy.Namespace.Data, policy.Name.Data)
		policyIndex[key] = struct{}{}
		rules := policy.GetRules()
		if rules.Error != nil {
			return nil, nil, rules.Error
		}
		for _, r := range rules.Data {
			rule := r.(*mqlK8sKyvernoRule)
			ruleIndex[key+"/"+rule.Name.Data] = struct{}{}
		}
	}
	return policyIndex, ruleIndex, nil
}

func (k *mqlK8sKyverno) mappingIndex() (map[string][]kyvernoMappingData, error) {
	mappings := k.GetMappings()
	if mappings.Error != nil {
		return nil, mappings.Error
	}
	idx := map[string][]kyvernoMappingData{}
	for _, item := range mappings.Data {
		m := item.(*mqlK8sKyvernoMapping)
		key := policyKey(m.KyvernoKind.Data, m.KyvernoNamespace.Data, m.KyvernoPolicy.Data) + "/" + m.KyvernoRule.Data
		idx[key] = append(idx[key], m.data)
	}
	return idx, nil
}

func (k *mqlK8sKyverno) resultExceptionIndex() (map[string][]kyvernoPolicyExceptionMatch, error) {
	objects, err := k.policyExceptionObjects()
	if err != nil {
		return nil, err
	}
	policyIndex, ruleIndex, err := k.policyRuleIndexes()
	if err != nil {
		return nil, err
	}
	mappingIndex, err := k.mappingIndex()
	if err != nil {
		return nil, err
	}

	idx := map[string][]kyvernoPolicyExceptionMatch{}
	for _, obj := range objects {
		metaObj, typeObj, manifest, err := objectParts(obj)
		if err != nil {
			return nil, err
		}
		data := kyvernoPolicyExceptionData(k.MqlRuntime, metaObj, manifest, policyIndex, ruleIndex, mappingIndex, map[string][]*kyvernoResultData{})
		id := kyvernoObjectId("policyexception", typeObj.GetAPIVersion(), typeObj.GetKind(), metaObj.GetNamespace(), metaObj.GetName())
		for _, policyRef := range data.policyRefs {
			policyLookupKey := preferredPolicyLookupKey(policyRef, policyIndex)
			reportPolicyName := policyReportName(policyRef)
			explicitRules := data.ruleNamesForPolicyRef(policyRef)
			rules := policyExceptionRulesForMapping(policyLookupKey, explicitRules, mappingIndex, ruleIndex)
			for _, rule := range rules {
				for _, resultRule := range policyExceptionResultRules(policyRef, rule, explicitRules) {
					key := policyLookupKey + "/" + resultRule
					idx[key] = append(idx[key], kyvernoPolicyExceptionMatch{id: id, policyRef: policyRef, data: data})
					if policyRefKind(policyRef) == "" {
						idx[reportPolicyName+"/"+resultRule] = append(idx[reportPolicyName+"/"+resultRule], kyvernoPolicyExceptionMatch{id: id, policyRef: policyRef, data: data})
					}
				}
			}
		}
	}
	for key := range idx {
		idx[key] = uniquePolicyExceptionMatches(idx[key])
	}
	return idx, nil
}

func enrichedKyvernoResultData(
	data *kyvernoResultData,
	mappingIndex map[string][]kyvernoMappingData,
	exceptionIndex map[string][]kyvernoPolicyExceptionMatch,
) *kyvernoResultData {
	enriched := clonedKyvernoResultData(data)
	mappings := preferredKyvernoMappings(kyvernoMappingsForResult(data, mappingIndex))
	enriched.mappedCheckUids = enriched.mappedCheckUids[:0]
	enriched.mappedCheckMrns = enriched.mappedCheckMrns[:0]
	for _, mapping := range mappings {
		enriched.mappedCheckUids = append(enriched.mappedCheckUids, mapping.mondooCheckUid)
		enriched.mappedCheckMrns = append(enriched.mappedCheckMrns, mapping.mondooCheckMrn)
	}
	enriched.mappedCheckUids = uniqueStrings(enriched.mappedCheckUids)
	enriched.mappedCheckMrns = uniqueStrings(enriched.mappedCheckMrns)
	mappedExceptionIds := enriched.mappedExceptionIds[:0]
	for _, matches := range kyvernoPolicyExceptionMatchesForResult(data, exceptionIndex) {
		mappedExceptionIds = append(mappedExceptionIds, matchingPolicyExceptionIds(data, matches)...)
	}
	enriched.mappedExceptionIds = uniqueStrings(mappedExceptionIds)
	return &enriched
}

func clonedKyvernoResultData(data *kyvernoResultData) kyvernoResultData {
	out := *data
	out.mappedCheckUids = append([]string(nil), data.mappedCheckUids...)
	out.mappedCheckMrns = append([]string(nil), data.mappedCheckMrns...)
	out.mappedExceptionIds = append([]string(nil), data.mappedExceptionIds...)
	return out
}

func kyvernoMappingsForResult(data *kyvernoResultData, mappingIndex map[string][]kyvernoMappingData) []kyvernoMappingData {
	for _, key := range kyvernoResultIdentityKeys(data) {
		if mappings := mappingIndex[key+"/"+data.rule]; len(mappings) > 0 {
			return mappings
		}
	}
	return kyvernoUnambiguousBareMappingsForResult(data, mappingIndex)
}

func kyvernoUnambiguousBareMappingsForResult(data *kyvernoResultData, mappingIndex map[string][]kyvernoMappingData) []kyvernoMappingData {
	policyNamespace, policyName := kyvernoResultPolicyParts(data)
	if policyName == "" {
		return nil
	}
	identities := map[string]struct{}{}
	out := []kyvernoMappingData{}
	for _, mappings := range mappingIndex {
		for _, mapping := range mappings {
			if mapping.kyvernoPolicy != policyName || mapping.kyvernoRule != data.rule {
				continue
			}
			if policyNamespace != "" && (!policyRefKindIsNamespaced(mapping.kyvernoKind) || mapping.kyvernoNamespace != policyNamespace) {
				continue
			}
			identity := policyKey(mapping.kyvernoKind, mapping.kyvernoNamespace, mapping.kyvernoPolicy)
			identities[identity] = struct{}{}
			out = append(out, mapping)
		}
	}
	if len(identities) != 1 {
		return nil
	}
	return out
}

func kyvernoPolicyExceptionMatchesForResult(data *kyvernoResultData, exceptionIndex map[string][]kyvernoPolicyExceptionMatch) [][]kyvernoPolicyExceptionMatch {
	keys := []string{}
	for _, identity := range kyvernoResultIdentityKeys(data) {
		keys = append(keys, identity+"/"+data.rule, identity+"/*")
	}
	if len(keys) == 0 {
		keys = append(keys, data.policy+"/"+data.rule, data.policy+"/*")
	} else {
		keys = append(keys, kyvernoUnambiguousBareExceptionKeysForResult(data, exceptionIndex)...)
	}

	out := [][]kyvernoPolicyExceptionMatch{}
	seen := map[string]struct{}{}
	for _, key := range keys {
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		if matches := exceptionIndex[key]; len(matches) > 0 {
			out = append(out, matches)
		}
	}
	return out
}

func kyvernoUnambiguousBareExceptionKeysForResult(data *kyvernoResultData, exceptionIndex map[string][]kyvernoPolicyExceptionMatch) []string {
	_, policyName := kyvernoResultPolicyParts(data)
	if policyName == "" {
		return nil
	}
	identities := map[string]struct{}{}
	keys := []string{policyName + "/" + data.rule, policyName + "/*"}
	for _, key := range keys {
		for _, match := range exceptionIndex[key] {
			identity := normalizePolicyRef(match.policyRef)
			if kind := policyRefKind(match.policyRef); kind != "" {
				namespace, name := splitNamespacedName(identity)
				identity = policyKey(kind, namespace, name)
			}
			identities[identity] = struct{}{}
		}
	}
	if len(identities) != 1 {
		return nil
	}
	return keys
}

func kyvernoResultIdentityKeys(data *kyvernoResultData) []string {
	if data == nil || data.policy == "" {
		return nil
	}
	namespace, name := kyvernoResultPolicyParts(data)
	kind := kyvernoPolicyKindFromResultSource(data.source)
	if kind == "" {
		if namespace != "" && name != "" {
			return []string{policyKey("Policy", namespace, name)}
		}
		return nil
	}
	if policyRefKindIsNamespaced(kind) && namespace == "" {
		return nil
	}
	if !policyRefKindIsNamespaced(kind) {
		namespace = ""
	}
	return []string{policyKey(kind, namespace, name)}
}

func kyvernoResultPolicyParts(data *kyvernoResultData) (string, string) {
	if data == nil {
		return "", ""
	}
	namespace, name := splitNamespacedName(data.policy)
	if namespace == "" {
		namespace = firstNonEmpty(data.properties["policy.namespace"], data.properties["policyNamespace"], data.properties["policy_namespace"])
	}
	return namespace, name
}

func kyvernoPolicyKindFromResultSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	switch {
	case strings.Contains(source, "namespacedimagevalidatingpolicy"):
		return "NamespacedImageValidatingPolicy"
	case strings.Contains(source, "imagevalidatingpolicy"):
		return "ImageValidatingPolicy"
	case strings.Contains(source, "namespacedvalidatingpolicy"):
		return "NamespacedValidatingPolicy"
	case strings.Contains(source, "validatingpolicy"):
		return "ValidatingPolicy"
	case strings.Contains(source, "namespacedmutatingpolicy"):
		return "NamespacedMutatingPolicy"
	case strings.Contains(source, "mutatingpolicy"):
		return "MutatingPolicy"
	case strings.Contains(source, "namespacedgeneratingpolicy"):
		return "NamespacedGeneratingPolicy"
	case strings.Contains(source, "generatingpolicy"):
		return "GeneratingPolicy"
	case strings.Contains(source, "namespaceddeletingpolicy"):
		return "NamespacedDeletingPolicy"
	case strings.Contains(source, "deletingpolicy"):
		return "DeletingPolicy"
	case strings.Contains(source, "clusterpolicy"):
		return "ClusterPolicy"
	case source == "policy" || strings.Contains(source, "kyvernopolicy"):
		return "Policy"
	default:
		return ""
	}
}

func preferredKyvernoMappings(mappings []kyvernoMappingData) []kyvernoMappingData {
	if len(mappings) == 0 {
		return nil
	}
	maxPriority := -1
	for _, mapping := range mappings {
		if priority := kyvernoMappingSourcePriority(mapping.source); priority > maxPriority {
			maxPriority = priority
		}
	}
	out := []kyvernoMappingData{}
	for _, mapping := range mappings {
		if kyvernoMappingSourcePriority(mapping.source) == maxPriority {
			out = append(out, mapping)
		}
	}
	return out
}

func policyExceptionRulesForMapping(
	policyName string,
	ruleNames []string,
	mappingIndex map[string][]kyvernoMappingData,
	ruleIndex map[string]struct{},
) []string {
	if len(ruleNames) > 0 {
		return ruleNames
	}
	rules := indexedRulesForPolicy(policyName, ruleIndex)
	if len(rules) > 0 {
		return rules
	}
	rules = mappedRulesForPolicy(policyName, mappingIndex)
	if len(rules) > 0 {
		return rules
	}
	return []string{"*"}
}

func (d *kyvernoExceptionData) ruleNamesForPolicyRef(policyRef string) []string {
	if d == nil {
		return nil
	}
	if rules := d.ruleNamesByPolicyRef[policyRef]; len(rules) > 0 {
		return rules
	}
	if normalized := normalizePolicyRef(policyRef); normalized != policyRef {
		if rules := d.ruleNamesByPolicyRef[normalized]; len(rules) > 0 {
			return rules
		}
	}
	return d.ruleNames
}

func policyExceptionResultRules(policyRef string, rule string, explicitRuleNames []string) []string {
	if len(explicitRuleNames) == 0 && policyRefUsesPolicyLevelException(policyRef) {
		return []string{"exception"}
	}
	return []string{rule}
}

func mappingKeysForExceptionRule(policyName string, rule string, mappingIndex map[string][]kyvernoMappingData) []string {
	if rule != "*" {
		return []string{policyName + "/" + rule}
	}
	keys := []string{}
	for _, mappedRule := range mappedRulesForPolicy(policyName, mappingIndex) {
		keys = append(keys, policyName+"/"+mappedRule)
	}
	return keys
}

func displayMappingKey(displayPolicyName string, policyLookupKey string, mappingKey string) string {
	if displayPolicyName == "" {
		return mappingKey
	}
	for _, prefix := range []string{policyLookupKey + "/", displayPolicyName + "/"} {
		if strings.HasPrefix(mappingKey, prefix) {
			return displayPolicyName + "/" + strings.TrimPrefix(mappingKey, prefix)
		}
	}
	if idx := strings.LastIndex(mappingKey, "/"); idx >= 0 && idx < len(mappingKey)-1 {
		rule := mappingKey[idx+1:]
		return displayPolicyName + "/" + rule
	}
	return mappingKey
}

func mappedRulesForPolicy(policyName string, mappingIndex map[string][]kyvernoMappingData) []string {
	rules := map[string]struct{}{}
	prefix := policyName + "/"
	for key, mappings := range mappingIndex {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rule := strings.TrimPrefix(key, prefix)
		if rule == "" || strings.Contains(rule, "/") {
			continue
		}
		if len(preferredKyvernoMappings(mappings)) == 0 {
			continue
		}
		rules[rule] = struct{}{}
	}
	return sortedStringSet(rules)
}

func indexedRulesForPolicy(policyName string, ruleIndex map[string]struct{}) []string {
	rules := map[string]struct{}{}
	prefix := policyName + "/"
	for key := range ruleIndex {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rule := strings.TrimPrefix(key, prefix)
		if rule == "" || strings.Contains(rule, "/") {
			continue
		}
		rules[rule] = struct{}{}
	}
	return sortedStringSet(rules)
}

func sortedStringSet(items map[string]struct{}) []string {
	out := make([]string, 0, len(items))
	for item := range items {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func kyvernoMappingSourcePriority(source string) int {
	switch source {
	case "annotation":
		return 3
	case "generated":
		return 2
	case "builtin":
		return 1
	default:
		return 0
	}
}

func (k *mqlK8sKyverno) resultIndex() (map[string][]*kyvernoResultData, error) {
	reports := k.GetPolicyReports()
	if reports.Error != nil {
		return nil, reports.Error
	}
	idx := map[string][]*kyvernoResultData{}
	for _, item := range reports.Data {
		report := item.(*mqlK8sKyvernoPolicyreport)
		for _, res := range report.resultData {
			if res.policy == "" || res.rule == "" {
				continue
			}
			keys := []string{res.policy + "/" + res.rule}
			for _, identity := range kyvernoResultIdentityKeys(res) {
				keys = append(keys, identity+"/"+res.rule)
			}
			for _, key := range keys {
				idx[key] = append(idx[key], res)
			}
		}
	}
	return idx, nil
}

func annotationMappingsForPolicy(runtime *plugin.Runtime, policy *mqlK8sKyvernoPolicy) ([]kyvernoMappingData, error) {
	obj, err := policy.initializedObject()
	if err != nil {
		return nil, err
	}
	annotations := obj.GetAnnotations()
	checkUid := firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_UIDS, kyvernoDefaultMappingAnnotationCheckUids...)...)
	checkMrn := firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_MRNS, kyvernoDefaultMappingAnnotationCheckMrns...)...)
	if checkUid == "" && checkMrn == "" {
		return nil, nil
	}
	mondooPolicy := firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_MAPPING_ANNOTATION_POLICY_UIDS, kyvernoDefaultMappingAnnotationPolicyUids...)...)
	reason := firstAnnotation(annotations, kyvernoAnnotationKeys(runtime, shared.OPTION_KYVERNO_MAPPING_ANNOTATION_REASONS, kyvernoDefaultMappingAnnotationReasons...)...)
	if reason == "" {
		reason = "Mapping provided by Kyverno policy annotations."
	}
	out := []kyvernoMappingData{}
	rules := policy.GetRules()
	if rules.Error != nil {
		return nil, rules.Error
	}
	for _, item := range rules.Data {
		rule := item.(*mqlK8sKyvernoRule)
		id := stableHash(policy.Kind.Data, policy.Namespace.Data, policy.Name.Data, rule.Name.Data, checkUid, checkMrn)
		out = append(out, kyvernoMappingData{
			id:               "kyverno-mapping:" + id,
			kyvernoKind:      policy.Kind.Data,
			kyvernoNamespace: policy.Namespace.Data,
			kyvernoPolicy:    policy.Name.Data,
			kyvernoRule:      rule.Name.Data,
			mondooPolicyUid:  mondooPolicy,
			mondooCheckUid:   checkUid,
			mondooCheckMrn:   checkMrn,
			source:           "annotation",
			confidence:       "high",
			reason:           reason,
		})
	}
	return out, nil
}

func builtinMappingsForPolicy(policy *mqlK8sKyvernoPolicy) ([]kyvernoMappingData, error) {
	out := []kyvernoMappingData{}
	rules := policy.GetRules()
	if rules.Error != nil {
		return nil, rules.Error
	}
	for _, mapping := range kyvernoBuiltinPolicyMappings {
		if mapping.policy != policy.Name.Data {
			continue
		}
		confidence := mapping.confidence
		if confidence == "" {
			confidence = "high"
		}
		reason := mapping.reason
		if reason == "" {
			reason = "Official Kyverno policy semantics match Mondoo Kubernetes security checks."
		}
		mondooPolicyUid := mapping.mondooPolicyUid
		if mondooPolicyUid == "" {
			mondooPolicyUid = kyvernoBuiltinMondooPolicyUid
		}
		ruleSet := kyvernoStringSet(mapping.rules)
		for _, item := range rules.Data {
			rule := item.(*mqlK8sKyvernoRule)
			if _, ok := ruleSet[rule.Name.Data]; !ok {
				continue
			}
			for _, checkUid := range mapping.checks {
				id := stableHash("builtin", policy.Kind.Data, policy.Namespace.Data, policy.Name.Data, rule.Name.Data, checkUid)
				out = append(out, kyvernoMappingData{
					id:               "kyverno-mapping:" + id,
					kyvernoKind:      policy.Kind.Data,
					kyvernoNamespace: policy.Namespace.Data,
					kyvernoPolicy:    policy.Name.Data,
					kyvernoRule:      rule.Name.Data,
					mondooPolicyUid:  mondooPolicyUid,
					mondooCheckUid:   checkUid,
					mondooCheckMrn:   kyvernoCheckMrn(mondooPolicyUid, checkUid),
					source:           "builtin",
					confidence:       confidence,
					reason:           reason,
				})
			}
		}
	}
	return out, nil
}

func kyvernoCheckMrn(policyUid string, checkUid string) string {
	return "//policy.api.mondoo.app/policies/" + policyUid + "/checks/" + checkUid
}

func kyvernoRoot(runtime *plugin.Runtime) (*mqlK8sKyverno, error) {
	root, err := CreateResource(runtime, "k8s", nil)
	if err != nil {
		return nil, err
	}
	return root.(*mqlK8s).kyverno()
}

func validationAction(manifest map[string]any) string {
	if action := stringFromPath(manifest, "spec", "validationFailureAction"); action != "" {
		return action
	}
	if actions := stringsFromPath(manifest, "spec", "validationActions"); len(actions) > 0 {
		return strings.Join(actions, ",")
	}
	return ""
}

func classicRuleType(rule map[string]any) string {
	for _, key := range []string{"validate", "mutate", "generate", "verifyImages", "imageExtractors", "cleanup"} {
		if _, ok := rule[key]; ok {
			return key
		}
	}
	return "rule"
}

func mapFromPath(m map[string]any, path ...string) map[string]any {
	cur := any(m)
	for _, part := range path {
		curMap, ok := cur.(map[string]any)
		if !ok {
			return map[string]any{}
		}
		cur = curMap[part]
	}
	return mapFromAny(cur)
}

func mapFromAny(v any) map[string]any {
	if v == nil {
		return map[string]any{}
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func mapWithoutKeys(m map[string]any, keys ...string) map[string]any {
	if len(m) == 0 {
		return map[string]any{}
	}
	excluded := map[string]struct{}{}
	for _, key := range keys {
		excluded[key] = struct{}{}
	}
	out := make(map[string]any, len(m))
	for key, value := range m {
		if _, ok := excluded[key]; ok {
			continue
		}
		out[key] = value
	}
	return out
}

func sliceOfMapsFromPath(m map[string]any, path ...string) []map[string]any {
	return sliceOfMapsFromAny(valueFromPath(m, path...))
}

func sliceOfMapsFromAny(v any) []map[string]any {
	items, ok := v.([]any)
	if !ok {
		if single := mapFromAny(v); len(single) > 0 {
			return []map[string]any{single}
		}
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m := mapFromAny(item); len(m) > 0 {
			out = append(out, m)
		}
	}
	return out
}

func stringFromPath(m map[string]any, path ...string) string {
	return stringFromAny(valueFromPath(m, path...))
}

func stringsFromPath(m map[string]any, path ...string) []string {
	return stringsFromAny(valueFromPath(m, path...))
}

func valueFromPath(m map[string]any, path ...string) any {
	cur := any(m)
	for _, part := range path {
		curMap, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = curMap[part]
	}
	return cur
}

func stringFromMap(m map[string]any, key string) string {
	return stringFromAny(m[key])
}

func stringFromAny(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case fmt.Stringer:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

func stringsFromAny(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s := stringFromAny(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	default:
		return nil
	}
}

func stringMapFromAny(v any) map[string]string {
	if typed, ok := v.(map[string]string); ok {
		return cloneStringMap(typed)
	}
	out := map[string]string{}
	for key, value := range mapFromAny(v) {
		out[key] = stringFromAny(value)
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func mergeStringMaps(base map[string]string, overlay map[string]string) map[string]string {
	out := cloneStringMap(base)
	if len(overlay) == 0 {
		return out
	}
	if out == nil {
		out = map[string]string{}
	}
	for key, value := range overlay {
		out[key] = value
	}
	return out
}

func boolFromPath(m map[string]any, defaultValue bool, path ...string) bool {
	return boolFromAny(valueFromPath(m, path...), defaultValue)
}

func boolFromAny(v any, defaultValue bool) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	case nil:
		return defaultValue
	default:
		return defaultValue
	}
}

func timeFromAny(v any) time.Time {
	switch t := v.(type) {
	case time.Time:
		return t
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
			parsed, err := time.Parse(layout, t)
			if err == nil {
				return parsed
			}
		}
	}
	return time.Time{}
}

func kyvernoDefaultMappingsEnabled(runtime *plugin.Runtime) bool {
	return kyvernoOptionBool(runtime, shared.OPTION_KYVERNO_DEFAULT_MAPPINGS, true)
}

func kyvernoOptionBool(runtime *plugin.Runtime, option string, defaultValue bool) bool {
	options := kyvernoInventoryOptions(runtime)
	value := strings.TrimSpace(options[option])
	if value == "" {
		return defaultValue
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}
	return enabled
}

func kyvernoOptionString(runtime *plugin.Runtime, option string, defaultValue string) string {
	options := kyvernoInventoryOptions(runtime)
	value := strings.TrimSpace(options[option])
	if value == "" {
		return defaultValue
	}
	return value
}

func kyvernoAnnotationKeys(runtime *plugin.Runtime, option string, defaults ...string) []string {
	options := kyvernoInventoryOptions(runtime)
	if configured := splitOptionList(options[option]); len(configured) > 0 {
		return configured
	}
	return defaults
}

func kyvernoInventoryOptions(runtime *plugin.Runtime) map[string]string {
	if runtime == nil || runtime.Connection == nil {
		return nil
	}
	conn, ok := runtime.Connection.(shared.Connection)
	if !ok || conn.InventoryConfig() == nil {
		return nil
	}
	return conn.InventoryConfig().Options
}

func splitOptionList(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func firstAnnotation(annotations map[string]string, keys ...string) string {
	for _, key := range keys {
		if annotations[key] != "" {
			return annotations[key]
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func kyvernoWorkloadChecks(suffixes ...string) []string {
	workloads := []string{"pod", "cronjob", "daemonset", "deployment", "job", "replicaset", "statefulset"}
	out := make([]string, 0, len(workloads)*len(suffixes))
	for _, suffix := range suffixes {
		for _, workload := range workloads {
			out = append(out, "mondoo-kubernetes-security-"+workload+"-"+suffix)
		}
	}
	return out
}

func kyvernoPSSBaselineChecks() []string {
	return kyvernoPSSBaselineChecksExcept()
}

func kyvernoPSSBaselineChecksExcept(excluded ...string) []string {
	skip := map[string]struct{}{}
	for _, suffix := range excluded {
		skip[suffix] = struct{}{}
	}
	suffixes := []string{
		"privilegedcontainer",
		"hostipc",
		"hostnetwork",
		"hostpid",
		"hostprocess",
		"proc-mount",
		"safe-sysctls",
		"selinux-type",
		"selinux-user-role",
		"seccomp-profile",
		"ports-hostport",
		"hostpath-readonly",
		"capability-net-raw",
		"capability-sys-admin",
	}
	out := []string{}
	for _, suffix := range suffixes {
		if _, ok := skip[suffix]; ok {
			continue
		}
		out = append(out, kyvernoWorkloadChecks(suffix)...)
	}
	return out
}

func kyvernoPSSRestrictedChecks() []string {
	checks := kyvernoPSSBaselineChecks()
	checks = append(checks, kyvernoWorkloadChecks(
		"allowprivilegeescalation",
		"runasnonroot",
		"capability-drop-all",
	)...)
	return checks
}

func kyvernoPSSRestrictedWithoutCapabilitiesChecks() []string {
	checks := kyvernoPSSBaselineChecksExcept("capability-net-raw", "capability-sys-admin")
	checks = append(checks, kyvernoWorkloadChecks(
		"allowprivilegeescalation",
		"runasnonroot",
	)...)
	return checks
}

func kyvernoPSSRestrictedWithoutSeccompChecks() []string {
	checks := kyvernoPSSBaselineChecksExcept("seccomp-profile")
	checks = append(checks, kyvernoWorkloadChecks(
		"allowprivilegeescalation",
		"runasnonroot",
		"capability-drop-all",
	)...)
	return checks
}

func kyvernoBestPracticeWorkloadChecks(suffixes ...string) []string {
	workloads := []string{"pod", "cronjob", "daemonset", "deployment", "job", "replicaset", "statefulset"}
	return kyvernoBestPracticeChecks(workloads, suffixes...)
}

func kyvernoBestPracticeChecks(workloads []string, suffixes ...string) []string {
	out := make([]string, 0, len(workloads)*len(suffixes))
	for _, suffix := range suffixes {
		for _, workload := range workloads {
			out = append(out, "mondoo-kubernetes-best-practices-"+workload+"-"+suffix)
		}
	}
	return out
}

func matchKinds(match map[string]any) []string {
	out := []string{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for key, value := range t {
				if key == "kinds" || key == "resources" {
					if key == "kinds" {
						out = append(out, stringsFromAny(value)...)
					}
					walk(value)
					continue
				}
				if key == "resourceRules" {
					for _, rr := range sliceOfMapsFromAny(value) {
						out = append(out, stringsFromAny(rr["resources"])...)
					}
				}
				walk(value)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		case []map[string]any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(match)
	out = append(out, celStringEqualities(match, kyvernoCELKindEquals...)...)
	return uniqueStrings(out)
}

func matchNamespaces(match map[string]any) []string {
	out := matchStringField(match, "namespaces")
	out = append(out, celStringEqualities(match, kyvernoCELNamespaceEquals...)...)
	return uniqueStrings(out)
}

func matchNames(match map[string]any) []string {
	out := matchStringField(match, "names")
	out = append(out, celStringEqualities(match, kyvernoCELNameEquals...)...)
	return uniqueStrings(out)
}

func kyvernoMirroredExceptionIds(runtime *plugin.Runtime, obj metav1.Object, manifest map[string]any, checks []string) []string {
	if !kyvernoOptionBool(runtime, shared.OPTION_KYVERNO_MIRROR_POLICY_EXCEPTIONS, false) || len(checks) == 0 {
		return nil
	}
	policyExceptionId := kyvernoObjectId(
		"policyexception",
		stringFromMap(manifest, "apiVersion"),
		stringFromMap(manifest, "kind"),
		obj.GetNamespace(),
		obj.GetName(),
	)
	out := make([]string, 0, len(checks))
	for _, check := range checks {
		out = append(out, "mondoo-exception:kyverno:"+stableHash(policyExceptionId, check)[:16])
	}
	return uniqueStrings(out)
}

func matchConditionKinds(match map[string]any) []string {
	return celStringEqualities(matchConditionsOnly(match), kyvernoCELKindEquals...)
}

func matchConditionNamespaces(match map[string]any) []string {
	return celStringEqualities(matchConditionsOnly(match), kyvernoCELNamespaceEquals...)
}

func matchConditionNames(match map[string]any) []string {
	return celStringEqualities(matchConditionsOnly(match), kyvernoCELNameEquals...)
}

func matchConditionsOnly(match map[string]any) map[string]any {
	conditions := valueFromPath(match, "matchConditions")
	if !valuePresent(conditions) {
		return map[string]any{}
	}
	return map[string]any{"matchConditions": conditions}
}

func matchStringField(match map[string]any, field string) []string {
	out := []string{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for key, value := range t {
				if key == field {
					out = append(out, stringsFromAny(value)...)
				}
				walk(value)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		case []map[string]any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(match)
	return uniqueStrings(out)
}

func celStringEqualities(match map[string]any, patterns ...*regexp.Regexp) []string {
	out := []string{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for key, value := range t {
				if key == "expression" {
					expression := stringFromAny(value)
					for _, pattern := range patterns {
						for _, found := range pattern.FindAllStringSubmatch(expression, -1) {
							if len(found) > 1 {
								out = append(out, found[1])
							}
						}
					}
				}
				walk(value)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		case []map[string]any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(match)
	return uniqueStrings(out)
}

func kyvernoExceptionHasMatchingResult(policyRef string, policyLookupKey string, policyName string, rules []string, exception *kyvernoExceptionData, resultIndex map[string][]*kyvernoResultData) bool {
	policyNames := []string{policyLookupKey}
	if policyRefKind(policyRef) == "" {
		policyNames = append(policyNames, policyName)
	}
	if len(rules) == 1 && rules[0] == "*" {
		for _, name := range policyNames {
			prefix := name + "/"
			for key, results := range resultIndex {
				if !strings.HasPrefix(key, prefix) {
					continue
				}
				if kyvernoExceptionMatchesAnyAppliedResult(policyRef, exception, results) {
					return true
				}
			}
		}
		return false
	}
	for _, rule := range rules {
		for _, name := range policyNames {
			if kyvernoExceptionMatchesAnyAppliedResult(policyRef, exception, resultIndex[name+"/"+rule]) {
				return true
			}
		}
	}
	return false
}

func kyvernoExceptionMatchesAnyAppliedResult(policyRef string, exception *kyvernoExceptionData, results []*kyvernoResultData) bool {
	for _, result := range results {
		if kyvernoPolicyExceptionAppliedToResult(policyRef, exception, result) {
			return true
		}
	}
	return false
}

func matchingPolicyExceptionIds(result *kyvernoResultData, exceptions []kyvernoPolicyExceptionMatch) []string {
	out := []string{}
	for _, exception := range exceptions {
		if kyvernoPolicyExceptionAppliedToResult(exception.policyRef, exception.data, result) {
			out = append(out, exception.id)
		}
	}
	return out
}

func kyvernoPolicyExceptionAppliedToResult(policyRef string, exception *kyvernoExceptionData, result *kyvernoResultData) bool {
	if !kyvernoResultIsPolicyExceptionSkip(result) {
		return false
	}
	if !kyvernoResultSourceMatchesPolicyRef(policyRef, result) {
		return false
	}
	if !kyvernoResultReferencesException(exception, result) {
		return false
	}
	return kyvernoPolicyExceptionMatchesResult(exception, result)
}

func kyvernoResultIsPolicyExceptionSkip(result *kyvernoResultData) bool {
	if result == nil {
		return false
	}
	reportResult := strings.ToLower(strings.TrimSpace(result.result))
	if strings.TrimSpace(result.properties["exceptions"]) != "" {
		return reportResult == "skip" || reportResult == "pass"
	}
	return reportResult == "skip" && strings.Contains(strings.ToLower(result.message), "policy exception")
}

func kyvernoResultReferencesException(exception *kyvernoExceptionData, result *kyvernoResultData) bool {
	if exception == nil || result == nil || exception.name == "" {
		return false
	}
	candidates := map[string]struct{}{
		exception.name: {},
	}
	if exception.namespace != "" {
		candidates[exception.namespace+"/"+exception.name] = struct{}{}
	}
	for _, value := range []string{result.properties["exceptions"], result.properties["exception"], result.message} {
		for _, token := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == '\'' || r == '"' || r == ':'
		}) {
			token = strings.Trim(strings.TrimSpace(token), ".,()[]{}")
			if _, ok := candidates[token]; ok {
				return true
			}
		}
	}
	return false
}

func kyvernoResultSourceMatchesPolicyRef(policyRef string, result *kyvernoResultData) bool {
	if result == nil {
		return false
	}
	kind := policyRefKind(policyRef)
	if kind == "" {
		return true
	}
	source := strings.ToLower(strings.TrimSpace(result.source))
	switch strings.ToLower(kind) {
	case "clusterpolicy", "policy":
		return source == "" || source == "kyverno"
	case "validatingpolicy", "namespacedvalidatingpolicy":
		return strings.Contains(source, "validatingpolicy")
	case "imagevalidatingpolicy", "namespacedimagevalidatingpolicy":
		return strings.Contains(source, "imagevalidatingpolicy")
	case "mutatingpolicy", "namespacedmutatingpolicy":
		return strings.Contains(source, "mutatingpolicy")
	case "generatingpolicy", "namespacedgeneratingpolicy":
		return strings.Contains(source, "generatingpolicy")
	case "deletingpolicy", "namespaceddeletingpolicy":
		return strings.Contains(source, "deletingpolicy")
	default:
		return true
	}
}

func kyvernoPolicyExceptionMatchesResult(exception *kyvernoExceptionData, result *kyvernoResultData) bool {
	if exception == nil || result == nil {
		return false
	}
	if exception.unsupportedScope || exception.matchScope.hasUnsupportedClauses() || exception.excludeScope.hasUnsupportedClauses() {
		return false
	}
	if exception.excludeScope.hasClauses() && exception.excludeScope.matches(result) {
		return false
	}
	if exception.matchScope.hasClauses() {
		return exception.matchScope.matches(result) && kyvernoPolicyExceptionMatchConditionsMatchResult(exception.match, result)
	}
	if !scopeValuesMatch(exception.matchKinds, result.scopeKind, normalizeK8sKind) {
		return false
	}
	if !scopeValuesMatch(exception.matchNamespaces, result.scopeNamespace, normalizeScopeString) {
		return false
	}
	if !scopeValuesMatch(exception.matchNames, result.scopeName, normalizeScopeString) {
		return false
	}
	if !labelSelectorsMatch(exception.matchLabelSelectors, result.scopeLabels) {
		return false
	}
	if !labelSelectorsMatch(exception.matchNamespaceSelectors, result.scopeNamespaceLabels) {
		return false
	}
	return true
}

func kyvernoPolicyExceptionMatchConditionsMatchResult(match map[string]any, result *kyvernoResultData) bool {
	if !scopeValuesMatch(matchConditionKinds(match), result.scopeKind, normalizeK8sKind) {
		return false
	}
	if !scopeValuesMatch(matchConditionNamespaces(match), result.scopeNamespace, normalizeScopeString) {
		return false
	}
	if !scopeValuesMatch(matchConditionNames(match), result.scopeName, normalizeScopeString) {
		return false
	}
	return true
}

func kyvernoMatchScopeFromMatch(match map[string]any) kyvernoMatchScope {
	scope := kyvernoMatchScope{}
	if len(match) == 0 {
		return scope
	}
	for _, item := range sliceOfMapsFromAny(match["any"]) {
		scope.anyClauses = append(scope.anyClauses, kyvernoMatchClauseFromAny(item))
	}
	for _, item := range sliceOfMapsFromAny(match["all"]) {
		scope.allClauses = append(scope.allClauses, kyvernoMatchClauseFromAny(item))
	}
	if len(scope.anyClauses) == 0 && len(scope.allClauses) == 0 {
		directMatch := mapWithoutKeys(match, "matchConditions")
		if len(directMatch) > 0 {
			scope.directClauses = append(scope.directClauses, kyvernoMatchClauseFromAny(directMatch))
		}
	}
	return scope
}

func kyvernoPolicyExceptionMatchFromSpec(spec map[string]any) map[string]any {
	match := mapFromAny(spec["match"])
	conditions := sliceOfMapsFromAny(spec["matchConditions"])
	if len(match) == 0 {
		if len(conditions) == 0 {
			return map[string]any{}
		}
		return map[string]any{"matchConditions": conditions}
	}
	if len(conditions) == 0 {
		return match
	}
	out := make(map[string]any, len(match)+1)
	for key, value := range match {
		out[key] = value
	}
	out["matchConditions"] = append(sliceOfMapsFromAny(match["matchConditions"]), conditions...)
	return out
}

func (s kyvernoMatchScope) hasClauses() bool {
	return len(s.directClauses)+len(s.anyClauses)+len(s.allClauses) > 0
}

func (s kyvernoMatchScope) hasUnsupportedClauses() bool {
	for _, clause := range append(append(s.directClauses, s.anyClauses...), s.allClauses...) {
		if clause.unsupported {
			return true
		}
	}
	return false
}

func (s kyvernoMatchScope) matches(result *kyvernoResultData) bool {
	for _, clause := range s.directClauses {
		if !clause.matches(result) {
			return false
		}
	}
	for _, clause := range s.allClauses {
		if !clause.matches(result) {
			return false
		}
	}
	if len(s.anyClauses) == 0 {
		return true
	}
	for _, clause := range s.anyClauses {
		if clause.matches(result) {
			return true
		}
	}
	return false
}

func kyvernoMatchClauseFromAny(value any) kyvernoMatchClause {
	item := mapFromAny(value)
	resources := mapFromAny(item["resources"])
	if len(resources) == 0 {
		resources = item
	}
	clause := kyvernoMatchClause{
		kinds:      uniqueStrings(stringsFromAny(resources["kinds"])),
		namespaces: uniqueStrings(stringsFromAny(resources["namespaces"])),
		names:      uniqueStrings(stringsFromAny(resources["names"])),
	}
	if selector, ok := labelSelectorFromAny(resources["selector"]); ok {
		clause.labelSelector = selector
	}
	if selector, ok := labelSelectorFromAny(resources["namespaceSelector"]); ok {
		clause.namespaceSelector = selector
	}
	if kyvernoResourcesContainUnsupportedScope(resources) {
		clause.unsupported = true
	}
	return clause
}

func (c kyvernoMatchClause) matches(result *kyvernoResultData) bool {
	if c.unsupported || result == nil {
		return false
	}
	if !scopeValuesMatch(c.kinds, result.scopeKind, normalizeK8sKind) {
		return false
	}
	if !scopeValuesMatch(c.namespaces, result.scopeNamespace, normalizeScopeString) {
		return false
	}
	if !scopeValuesMatch(c.names, result.scopeName, normalizeScopeString) {
		return false
	}
	if c.labelSelector != nil && !singleLabelSelectorMatches(c.labelSelector, result.scopeLabels) {
		return false
	}
	if c.namespaceSelector != nil && !singleLabelSelectorMatches(c.namespaceSelector, result.scopeNamespaceLabels) {
		return false
	}
	return true
}

func kyvernoPolicyExceptionHasUnsupportedScope(manifest map[string]any) bool {
	return valuePresent(valueFromPath(manifest, "spec", "conditions")) ||
		valuePresent(valueFromPath(manifest, "spec", "podSecurity"))
}

func kyvernoResourcesContainUnsupportedScope(resources map[string]any) bool {
	for _, key := range []string{"operations", "subjects", "roles", "clusterRoles"} {
		if valuePresent(resources[key]) {
			return true
		}
	}
	return false
}

func valuePresent(value any) bool {
	switch v := value.(type) {
	case nil:
		return false
	case string:
		return strings.TrimSpace(v) != ""
	case []any:
		return len(v) > 0
	case []map[string]any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	default:
		return true
	}
}

func matchResourceLabelSelectors(match map[string]any, field string) []labels.Selector {
	selectorByString := map[string]labels.Selector{}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			if resources := mapFromAny(t["resources"]); len(resources) > 0 {
				if selector, ok := labelSelectorFromAny(resources[field]); ok {
					selectorByString[selector.String()] = selector
				}
			}
			for _, value := range t {
				walk(value)
			}
		case []any:
			for _, item := range t {
				walk(item)
			}
		case []map[string]any:
			for _, item := range t {
				walk(item)
			}
		}
	}
	walk(match)

	keys := make([]string, 0, len(selectorByString))
	for key := range selectorByString {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]labels.Selector, 0, len(keys))
	for _, key := range keys {
		out = append(out, selectorByString[key])
	}
	return out
}

func labelSelectorFromAny(v any) (labels.Selector, bool) {
	raw := mapFromAny(v)
	if len(raw) == 0 {
		return nil, false
	}
	selector := &metav1.LabelSelector{
		MatchLabels: stringMapFromAny(raw["matchLabels"]),
	}
	for _, expr := range sliceOfMapsFromAny(raw["matchExpressions"]) {
		requirement := metav1.LabelSelectorRequirement{
			Key:      stringFromMap(expr, "key"),
			Operator: metav1.LabelSelectorOperator(stringFromMap(expr, "operator")),
			Values:   stringsFromAny(expr["values"]),
		}
		if requirement.Key == "" || requirement.Operator == "" {
			log.Debug().Interface("selector", raw).Msg("invalid Kyverno PolicyException label selector expression")
			return labels.Nothing(), true
		}
		selector.MatchExpressions = append(selector.MatchExpressions, requirement)
	}
	if len(selector.MatchLabels) == 0 && len(selector.MatchExpressions) == 0 {
		return nil, false
	}
	parsed, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		log.Debug().Err(err).Interface("selector", raw).Msg("invalid Kyverno PolicyException label selector")
		return labels.Nothing(), true
	}
	return parsed, true
}

func labelSelectorsMatch(selectors []labels.Selector, values map[string]string) bool {
	if len(selectors) == 0 {
		return true
	}
	if values == nil {
		return false
	}
	set := labels.Set(values)
	for _, selector := range selectors {
		if selector.Matches(set) {
			return true
		}
	}
	return false
}

func singleLabelSelectorMatches(selector labels.Selector, values map[string]string) bool {
	if values == nil {
		return false
	}
	return selector.Matches(labels.Set(values))
}

func scopeValuesMatch(patterns []string, value string, normalize func(string) string) bool {
	if len(patterns) == 0 {
		return true
	}
	value = normalize(value)
	if value == "" {
		return false
	}
	for _, patternValue := range patterns {
		patternValue = normalize(patternValue)
		if patternValue == "" {
			continue
		}
		if patternValue == "*" || patternValue == value {
			return true
		}
		if ok, err := path.Match(patternValue, value); err == nil && ok {
			return true
		}
	}
	return false
}

func normalizeScopeString(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeK8sKind(value string) string {
	value = normalizeScopeString(value)
	if idx := strings.LastIndex(value, "/"); idx >= 0 {
		value = value[idx+1:]
	}
	if singular, ok := kyvernoK8sKindPluralAliases[value]; ok {
		return singular
	}
	return value
}

func isExpired(validUntil string) bool {
	if validUntil == "" {
		return false
	}
	t := timeFromAny(validUntil)
	return !t.IsZero() && time.Now().After(t)
}

func isBroadException(data *kyvernoExceptionData) bool {
	if (len(data.ruleNames) == 0 && !policyRefsUsePolicyLevelExceptions(data.policyRefs)) || containsString(data.ruleNames, "*") {
		return true
	}
	if data.matchScope.hasClauses() {
		if !data.matchScope.isBroad() {
			return false
		}
		return len(matchConditionNamespaces(data.match)) == 0 && len(matchConditionNames(data.match)) == 0
	}
	if len(data.matchKinds) == 0 || containsString(data.matchKinds, "*") {
		return true
	}
	if len(data.matchNamespaces) == 0 && len(data.matchNames) == 0 && len(data.matchLabelSelectors) == 0 && len(data.matchNamespaceSelectors) == 0 {
		return true
	}
	return false
}

type kyvernoBroadScope struct {
	kinds                    []string
	namespaces               []string
	names                    []string
	hasLabelSelector         bool
	hasNamespaceSelector     bool
	hasUnsupportedConstraint bool
}

func (s kyvernoMatchScope) isBroad() bool {
	common := kyvernoBroadScope{}
	for _, clause := range s.directClauses {
		common.add(clause)
	}
	for _, clause := range s.allClauses {
		common.add(clause)
	}
	if len(s.anyClauses) == 0 {
		return common.isBroad()
	}
	for _, clause := range s.anyClauses {
		branch := common
		branch.add(clause)
		if branch.isBroad() {
			return true
		}
	}
	return false
}

func (s *kyvernoBroadScope) add(clause kyvernoMatchClause) {
	s.kinds = append(s.kinds, clause.kinds...)
	s.namespaces = append(s.namespaces, clause.namespaces...)
	s.names = append(s.names, clause.names...)
	s.hasLabelSelector = s.hasLabelSelector || clause.labelSelector != nil
	s.hasNamespaceSelector = s.hasNamespaceSelector || clause.namespaceSelector != nil
	s.hasUnsupportedConstraint = s.hasUnsupportedConstraint || clause.unsupported
}

func (s kyvernoBroadScope) isBroad() bool {
	if s.hasUnsupportedConstraint {
		return true
	}
	if len(s.kinds) == 0 || containsString(s.kinds, "*") {
		return true
	}
	if len(s.namespaces) == 0 && len(s.names) == 0 && !s.hasLabelSelector && !s.hasNamespaceSelector {
		return true
	}
	return false
}

var kyvernoExceptionStatusOrder = map[string]int{
	"active":      0,
	"applied":     1,
	"notObserved": 2,
	"broad":       3,
	"unmapped":    4,
	"orphaned":    5,
	"expired":     6,
	"invalid":     7,
}

func worseStatus(current, candidate string) string {
	if kyvernoExceptionStatusOrder[candidate] > kyvernoExceptionStatusOrder[current] {
		return candidate
	}
	return current
}

func normalizePolicyRef(ref string) string {
	if idx := strings.Index(ref, ":"); idx >= 0 {
		ref = ref[idx+1:]
	}
	return ref
}

func preferredPolicyLookupKey(ref string, policyIndex map[string]struct{}) string {
	kind := policyRefKind(ref)
	name := normalizePolicyRef(ref)
	if kind != "" {
		namespace, policy := splitNamespacedName(name)
		return policyKey(kind, namespace, policy)
	}
	matches := policyLookupMatches(name, policyIndex)
	if len(matches) == 1 {
		return matches[0]
	}
	return name
}

func policyLookupMatches(ref string, policyIndex map[string]struct{}) []string {
	refNamespace, refName := splitNamespacedName(ref)
	matches := []string{}
	for key := range policyIndex {
		_, namespace, name, ok := splitPolicyKey(key)
		if !ok {
			continue
		}
		if name != refName {
			continue
		}
		if refNamespace != "" && namespace != refNamespace {
			continue
		}
		matches = append(matches, key)
	}
	sort.Strings(matches)
	return matches
}

func policyReportName(ref string) string {
	_, name := splitNamespacedName(normalizePolicyRef(ref))
	return name
}

func policyRefKind(ref string) string {
	kind, _, ok := strings.Cut(ref, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(kind)
}

func splitNamespacedName(name string) (string, string) {
	name = strings.TrimSpace(name)
	namespace, policy, ok := strings.Cut(name, "/")
	if !ok {
		return "", name
	}
	return namespace, policy
}

func policyRefsUsePolicyLevelExceptions(refs []string) bool {
	if len(refs) == 0 {
		return false
	}
	for _, ref := range refs {
		if !policyRefUsesPolicyLevelException(ref) {
			return false
		}
	}
	return true
}

func policyRefUsesPolicyLevelException(ref string) bool {
	switch strings.ToLower(policyRefKind(ref)) {
	case "validatingpolicy", "imagevalidatingpolicy", "mutatingpolicy", "generatingpolicy", "deletingpolicy",
		"namespacedvalidatingpolicy", "namespacedimagevalidatingpolicy", "namespacedmutatingpolicy", "namespacedgeneratingpolicy", "namespaceddeletingpolicy":
		return true
	default:
		return false
	}
}

func policyRefKindIsNamespaced(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "policy", "namespacedvalidatingpolicy", "namespacedimagevalidatingpolicy", "namespacedmutatingpolicy", "namespacedgeneratingpolicy", "namespaceddeletingpolicy":
		return true
	default:
		return false
	}
}

func policyKey(kind, namespace, name string) string {
	if namespace == "" {
		return kind + ":" + name
	}
	return kind + ":" + namespace + "/" + name
}

func splitPolicyKey(key string) (kind, namespace, name string, ok bool) {
	kind, name, ok = strings.Cut(key, ":")
	if !ok || strings.TrimSpace(kind) == "" || strings.TrimSpace(name) == "" {
		return "", "", "", false
	}
	namespace, name = splitNamespacedName(name)
	return kind, namespace, name, true
}

func kyvernoObjectId(prefix, apiVersion, kind, namespace, name string) string {
	parts := []string{prefix, apiVersion, strings.ToLower(kind)}
	if namespace != "" {
		parts = append(parts, namespace)
	}
	parts = append(parts, name)
	return strings.Join(parts, ":")
}

func kyvernoRuleId(kind, namespace, policyName, ruleName string) string {
	if namespace == "" {
		return fmt.Sprintf("kyverno-rule:%s:%s:%s", strings.ToLower(kind), policyName, ruleName)
	}
	return fmt.Sprintf("kyverno-rule:%s:%s:%s:%s", strings.ToLower(kind), namespace, policyName, ruleName)
}

func stableHash(parts ...string) string {
	h := sha256.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		set[item] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func uniquePolicyExceptionMatches(in []kyvernoPolicyExceptionMatch) []kyvernoPolicyExceptionMatch {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]kyvernoPolicyExceptionMatch, 0, len(in))
	for _, item := range in {
		if item.id == "" {
			continue
		}
		if _, ok := seen[item.id]; ok {
			continue
		}
		seen[item.id] = struct{}{}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func containsString(items []string, needle string) bool {
	for _, item := range items {
		if item == needle {
			return true
		}
	}
	return false
}

func kyvernoStringSet(items []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		out[item] = struct{}{}
	}
	return out
}

func kyvernoStringsToAny(items []string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

func mapsToAny(items []map[string]any) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	return out
}

func sortKyvernoPolicies(items []any) {
	sort.Slice(items, func(i, j int) bool {
		a := items[i].(*mqlK8sKyvernoPolicy)
		b := items[j].(*mqlK8sKyvernoPolicy)
		return a.Id.Data < b.Id.Data
	})
}

func sortKyvernoReports(items []any) {
	sort.Slice(items, func(i, j int) bool {
		a := items[i].(*mqlK8sKyvernoPolicyreport)
		b := items[j].(*mqlK8sKyvernoPolicyreport)
		return a.Id.Data < b.Id.Data
	})
}

func sortKyvernoExceptions(items []any) {
	sort.Slice(items, func(i, j int) bool {
		a := items[i].(*mqlK8sKyvernoPolicyexception)
		b := items[j].(*mqlK8sKyvernoPolicyexception)
		return a.Id.Data < b.Id.Data
	})
}
