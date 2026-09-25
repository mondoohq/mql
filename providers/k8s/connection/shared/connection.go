// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
)

const (
	OPTION_GIT_HTTP                 = "http-url"
	OPTION_MANIFEST                 = "path"
	OPTION_IMMEMORY_CONTENT         = "manifest-content"
	OPTION_NAMESPACE                = "namespaces"
	OPTION_NAMESPACE_EXCLUDE        = "namespaces-exclude"
	OPTION_NAMESPACE_LABEL_SELECTOR = "namespace-label-selector"
	OPTION_OBJECT_LABEL_SELECTOR    = "object-label-selector"
	OPTION_IMAGES                   = "images"
	OPTION_IMAGES_EXCLUDE           = "images-exclude"
	OPTION_ADMISSION                = "k8s-admission-review"
	OPTION_OBJECT_KIND              = "object-kind"
	OPTION_CONTEXT                  = "context"
	OPTION_KUBELOGIN                = "kubelogin"

	OPTION_KYVERNO_DEFAULT_MAPPINGS                    = "kyverno-default-mappings"
	OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_UIDS       = "kyverno-mapping-annotation-check-uids"
	OPTION_KYVERNO_MAPPING_ANNOTATION_CHECK_MRNS       = "kyverno-mapping-annotation-check-mrns"
	OPTION_KYVERNO_MAPPING_ANNOTATION_POLICY_UIDS      = "kyverno-mapping-annotation-policy-uids"
	OPTION_KYVERNO_MAPPING_ANNOTATION_REASONS          = "kyverno-mapping-annotation-reasons"
	OPTION_KYVERNO_EXCEPTION_ANNOTATION_VALID_UNTIL    = "kyverno-exception-annotation-valid-until"
	OPTION_KYVERNO_EXCEPTION_ANNOTATION_JUSTIFICATIONS = "kyverno-exception-annotation-justifications"
	OPTION_KYVERNO_EXCEPTION_ANNOTATION_OWNERS         = "kyverno-exception-annotation-owners"
	OPTION_KYVERNO_EXCEPTION_ANNOTATION_TICKETS        = "kyverno-exception-annotation-tickets"
	OPTION_KYVERNO_MIRROR_POLICY_EXCEPTIONS            = "kyverno-mirror-policy-exceptions"
	OPTION_KYVERNO_MIRRORED_EXCEPTION_APPROVAL         = "kyverno-mirrored-exception-approval"
	OPTION_KYVERNO_MIRRORED_EXCEPTION_ACTION           = "kyverno-mirrored-exception-action"
	OPTION_KYVERNO_FAIL_EXPIRED_POLICY_EXCEPTIONS      = "kyverno-fail-expired-policy-exceptions"
	OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_EXCEPTIONS   = "kyverno-report-unmapped-policy-exceptions"
	OPTION_KYVERNO_REPORT_UNMAPPED_POLICY_RESULTS      = "kyverno-report-unmapped-policy-results"
	IdPrefix                                           = "//platformid.api.mondoo.app/runtime/k8s/uid/"
)

type ConnectionType string

type Connection interface {
	plugin.Connection
	Name() string
	Runtime() string

	// Resources returns the resources that match the provided kind and name. If not kind and name
	// are provided, then all cluster resources are returned.
	Resources(kind string, name string, namespace string) (*ResourceResult, error)
	ServerVersion() *version.Info
	SupportedResourceTypes() (*resources.ApiResourceIndex, error)
	Platform() *inventory.Platform
	Asset() *inventory.Asset
	AssetId() (string, error)
	BasePlatformId() (string, error)

	AdmissionReviews() ([]admissionv1.AdmissionReview, error)
	Namespace(name string) (*v1.Namespace, error)
	Namespaces() ([]v1.Namespace, error)

	InventoryConfig() *inventory.Config
}

type ClusterInfo struct {
	Name string
}

type ResourceResult struct {
	Name         string
	Kind         string
	ResourceType *resources.ApiResource // resource type that matched kind

	// Resources the resources that match the name, kind and namespace
	Resources []runtime.Object
	Namespace string
	AllNs     bool
}

func sliceToPtrSlice[T any](items []T) []*T {
	ptrItems := make([]*T, 0, len(items))
	for i := range items {
		ptrItems = append(ptrItems, &items[i])
	}
	return ptrItems
}

func NewPlatformId(assetId string) string {
	return IdPrefix + assetId
}

func NewWorkloadPlatformId(basePlatformId, clusterIdentifier, workloadType, namespace, name, uid string) string {
	if workloadType == "namespace" {
		return NewNamespacePlatformId(basePlatformId, name, uid)
	}

	platformIdentifier := clusterIdentifier
	// when mondoo is called with "--namespace xyz" the cluster identifier already contains the namespace
	// when called without the namespace, it is missing, but we need it to identify workloads
	if !strings.Contains(clusterIdentifier, "namespace") && namespace != "" {
		platformIdentifier += "/namespace/" + namespace
	}
	// add plural "s"
	platformIdentifier += "/" + workloadType + "s" + "/name/" + name
	return platformIdentifier
}

func NewNamespacePlatformId(basePlatformId, name, uid string) string {
	return fmt.Sprintf("%s%s/namespace/%s", basePlatformId, uid, name)
}
