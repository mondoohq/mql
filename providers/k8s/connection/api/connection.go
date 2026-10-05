// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/providers/k8s/connection/shared/resources"
	admissionv1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/util/homedir"
)

type Connection struct {
	plugin.Connection
	asset              *inventory.Asset
	d                  *resources.Discovery
	config             *rest.Config
	namespace          string
	nsFilter           shared.NamespaceFilter
	clientset          *kubernetes.Clientset
	currentClusterName string
}

func NewConnection(id uint32, asset *inventory.Asset, discoveryCache *resources.DiscoveryCache) (shared.Connection, error) {
	// check if the user .kube/config file exists
	// NOTE: BuildConfigFromFlags falls back to cluster loading when .kube/config string is empty
	// therefore we want to only change the kubeconfig string when the file really exists
	var kubeconfigPath string

	// use KUBECONFIG as default
	// https://kubernetes.io/docs/tasks/access-application-cluster/configure-access-multiple-clusters/#set-the-kubeconfig-environment-variable
	kubeconfigPath = os.Getenv("KUBECONFIG")

	// if no config is set, try to load the default kubeconfig path if nothing was provided
	if kubeconfigPath == "" {
		if home := homedir.HomeDir(); home != "" {
			kubeconfigPathHome := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(kubeconfigPathHome); err == nil {
				kubeconfigPath = kubeconfigPathHome
			}
		}
	}

	config, err := buildConfigFromFlags("", kubeconfigPath, "")
	if err != nil {
		return nil, err
	}

	kubeConfig, err := (&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}).Load()
	if err != nil {
		return nil, err
	}

	err = attemptKubeloginAuthFlow(asset, config)
	if err != nil {
		return nil, err
	}

	err = attemptGKEAuthFlow(config)
	if err != nil {
		return nil, err
	}

	err = attemptEKSAuthFlow(config)
	if err != nil {
		return nil, err
	}

	// enable-client side throttling
	// avoids the cli warning: Waited for 1.000907542s due to client-side throttling, not priority and fairness
	config.QPS = 1000
	config.Burst = 1000

	// initialize api
	d, err := discoveryCache.Get(config)
	if err != nil {
		return nil, err
	}
	log.Debug().Msg("loaded kubeconfig successfully")

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, errors.Wrap(err, "could not create kubernetes clientset")
	}

	currentClusterName := ""
	if ctx, ok := kubeConfig.Contexts[kubeConfig.CurrentContext]; ok {
		currentClusterName = ctx.Cluster
	} else {
		// right now we use the name of the first node to identify the cluster
		result, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			return nil, err
		}

		if len(result.Items) > 0 {
			currentClusterName = result.Items[0].GetName()
		}
	}

	res := Connection{
		Connection:         plugin.NewConnection(id, asset),
		asset:              asset,
		d:                  d,
		config:             config,
		clientset:          clientset,
		currentClusterName: currentClusterName,
	}

	// --namespaces accepts a comma-separated list of globs, and
	// --namespaces-exclude removes namespaces. Only a filter naming exactly one
	// namespace can be pushed down to the API server as a scoped list request;
	// anything else has to list across namespaces and filter the result.
	res.nsFilter, err = shared.NewNamespaceFilter(
		asset.Connections[0].Options[shared.OPTION_NAMESPACE],
		asset.Connections[0].Options[shared.OPTION_NAMESPACE_EXCLUDE],
	)
	if err != nil {
		return nil, err
	}
	if ns, ok := res.nsFilter.SingleNamespace(); ok {
		res.namespace = ns
	}

	return &res, nil
}

// buildConfigFromFlags we rebuild clientcmd.BuildConfigFromFlags to make sure we do not log warnings for every
// scan.
func buildConfigFromFlags(masterUrl, kubeconfigPath string, context string) (*rest.Config, error) {
	if kubeconfigPath == "" && masterUrl == "" {
		kubeconfig, err := rest.InClusterConfig()
		if err == nil {
			return kubeconfig, nil
		}
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath},
		&clientcmd.ConfigOverrides{ClusterInfo: clientcmdapi.Cluster{Server: masterUrl}, CurrentContext: context}).ClientConfig()
}

func (c *Connection) Runtime() string {
	return "k8s-cluster"
}

func (c *Connection) InventoryConfig() *inventory.Config {
	return c.asset.Connections[0]
}

func (c *Connection) ClusterName() (string, error) {
	ctx := context.Background()

	// right now we use the name of the first node to identify the cluster
	result, err := c.clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", err
	}

	if len(result.Items) > 0 {
		node := result.Items[0]
		return node.GetName(), nil
	}

	return "", fmt.Errorf("cannot determine cluster name")
}

func (c *Connection) Name() string {
	opts := c.asset.Connections[0].Options

	var clusterName string
	// the name is still a bit unreliable
	// see https://github.com/kubernetes/kubernetes/issues/44954
	if len(opts["context"]) > 0 {
		clusterName = opts["context"]
		log.Info().Str("cluster-name", clusterName).Msg("use cluster name from --context")
	} else {
		clusterName = ""

		// try to parse context from kubectl config
		if clusterName == "" && len(c.currentClusterName) > 0 {
			clusterName = c.currentClusterName
		}

		// fallback to first node name if we could not gather the name from kubeconfig
		if clusterName == "" {
			name, err := c.ClusterName()
			if err == nil {
				clusterName = name
				log.Info().Str("cluster-name", clusterName).Msg("use cluster name from node name")
			}
		}

		clusterName = "K8s Cluster " + clusterName
	}
	return clusterName
}

func (c *Connection) Asset() *inventory.Asset {
	return c.asset
}

func (c *Connection) ServerVersion() *version.Info {
	return c.d.ServerVersion
}

func (c *Connection) SupportedResourceTypes() (*resources.ApiResourceIndex, error) {
	return c.d.SupportedResourceTypes()
}

func (c *Connection) Platform() *inventory.Platform {
	v := c.ServerVersion()
	return &inventory.Platform{
		Name:                  "k8s-cluster",
		Build:                 v.BuildDate,
		Version:               v.GitVersion,
		Arch:                  v.Platform,
		Family:                []string{"k8s"},
		Kind:                  "api",
		Runtime:               c.Runtime(),
		Title:                 "Kubernetes Cluster",
		TechnologyUrlSegments: []string{"k8s", "k8s-cluster"},
	}
}

func (c *Connection) BasePlatformId() (string, error) {
	return shared.IdPrefix, nil
}

func (c *Connection) AssetId() (string, error) {
	// we use "kube-system" namespace uid as identifier for the cluster
	// use the internal resources function to make sure we can get the right namespace
	result, err := c.resources("namespaces", "kube-system", "")
	if err != nil {
		return "", err
	}

	if len(result.Resources) != 1 {
		return "", errors.New("could not identify the k8s cluster")
	}

	resource := result.Resources[0]
	obj, err := meta.Accessor(resource)
	if err != nil {
		return "", err
	}

	uid := string(obj.GetUID())
	return shared.NewPlatformId(uid), nil
}

// Resources retrieves the cluster resources. If the connection has a global namespace set, then that's used
func (c *Connection) Resources(kind string, name string, namespace string) (*shared.ResourceResult, error) {
	// The connection namespace has precedence
	if c.namespace != "" {
		namespace = c.namespace
	}

	return c.resources(kind, name, namespace)
}

// resources retrieves the cluster resources
func (c *Connection) resources(kind string, name string, namespace string) (*shared.ResourceResult, error) {
	ctx := context.Background()
	allNs := false
	if len(namespace) == 0 {
		allNs = true
	}

	// discover api and resources that have a list method
	resTypes, err := c.d.SupportedResourceTypes()
	if err != nil {
		return nil, err
	}
	log.Debug().Msg("completed querying resource types")

	resType, err := resTypes.Lookup(kind)
	if err != nil {
		return nil, err
	}

	log.Debug().Msgf("fetch all %s resources", kind)
	objs, err := c.d.GetKindResources(ctx, *resType, namespace, allNs)
	if err != nil {
		return nil, err
	}
	log.Debug().Msgf("found %d resource objects", len(objs))

	objs, err = resources.FilterResource(resType, objs, name, namespace)
	if err != nil {
		return nil, err
	}

	// A multi-namespace or glob filter cannot be pushed into the list request,
	// so it is applied here. Cluster-scoped kinds have no namespace to match and
	// stay in scope, and a filter naming exactly one namespace was already
	// pushed down to the API server, so re-checking it would be redundant.
	if resType.Resource.Namespaced && !c.nsFilter.IsEmpty() && c.namespace == "" {
		filtered := make([]runtime.Object, 0, len(objs))
		for i := range objs {
			obj, err := meta.Accessor(objs[i])
			if err != nil {
				// dropping it silently would look identical to the filter
				// simply not matching, which is the bug this block fixes
				log.Warn().Err(err).Str("kind", kind).
					Msg("skipping object: cannot read metadata to match the namespace filter")
				continue
			}
			if c.nsFilter.Matches(obj.GetNamespace()) {
				filtered = append(filtered, objs[i])
			}
		}
		objs = filtered
	}

	return &shared.ResourceResult{
		Name:         name,
		Kind:         kind,
		ResourceType: resType,
		Resources:    objs,
		Namespace:    namespace,
		AllNs:        allNs,
	}, err
}

func (c *Connection) AdmissionReviews() ([]admissionv1.AdmissionReview, error) {
	return []admissionv1.AdmissionReview{}, nil
}

// SubjectAccessAllowed asks the API server, authoritatively, whether the given
// subject may perform verb on the (group, resource, name) in namespace. It
// returns the decision and the authorizer's reason. This folds in aggregated
// ClusterRoles, group bindings, and built-in roles that a static rule analysis
// cannot reconstruct.
func (c *Connection) SubjectAccessAllowed(ctx context.Context, subject, namespace, verb, group, resource, name string) (bool, string, error) {
	return subjectAccessAllowed(ctx, c.clientset, subject, namespace, verb, group, resource, name)
}

// subjectAccessAllowed runs a SubjectAccessReview against the given client. It is
// split out from the connection method so it can be tested with a fake clientset.
func subjectAccessAllowed(ctx context.Context, client kubernetes.Interface, subject, namespace, verb, group, resource, name string) (bool, string, error) {
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: subject,
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     group,
				Resource:  resource,
				Name:      name,
			},
		},
	}
	res, err := client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return false, "", err
	}
	return res.Status.Allowed, res.Status.Reason, nil
}

func (c *Connection) Namespace(name string) (*v1.Namespace, error) {
	ctx := context.Background()
	ns, err := c.clientset.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	// needed because of https://github.com/kubernetes/client-go/issues/861
	ns.SetGroupVersionKind(v1.SchemeGroupVersion.WithKind("Namespace"))
	return ns, err
}

func (c *Connection) Namespaces() ([]v1.Namespace, error) {
	ctx := context.Background()
	list, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	// needed because of https://github.com/kubernetes/client-go/issues/861
	for i := range list.Items {
		list.Items[i].SetGroupVersionKind(v1.SchemeGroupVersion.WithKind("Namespace"))
	}
	return list.Items, err
}
