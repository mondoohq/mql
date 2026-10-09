// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/k8s/connection/shared/distro"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	distroTimeout   = 20 * time.Second
	probeTimeout    = 5 * time.Second
	metadataTimeout = 2 * time.Second
	// link-local address of the AWS, Azure and GCP metadata services
	metadataHost = "http://169.254.169.254"
)

// kubeconfigInfo reads what the kubeconfig says about the cluster. It must run
// before the authentication helpers, which replace the exec plugin with a
// token.
func kubeconfigInfo(kubeConfig *clientcmdapi.Config, contextOverride string, config *rest.Config, kubelogin bool) *distro.Kubeconfig {
	k := &distro.Kubeconfig{Kubelogin: kubelogin}
	if config.ExecProvider != nil {
		k.ExecCommand = config.ExecProvider.Command
		k.ExecArgs = append([]string{}, config.ExecProvider.Args...)
	}
	if config.AuthProvider != nil {
		k.AuthProvider = config.AuthProvider.Name
	}
	if kubeConfig != nil {
		current := kubeConfig.CurrentContext
		if contextOverride != "" {
			current = contextOverride
		}
		if ctx, ok := kubeConfig.Contexts[current]; ok && ctx != nil {
			k.ClusterEntry = ctx.Cluster
		}
	}
	return k
}

// Distro detects the cluster's distribution once per API server and caches it.
func (c *Connection) Distro() *distro.Result {
	return c.d.Distro(func() *distro.Result {
		ctx, cancel := context.WithTimeout(context.Background(), distroTimeout)
		defer cancel()
		res := distro.Detect(ctx, c.distroProbes())
		log.Debug().Str("distro", res.Name).Str("source", res.Source).Msg("detected kubernetes distribution")
		return res
	})
}

func (c *Connection) distroProbes() distro.Probes {
	p := distro.Probes{
		Version: func(context.Context) (string, error) {
			if v := c.ServerVersion(); v != nil {
				return v.GitVersion, nil
			}
			return "", errors.New("no server version")
		},
		Certificate: func(ctx context.Context) ([]string, error) {
			return certificateNames(ctx, c.config)
		},
		Host:       c.config.Host,
		Kubeconfig: c.kubeconfig,
		APIGroups: func(ctx context.Context) ([]string, error) {
			return apiGroupNames(c.config)
		},
		Nodes: func(ctx context.Context) ([]distro.Node, error) {
			return listNodes(ctx, c.clientset)
		},
	}
	if c.inCluster {
		client := &http.Client{Timeout: metadataTimeout}
		p.Metadata = func(ctx context.Context) (*distro.MetadataResult, error) {
			return cloudMetadata(ctx, client, metadataHost)
		}
	}
	return p
}

// certificateNames returns the DNS names of the API server's certificate, from
// the TLS handshake of an ordinary request. /version needs no permission, and
// the handshake completes even when the request is refused.
func certificateNames(ctx context.Context, config *rest.Config) ([]string, error) {
	rt, err := rest.TransportFor(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(config.Host, "/")+"/version", nil)
	if err != nil {
		return nil, err
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, errors.New("API server connection is not TLS")
	}
	return resp.TLS.PeerCertificates[0].DNSNames, nil
}

func apiGroupNames(config *rest.Config) ([]string, error) {
	cfg := rest.CopyConfig(config)
	cfg.Timeout = probeTimeout
	dc, err := discovery.NewDiscoveryClientForConfig(cfg)
	if err != nil {
		return nil, err
	}
	groups, err := dc.ServerGroups()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(groups.Groups))
	for _, g := range groups.Groups {
		names = append(names, g.Name)
	}
	return names, nil
}

func listNodes(ctx context.Context, client kubernetes.Interface) ([]distro.Node, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	list, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return nil, err
	}
	nodes := make([]distro.Node, 0, len(list.Items))
	for _, n := range list.Items {
		nodes = append(nodes, distro.Node{ProviderID: n.Spec.ProviderID, Labels: n.Labels})
	}
	return nodes, nil
}

// cloudMetadata asks the AWS, Azure and GCP metadata services in parallel. It
// runs only inside the cluster, where the scanner runs on a node.
func cloudMetadata(ctx context.Context, client *http.Client, base string) (*distro.MetadataResult, error) {
	type answer struct {
		res *distro.MetadataResult
		err error
	}
	probes := []func(context.Context, *http.Client, string) (*distro.MetadataResult, error){
		gcpMetadata, azureMetadata, awsMetadata,
	}
	answers := make([]answer, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func(i int, probe func(context.Context, *http.Client, string) (*distro.MetadataResult, error)) {
			defer wg.Done()
			res, err := probe(ctx, client, base)
			answers[i] = answer{res, err}
		}(i, probe)
	}
	wg.Wait()

	var errs []string
	var fallback *distro.MetadataResult
	for _, a := range answers {
		if a.err != nil {
			errs = append(errs, a.err.Error())
			continue
		}
		if a.res == nil {
			continue
		}
		if a.res.Distro != "" {
			return a.res, nil
		}
		if fallback == nil {
			fallback = a.res
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return nil, nil
}

func metadataGet(ctx context.Context, client *http.Client, url string, header map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, err
}

// gcpMetadata reads the attributes GKE sets on its nodes.
func gcpMetadata(ctx context.Context, client *http.Client, base string) (*distro.MetadataResult, error) {
	h := map[string]string{"Metadata-Flavor": "Google"}
	get := func(path string) string {
		body, status, err := metadataGet(ctx, client, base+"/computeMetadata/v1/"+path, h)
		if err != nil || status != http.StatusOK {
			return ""
		}
		return strings.TrimSpace(string(body))
	}
	project := get("project/project-id")
	if project == "" {
		return nil, nil
	}
	res := &distro.MetadataResult{Value: "gcp", Identity: distro.Identity{Account: project}}
	if name := get("instance/attributes/cluster-name"); name != "" {
		res.Distro = distro.GKE
		res.Value = "gcp instance attribute cluster-name"
		res.Identity.ClusterName = name
		res.Identity.Region = get("instance/attributes/cluster-location")
	}
	return res, nil
}

// azureMetadata reads the tags AKS sets on its node VMs.
func azureMetadata(ctx context.Context, client *http.Client, base string) (*distro.MetadataResult, error) {
	body, status, err := metadataGet(ctx, client, base+"/metadata/instance/compute?api-version=2021-02-01", map[string]string{"Metadata": "true"})
	if err != nil || status != http.StatusOK {
		return nil, nil
	}
	var compute struct {
		Location       string `json:"location"`
		SubscriptionID string `json:"subscriptionId"`
		TagsList       []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"tagsList"`
	}
	if err := json.Unmarshal(body, &compute); err != nil {
		return nil, fmt.Errorf("azure metadata: %w", err)
	}
	res := &distro.MetadataResult{Value: "azure", Identity: distro.Identity{Region: compute.Location, Account: compute.SubscriptionID}}
	for _, t := range compute.TagsList {
		if strings.HasPrefix(t.Name, "aks-managed-") {
			res.Distro = distro.AKS
			res.Value = "azure tag " + t.Name
			break
		}
	}
	return res, nil
}

// awsMetadata reads the instance's tags (when the instance publishes them to
// the metadata service) for the tag EKS sets on its nodes. IMDSv2 needs a
// token first; from a pod, that needs a hop limit of 2.
func awsMetadata(ctx context.Context, client *http.Client, base string) (*distro.MetadataResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base+"/latest/api/token", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	token, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}
	h := map[string]string{"X-aws-ec2-metadata-token": string(token)}
	get := func(path string) string {
		body, status, err := metadataGet(ctx, client, base+"/latest/meta-data/"+path, h)
		if err != nil || status != http.StatusOK {
			return ""
		}
		return strings.TrimSpace(string(body))
	}
	res := &distro.MetadataResult{Value: "aws", Identity: distro.Identity{Region: get("placement/region")}}
	if name := get("tags/instance/eks:cluster-name"); name != "" {
		res.Distro = distro.EKS
		res.Value = "aws instance tag eks:cluster-name"
		res.Identity.ClusterName = name
	}
	return res, nil
}
