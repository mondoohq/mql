// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"time"

	"github.com/gophercloud/gophercloud/v2/openstack/containerinfra/v1/certificates"
	"github.com/gophercloud/gophercloud/v2/openstack/containerinfra/v1/nodegroups"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

type mqlOpenstackContainerinfraClusterNodeGroupInternal struct {
	cacheCluster   *mqlOpenstackContainerinfraCluster
	cacheImageID   string
	cacheFlavorID  string
	cacheProjectID string
}

func (r *mqlOpenstackContainerinfraClusterNodeGroup) id() (string, error) {
	return "openstack.containerinfra.cluster.nodeGroup/" + r.Id.Data, nil
}

// nodeGroups reads the groups making up this cluster. They are only addressable
// under their cluster, so this is one call per cluster and it stays lazy until
// the field is asked for.
func (r *mqlOpenstackContainerinfraCluster) nodeGroups() ([]any, error) {
	client, err := conn(r.MqlRuntime).ContainerInfraClient()
	if err != nil {
		return nil, err
	}
	pages, err := nodegroups.List(client, r.Id.Data, nodegroups.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := nodegroups.ExtractNodeGroups(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, ng := range items {
		maxNodes := int64(0)
		if ng.MaxNodeCount != nil {
			maxNodes = int64(*ng.MaxNodeCount)
		}
		volumeSize := int64(0)
		if ng.DockerVolumeSize != nil {
			volumeSize = int64(*ng.DockerVolumeSize)
		}
		res, err := CreateResource(r.MqlRuntime, "openstack.containerinfra.cluster.nodeGroup", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.containerinfra.cluster.nodeGroup/" + ng.UUID),
			"id":               llx.StringData(ng.UUID),
			"name":             llx.StringData(ng.Name),
			"role":             llx.StringData(ng.Role),
			"status":           llx.StringData(ng.Status),
			"statusReason":     llx.StringData(ng.StatusReason),
			"nodeCount":        llx.IntData(int64(ng.NodeCount)),
			"minNodeCount":     llx.IntData(int64(ng.MinNodeCount)),
			"maxNodeCount":     llx.IntData(maxNodes),
			"isDefault":        llx.BoolData(ng.IsDefault),
			"dockerVolumeSize": llx.IntData(volumeSize),
			"labels":           stringMapData(ng.Labels),
			"nodeAddresses":    stringSliceData(ng.NodeAddresses),
		})
		if err != nil {
			return nil, err
		}
		mqlNG := res.(*mqlOpenstackContainerinfraClusterNodeGroup)
		mqlNG.cacheCluster = r
		mqlNG.cacheImageID = ng.ImageID
		mqlNG.cacheFlavorID = ng.FlavorID
		mqlNG.cacheProjectID = ng.ProjectID
		out = append(out, mqlNG)
	}
	return out, nil
}

func (r *mqlOpenstackContainerinfraClusterNodeGroup) cluster() (*mqlOpenstackContainerinfraCluster, error) {
	if r.cacheCluster == nil {
		r.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.cacheCluster, nil
}

func (r *mqlOpenstackContainerinfraClusterNodeGroup) image() (*mqlOpenstackImage, error) {
	return resolveImage(r.MqlRuntime, r.cacheImageID, &r.Image)
}

func (r *mqlOpenstackContainerinfraClusterNodeGroup) flavor() (*mqlOpenstackComputeFlavor, error) {
	return resolveFlavor(r.MqlRuntime, r.cacheFlavorID, &r.Flavor)
}

func (r *mqlOpenstackContainerinfraClusterNodeGroup) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

// ---- cluster certificate authority ----

func (r *mqlOpenstackContainerinfraCluster) caCertificateExpiresAt() (*time.Time, error) {
	cert, err := r.certificateAuthority()
	if err != nil {
		return nil, err
	}
	if cert == nil {
		r.CaCertificateExpiresAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return &cert.NotAfter, nil
}

func (r *mqlOpenstackContainerinfraCluster) caCertificateSubject() (string, error) {
	cert, err := r.certificateAuthority()
	if err != nil {
		return "", err
	}
	if cert == nil {
		return "", nil
	}
	return cert.Subject.String(), nil
}

// certificateAuthority fetches and parses the cluster's CA certificate. It
// returns nil when the authority is not readable, which is the common case for
// a caller without the cluster's own credentials. Both certificate fields share
// this one call, and the two can resolve concurrently, so the result is fetched
// once behind a sync.Once.
func (r *mqlOpenstackContainerinfraCluster) certificateAuthority() (*x509.Certificate, error) {
	r.caOnce.Do(func() {
		client, err := conn(r.MqlRuntime).ContainerInfraClient()
		if err != nil {
			r.caErr = err
			return
		}
		cert, err := certificates.Get(ctx(), client, r.Id.Data).Extract()
		if err != nil {
			if translateOpenstackError(err) == nil {
				return
			}
			r.caErr = err
			return
		}
		r.caCert, r.caErr = parseCertificatePEM(cert.PEM)
	})
	return r.caCert, r.caErr
}

// parseCertificatePEM reads the first certificate out of a PEM bundle. A bundle
// that holds no certificate block yields nil rather than an error, so a cluster
// whose authority is withheld reports nothing instead of failing the query.
func parseCertificatePEM(raw string) (*x509.Certificate, error) {
	rest := []byte(raw)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("cluster certificate authority is not a parseable certificate: " + err.Error())
		}
		return cert, nil
	}
}
