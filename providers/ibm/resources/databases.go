// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/IBM/cloud-databases-go-sdk/clouddatabasesv5"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// isDatabaseService reports whether a CRN service name is an IBM Cloud
// Databases offering, such as databases-for-postgresql or
// messages-for-rabbitmq.
func isDatabaseService(service string) bool {
	return strings.HasPrefix(service, "databases-for-") || service == "messages-for-rabbitmq"
}

type mqlIbmDatabaseInternal struct {
	cacheResourceGroupID string
}

func (r *mqlIbm) databases() ([]any, error) {
	items, err := listResourceInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, ri := range items {
		crn := derefStr(ri.CRN)
		service := crnService(crn)
		if !isDatabaseService(service) {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.database", map[string]*llx.RawData{
			"__id":      llx.StringData("ibm.database/" + crn),
			"id":        llx.StringData(crn),
			"guid":      strData(ri.GUID),
			"name":      strData(ri.Name),
			"service":   llx.StringData(service),
			"region":    strData(ri.RegionID),
			"state":     strData(ri.State),
			"createdAt": dateTimeData(ri.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmDatabase).cacheResourceGroupID = derefStr(ri.ResourceGroupID)
		out = append(out, res)
	}
	return out, nil
}

// permission is the IAM action reading the deployment needs; it is named
// after the deployment's own service, such as
// databases-for-mysql.deployment.read.
func (r *mqlIbmDatabase) permission() string {
	return r.Service.Data + ".deployment.read"
}

func (r *mqlIbmDatabase) client() (*clouddatabasesv5.CloudDatabasesV5, error) {
	return conn(r.MqlRuntime).Databases(r.Region.Data)
}

func (r *mqlIbmDatabase) deployment() (*clouddatabasesv5.Deployment, error) {
	v, err := conn(r.MqlRuntime).Memo("databases/deployment/"+r.Id.Data, func() (any, error) {
		svc, err := r.client()
		if err != nil {
			return nil, err
		}
		res, _, err := svc.GetDeploymentInfo(&clouddatabasesv5.GetDeploymentInfoOptions{ID: &r.Id.Data})
		if err != nil {
			return nil, classifyError(err, r.permission())
		}
		if res == nil || res.Deployment == nil {
			return &clouddatabasesv5.Deployment{}, nil
		}
		return res.Deployment, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*clouddatabasesv5.Deployment), nil
}

func (r *mqlIbmDatabase) compute_type() (string, error) {
	d, err := r.deployment()
	if err != nil {
		return "", err
	}
	return derefStr(d.Type), nil
}

func (r *mqlIbmDatabase) version() (string, error) {
	d, err := r.deployment()
	if err != nil {
		return "", err
	}
	return derefStr(d.Version), nil
}

func (r *mqlIbmDatabase) publicEndpointEnabled() (bool, error) {
	d, err := r.deployment()
	if err != nil {
		return false, err
	}
	return isTrue(d.EnablePublicEndpoints), nil
}

func (r *mqlIbmDatabase) privateEndpointEnabled() (bool, error) {
	d, err := r.deployment()
	if err != nil {
		return false, err
	}
	return isTrue(d.EnablePrivateEndpoints), nil
}

func (r *mqlIbmDatabase) allowlist() ([]any, error) {
	svc, err := r.client()
	if err != nil {
		return nil, err
	}
	res, _, err := svc.GetAllowlist(&clouddatabasesv5.GetAllowlistOptions{ID: &r.Id.Data})
	if err != nil {
		return nil, classifyError(err, r.permission())
	}
	out := []any{}
	if res == nil {
		return out, nil
	}
	for _, e := range res.IPAddresses {
		if a := derefStr(e.Address); a != "" {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *mqlIbmDatabase) memberCount() (int64, error) {
	svc, err := r.client()
	if err != nil {
		return 0, err
	}
	res, _, err := svc.ListDeploymentScalingGroups(&clouddatabasesv5.ListDeploymentScalingGroupsOptions{ID: &r.Id.Data})
	if err != nil {
		return 0, classifyError(err, r.permission())
	}
	if res != nil {
		for _, g := range res.Groups {
			if derefStr(g.ID) == "member" && g.Count != nil {
				return *g.Count, nil
			}
		}
	}
	// The deployment reports no member group.
	r.MemberCount.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

// platformKey reads an encryption key CRN from the deployment's platform
// options, empty when IBM manages the key.
func platformKey(d *clouddatabasesv5.Deployment, key string) string {
	if d == nil {
		return ""
	}
	s, _ := d.PlatformOptions[key].(string)
	return s
}

func (r *mqlIbmDatabase) diskEncryptionKey() (*mqlIbmKmsKey, error) {
	d, err := r.deployment()
	if err != nil {
		return nil, err
	}
	return kmsKeyByCRN(r.MqlRuntime, platformKey(d, "disk_encryption_key_crn"), &r.DiskEncryptionKey)
}

func (r *mqlIbmDatabase) backupEncryptionKey() (*mqlIbmKmsKey, error) {
	d, err := r.deployment()
	if err != nil {
		return nil, err
	}
	return kmsKeyByCRN(r.MqlRuntime, platformKey(d, "backup_encryption_key_crn"), &r.BackupEncryptionKey)
}

func (r *mqlIbmDatabase) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmDatabase) tags() ([]any, error)       { return userTags(r.MqlRuntime, r.Id.Data) }
func (r *mqlIbmDatabase) accessTags() ([]any, error) { return accessTags(r.MqlRuntime, r.Id.Data) }
