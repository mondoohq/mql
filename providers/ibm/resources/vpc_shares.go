// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- file shares ----

type mqlIbmVpcShareInternal struct {
	cacheResourceGroupID  string
	cacheEncryptionKeyCRN string
}

func (r *mqlIbm) vpcShares() ([]any, error) {
	items, err := listAllRegions(r.MqlRuntime, "is.share.share.list", func(c *vpcv1.VpcV1) ([]vpcv1.Share, error) {
		pager, err := c.NewSharesPager(&vpcv1.ListSharesOptions{})
		if err != nil {
			return nil, err
		}
		return pager.GetAll()
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		s := it.item
		keyCRN := ""
		if s.EncryptionKey != nil {
			keyCRN = derefStr(s.EncryptionKey.CRN)
		}
		args := map[string]*llx.RawData{
			"__id":                          llx.StringData("ibm.vpc.share/" + derefStr(s.CRN)),
			"id":                            strData(s.ID),
			"crn":                           strData(s.CRN),
			"name":                          strData(s.Name),
			"region":                        llx.StringData(it.region),
			"zone":                          llx.StringData(zoneName(s.Zone)),
			"profile":                       llx.StringData(""),
			"size":                          intPtrData(s.Size),
			"iops":                          intPtrData(s.Iops),
			"encryption":                    strData(s.Encryption),
			"encryptionKeyService":          llx.StringData(keyServiceOf(keyCRN)),
			"accessControlMode":             strData(s.AccessControlMode),
			"allowedTransitEncryptionModes": stringsData(s.AllowedTransitEncryptionModes),
			"lifecycleState":                strData(s.LifecycleState),
			"replicationRole":               strData(s.ReplicationRole),
			"createdAt":                     dateTimeData(s.CreatedAt),
		}
		if s.Profile != nil {
			args["profile"] = strData(s.Profile.Name)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.share", args)
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmVpcShare)
		m.cacheResourceGroupID = resourceGroupID(s.ResourceGroup)
		m.cacheEncryptionKeyCRN = keyCRN
		out = append(out, m)
	}
	return out, nil
}

// keyServiceOf is the key management service holding a customer-managed key,
// from the service name in the key's CRN: kms (Key Protect) or hs-crypto
// (Hyper Protect Crypto Services). It is empty when IBM manages the key.
func keyServiceOf(keyCRN string) string {
	if keyCRN == "" {
		return ""
	}
	return crnService(keyCRN)
}

func (r *mqlIbmVpcShare) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmVpcShare) encryptionKey() (*mqlIbmKmsKey, error) {
	return kmsKeyByCRN(r.MqlRuntime, r.cacheEncryptionKeyCRN, &r.EncryptionKey)
}

func (r *mqlIbmVpcShare) tags() ([]any, error)       { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmVpcShare) accessTags() ([]any, error) { return accessTags(r.MqlRuntime, r.Crn.Data) }

// vpcClientForRegion returns the VPC client of a region the connection
// queries.
func vpcClientForRegion(runtime *plugin.Runtime, name string) (*vpcv1.VpcV1, error) {
	c := conn(runtime)
	regions, err := c.VpcRegions()
	if err != nil {
		return nil, classifyError(err, "is.region.region.read")
	}
	for _, reg := range regions {
		if derefStr(reg.Name) == name {
			return c.VpcClient(reg)
		}
	}
	return nil, fmt.Errorf("VPC region %q is not queried by this connection", name)
}

func (r *mqlIbmVpcShare) mountTargets() ([]any, error) {
	client, err := vpcClientForRegion(r.MqlRuntime, r.Region.Data)
	if err != nil {
		return nil, err
	}
	pager, err := client.NewShareMountTargetsPager(&vpcv1.ListShareMountTargetsOptions{ShareID: &r.Id.Data})
	if err != nil {
		return nil, err
	}
	items, err := pager.GetAll()
	if err != nil {
		return nil, classifyError(err, "is.share.share.read")
	}
	out := make([]any, 0, len(items))
	for _, t := range items {
		res, err := CreateResource(r.MqlRuntime, "ibm.vpc.share.mountTarget", map[string]*llx.RawData{
			"__id":              llx.StringData("ibm.vpc.share.mountTarget/" + r.Id.Data + "/" + derefStr(t.ID)),
			"id":                strData(t.ID),
			"name":              strData(t.Name),
			"accessControlMode": strData(t.AccessControlMode),
			"accessProtocol":    strData(t.AccessProtocol),
			"transitEncryption": strData(t.TransitEncryption),
			"lifecycleState":    strData(t.LifecycleState),
			"mountPath":         strData(t.MountPath),
			"createdAt":         dateTimeData(t.CreatedAt),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmVpcShareMountTarget).cacheVpcID = vpcID(t.VPC)
		out = append(out, res)
	}
	return out, nil
}

// ---- mount targets ----

type mqlIbmVpcShareMountTargetInternal struct {
	cacheVpcID string
}

func (r *mqlIbmVpcShareMountTarget) vpc() (*mqlIbmVpc, error) {
	return vpcByID(r.MqlRuntime, r.cacheVpcID, &r.Vpc)
}
