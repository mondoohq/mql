// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// kmsPageSize is the page size for key and registration listings; the API
// accepts up to 5000.
const kmsPageSize = 200

// kmsServices are the CRN service names of the key management services that
// share the Key Protect API.
var kmsServices = map[string]bool{"kms": true, "hs-crypto": true}

// keyStates names the numeric key states of the Key Protect API.
var keyStates = map[int64]string{
	0: "preActivation",
	1: "active",
	2: "suspended",
	3: "deactivated",
	5: "destroyed",
}

func keyStateName(s *int64) string {
	if s == nil {
		return ""
	}
	return keyStates[*s]
}

// kmsEndpoint is the public API endpoint of a key management instance, from
// its resource controller extensions, falling back to the regional Key
// Protect endpoint. The SDK's GetServiceURLForRegion supports no region, so
// the fallback is built here.
func kmsEndpoint(ri resourcecontrollerv2.ResourceInstance) (string, error) {
	if eps, ok := ri.Extensions["endpoints"].(map[string]any); ok {
		if u, ok := eps["public"].(string); ok && u != "" {
			return u, nil
		}
	}
	region := derefStr(ri.RegionID)
	if region == "" {
		return "", errors.New("no region and no endpoint for the key management instance")
	}
	return "https://" + region + ".kms.cloud.ibm.com", nil
}

// ---- instances ----

type mqlIbmKmsInstanceInternal struct {
	cacheEndpoint        string
	cacheResourceGroupID string
}

func (r *mqlIbm) kmsInstances() ([]any, error) {
	items, err := listResourceInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, ri := range items {
		crn := derefStr(ri.CRN)
		service := crnService(crn)
		if !kmsServices[service] {
			continue
		}
		endpoint, err := kmsEndpoint(ri)
		if err != nil {
			log.Debug().Err(err).Str("instance", crn).Msg("ibm> no key management endpoint, skipping instance")
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.kms.instance", map[string]*llx.RawData{
			"__id":    llx.StringData("ibm.kms.instance/" + crn),
			"id":      llx.StringData(crn),
			"guid":    strData(ri.GUID),
			"name":    strData(ri.Name),
			"service": llx.StringData(service),
			"region":  strData(ri.RegionID),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmKmsInstance)
		m.cacheEndpoint = endpoint
		m.cacheResourceGroupID = derefStr(ri.ResourceGroupID)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmKmsInstance) client() (*ibmkeyprotectapiv2.IbmKeyProtectApiV2, error) {
	return conn(r.MqlRuntime).KeyProtect(r.cacheEndpoint)
}

func (r *mqlIbmKmsInstance) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmKmsInstance) tags() ([]any, error)       { return userTags(r.MqlRuntime, r.Id.Data) }
func (r *mqlIbmKmsInstance) accessTags() ([]any, error) { return accessTags(r.MqlRuntime, r.Id.Data) }

// instancePolicies are an instance's policies as the API returns them. The
// SDK keeps only some attributes, so they are read here directly. A policy
// that was never set is absent from the list.
type instancePolicies struct {
	Resources []struct {
		PolicyType string `json:"policy_type"`
		PolicyData struct {
			Enabled    *bool `json:"enabled"`
			Attributes struct {
				AllowedNetwork    *string  `json:"allowed_network"`
				AllowedIP         []string `json:"allowed_ip"`
				IntervalMonth     *int64   `json:"interval_month"`
				CreateRootKey     *bool    `json:"create_root_key"`
				CreateStandardKey *bool    `json:"create_standard_key"`
				ImportRootKey     *bool    `json:"import_root_key"`
				ImportStandardKey *bool    `json:"import_standard_key"`
				EnforceToken      *bool    `json:"enforce_token"`
			} `json:"attributes"`
		} `json:"policy_data"`
	} `json:"resources"`
}

// instancePolicyArgs maps the policies onto the instance's fields. An absent
// policy is a disabled one: its switch reads false and its attributes null.
func instancePolicyArgs(p instancePolicies) map[string]*llx.RawData {
	args := map[string]*llx.RawData{
		"dualAuthDeleteEnabled":        llx.BoolFalse,
		"rotationEnabled":              llx.BoolFalse,
		"rotationIntervalMonth":        llx.NilData,
		"metricsEnabled":               llx.BoolFalse,
		"allowedNetwork":               llx.NilData,
		"allowedIpEnabled":             llx.BoolFalse,
		"allowedIps":                   stringsData(nil),
		"keyCreateImportAccessEnabled": llx.BoolFalse,
		"createRootKey":                llx.NilData,
		"createStandardKey":            llx.NilData,
		"importRootKey":                llx.NilData,
		"importStandardKey":            llx.NilData,
		"enforceToken":                 llx.NilData,
	}
	enabled := func(b *bool) *llx.RawData { return llx.BoolData(b != nil && *b) }
	for _, pol := range p.Resources {
		d := pol.PolicyData
		a := d.Attributes
		switch pol.PolicyType {
		case "dualAuthDelete":
			args["dualAuthDeleteEnabled"] = enabled(d.Enabled)
		case "rotation":
			args["rotationEnabled"] = enabled(d.Enabled)
			args["rotationIntervalMonth"] = llx.IntDataPtr(a.IntervalMonth)
		case "metrics":
			args["metricsEnabled"] = enabled(d.Enabled)
		case "allowedNetwork":
			args["allowedNetwork"] = llx.StringDataPtr(a.AllowedNetwork)
		case "allowedIP":
			args["allowedIpEnabled"] = enabled(d.Enabled)
			args["allowedIps"] = stringsData(a.AllowedIP)
		case "keyCreateImportAccess":
			args["keyCreateImportAccessEnabled"] = enabled(d.Enabled)
			args["createRootKey"] = llx.BoolDataPtr(a.CreateRootKey)
			args["createStandardKey"] = llx.BoolDataPtr(a.CreateStandardKey)
			args["importRootKey"] = llx.BoolDataPtr(a.ImportRootKey)
			args["importStandardKey"] = llx.BoolDataPtr(a.ImportStandardKey)
			args["enforceToken"] = llx.BoolDataPtr(a.EnforceToken)
		}
	}
	return args
}

// policies reads the instance policies once and sets every field they feed.
func (r *mqlIbmKmsInstance) policies() (map[string]*llx.RawData, error) {
	v, err := conn(r.MqlRuntime).Memo("kms/policies/"+r.Id.Data, func() (any, error) {
		svc, err := r.client()
		if err != nil {
			return nil, err
		}
		var p instancePolicies
		if err := getJSON(svc.Service, "/api/v2/instance/policies", map[string]string{"Bluemix-Instance": r.Guid.Data}, &p); err != nil {
			return nil, classifyError(err, "kms.instancepolicies.read")
		}
		return instancePolicyArgs(p), nil
	})
	if err != nil {
		return nil, err
	}
	return v.(map[string]*llx.RawData), nil
}

func policyBool(r *mqlIbmKmsInstance, field string) (bool, error) {
	p, err := r.policies()
	if err != nil {
		return false, err
	}
	v, _ := p[field].Value.(bool)
	return v, nil
}

func (r *mqlIbmKmsInstance) dualAuthDeleteEnabled() (bool, error) {
	return policyBool(r, "dualAuthDeleteEnabled")
}

func (r *mqlIbmKmsInstance) rotationEnabled() (bool, error) { return policyBool(r, "rotationEnabled") }

func (r *mqlIbmKmsInstance) rotationIntervalMonth() (int64, error) {
	p, err := r.policies()
	if err != nil {
		return 0, err
	}
	if v, ok := p["rotationIntervalMonth"].Value.(int64); ok {
		return v, nil
	}
	r.RotationIntervalMonth.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

func (r *mqlIbmKmsInstance) metricsEnabled() (bool, error) { return policyBool(r, "metricsEnabled") }

func (r *mqlIbmKmsInstance) allowedNetwork() (string, error) {
	p, err := r.policies()
	if err != nil {
		return "", err
	}
	if v, ok := p["allowedNetwork"].Value.(string); ok {
		return v, nil
	}
	r.AllowedNetwork.State = plugin.StateIsSet | plugin.StateIsNull
	return "", nil
}

func (r *mqlIbmKmsInstance) allowedIpEnabled() (bool, error) {
	return policyBool(r, "allowedIpEnabled")
}

func (r *mqlIbmKmsInstance) allowedIps() ([]any, error) {
	p, err := r.policies()
	if err != nil {
		return nil, err
	}
	v, _ := p["allowedIps"].Value.([]any)
	return v, nil
}

func (r *mqlIbmKmsInstance) keyCreateImportAccessEnabled() (bool, error) {
	return policyBool(r, "keyCreateImportAccessEnabled")
}

// optionalPolicyBool reads a key creation and import access attribute, null
// when the policy is not set.
func optionalPolicyBool(r *mqlIbmKmsInstance, field string, tv *plugin.TValue[bool]) (bool, error) {
	p, err := r.policies()
	if err != nil {
		return false, err
	}
	if v, ok := p[field].Value.(bool); ok {
		return v, nil
	}
	tv.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

func (r *mqlIbmKmsInstance) createRootKey() (bool, error) {
	return optionalPolicyBool(r, "createRootKey", &r.CreateRootKey)
}

func (r *mqlIbmKmsInstance) createStandardKey() (bool, error) {
	return optionalPolicyBool(r, "createStandardKey", &r.CreateStandardKey)
}

func (r *mqlIbmKmsInstance) importRootKey() (bool, error) {
	return optionalPolicyBool(r, "importRootKey", &r.ImportRootKey)
}

func (r *mqlIbmKmsInstance) importStandardKey() (bool, error) {
	return optionalPolicyBool(r, "importStandardKey", &r.ImportStandardKey)
}

func (r *mqlIbmKmsInstance) enforceToken() (bool, error) {
	return optionalPolicyBool(r, "enforceToken", &r.EnforceToken)
}

// ---- keys ----

type mqlIbmKmsKeyInternal struct {
	cacheInstance *mqlIbmKmsInstance
}

func (r *mqlIbmKmsInstance) keys() ([]any, error) {
	svc, err := r.client()
	if err != nil {
		return nil, err
	}
	var all []ibmkeyprotectapiv2.KeyFullRepresentation
	offset := int64(0)
	for {
		res, _, err := svc.GetKeys(&ibmkeyprotectapiv2.GetKeysOptions{
			BluemixInstance: core.StringPtr(r.Guid.Data),
			Limit:           core.Int64Ptr(kmsPageSize),
			Offset:          core.Int64Ptr(offset),
		})
		if err != nil {
			return nil, classifyError(err, "kms.secrets.list")
		}
		if res == nil {
			break
		}
		all = append(all, res.Resources...)
		if len(res.Resources) < kmsPageSize {
			break
		}
		offset += int64(len(res.Resources))
	}
	out := make([]any, 0, len(all))
	for _, k := range all {
		res, err := CreateResource(r.MqlRuntime, "ibm.kms.key", keyArgs(k))
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmKmsKey).cacheInstance = r
		out = append(out, res)
	}
	return out, nil
}

func keyArgs(k ibmkeyprotectapiv2.KeyFullRepresentation) map[string]*llx.RawData {
	dualAuth := llx.BoolFalse
	if k.DualAuthDelete != nil {
		dualAuth = llx.BoolData(k.DualAuthDelete.Enabled != nil && *k.DualAuthDelete.Enabled)
	}
	return map[string]*llx.RawData{
		"__id":                  llx.StringData("ibm.kms.key/" + derefStr(k.Crn)),
		"id":                    strData(k.ID),
		"crn":                   strData(k.Crn),
		"name":                  strData(k.Name),
		"description":           strData(k.Description),
		"standardKey":           llx.BoolDataPtr(k.Extractable),
		"state":                 llx.StringData(keyStateName(k.State)),
		"imported":              llx.BoolDataPtr(k.Imported),
		"keyRingId":             strData(k.KeyRingID),
		"algorithmType":         strData(k.AlgorithmType),
		"deleted":               llx.BoolDataPtr(k.Deleted),
		"dualAuthDeleteEnabled": dualAuth,
		"createdAt":             dateTimeData(k.CreationDate),
		"createdBy":             strData(k.CreatedBy),
		"updatedAt":             dateTimeData(k.LastUpdateDate),
		"lastRotatedAt":         dateTimeData(k.LastRotateDate),
		"expiresAt":             dateTimeData(k.ExpirationDate),
	}
}

func (r *mqlIbm) kmsKeys() ([]any, error) {
	instances := r.GetKmsInstances()
	if instances.Error != nil {
		return nil, instances.Error
	}
	names := make([]string, len(instances.Data))
	results := make([][]any, len(instances.Data))
	errs := make([]error, len(instances.Data))
	for i, e := range instances.Data {
		inst := e.(*mqlIbmKmsInstance)
		names[i] = inst.Name.Data
		keys := inst.GetKeys()
		results[i], errs[i] = keys.Data, keys.Error
	}
	// An instance that refuses is skipped so the others' keys survive.
	merged, err := mergeRegionResults(names, results, errs, "kms.secrets.list")
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(merged))
	for _, m := range merged {
		out = append(out, m.item)
	}
	return out, nil
}

func (r *mqlIbmKmsKey) instance() (*mqlIbmKmsInstance, error) {
	if r.cacheInstance == nil {
		nullResource(&r.Instance)
		return nil, nil
	}
	return r.cacheInstance, nil
}

// keyPolicies are a key's own policies as the API returns them.
type keyPolicies struct {
	Resources []struct {
		Rotation *struct {
			Enabled       *bool  `json:"enabled"`
			IntervalMonth *int64 `json:"interval_month"`
		} `json:"rotation"`
	} `json:"resources"`
}

// rotationPolicy returns the key's rotation policy, nil when it has none.
// Standard keys cannot rotate, so only root keys are asked.
func (r *mqlIbmKmsKey) rotationPolicy() (*keyRotation, error) {
	if r.StandardKey.Data || r.cacheInstance == nil {
		return nil, nil
	}
	v, err := conn(r.MqlRuntime).Memo("kms/keypolicies/"+r.Crn.Data, func() (any, error) {
		svc, err := r.cacheInstance.client()
		if err != nil {
			return nil, err
		}
		var p keyPolicies
		if err := getJSON(svc.Service, "/api/v2/keys/"+r.Id.Data+"/policies", map[string]string{"Bluemix-Instance": r.cacheInstance.Guid.Data}, &p); err != nil {
			return nil, classifyError(err, "kms.policies.read")
		}
		return rotationOf(p), nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*keyRotation), nil
}

type keyRotation struct {
	enabled       bool
	intervalMonth *int64
}

func rotationOf(p keyPolicies) *keyRotation {
	for _, res := range p.Resources {
		if res.Rotation != nil {
			return &keyRotation{
				enabled:       res.Rotation.Enabled != nil && *res.Rotation.Enabled,
				intervalMonth: res.Rotation.IntervalMonth,
			}
		}
	}
	return nil
}

func (r *mqlIbmKmsKey) rotationEnabled() (bool, error) {
	rot, err := r.rotationPolicy()
	if err != nil {
		return false, err
	}
	return rot != nil && rot.enabled, nil
}

func (r *mqlIbmKmsKey) rotationIntervalMonth() (int64, error) {
	rot, err := r.rotationPolicy()
	if err != nil {
		return 0, err
	}
	if rot == nil || rot.intervalMonth == nil {
		r.RotationIntervalMonth.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *rot.intervalMonth, nil
}

// registrations reads every registration of the instance once and keeps the
// key's.
func (r *mqlIbmKmsKey) registrations() ([]any, error) {
	if r.cacheInstance == nil {
		return []any{}, nil
	}
	all, err := instanceRegistrations(r.cacheInstance)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, reg := range all {
		if derefStr(reg.KeyID) != r.Id.Data {
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.kms.key.registration", map[string]*llx.RawData{
			"__id":               llx.StringData("ibm.kms.key.registration/" + r.Crn.Data + "/" + derefStr(reg.ResourceCrn)),
			"resourceCrn":        strData(reg.ResourceCrn),
			"preventKeyDeletion": llx.BoolDataPtr(reg.PreventKeyDeletion),
			"description":        strData(reg.Description),
			"createdAt":          dateTimeData(reg.CreationDate),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func instanceRegistrations(inst *mqlIbmKmsInstance) ([]ibmkeyprotectapiv2.RegistrationResource, error) {
	v, err := conn(inst.MqlRuntime).Memo("kms/registrations/"+inst.Id.Data, func() (any, error) {
		svc, err := inst.client()
		if err != nil {
			return nil, err
		}
		var all []ibmkeyprotectapiv2.RegistrationResource
		offset := int64(0)
		for {
			res, _, err := svc.GetRegistrationsAllKeys(&ibmkeyprotectapiv2.GetRegistrationsAllKeysOptions{
				BluemixInstance: core.StringPtr(inst.Guid.Data),
				Limit:           core.Int64Ptr(kmsPageSize),
				Offset:          core.Int64Ptr(offset),
			})
			if err != nil {
				return nil, classifyError(err, "kms.registrations.list")
			}
			if res == nil {
				break
			}
			all = append(all, res.Resources...)
			if len(res.Resources) < kmsPageSize {
				break
			}
			offset += int64(len(res.Resources))
		}
		return all, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]ibmkeyprotectapiv2.RegistrationResource), nil
}

// kmsKeyByCRN resolves a key reference through the listed keys, null when
// the key is not in one of the account's instances.
func kmsKeyByCRN(runtime *plugin.Runtime, crn string, field *plugin.TValue[*mqlIbmKmsKey]) (*mqlIbmKmsKey, error) {
	if crn == "" {
		nullResource(field)
		return nil, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	return resolveOne(field, ns.GetKmsKeys(), crn, func(k *mqlIbmKmsKey) string { return k.Crn.Data })
}
