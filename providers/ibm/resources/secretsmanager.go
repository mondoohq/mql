// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strings"

	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
	"github.com/IBM/secrets-manager-go-sdk/v2/secretsmanagerv2"
	"github.com/go-openapi/strfmt"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
)

// secretsManagerService is the CRN service name of Secrets Manager.
const secretsManagerService = "secrets-manager"

// secretsManagerEndpoint is the public API endpoint of a Secrets Manager
// instance, from its resource controller extensions, falling back to the
// endpoint IBM Cloud builds from the instance GUID and region.
func secretsManagerEndpoint(ri resourcecontrollerv2.ResourceInstance) (string, error) {
	if eps, ok := ri.Extensions["endpoints"].(map[string]any); ok {
		if u, ok := eps["public"].(string); ok && u != "" {
			if !strings.Contains(u, "://") {
				u = "https://" + u
			}
			return u, nil
		}
	}
	guid, region := derefStr(ri.GUID), derefStr(ri.RegionID)
	if guid == "" || region == "" {
		return "", errors.New("no GUID or region and no endpoint for the Secrets Manager instance")
	}
	return "https://" + guid + "." + region + ".secrets-manager.appdomain.cloud", nil
}

// ---- instances ----

type mqlIbmSecretsManagerInstanceInternal struct {
	cacheEndpoint        string
	cacheResourceGroupID string
}

func (r *mqlIbm) secretsManagerInstances() ([]any, error) {
	items, err := listResourceInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, ri := range items {
		crn := derefStr(ri.CRN)
		if crnService(crn) != secretsManagerService {
			continue
		}
		endpoint, err := secretsManagerEndpoint(ri)
		if err != nil {
			log.Debug().Err(err).Str("instance", crn).Msg("ibm> no Secrets Manager endpoint, skipping instance")
			continue
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.secretsManager.instance", map[string]*llx.RawData{
			"__id":   llx.StringData("ibm.secretsManager.instance/" + crn),
			"id":     llx.StringData(crn),
			"guid":   strData(ri.GUID),
			"name":   strData(ri.Name),
			"region": strData(ri.RegionID),
			"state":  strData(ri.State),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmSecretsManagerInstance)
		m.cacheEndpoint = endpoint
		m.cacheResourceGroupID = derefStr(ri.ResourceGroupID)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmSecretsManagerInstance) client() (*secretsmanagerv2.SecretsManagerV2, error) {
	return conn(r.MqlRuntime).SecretsManager(r.cacheEndpoint)
}

func (r *mqlIbmSecretsManagerInstance) resourceGroup() (*mqlIbmResourceGroup, error) {
	return resourceGroupByID(r.MqlRuntime, r.cacheResourceGroupID, &r.ResourceGroup)
}

func (r *mqlIbmSecretsManagerInstance) tags() ([]any, error) {
	return userTags(r.MqlRuntime, r.Id.Data)
}

func (r *mqlIbmSecretsManagerInstance) accessTags() ([]any, error) {
	return accessTags(r.MqlRuntime, r.Id.Data)
}

// notificationsRegistration is the CRN of the connected Event Notifications
// instance, read once; an instance that is not connected answers 404, which
// is the empty string.
func (r *mqlIbmSecretsManagerInstance) notificationsRegistration() (string, error) {
	v, err := conn(r.MqlRuntime).Memo("secretsManager/notifications/"+r.Id.Data, func() (any, error) {
		svc, err := r.client()
		if err != nil {
			return nil, err
		}
		res, resp, err := svc.GetNotificationsRegistration(&secretsmanagerv2.GetNotificationsRegistrationOptions{})
		if err != nil {
			err = classifyError(withStatus(err, resp), "secrets-manager.notifications-registration.read")
			if llx.KindOf(err) == llx.ErrorKind_ERROR_KIND_NOT_FOUND {
				return "", nil
			}
			return nil, err
		}
		if res == nil {
			return "", nil
		}
		return derefStr(res.EventNotificationsInstanceCrn), nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (r *mqlIbmSecretsManagerInstance) eventNotificationsInstanceCrn() (string, error) {
	return r.notificationsRegistration()
}

func (r *mqlIbmSecretsManagerInstance) notificationsEnabled() (bool, error) {
	crn, err := r.notificationsRegistration()
	if err != nil {
		return false, err
	}
	return crn != "", nil
}

// secretMetadata is the flat form of every secret type's metadata; the SDK
// models each type as its own struct.
type secretMetadata struct {
	ID                 *string          `json:"id"`
	Crn                *string          `json:"crn"`
	Name               *string          `json:"name"`
	Description        *string          `json:"description"`
	SecretType         *string          `json:"secret_type"`
	SecretGroupID      *string          `json:"secret_group_id"`
	StateDescription   *string          `json:"state_description"`
	State              *int64           `json:"state"`
	ExpirationDate     *strfmt.DateTime `json:"expiration_date"`
	NextRotationDate   *strfmt.DateTime `json:"next_rotation_date"`
	LastRotationFailed *bool            `json:"last_rotation_failed"`
	Issuer             *string          `json:"issuer"`
	CommonName         *string          `json:"common_name"`
	VersionsTotal      *int64           `json:"versions_total"`
	CreatedAt          *strfmt.DateTime `json:"created_at"`
	UpdatedAt          *strfmt.DateTime `json:"updated_at"`
	Rotation           *struct {
		AutoRotate *bool   `json:"auto_rotate"`
		Interval   *int64  `json:"interval"`
		Unit       *string `json:"unit"`
		RotateKeys *bool   `json:"rotate_keys"`
	} `json:"rotation"`
}

// secretStates names the numeric secret states of the Secrets Manager API.
var secretStates = map[int64]string{
	0: "pre_activation",
	1: "active",
	2: "suspended",
	3: "deactivated",
	5: "destroyed",
}

func secretState(m secretMetadata) string {
	if m.State != nil {
		if s, ok := secretStates[*m.State]; ok {
			return s
		}
	}
	return strings.ToLower(derefStr(m.StateDescription))
}

// certificateIssuerType says who issued a certificate secret, from its type.
func certificateIssuerType(secretType string) string {
	switch secretType {
	case "imported_cert":
		return "imported"
	case "public_cert":
		return "public"
	case "private_cert":
		return "private"
	}
	return ""
}

func secretArgs(m secretMetadata) map[string]*llx.RawData {
	autoRotate, rotateKeys := false, false
	interval, unit := int64(0), ""
	if m.Rotation != nil {
		autoRotate = isTrue(m.Rotation.AutoRotate)
		rotateKeys = isTrue(m.Rotation.RotateKeys)
		if m.Rotation.Interval != nil {
			interval = *m.Rotation.Interval
		}
		unit = derefStr(m.Rotation.Unit)
	}
	versions := int64(0)
	if m.VersionsTotal != nil {
		versions = *m.VersionsTotal
	}
	secretType := derefStr(m.SecretType)
	return map[string]*llx.RawData{
		"id":                 strData(m.ID),
		"crn":                strData(m.Crn),
		"name":               strData(m.Name),
		"description":        strData(m.Description),
		"type":               llx.StringData(secretType),
		"secretGroupId":      strData(m.SecretGroupID),
		"state":              llx.StringData(secretState(m)),
		"autoRotate":         llx.BoolData(autoRotate),
		"rotationInterval":   llx.IntData(interval),
		"rotationUnit":       llx.StringData(unit),
		"rotateKeys":         llx.BoolData(rotateKeys),
		"nextRotationDate":   dateTimeData(m.NextRotationDate),
		"lastRotationFailed": llx.BoolData(isTrue(m.LastRotationFailed)),
		"expirationDate":     dateTimeData(m.ExpirationDate),
		"issuerType":         llx.StringData(certificateIssuerType(secretType)),
		"issuer":             strData(m.Issuer),
		"commonName":         strData(m.CommonName),
		"versionsTotal":      llx.IntData(versions),
		"createdAt":          dateTimeData(m.CreatedAt),
		"updatedAt":          dateTimeData(m.UpdatedAt),
	}
}

func (r *mqlIbmSecretsManagerInstance) secrets() ([]any, error) {
	svc, err := r.client()
	if err != nil {
		return nil, err
	}
	pager, err := svc.NewSecretsPager(&secretsmanagerv2.ListSecretsOptions{})
	if err != nil {
		return nil, err
	}
	items, err := pager.GetAll()
	if err != nil {
		return nil, classifyError(err, "secrets-manager.secrets.list")
	}
	out := make([]any, 0, len(items))
	for _, it := range items {
		var m secretMetadata
		if err := asJSON(it, &m); err != nil {
			return nil, err
		}
		args := secretArgs(m)
		args["__id"] = llx.StringData("ibm.secretsManager.secret/" + r.Id.Data + "/" + derefStr(m.ID))
		res, err := CreateResource(r.MqlRuntime, "ibm.secretsManager.secret", args)
		if err != nil {
			return nil, err
		}
		res.(*mqlIbmSecretsManagerSecret).cacheInstance = r
		out = append(out, res)
	}
	return out, nil
}

// ---- secrets ----

type mqlIbmSecretsManagerSecretInternal struct {
	cacheInstance *mqlIbmSecretsManagerInstance
}

func (r *mqlIbmSecretsManagerSecret) instance() (*mqlIbmSecretsManagerInstance, error) {
	if r.cacheInstance == nil {
		nullResource(&r.Instance)
		return nil, nil
	}
	return r.cacheInstance, nil
}
