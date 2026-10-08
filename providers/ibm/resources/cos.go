// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/IBM/ibm-cos-sdk-go/aws"
	"github.com/IBM/ibm-cos-sdk-go/aws/awserr"
	"github.com/IBM/ibm-cos-sdk-go/service/s3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ibm/connection"
)

// cosService is the CRN service name of Cloud Object Storage instances.
const cosService = "cloud-object-storage"

// publicAccessGroupID is the account's built-in Public Access group: a policy
// granting it access opens a resource to anyone on the internet.
const publicAccessGroupID = "AccessGroupId-PublicAccess"

// allUsersURI is the ACL grantee that stands for anyone.
const allUsersURI = "http://acs.amazonaws.com/groups/global/AllUsers"

// splitLocationConstraint splits a bucket's location constraint, such as
// us-south-smart, us-standard, or ams03-onerate_active, into its location and
// storage class. The storage class is the last dash-separated part.
func splitLocationConstraint(lc string) (location, storageClass string) {
	i := strings.LastIndex(lc, "-")
	if i <= 0 {
		return lc, ""
	}
	return lc[:i], lc[i+1:]
}

// bucketCRN builds a bucket's CRN from its instance's CRN, which ends in
// "::": crn:...:<instance guid>:bucket:<name>.
func bucketCRN(instanceCRN, name string) string {
	return strings.TrimSuffix(instanceCRN, "::") + ":bucket:" + name
}

type mqlIbmCosBucketInternal struct {
	cacheInstanceCRN string
	cacheEndpoint    string
}

func (r *mqlIbm) cosBuckets() ([]any, error) {
	items, err := listResourceInstances(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	c := conn(r.MqlRuntime)
	client, err := c.CosClient(connection.CosListEndpoint)
	if err != nil {
		return nil, err
	}
	var names []string
	var results [][]any
	var errs []error
	for _, ri := range items {
		crn := derefStr(ri.CRN)
		if crnService(crn) != cosService || crnSegment(crn, 8) != "" {
			continue
		}
		buckets, err := r.listBuckets(client, crn)
		names = append(names, derefStr(ri.Name))
		results = append(results, buckets)
		errs = append(errs, err)
	}
	// An instance that refuses is skipped so the others' buckets survive.
	merged, err := mergeRegionResults(names, results, errs, "cloud-object-storage.bucket.list_bucket_crn")
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(merged))
	for _, m := range merged {
		out = append(out, m.item)
	}
	return out, nil
}

func (r *mqlIbm) listBuckets(client *s3.S3, instanceCRN string) ([]any, error) {
	var buckets []*s3.BucketExtended
	err := client.ListBucketsExtendedPages(&s3.ListBucketsExtendedInput{IBMServiceInstanceId: aws.String(instanceCRN)},
		func(page *s3.ListBucketsExtendedOutput, _ bool) bool {
			buckets = append(buckets, page.Buckets...)
			return true
		})
	if err != nil {
		return nil, classifyError(err, "cloud-object-storage.bucket.list_bucket_crn")
	}
	out := make([]any, 0, len(buckets))
	for _, b := range buckets {
		if b == nil {
			continue
		}
		name := aws.StringValue(b.Name)
		location, storageClass := splitLocationConstraint(aws.StringValue(b.LocationConstraint))
		crn := bucketCRN(instanceCRN, name)
		createdAt := llx.NilData
		if b.CreationDate != nil {
			createdAt = llx.TimeData(*b.CreationDate)
		}
		res, err := CreateResource(r.MqlRuntime, "ibm.cos.bucket", map[string]*llx.RawData{
			"__id":         llx.StringData("ibm.cos.bucket/" + crn),
			"name":         llx.StringData(name),
			"crn":          llx.StringData(crn),
			"location":     llx.StringData(location),
			"storageClass": llx.StringData(storageClass),
			"createdAt":    createdAt,
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlIbmCosBucket)
		m.cacheInstanceCRN = instanceCRN
		m.cacheEndpoint = connection.CosEndpoint(location)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlIbmCosBucket) instance() (*mqlIbmResourceInstance, error) {
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return resolveOne(&r.Instance, ns.GetResourceInstances(), r.cacheInstanceCRN, func(i *mqlIbmResourceInstance) string { return i.Id.Data })
}

func (r *mqlIbmCosBucket) tags() ([]any, error)       { return userTags(r.MqlRuntime, r.Crn.Data) }
func (r *mqlIbmCosBucket) accessTags() ([]any, error) { return accessTags(r.MqlRuntime, r.Crn.Data) }

// ---- bucket configuration ----

// bucketConfig is a bucket's configuration as the API returns it. The SDK's
// firewall model drops the denied addresses and network types, so the
// response is read here directly.
type bucketConfig struct {
	TimeUpdated *string `json:"time_updated"`
	ObjectCount *int64  `json:"object_count"`
	BytesUsed   *int64  `json:"bytes_used"`
	HardQuota   *int64  `json:"hard_quota"`
	Firewall    *struct {
		AllowedIP          []string `json:"allowed_ip"`
		DeniedIP           []string `json:"denied_ip"`
		AllowedNetworkType []string `json:"allowed_network_type"`
	} `json:"firewall"`
	ActivityTracking *struct {
		ReadDataEvents   *bool `json:"read_data_events"`
		WriteDataEvents  *bool `json:"write_data_events"`
		ManagementEvents *bool `json:"management_events"`
	} `json:"activity_tracking"`
	MetricsMonitoring *struct {
		UsageMetricsEnabled   *bool `json:"usage_metrics_enabled"`
		RequestMetricsEnabled *bool `json:"request_metrics_enabled"`
	} `json:"metrics_monitoring"`
}

func (r *mqlIbmCosBucket) config() (*bucketConfig, error) {
	c := conn(r.MqlRuntime)
	v, err := c.Memo("cos/config/"+r.Name.Data, func() (any, error) {
		svc, err := c.CosConfig()
		if err != nil {
			return nil, err
		}
		var cfg bucketConfig
		if err := getJSON(svc.Service, "/b/"+r.Name.Data, nil, &cfg); err != nil {
			return nil, classifyError(err, "cloud-object-storage.bucket.get")
		}
		return &cfg, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*bucketConfig), nil
}

func (r *mqlIbmCosBucket) updatedAt() (*time.Time, error) {
	cfg, err := r.config()
	if err != nil {
		return nil, err
	}
	if cfg.TimeUpdated == nil {
		r.UpdatedAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, *cfg.TimeUpdated)
	if err != nil {
		r.UpdatedAt.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return &t, nil
}

// optionalInt reads an optional count into a field, null when absent.
func optionalInt(v *int64, field *plugin.TValue[int64]) (int64, error) {
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return *v, nil
}

func (r *mqlIbmCosBucket) objectCount() (int64, error) {
	cfg, err := r.config()
	if err != nil {
		return 0, err
	}
	return optionalInt(cfg.ObjectCount, &r.ObjectCount)
}

func (r *mqlIbmCosBucket) bytesUsed() (int64, error) {
	cfg, err := r.config()
	if err != nil {
		return 0, err
	}
	return optionalInt(cfg.BytesUsed, &r.BytesUsed)
}

func (r *mqlIbmCosBucket) hardQuota() (int64, error) {
	cfg, err := r.config()
	if err != nil {
		return 0, err
	}
	return optionalInt(cfg.HardQuota, &r.HardQuota)
}

func anyList(in []string) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, s)
	}
	return out
}

func (r *mqlIbmCosBucket) allowedIps() ([]any, error) {
	cfg, err := r.config()
	if err != nil || cfg.Firewall == nil {
		return []any{}, err
	}
	return anyList(cfg.Firewall.AllowedIP), nil
}

func (r *mqlIbmCosBucket) deniedIps() ([]any, error) {
	cfg, err := r.config()
	if err != nil || cfg.Firewall == nil {
		return []any{}, err
	}
	return anyList(cfg.Firewall.DeniedIP), nil
}

func (r *mqlIbmCosBucket) allowedNetworkTypes() ([]any, error) {
	cfg, err := r.config()
	if err != nil || cfg.Firewall == nil {
		return []any{}, err
	}
	return anyList(cfg.Firewall.AllowedNetworkType), nil
}

// isTrue reads an optional flag; a bucket without the setting sends nothing,
// which means the feature is off.
func isTrue(b *bool) bool { return b != nil && *b }

func (r *mqlIbmCosBucket) activityTrackingReadDataEvents() (bool, error) {
	cfg, err := r.config()
	if err != nil || cfg.ActivityTracking == nil {
		return false, err
	}
	return isTrue(cfg.ActivityTracking.ReadDataEvents), nil
}

func (r *mqlIbmCosBucket) activityTrackingWriteDataEvents() (bool, error) {
	cfg, err := r.config()
	if err != nil || cfg.ActivityTracking == nil {
		return false, err
	}
	return isTrue(cfg.ActivityTracking.WriteDataEvents), nil
}

func (r *mqlIbmCosBucket) activityTrackingManagementEvents() (bool, error) {
	cfg, err := r.config()
	if err != nil || cfg.ActivityTracking == nil {
		return false, err
	}
	return isTrue(cfg.ActivityTracking.ManagementEvents), nil
}

func (r *mqlIbmCosBucket) usageMetricsEnabled() (bool, error) {
	cfg, err := r.config()
	if err != nil || cfg.MetricsMonitoring == nil {
		return false, err
	}
	return isTrue(cfg.MetricsMonitoring.UsageMetricsEnabled), nil
}

func (r *mqlIbmCosBucket) requestMetricsEnabled() (bool, error) {
	cfg, err := r.config()
	if err != nil || cfg.MetricsMonitoring == nil {
		return false, err
	}
	return isTrue(cfg.MetricsMonitoring.RequestMetricsEnabled), nil
}

// ---- S3 settings ----

// s3Call runs one S3 read for the bucket once per connection, on the bucket's
// own endpoint.
func s3Call[T any](r *mqlIbmCosBucket, name string, fn func(c *s3.S3, bucket *string) (T, error)) (T, error) {
	var zero T
	c := conn(r.MqlRuntime)
	v, err := c.Memo("cos/"+name+"/"+r.Name.Data, func() (any, error) {
		client, err := c.CosClient(r.cacheEndpoint)
		if err != nil {
			return nil, err
		}
		return fn(client, aws.String(r.Name.Data))
	})
	if err != nil {
		return zero, err
	}
	return v.(T), nil
}

// notConfigured reports an S3 answer that means the bucket has no such
// configuration, which is a value (off), not a failure.
func notConfigured(err error) bool {
	var aerr awserr.Error
	if !errors.As(err, &aerr) {
		return false
	}
	switch aerr.Code() {
	case "NoSuchWebsiteConfiguration", "ObjectLockConfigurationNotFoundError",
		"NoSuchPublicAccessBlockConfiguration", "NoSuchBucketProtectionConfiguration":
		return true
	}
	return false
}

func (r *mqlIbmCosBucket) head() (*s3.HeadBucketOutput, error) {
	return s3Call(r, "head", func(c *s3.S3, b *string) (*s3.HeadBucketOutput, error) {
		out, err := c.HeadBucket(&s3.HeadBucketInput{Bucket: b})
		if err != nil {
			return nil, classifyError(err, "cloud-object-storage.bucket.head")
		}
		return out, nil
	})
}

func (r *mqlIbmCosBucket) kmsEnabled() (bool, error) {
	h, err := r.head()
	if err != nil {
		return false, err
	}
	return isTrue(h.IBMSSEKPEnabled), nil
}

func (r *mqlIbmCosBucket) kmsKey() (*mqlIbmKmsKey, error) {
	h, err := r.head()
	if err != nil {
		return nil, err
	}
	return kmsKeyByCRN(r.MqlRuntime, aws.StringValue(h.IBMSSEKPCrkId), &r.KmsKey)
}

func (r *mqlIbmCosBucket) versioning() (string, error) {
	out, err := s3Call(r, "versioning", func(c *s3.S3, b *string) (*s3.GetBucketVersioningOutput, error) {
		out, err := c.GetBucketVersioning(&s3.GetBucketVersioningInput{Bucket: b})
		if err != nil {
			return nil, classifyError(err, "cloud-object-storage.bucket.get_versioning")
		}
		return out, nil
	})
	if err != nil {
		return "", err
	}
	return aws.StringValue(out.Status), nil
}

func (r *mqlIbmCosBucket) objectLockEnabled() (bool, error) {
	out, err := s3Call(r, "objectlock", func(c *s3.S3, b *string) (*s3.GetObjectLockConfigurationOutput, error) {
		out, err := c.GetObjectLockConfiguration(&s3.GetObjectLockConfigurationInput{Bucket: b})
		if notConfigured(err) {
			return &s3.GetObjectLockConfigurationOutput{}, nil
		}
		if err != nil {
			return nil, classifyError(err, "cloud-object-storage.bucket.get_object_lock_configuration")
		}
		return out, nil
	})
	if err != nil {
		return false, err
	}
	return out.ObjectLockConfiguration != nil && aws.StringValue(out.ObjectLockConfiguration.ObjectLockEnabled) == "Enabled", nil
}

func (r *mqlIbmCosBucket) protection() (*s3.ProtectionConfiguration, error) {
	return s3Call(r, "protection", func(c *s3.S3, b *string) (*s3.ProtectionConfiguration, error) {
		out, err := c.GetBucketProtectionConfiguration(&s3.GetBucketProtectionConfigurationInput{Bucket: b})
		if notConfigured(err) {
			return nil, nil
		}
		if err != nil {
			return nil, classifyError(err, "cloud-object-storage.bucket.get_protection")
		}
		if out == nil {
			return nil, nil
		}
		return out.ProtectionConfiguration, nil
	})
}

func (r *mqlIbmCosBucket) retentionEnabled() (bool, error) {
	p, err := r.protection()
	if err != nil {
		return false, err
	}
	return p != nil && aws.StringValue(p.Status) == "COMPLIANCE", nil
}

func retentionDays(p *s3.ProtectionConfiguration, pick func(*s3.ProtectionConfiguration) *int64, field *plugin.TValue[int64]) (int64, error) {
	if p == nil || aws.StringValue(p.Status) != "COMPLIANCE" {
		return optionalInt(nil, field)
	}
	return optionalInt(pick(p), field)
}

func (r *mqlIbmCosBucket) retentionDefaultDays() (int64, error) {
	p, err := r.protection()
	if err != nil {
		return 0, err
	}
	return retentionDays(p, func(p *s3.ProtectionConfiguration) *int64 {
		if p.DefaultRetention == nil {
			return nil
		}
		return p.DefaultRetention.Days
	}, &r.RetentionDefaultDays)
}

func (r *mqlIbmCosBucket) retentionMinimumDays() (int64, error) {
	p, err := r.protection()
	if err != nil {
		return 0, err
	}
	return retentionDays(p, func(p *s3.ProtectionConfiguration) *int64 {
		if p.MinimumRetention == nil {
			return nil
		}
		return p.MinimumRetention.Days
	}, &r.RetentionMinimumDays)
}

func (r *mqlIbmCosBucket) retentionMaximumDays() (int64, error) {
	p, err := r.protection()
	if err != nil {
		return 0, err
	}
	return retentionDays(p, func(p *s3.ProtectionConfiguration) *int64 {
		if p.MaximumRetention == nil {
			return nil
		}
		return p.MaximumRetention.Days
	}, &r.RetentionMaximumDays)
}

func (r *mqlIbmCosBucket) permanentRetentionEnabled() (bool, error) {
	p, err := r.protection()
	if err != nil {
		return false, err
	}
	return p != nil && isTrue(p.EnablePermanentRetention), nil
}

func (r *mqlIbmCosBucket) publicAcl() (bool, error) {
	out, err := s3Call(r, "acl", func(c *s3.S3, b *string) (*s3.GetBucketAclOutput, error) {
		out, err := c.GetBucketAcl(&s3.GetBucketAclInput{Bucket: b})
		if err != nil {
			return nil, classifyError(err, "cloud-object-storage.bucket.get_acl")
		}
		return out, nil
	})
	if err != nil {
		return false, err
	}
	return grantsAllUsers(out.Grants), nil
}

func grantsAllUsers(grants []*s3.Grant) bool {
	for _, g := range grants {
		if g != nil && g.Grantee != nil && aws.StringValue(g.Grantee.URI) == allUsersURI {
			return true
		}
	}
	return false
}

func (r *mqlIbmCosBucket) websiteEnabled() (bool, error) {
	return s3Call(r, "website", func(c *s3.S3, b *string) (bool, error) {
		_, err := c.GetBucketWebsite(&s3.GetBucketWebsiteInput{Bucket: b})
		if notConfigured(err) || connection.StatusCode(err) == http.StatusNotFound {
			return false, nil
		}
		if err != nil {
			return false, classifyError(err, "cloud-object-storage.bucket.get_website")
		}
		return true, nil
	})
}

// isPublic combines the bucket ACL with the account's Public Access group: a
// policy granting the group access to the bucket opens it to anyone, as long
// as the account has the group enabled.
func (r *mqlIbmCosBucket) isPublic() (bool, error) {
	acl := r.GetPublicAcl()
	if acl.Error != nil {
		return false, acl.Error
	}
	if acl.Data {
		return true, nil
	}
	ns, err := root(r.MqlRuntime)
	if err != nil {
		return false, err
	}
	settings := ns.GetIamAccountSettings()
	if settings.Error != nil {
		return false, settings.Error
	}
	enabled := settings.Data.GetPublicAccessEnabled()
	if enabled.Error != nil {
		return false, enabled.Error
	}
	if !enabled.Data {
		return false, nil
	}
	policies := ns.GetIamPolicies()
	if policies.Error != nil {
		return false, policies.Error
	}
	instanceGUID := crnSegment(r.cacheInstanceCRN, 7)
	for _, e := range policies.Data {
		p := e.(*mqlIbmIamPolicy)
		if p.Type.Data != "access" || (p.State.Data != "" && p.State.Data != "active") {
			continue
		}
		if publicAccessGrant(stringMap(p.SubjectAttributes.Data), stringMap(p.ResourceAttributes.Data), instanceGUID, r.Name.Data) {
			return true, nil
		}
	}
	return false, nil
}

func stringMap(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// publicAccessGrant reports whether a policy grants the Public Access group
// access to the bucket. An empty resource attribute selects everything, so a
// policy on all of Cloud Object Storage, the instance, or the bucket counts.
func publicAccessGrant(subject, resource map[string]string, instanceGUID, bucket string) bool {
	if subject["access_group_id"] != publicAccessGroupID {
		return false
	}
	matches := func(key, want string) bool {
		v := resource[key]
		return v == "" || v == want
	}
	if v := resource["serviceName"]; v != "" && v != cosService {
		return false
	}
	if t := resource["resourceType"]; t != "" && t != "bucket" {
		return false
	}
	return matches("serviceInstance", instanceGUID) && matches("resource", bucket)
}
