// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"reflect"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/functions"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// functionContainerImage returns the image and digest of a container-image
// function. Archive and pre-built functions run no customer image, so both
// are nil for them.
func functionContainerImage(src functions.FunctionSourceDetails) (image, digest *string) {
	switch d := src.(type) {
	case functions.ContainerImageFunctionSourceDetails:
		return d.Image, d.ImageDigest
	case *functions.ContainerImageFunctionSourceDetails:
		if d != nil {
			return d.Image, d.ImageDigest
		}
	}
	return nil, nil
}

// functionSource is what a function's source details say about the code it
// runs. Every field is nil when it does not apply to the source type, so each
// one reads as null rather than as an empty string.
type functionSource struct {
	sourceType            *string
	runtime               *string
	runtimeUpdateStrategy *string
	handler               *string
	sourceCodeSha256      *string
	bucketNamespace       *string
	bucketName            *string
	objectName            *string
}

// decodeFunctionSource flattens the polymorphic source details of a function.
// A source type this SDK does not know still reports its discriminator, so a
// new kind of function shows up by name instead of as null.
func decodeFunctionSource(src functions.FunctionSourceDetails) functionSource {
	var res functionSource
	switch d := src.(type) {
	case functions.ContainerImageFunctionSourceDetails:
		res.sourceType = common.String(string(functions.FunctionSourceDetailsSourceTypeContainerImage))
	case *functions.ContainerImageFunctionSourceDetails:
		if d != nil {
			res.sourceType = common.String(string(functions.FunctionSourceDetailsSourceTypeContainerImage))
		}
	case functions.ArchiveFunctionSourceDetails:
		res = decodeArchiveFunctionSource(d)
	case *functions.ArchiveFunctionSourceDetails:
		if d != nil {
			res = decodeArchiveFunctionSource(*d)
		}
	case functions.PreBuiltFunctionSourceDetails:
		res.sourceType = common.String(string(functions.FunctionSourceDetailsSourceTypePreBuiltFunctions))
	case *functions.PreBuiltFunctionSourceDetails:
		if d != nil {
			res.sourceType = common.String(string(functions.FunctionSourceDetailsSourceTypePreBuiltFunctions))
		}
	default:
		res.sourceType = unknownDiscriminator(src, "SourceType")
	}
	return res
}

func decodeArchiveFunctionSource(d functions.ArchiveFunctionSourceDetails) functionSource {
	res := functionSource{
		sourceType:       common.String(string(functions.FunctionSourceDetailsSourceTypeArchive)),
		handler:          nonEmpty(d.Handler),
		sourceCodeSha256: nonEmpty(d.SourceCodeSha256),
	}

	switch rc := d.RuntimeConfig.(type) {
	case functions.FunctionUpdateRuntimeConfig:
		res.runtime = nonEmpty(rc.FunctionsRuntimeName)
		res.runtimeUpdateStrategy = common.String(string(functions.RuntimeConfigRuntimeConfigTypeFunctionUpdate))
	case *functions.FunctionUpdateRuntimeConfig:
		if rc != nil {
			res.runtime = nonEmpty(rc.FunctionsRuntimeName)
			res.runtimeUpdateStrategy = common.String(string(functions.RuntimeConfigRuntimeConfigTypeFunctionUpdate))
		}
	case functions.ManualRuntimeConfig:
		res.runtime = nonEmpty(rc.FunctionsRuntimeName)
		res.runtimeUpdateStrategy = common.String(string(functions.RuntimeConfigRuntimeConfigTypeManual))
	case *functions.ManualRuntimeConfig:
		if rc != nil {
			res.runtime = nonEmpty(rc.FunctionsRuntimeName)
			res.runtimeUpdateStrategy = common.String(string(functions.RuntimeConfigRuntimeConfigTypeManual))
		}
	default:
		res.runtimeUpdateStrategy = unknownDiscriminator(rc, "RuntimeConfigType")
	}

	var obj *functions.ObjectStorageArchiveSourceDetails
	switch a := d.ArchiveSourceDetails.(type) {
	case functions.ObjectStorageArchiveSourceDetails:
		obj = &a
	case *functions.ObjectStorageArchiveSourceDetails:
		obj = a
	}
	if obj != nil {
		res.bucketNamespace = nonEmpty(obj.Namespace)
		res.bucketName = nonEmpty(obj.BucketName)
		res.objectName = nonEmpty(obj.ObjectName)
	}
	return res
}

// unknownDiscriminator reads the discriminator of a polymorphic value the SDK
// could not map to a known variant. The SDK hands such values back as its own
// unexported base struct, whose discriminator field is still exported.
func unknownDiscriminator(v any, field string) *string {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return nil
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil
	}
	f := rv.FieldByName(field)
	if !f.IsValid() || f.Kind() != reflect.String || f.String() == "" {
		return nil
	}
	return common.String(f.String())
}

// nonEmpty treats an empty string like an absent one.
func nonEmpty(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

func (o *mqlOciFunctions) id() (string, error) {
	return "oci.functions", nil
}

func (o *mqlOciFunctions) applications() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci functions with region %s", region)

			svc, err := conn.FunctionsManagementClient(region)
			if err != nil {
				return nil, err
			}

			items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]functions.ApplicationSummary, *string, error) {
				response, err := svc.ListApplications(ctx, functions.ListApplicationsRequest{
					CompartmentId: common.String(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range items {
				app := items[i]

				var created *time.Time
				if app.TimeCreated != nil {
					created = &app.TimeCreated.Time
				}
				var timeUpdated *time.Time
				if app.TimeUpdated != nil {
					timeUpdated = &app.TimeUpdated.Time
				}

				traceConfig, err := convert.JsonToDict(app.TraceConfig)
				if err != nil {
					return nil, err
				}

				imagePolicyConfig, err := convert.JsonToDict(app.ImagePolicyConfig)
				if err != nil {
					return nil, err
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.functions.application", stringValue(app.CompartmentId), map[string]*llx.RawData{
					"id":                llx.StringDataPtr(app.Id),
					"name":              llx.StringDataPtr(app.DisplayName),
					"state":             llx.StringData(string(app.LifecycleState)),
					"shape":             llx.StringData(string(app.Shape)),
					"traceConfig":       llx.DictData(traceConfig),
					"imagePolicyConfig": llx.DictData(imagePolicyConfig),
					"created":           llx.TimeDataPtr(created),
					"timeUpdated":       llx.TimeDataPtr(timeUpdated),
					"freeformTags":      llx.MapData(strMapToAny(app.FreeformTags), types.String),
					"definedTags":       llx.MapData(definedTagsToAny(app.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlApp := mqlInstance.(*mqlOciFunctionsApplication)
				mqlApp.cacheRegion = region
				mqlApp.cacheSubnetIDs = app.SubnetIds
				mqlApp.cacheNsgIDs = app.NetworkSecurityGroupIds
				mqlApp.cacheTraceConfig = app.TraceConfig
				mqlApp.cacheImagePolicyConfig = app.ImagePolicyConfig
				res = append(res, mqlApp)
			}

			return res, nil
		})
}

type mqlOciFunctionsApplicationInternal struct {
	ociCompartmentRef
	app            ociRetryLazy[*functions.Application]
	cacheRegion    string
	cacheSubnetIDs []string
	cacheNsgIDs    []string

	cacheTraceConfig       *functions.ApplicationTraceConfig
	cacheImagePolicyConfig *functions.ImagePolicyConfig
}

// tracing builds the application's distributed tracing settings.
//
// Null when the application reports no trace configuration.
func (o *mqlOciFunctionsApplication) tracing() (*mqlOciFunctionsApplicationTraceConfig, error) {
	tc := o.cacheTraceConfig
	if tc == nil {
		o.Tracing.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.functions.applicationTraceConfig", map[string]*llx.RawData{
		"__id":      llx.StringData(o.Id.Data + "/traceConfig"),
		"isEnabled": llx.BoolDataPtr(tc.IsEnabled),
		"domainId":  llx.StringDataPtr(tc.DomainId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciFunctionsApplicationTraceConfig), nil
}

// imagePolicy builds the application's signed-image enforcement policy.
//
// Null when the application reports no image policy configuration.
func (o *mqlOciFunctionsApplication) imagePolicy() (*mqlOciFunctionsImagePolicyConfig, error) {
	ipc := o.cacheImagePolicyConfig
	if ipc == nil {
		o.ImagePolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.functions.imagePolicyConfig", map[string]*llx.RawData{
		"__id":            llx.StringData(o.Id.Data + "/imagePolicyConfig"),
		"isPolicyEnabled": llx.BoolDataPtr(ipc.IsPolicyEnabled),
	})
	if err != nil {
		return nil, err
	}
	keyIDs := make([]string, 0, len(ipc.KeyDetails))
	for _, kd := range ipc.KeyDetails {
		keyIDs = append(keyIDs, stringValue(kd.KmsKeyId))
	}
	mqlPolicy := res.(*mqlOciFunctionsImagePolicyConfig)
	// Assigned rather than appended: CreateResource returns the cached
	// resource on a second call for the same application, and appending would
	// list every trusted key twice.
	mqlPolicy.cacheKeyIDs = keyIDs
	return mqlPolicy, nil
}

type mqlOciFunctionsImagePolicyConfigInternal struct {
	cacheKeyIDs []string
}

// keys resolves the vault keys trusted to verify image signatures.
//
// Empty both when signature verification is off and when it is on with no key
// configured, which leaves nothing to verify against. isPolicyEnabled is what
// separates the two.
func (o *mqlOciFunctionsImagePolicyConfig) keys() ([]any, error) {
	res := make([]any, 0, len(o.cacheKeyIDs))
	for _, id := range o.cacheKeyIDs {
		if id == "" {
			continue
		}
		key, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, key)
	}
	return res, nil
}

func (o *mqlOciFunctionsApplication) id() (string, error) {
	return "oci.functions.application/" + o.Id.Data, nil
}

func (o *mqlOciFunctionsApplication) fetchApplication() (*functions.Application, error) {
	return o.app.get(func() (*functions.Application, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)

		svc, err := conn.FunctionsManagementClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		resp, err := svc.GetApplication(context.Background(), functions.GetApplicationRequest{
			ApplicationId: common.String(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.Application, nil
	})
}

func (o *mqlOciFunctionsApplication) config() (map[string]interface{}, error) {
	app, err := o.fetchApplication()
	if err != nil {
		return nil, err
	}

	config := make(map[string]interface{}, len(app.Config))
	for k, v := range app.Config {
		config[k] = v
	}
	return config, nil
}

func (o *mqlOciFunctionsApplication) syslogUrl() (string, error) {
	app, err := o.fetchApplication()
	if err != nil {
		return "", err
	}
	return stringValue(app.SyslogUrl), nil
}

func (o *mqlOciFunctionsApplication) subnets() ([]any, error) {
	res := make([]any, 0, len(o.cacheSubnetIDs))
	for _, id := range o.cacheSubnetIDs {
		mqlSubnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// Skip an element we cannot resolve rather than failing the
			// whole list and losing the ones that did resolve.
			log.Debug().Err(err).Str("subnet", id).Msg("skipping unresolvable oci reference")
			continue
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (o *mqlOciFunctionsApplication) networkSecurityGroups() ([]any, error) {
	res := make([]any, 0, len(o.cacheNsgIDs))
	for _, id := range o.cacheNsgIDs {
		mqlNsg, err := NewResource(o.MqlRuntime, "oci.network.networkSecurityGroup", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// Skip an element we cannot resolve rather than failing the
			// whole list and losing the ones that did resolve.
			log.Debug().Err(err).Str("nsg", id).Msg("skipping unresolvable oci reference")
			continue
		}
		res = append(res, mqlNsg)
	}
	return res, nil
}

func (o *mqlOciFunctionsApplication) functions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	svc, err := conn.FunctionsManagementClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]functions.FunctionSummary, *string, error) {
		response, err := svc.ListFunctions(ctx, functions.ListFunctionsRequest{
			ApplicationId: common.String(o.Id.Data),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		fn := items[i]

		var created *time.Time
		if fn.TimeCreated != nil {
			created = &fn.TimeCreated.Time
		}
		var timeUpdated *time.Time
		if fn.TimeUpdated != nil {
			timeUpdated = &fn.TimeUpdated.Time
		}

		traceConfig, err := convert.JsonToDict(fn.TraceConfig)
		if err != nil {
			return nil, err
		}
		image, imageDigest := functionContainerImage(fn.SourceDetails)

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.functions.function", stringValue(fn.CompartmentId), map[string]*llx.RawData{
			"id":               llx.StringDataPtr(fn.Id),
			"name":             llx.StringDataPtr(fn.DisplayName),
			"applicationId":    llx.StringDataPtr(fn.ApplicationId),
			"state":            llx.StringData(string(fn.LifecycleState)),
			"image":            llx.StringDataPtr(image),
			"imageDigest":      llx.StringDataPtr(imageDigest),
			"shape":            llx.StringData(string(fn.Shape)),
			"memoryInMBs":      llx.IntData(int64Value(fn.MemoryInMBs)),
			"timeoutInSeconds": llx.IntData(intValue(fn.TimeoutInSeconds)),
			"invokeEndpoint":   llx.StringDataPtr(fn.InvokeEndpoint),
			"traceConfig":      llx.DictData(traceConfig),
			"created":          llx.TimeDataPtr(created),
			"timeUpdated":      llx.TimeDataPtr(timeUpdated),
			"freeformTags":     llx.MapData(strMapToAny(fn.FreeformTags), types.String),
			"definedTags":      llx.MapData(definedTagsToAny(fn.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlFn := mqlInstance.(*mqlOciFunctionsFunction)
		mqlFn.cacheRegion = o.cacheRegion
		mqlFn.cacheTraceConfig = fn.TraceConfig
		mqlFn.cacheSourceDetails = fn.SourceDetails
		res = append(res, mqlFn)
	}

	return res, nil
}

type mqlOciFunctionsFunctionInternal struct {
	ociCompartmentRef
	fn          ociRetryLazy[*functions.Function]
	cacheRegion string

	cacheTraceConfig *functions.FunctionTraceConfig
	// cacheSourceDetails is the source as ListFunctions reported it. The
	// summary marks it optional, so when it is absent the source is read from
	// GetFunction, where it is mandatory.
	cacheSourceDetails functions.FunctionSourceDetails
	source             ociRetryLazy[functionSource]
}

// getSource decodes the function's source details once for every source
// field.
func (o *mqlOciFunctionsFunction) getSource() (functionSource, error) {
	return o.source.get(func() (functionSource, error) {
		if o.cacheSourceDetails != nil {
			return decodeFunctionSource(o.cacheSourceDetails), nil
		}
		fn, err := o.fetchFunction()
		if err != nil {
			return functionSource{}, err
		}
		return decodeFunctionSource(fn.SourceDetails), nil
	})
}

// sourceString resolves one string field of the function's source, setting
// the field to null when the value does not apply.
func (o *mqlOciFunctionsFunction) sourceString(field *plugin.TValue[string], pick func(functionSource) *string) (string, error) {
	src, err := o.getSource()
	if err != nil {
		return "", err
	}
	v := pick(src)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

func (o *mqlOciFunctionsFunction) sourceType() (string, error) {
	return o.sourceString(&o.SourceType, func(s functionSource) *string { return s.sourceType })
}

func (o *mqlOciFunctionsFunction) runtime() (string, error) {
	return o.sourceString(&o.Runtime, func(s functionSource) *string { return s.runtime })
}

func (o *mqlOciFunctionsFunction) runtimeUpdateStrategy() (string, error) {
	return o.sourceString(&o.RuntimeUpdateStrategy, func(s functionSource) *string { return s.runtimeUpdateStrategy })
}

func (o *mqlOciFunctionsFunction) handler() (string, error) {
	return o.sourceString(&o.Handler, func(s functionSource) *string { return s.handler })
}

func (o *mqlOciFunctionsFunction) sourceCodeSha256() (string, error) {
	return o.sourceString(&o.SourceCodeSha256, func(s functionSource) *string { return s.sourceCodeSha256 })
}

func (o *mqlOciFunctionsFunction) sourceObjectName() (string, error) {
	return o.sourceString(&o.SourceObjectName, func(s functionSource) *string { return s.objectName })
}

// sourceBucket resolves the Object Storage bucket holding the function's code
// archive.
//
// The archive details carry the bucket's namespace and name but no region,
// so the function's own region is used for the bucket's detail call. A bucket
// that does not answer there reads as null rather than failing the listing. The bucket is
// resolved through its init rather than by scanning oci.objectStorage.buckets:
// that listing reads only the tenancy's root compartment, so a bucket in any
// other compartment would never match. Repeated references to one bucket
// share a single cached resource and a single detail call.
func (o *mqlOciFunctionsFunction) sourceBucket() (*mqlOciObjectStorageBucket, error) {
	src, err := o.getSource()
	if err != nil {
		return nil, err
	}
	// Both parts are required: an empty namespace would build the cache key
	// "oci.objectStorage.bucket//<name>", shared by every such bucket.
	if src.bucketNamespace == nil || src.bucketName == nil || o.cacheRegion == "" {
		o.SourceBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	regionRes, err := NewResource(o.MqlRuntime, "oci.region", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheRegion),
	})
	if err != nil {
		return nil, err
	}

	res, err := NewResource(o.MqlRuntime, "oci.objectStorage.bucket", map[string]*llx.RawData{
		"namespace": llx.StringData(*src.bucketNamespace),
		"name":      llx.StringData(*src.bucketName),
		"region":    llx.ResourceData(regionRes, "oci.region"),
	})
	if err != nil {
		// The bucket can be deleted after the function is deployed; the
		// function keeps running the code it already pulled. That is a real
		// state of the tenancy, so the reference reads as null.
		if ociReferentGone(err) {
			log.Debug().Str("bucket", *src.bucketName).Msg("function source bucket no longer exists")
			o.SourceBucket.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return res.(*mqlOciObjectStorageBucket), nil
}

// tracing builds the function's distributed tracing settings.
//
// Null when the function reports no trace configuration.
func (o *mqlOciFunctionsFunction) tracing() (*mqlOciFunctionsFunctionTraceConfig, error) {
	tc := o.cacheTraceConfig
	if tc == nil {
		o.Tracing.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.functions.functionTraceConfig", map[string]*llx.RawData{
		"__id":      llx.StringData(o.Id.Data + "/traceConfig"),
		"isEnabled": llx.BoolDataPtr(tc.IsEnabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciFunctionsFunctionTraceConfig), nil
}

func (o *mqlOciFunctionsFunction) id() (string, error) {
	return "oci.functions.function/" + o.Id.Data, nil
}

func (o *mqlOciFunctionsFunction) fetchFunction() (*functions.Function, error) {
	return o.fn.get(func() (*functions.Function, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)

		svc, err := conn.FunctionsManagementClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		resp, err := svc.GetFunction(context.Background(), functions.GetFunctionRequest{
			FunctionId: common.String(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.Function, nil
	})
}

func (o *mqlOciFunctionsFunction) config() (map[string]interface{}, error) {
	fn, err := o.fetchFunction()
	if err != nil {
		return nil, err
	}

	config := make(map[string]interface{}, len(fn.Config))
	for k, v := range fn.Config {
		config[k] = v
	}
	return config, nil
}
