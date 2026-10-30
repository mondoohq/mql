// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/managedkafka"
	"github.com/oracle/oci-go-sdk/v65/queue"
	"github.com/oracle/oci-go-sdk/v65/streaming"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// ----- Streaming -----

func (o *mqlOciStreaming) id() (string, error) {
	return "oci.streaming", nil
}

func (o *mqlOciStreaming) streams() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.StreamAdminClient(region)
			if err != nil {
				return nil, err
			}

			streams, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]streaming.StreamSummary, *string, error) {
				response, err := client.ListStreams(ctx, streaming.ListStreamsRequest{
					CompartmentId: new(compartmentID),
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

			res := make([]any, 0, len(streams))
			for i := range streams {
				s := streams[i]

				mqlStream, err := CreateResource(o.MqlRuntime, "oci.streaming.stream", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(s.Id),
					"name":             llx.StringDataPtr(s.Name),
					"partitions":       llx.IntDataDefault(s.Partitions, 0),
					"messagesEndpoint": llx.StringDataPtr(s.MessagesEndpoint),
					"state":            llx.StringData(string(s.LifecycleState)),
					"created":          sdkTimeData(s.TimeCreated),
					"freeformTags":     llx.MapData(strMapToAny(s.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(s.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlStreamTyped := mqlStream.(*mqlOciStreamingStream)
				mqlStreamTyped.cacheCompartmentID = stringValue(s.CompartmentId)
				mqlStreamTyped.cacheStreamPoolID = stringValue(s.StreamPoolId)
				res = append(res, mqlStreamTyped)
			}

			return res, nil
		})
}

func (o *mqlOciStreaming) streamPools() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.StreamAdminClient(region)
			if err != nil {
				return nil, err
			}

			pools, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]streaming.StreamPoolSummary, *string, error) {
				response, err := client.ListStreamPools(ctx, streaming.ListStreamPoolsRequest{
					CompartmentId: new(compartmentID),
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

			res := make([]any, 0, len(pools))
			for i := range pools {
				p := pools[i]

				mqlPool, err := CreateResource(o.MqlRuntime, "oci.streaming.streamPool", map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(p.Id),
					"name":               llx.StringDataPtr(p.Name),
					"isPrivate":          llx.BoolData(boolValue(p.IsPrivate)),
					"securityAttributes": llx.MapData(definedTagsToAny(p.SecurityAttributes), types.Dict),
					"state":              llx.StringData(string(p.LifecycleState)),
					"created":            sdkTimeData(p.TimeCreated),
					"freeformTags":       llx.MapData(strMapToAny(p.FreeformTags), types.String),
					"definedTags":        llx.MapData(definedTagsToAny(p.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlPoolTyped := mqlPool.(*mqlOciStreamingStreamPool)
				mqlPoolTyped.cacheCompartmentID = stringValue(p.CompartmentId)
				mqlPoolTyped.cacheRegion = region
				res = append(res, mqlPoolTyped)
			}

			return res, nil
		})
}

type mqlOciStreamingStreamInternal struct {
	cacheCompartmentID string
	cacheStreamPoolID  string
}

func (o *mqlOciStreamingStream) id() (string, error) {
	return "oci.streaming.stream/" + o.Id.Data, nil
}

func (o *mqlOciStreamingStream) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciStreamingStream) streamPool() (*mqlOciStreamingStreamPool, error) {
	if o.cacheStreamPoolID == "" {
		o.StreamPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(o.MqlRuntime, "oci.streaming.streamPool", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheStreamPoolID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciStreamingStreamPool), nil
}

// The pool listing reports only isPrivate and lifecycle. Encryption, the
// private-endpoint placement and the Kafka settings are detail-only, so they
// share one fetch.
type mqlOciStreamingStreamPoolInternal struct {
	cacheCompartmentID string
	cacheRegion        string

	detail ociLazy[*streaming.StreamPool]
}

// initOciStreamingStreamPool resolves a stream pool by OCID.
//
// Without an init, NewResource falls straight through to Create with whatever
// args it was handed - here just an id - so `oci.streaming.streams.streamPool`
// produced a resource with every other field unset and an empty cacheRegion,
// which then built a client against an empty region. Resolving through the
// pool listing returns the fully populated instance instead.
func initOciStreamingStreamPool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		return nil, nil, errors.New("id required to fetch oci.streaming.streamPool")
	}

	obj, err := CreateResource(runtime, "oci.streaming", nil)
	if err != nil {
		return nil, nil, err
	}
	s := obj.(*mqlOciStreaming)

	rawPools := s.GetStreamPools()
	if rawPools.Error != nil {
		return nil, nil, rawPools.Error
	}

	for _, raw := range rawPools.Data {
		pool := raw.(*mqlOciStreamingStreamPool)
		if pool.Id.Data == idVal {
			return args, pool, nil
		}
	}

	return nil, nil, errors.New("oci.streaming.streamPool not found: " + idVal)
}

func (o *mqlOciStreamingStreamPool) id() (string, error) {
	return "oci.streaming.streamPool/" + o.Id.Data, nil
}

func (o *mqlOciStreamingStreamPool) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciStreamingStreamPool) getDetail() (*streaming.StreamPool, error) {
	return o.detail.get(func() (*streaming.StreamPool, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		client, err := conn.StreamAdminClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		response, err := client.GetStreamPool(context.Background(), streaming.GetStreamPoolRequest{
			StreamPoolId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &response.StreamPool, nil
	})
}

func (o *mqlOciStreamingStreamPool) endpointFqdn() (string, error) {
	detail, err := o.getDetail()
	if err != nil {
		return "", err
	}
	return stringValue(detail.EndpointFqdn), nil
}

func (o *mqlOciStreamingStreamPool) subnet() (*mqlOciNetworkSubnet, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	if detail.PrivateEndpointSettings == nil {
		o.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveOciSubnet(o.MqlRuntime, stringValue(detail.PrivateEndpointSettings.SubnetId), &o.Subnet)
}

func (o *mqlOciStreamingStreamPool) securityGroups() ([]any, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	if detail.PrivateEndpointSettings == nil {
		return []any{}, nil
	}
	return resolveOciSecurityGroups(o.MqlRuntime, stringsToAny(detail.PrivateEndpointSettings.NsgIds))
}

func (o *mqlOciStreamingStreamPool) privateEndpointIp() (string, error) {
	detail, err := o.getDetail()
	if err != nil {
		return "", err
	}
	if detail.PrivateEndpointSettings == nil {
		return "", nil
	}
	return stringValue(detail.PrivateEndpointSettings.PrivateEndpointIp), nil
}

func (o *mqlOciStreamingStreamPool) encryptionKey() (*mqlOciKmsKey, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	return resolveOciKmsKey(o.MqlRuntime, ociCustomEncryptionKeyId(detail.CustomEncryptionKey), &o.EncryptionKey)
}

func (o *mqlOciStreamingStreamPool) encryptionKeyState() (string, error) {
	detail, err := o.getDetail()
	if err != nil {
		return "", err
	}
	if detail.CustomEncryptionKey == nil {
		return string(streaming.CustomEncryptionKeyKeyStateNone), nil
	}
	return string(detail.CustomEncryptionKey.KeyState), nil
}

func (o *mqlOciStreamingStreamPool) kafkaSettings() (any, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	if detail.KafkaSettings == nil {
		return nil, nil
	}
	return convert.JsonToDict(detail.KafkaSettings)
}

// kafka builds the pool's Kafka compatibility settings.
//
// Null when the pool reports none, which says nothing reaches it through the
// Kafka-compatible endpoint rather than that the endpoint accepts anything.
func (o *mqlOciStreamingStreamPool) kafka() (*mqlOciStreamingKafkaConfig, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	ks := detail.KafkaSettings
	if ks == nil {
		o.Kafka.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.streaming.kafkaConfig", map[string]*llx.RawData{
		"__id":                   llx.StringData(o.Id.Data + "/kafkaSettings"),
		"bootstrapServers":       llx.StringDataPtr(ks.BootstrapServers),
		"autoCreateTopicsEnable": llx.BoolDataPtr(ks.AutoCreateTopicsEnable),
		"logRetentionHours":      llx.IntDataPtr(intPtrToInt64(ks.LogRetentionHours)),
		"numPartitions":          llx.IntDataPtr(intPtrToInt64(ks.NumPartitions)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciStreamingKafkaConfig), nil
}

// ociCustomEncryptionKeyId pulls the KMS key OCID out of a stream pool's
// encryption block. A NONE key state means Oracle-managed encryption, which
// carries no customer key to resolve.
func ociCustomEncryptionKeyId(key *streaming.CustomEncryptionKey) string {
	if key == nil {
		return ""
	}
	return stringValue(key.KmsKeyId)
}

// ----- Queue -----

func (o *mqlOciQueue) id() (string, error) {
	return "oci.queue", nil
}

func (o *mqlOciQueue) queues() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.QueueAdminClient(region)
			if err != nil {
				return nil, err
			}

			queues, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]queue.QueueSummary, *string, error) {
				response, err := client.ListQueues(ctx, queue.ListQueuesRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.QueueCollection.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(queues))
			for i := range queues {
				q := queues[i]

				capabilities := make([]string, 0, len(q.Capabilities))
				for _, c := range q.Capabilities {
					capabilities = append(capabilities, string(c))
				}

				mqlQueue, err := CreateResource(o.MqlRuntime, "oci.queue.queue", map[string]*llx.RawData{
					"id":               llx.StringDataPtr(q.Id),
					"name":             llx.StringDataPtr(q.DisplayName),
					"messagesEndpoint": llx.StringDataPtr(q.MessagesEndpoint),
					"capabilities":     llx.ArrayData(stringsToAny(capabilities), types.String),
					"state":            llx.StringData(string(q.LifecycleState)),
					"stateDetails":     llx.StringDataPtr(q.LifecycleDetails),
					"created":          sdkTimeData(q.TimeCreated),
					"updated":          sdkTimeData(q.TimeUpdated),
					"freeformTags":     llx.MapData(strMapToAny(q.FreeformTags), types.String),
					"definedTags":      llx.MapData(definedTagsToAny(q.DefinedTags), types.Any),
					"systemTags":       llx.MapData(definedTagsToAny(q.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlQueueTyped := mqlQueue.(*mqlOciQueueQueue)
				mqlQueueTyped.cacheCompartmentID = stringValue(q.CompartmentId)
				mqlQueueTyped.cacheRegion = region
				res = append(res, mqlQueueTyped)
			}

			return res, nil
		})
}

// The queue listing omits the encryption key and every timer, so all five
// detail-backed fields share one fetch.
type mqlOciQueueQueueInternal struct {
	cacheCompartmentID string
	cacheRegion        string

	detail ociLazy[*queue.Queue]
}

func (o *mqlOciQueueQueue) id() (string, error) {
	return "oci.queue.queue/" + o.Id.Data, nil
}

func (o *mqlOciQueueQueue) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciQueueQueue) getDetail() (*queue.Queue, error) {
	return o.detail.get(func() (*queue.Queue, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		client, err := conn.QueueAdminClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		response, err := client.GetQueue(context.Background(), queue.GetQueueRequest{
			QueueId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &response.Queue, nil
	})
}

func (o *mqlOciQueueQueue) encryptionKey() (*mqlOciKmsKey, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	return resolveOciKmsKey(o.MqlRuntime, stringValue(detail.CustomEncryptionKeyId), &o.EncryptionKey)
}

func (o *mqlOciQueueQueue) retentionInSeconds() (int64, error) {
	detail, err := o.getDetail()
	if err != nil {
		return 0, err
	}
	return intValue(detail.RetentionInSeconds), nil
}

func (o *mqlOciQueueQueue) visibilityInSeconds() (int64, error) {
	detail, err := o.getDetail()
	if err != nil {
		return 0, err
	}
	return intValue(detail.VisibilityInSeconds), nil
}

func (o *mqlOciQueueQueue) timeoutInSeconds() (int64, error) {
	detail, err := o.getDetail()
	if err != nil {
		return 0, err
	}
	return intValue(detail.TimeoutInSeconds), nil
}

func (o *mqlOciQueueQueue) deadLetterQueueDeliveryCount() (int64, error) {
	detail, err := o.getDetail()
	if err != nil {
		return 0, err
	}
	return intValue(detail.DeadLetterQueueDeliveryCount), nil
}

// ----- Managed Kafka -----

func (o *mqlOciKafka) id() (string, error) {
	return "oci.kafka", nil
}

func (o *mqlOciKafka) clusters() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.KafkaClusterClient(region)
			if err != nil {
				return nil, err
			}

			clusters, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]managedkafka.KafkaClusterSummary, *string, error) {
				response, err := client.ListKafkaClusters(ctx, managedkafka.ListKafkaClustersRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.KafkaClusterCollection.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(clusters))
			for i := range clusters {
				c := clusters[i]

				var brokerShape map[string]any
				if c.BrokerShape != nil {
					brokerShape, err = convert.JsonToDict(c.BrokerShape)
					if err != nil {
						return nil, err
					}
				}

				mqlCluster, err := CreateResource(o.MqlRuntime, "oci.kafka.cluster", map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(c.Id),
					"name":                 llx.StringDataPtr(c.DisplayName),
					"kafkaVersion":         llx.StringDataPtr(c.KafkaVersion),
					"clusterType":          llx.StringData(string(c.ClusterType)),
					"coordinationType":     llx.StringData(string(c.CoordinationType)),
					"brokerShape":          llx.DictData(brokerShape),
					"clusterConfigId":      llx.StringDataPtr(c.ClusterConfigId),
					"clusterConfigVersion": llx.IntDataDefault(c.ClusterConfigVersion, 0),
					"state":                llx.StringData(string(c.LifecycleState)),
					"stateDetails":         llx.StringDataPtr(c.LifecycleDetails),
					"created":              sdkTimeData(c.TimeCreated),
					"updated":              sdkTimeData(c.TimeUpdated),
					"freeformTags":         llx.MapData(strMapToAny(c.FreeformTags), types.String),
					"definedTags":          llx.MapData(definedTagsToAny(c.DefinedTags), types.Any),
					"systemTags":           llx.MapData(definedTagsToAny(c.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlClusterTyped := mqlCluster.(*mqlOciKafkaCluster)
				mqlClusterTyped.cacheCompartmentID = stringValue(c.CompartmentId)
				mqlClusterTyped.cacheRegion = region
				mqlClusterTyped.cacheSubnetIDs = ociKafkaAccessSubnetIds(c.AccessSubnets)
				res = append(res, mqlClusterTyped)
			}

			return res, nil
		})
}

// ociKafkaAccessSubnetIds flattens the cluster's access-subnet sets into a
// single OCID list. The service groups subnets into sets, but for reachability
// the distinction does not matter: any subnet in any set can reach the cluster.
func ociKafkaAccessSubnetIds(sets []managedkafka.SubnetSet) []string {
	ids := []string{}
	for i := range sets {
		ids = append(ids, sets[i].Subnets...)
	}
	return ids
}

// The bootstrap URLs and the superuser secret are detail-only.
type mqlOciKafkaClusterInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	cacheSubnetIDs     []string

	detail ociLazy[*managedkafka.KafkaCluster]
}

func (o *mqlOciKafkaCluster) id() (string, error) {
	return "oci.kafka.cluster/" + o.Id.Data, nil
}

func (o *mqlOciKafkaCluster) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciKafkaCluster) subnets() ([]any, error) {
	res := make([]any, 0, len(o.cacheSubnetIDs))
	for _, id := range o.cacheSubnetIDs {
		if id == "" {
			continue
		}
		subnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// A subnet we cannot resolve must not take the rest of the list
			// with it, matching resolveOciSecurityGroups.
			continue
		}
		res = append(res, subnet)
	}
	return res, nil
}

func (o *mqlOciKafkaCluster) getDetail() (*managedkafka.KafkaCluster, error) {
	return o.detail.get(func() (*managedkafka.KafkaCluster, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)
		client, err := conn.KafkaClusterClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		response, err := client.GetKafkaCluster(context.Background(), managedkafka.GetKafkaClusterRequest{
			KafkaClusterId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &response.KafkaCluster, nil
	})
}

func (o *mqlOciKafkaCluster) bootstrapUrls() ([]any, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	if len(detail.KafkaBootstrapUrls) == 0 {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(detail.KafkaBootstrapUrls)
}

func (o *mqlOciKafkaCluster) superuserSecret() (*mqlOciVaultSecret, error) {
	detail, err := o.getDetail()
	if err != nil {
		return nil, err
	}
	if stringValue(detail.SecretId) == "" {
		o.SuperuserSecret.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(o.MqlRuntime, "oci.vault.secret", map[string]*llx.RawData{
		"id": llx.StringData(stringValue(detail.SecretId)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciVaultSecret), nil
}
