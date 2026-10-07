// Trimmed from the generated SDK: only the request builders the tests read.
package armkusto

func (client *DatabasesClient) listByClusterCreateRequest(ctx context.Context, resourceGroupName string, clusterName string, _ *DatabasesClientListByClusterOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Kusto/clusters/{clusterName}/databases"
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	return req, err
}

func (client *DatabasesClient) getCreateRequest(ctx context.Context, resourceGroupName string, clusterName string, databaseName string, _ *DatabasesClientGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Kusto/clusters/{clusterName}/databases/{databaseName}"
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	return req, err
}
