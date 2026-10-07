// Trimmed from the generated SDK: only the request builders the tests read.
package armkusto

func (client *ClustersClient) listCalloutPoliciesCreateRequest(ctx context.Context, resourceGroupName string, clusterName string, _ *ClustersClientListCalloutPoliciesOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Kusto/clusters/{clusterName}/listCalloutPolicies"
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.internal.Endpoint(), urlPath))
	return req, err
}
