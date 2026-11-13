// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
)

// describe returns the secret's DescribeSecret response, fetching it once.
// A secret created through init seeds it from the response init already read.
func (a *mqlAwsSecretsmanagerSecret) describe() (*secretsmanager.DescribeSecretOutput, error) {
	a.describeLock.Lock()
	defer a.describeLock.Unlock()
	if a.describeResp != nil {
		return a.describeResp, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := a.Arn.Data
	resp, err := conn.Secretsmanager(a.cacheRegion).DescribeSecret(context.Background(), &secretsmanager.DescribeSecretInput{
		SecretId: &arn,
	})
	if err != nil {
		return nil, err
	}
	a.describeResp = resp
	return resp, nil
}

func (a *mqlAwsSecretsmanagerSecret) crossAccountReplicas() ([]any, error) {
	resp, err := a.describe()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(resp.CrossAccountReplicas))
	for _, r := range resp.CrossAccountReplicas {
		arn := convert.ToValue(r.ReplicaSecretARN)
		if arn == "" {
			continue
		}
		mqlReplica, err := CreateResource(a.MqlRuntime, "aws.secretsmanager.secret.crossAccountReplica",
			map[string]*llx.RawData{
				"__id":          llx.StringData(a.Arn.Data + "/crossAccountReplica/" + arn),
				"arn":           llx.StringData(arn),
				"status":        llx.StringData(string(r.ReplicationStatus)),
				"statusMessage": llx.StringDataPtr(r.StatusMessage),
			})
		if err != nil {
			return nil, err
		}
		mqlReplica.(*mqlAwsSecretsmanagerSecretCrossAccountReplica).cacheRoleArn = r.ReplicationRoleARN
		res = append(res, mqlReplica)
	}
	return res, nil
}

func (a *mqlAwsSecretsmanagerSecret) crossAccountPrimaryArn() (string, error) {
	resp, err := a.describe()
	if err != nil {
		return "", err
	}
	if resp.CrossAccountPrimary == nil || resp.CrossAccountPrimary.PrimarySecretARN == nil {
		a.CrossAccountPrimaryArn.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *resp.CrossAccountPrimary.PrimarySecretARN, nil
}

func (a *mqlAwsSecretsmanagerSecret) crossAccountPrimaryStatus() (string, error) {
	resp, err := a.describe()
	if err != nil {
		return "", err
	}
	if resp.CrossAccountPrimary == nil || resp.CrossAccountPrimary.ReplicationStatus == "" {
		a.CrossAccountPrimaryStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(resp.CrossAccountPrimary.ReplicationStatus), nil
}

func (a *mqlAwsSecretsmanagerSecret) crossAccountPrimaryStatusMessage() (string, error) {
	resp, err := a.describe()
	if err != nil {
		return "", err
	}
	if resp.CrossAccountPrimary == nil || resp.CrossAccountPrimary.StatusMessage == nil {
		a.CrossAccountPrimaryStatusMessage.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *resp.CrossAccountPrimary.StatusMessage, nil
}

type mqlAwsSecretsmanagerSecretCrossAccountReplicaInternal struct {
	cacheRoleArn *string
}

func (a *mqlAwsSecretsmanagerSecretCrossAccountReplica) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsSecretsmanagerSecretCrossAccountReplica) replicationRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.ReplicationRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}
