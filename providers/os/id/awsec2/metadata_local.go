// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package awsec2

import (
	"context"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"go.mondoo.com/mql/providers/os/id/metadata"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func NewLocal(cfg aws.Config) *LocalEc2InstanceMetadata {
	return &LocalEc2InstanceMetadata{config: cfg}
}

// Ec2InstanceMetadata returns the instance id
// TODO: we may want to implement instance verification as documented in
// https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html
type LocalEc2InstanceMetadata struct {
	config aws.Config
}

func (m *LocalEc2InstanceMetadata) RawMetadata() (any, error) {
	return metadata.Crawl(m, "")
}

func (m *LocalEc2InstanceMetadata) GetMetadataValue(path string) (string, error) {
	client := imds.NewFromConfig(m.config)
	return m.getMetadataValue(client, path)
}

func (m *LocalEc2InstanceMetadata) Identify() (Identity, error) {
	metadata := imds.NewFromConfig(m.config)
	ec2svc := ec2.NewFromConfig(m.config)
	ctx := context.Background()
	doc, err := metadata.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		return Identity{}, err
	}
	name := ""
	// try and fetch this from the metadata, if the tag metadata service is enabled.
	nameTag, err := m.getMetadataValue(metadata, "tags/instance/Name")
	if err == nil {
		name = nameTag
	} else {
		// if not enabled, try and use the aws api as a fallback. this only works if the aws config is setup
		// correctly on the ec2 instance.
		filters := []ec2types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{doc.InstanceID},
			},
		}
		tags, err := ec2svc.DescribeTags(ctx, &ec2.DescribeTagsInput{Filters: filters})
		if err == nil {
			for _, t := range tags.Tags {
				if t.Key != nil && *t.Key == "Name" && t.Value != nil {
					name = *t.Value
				}
			}
		}
	}
	if name == "" {
		name = doc.InstanceID
	}
	return Identity{
		InstanceName: name,
		InstanceID:   MondooInstanceID(doc.AccountID, doc.Region, doc.InstanceID),
		AccountID:    "//platformid.api.mondoo.app/runtime/aws/accounts/" + doc.AccountID,
	}, nil
}

// gets the metadata at the relative specified path. The base path is /latest/meta-data
// so the path param needs to only specify which metadata path is requested
func (m *LocalEc2InstanceMetadata) getMetadataValue(client *imds.Client, path string) (string, error) {
	output, err := client.GetMetadata(context.TODO(), &imds.GetMetadataInput{
		Path: path,
	})
	if err != nil {
		return "", err
	}
	defer output.Content.Close()
	bytes, err := io.ReadAll(output.Content)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
