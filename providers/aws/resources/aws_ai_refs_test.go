// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

func TestS3BucketNameFromUri(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{"bucket and key", "s3://my-training-data/prefix/file.jsonl", "my-training-data"},
		{"bucket only", "s3://my-training-data", "my-training-data"},
		{"bucket with trailing slash", "s3://my-training-data/", "my-training-data"},
		{"empty", "", ""},
		// A location without the scheme must not be read as a bucket name: training
		// and output configs also carry file-system paths, and treating one as a
		// bucket would resolve a reference to a bucket that does not exist.
		{"no scheme", "my-training-data/prefix", ""},
		{"absolute path", "/mnt/efs/training", ""},
		{"other scheme", "https://example.com/bucket", ""},
		{"scheme only", "s3://", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s3BucketNameFromUri(tt.uri); got != tt.want {
				t.Errorf("s3BucketNameFromUri(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}

func TestEcrRepositoryArnFromImageUri(t *testing.T) {
	tests := []struct {
		name  string
		image string
		want  string
	}{
		{
			name:  "tagged image",
			image: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-inference:latest",
			want:  "arn:aws:ecr:us-east-1:123456789012:repository/my-inference",
		},
		{
			name:  "digest image",
			image: "123456789012.dkr.ecr.eu-west-2.amazonaws.com/my-inference@sha256:abc123",
			want:  "arn:aws:ecr:eu-west-2:123456789012:repository/my-inference",
		},
		{
			name:  "no tag or digest",
			image: "123456789012.dkr.ecr.us-west-2.amazonaws.com/team/model-server",
			want:  "arn:aws:ecr:us-west-2:123456789012:repository/team/model-server",
		},
		{
			// SageMaker's own inference images live in AWS-owned accounts and are
			// still ECR repositories, so they resolve the same way.
			name:  "aws-owned inference image",
			image: "763104351884.dkr.ecr.us-east-1.amazonaws.com/pytorch-inference:2.1-gpu-py310",
			want:  "arn:aws:ecr:us-east-1:763104351884:repository/pytorch-inference",
		},
		{"docker hub", "nginx:latest", ""},
		{"public ecr", "public.ecr.aws/lambda/python:3.12", ""},
		{"empty", "", ""},
		{"host only", "123456789012.dkr.ecr.us-east-1.amazonaws.com", ""},
		{"host with empty repo", "123456789012.dkr.ecr.us-east-1.amazonaws.com/", ""},
		{"malformed host", "dkr.ecr/my-repo", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ecrRepositoryArnFromImageUri(tt.image); got != tt.want {
				t.Errorf("ecrRepositoryArnFromImageUri(%q) = %q, want %q", tt.image, got, tt.want)
			}
		})
	}
}
