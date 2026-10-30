// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package purl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestNewPlatformPurl(t *testing.T) {
	tests := []struct {
		name     string
		platform *inventory.Platform
		want     string
		wantErr  string
	}{
		{
			name: "valid ubuntu platform",
			platform: &inventory.Platform{
				Name:    "ubuntu",
				Version: "22.04",
			},
			want:    "pkg:platform/ubuntu@22.04?distro=ubuntu-22.04",
			wantErr: "",
		},
		{
			name: "valid windows platform",
			platform: &inventory.Platform{
				Name:    "windows",
				Version: "19045",
			},
			want:    "pkg:platform/windows@19045?distro=windows-19045",
			wantErr: "",
		},
		{
			name: "platform with arch",
			platform: &inventory.Platform{
				Name:    "ubuntu",
				Version: "22.04",
				Arch:    "amd64",
			},
			want:    "pkg:platform/ubuntu@22.04?arch=amd64&distro=ubuntu-22.04",
			wantErr: "",
		},
		{
			name: "platform with x86_64 arch",
			platform: &inventory.Platform{
				Name:    "ubuntu",
				Version: "22.04",
				Arch:    "x86_64",
			},
			want:    "pkg:platform/ubuntu@22.04?arch=x86_64&distro=ubuntu-22.04",
			wantErr: "",
		},
		{
			name: "platform with arm64 arch",
			platform: &inventory.Platform{
				Name:    "ubuntu",
				Version: "22.04",
				Arch:    "arm64",
			},
			want:    "pkg:platform/ubuntu@22.04?arch=arm64&distro=ubuntu-22.04",
			wantErr: "",
		},
		{
			name: "macOS with apple silicon",
			platform: &inventory.Platform{
				Name:    "macos",
				Version: "14.5.1",
				Arch:    "arm64",
			},
			want:    "pkg:platform/macos@14.5.1?arch=arm64&distro=macos-14.5.1",
			wantErr: "",
		},
		{
			name: "windows with x86 arch",
			platform: &inventory.Platform{
				Name:    "windows",
				Version: "19045",
				Arch:    "x86",
			},
			want:    "pkg:platform/windows@19045?arch=x86&distro=windows-19045",
			wantErr: "",
		},
		{
			name: "vsphere platform",
			platform: &inventory.Platform{
				Name:    "vsphere",
				Version: "7.0.3",
			},
			want:    "pkg:platform/vsphere@7.0.3?distro=vsphere-7.0.3",
			wantErr: "",
		},
		{
			name: "esxi platform",
			platform: &inventory.Platform{
				Name:    "esxi",
				Version: "7.0.3",
				Arch:    "x86_64",
			},
			want:    "pkg:platform/esxi@7.0.3?arch=x86_64&distro=esxi-7.0.3",
			wantErr: "",
		},
		{
			name: "kubernetes deployment",
			platform: &inventory.Platform{
				Name:    "k8s-deployment",
				Version: "1.27",
			},
			want:    "pkg:platform/k8s-deployment@1.27?distro=k8s-deployment-1.27",
			wantErr: "",
		},
		{
			name: "aws platform",
			platform: &inventory.Platform{
				Name: "aws",
			},
			want:    "pkg:platform/aws?distro=aws",
			wantErr: "",
		},
		{
			name: "gcp platform",
			platform: &inventory.Platform{
				Name: "gcp",
			},
			want:    "pkg:platform/gcp?distro=gcp",
			wantErr: "",
		},
		{
			name: "azure platform",
			platform: &inventory.Platform{
				Name: "azure",
			},
			want:    "pkg:platform/azure?distro=azure",
			wantErr: "",
		},
		{
			name: "platform with build instead of version",
			platform: &inventory.Platform{
				Name:  "centplatform",
				Build: "8.5",
			},
			want:    "pkg:platform/centplatform?build=8.5&distro=centplatform-8.5",
			wantErr: "",
		},
		{
			name: "rolling release without a version",
			platform: &inventory.Platform{
				Name:  "arch",
				Arch:  "x86_64",
				Build: "rolling",
			},
			want:    "pkg:platform/arch?arch=x86_64&build=rolling&distro=arch-rolling",
			wantErr: "",
		},
		{
			name:     "nil platform",
			platform: nil,
			want:     "",
			wantErr:  "platform is required",
		},
		{
			name: "debian bookworm platform",
			platform: &inventory.Platform{
				Name:    "debian",
				Version: "12",
				Title:   "Debian GNU/Linux 12 (bookworm)",
			},
			want:    "pkg:platform/debian@12?distro=debian-12",
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPlatformPurl(tt.platform)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
