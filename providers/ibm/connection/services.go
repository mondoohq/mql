// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"

	"github.com/IBM/cloud-databases-go-sdk/clouddatabasesv5"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-cos-sdk-go-config/v2/resourceconfigurationv1"
	"github.com/IBM/ibm-cos-sdk-go/aws"
	"github.com/IBM/ibm-cos-sdk-go/aws/credentials/ibmiam"
	"github.com/IBM/ibm-cos-sdk-go/aws/session"
	"github.com/IBM/ibm-cos-sdk-go/service/s3"
	"github.com/IBM/keyprotect-go-client/ibmkeyprotectapiv2"
	"github.com/IBM/platform-services-go-sdk/accountmanagementv4"
	"github.com/IBM/platform-services-go-sdk/atrackerv2"
	"github.com/IBM/platform-services-go-sdk/usermanagementv1"
)

// iamTokenURL is where the Cloud Object Storage S3 client exchanges the API
// key for a token; it keeps its own token rather than sharing the
// authenticator's.
const iamTokenURL = "https://iam.cloud.ibm.com/identity/token"

// CosListEndpoint answers bucket listings for every location of an instance.
const CosListEndpoint = "https://s3.us.cloud-object-storage.appdomain.cloud"

// CosEndpoint is the public S3 endpoint of a bucket location, such as
// us-south, us, or ams03. A bucket only answers on its own location's
// endpoint; another one redirects.
func CosEndpoint(location string) string {
	return fmt.Sprintf("https://s3.%s.cloud-object-storage.appdomain.cloud", location)
}

// CosClient returns the S3 client for an endpoint, created once.
func (c *IbmConnection) CosClient(endpoint string) (*s3.S3, error) {
	v, err := c.Memo("cos/"+endpoint, func() (any, error) {
		conf := aws.NewConfig().
			WithEndpoint(endpoint).
			WithCredentials(ibmiam.NewStaticCredentials(aws.NewConfig(), iamTokenURL, c.auth.ApiKey, "")).
			WithS3ForcePathStyle(true).
			WithHTTPClient(newHTTPClient()).
			WithMaxRetries(maxRetries)
		sess, err := session.NewSession()
		if err != nil {
			return nil, err
		}
		return s3.New(sess, conf), nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*s3.S3), nil
}

// CosConfig returns the global Cloud Object Storage bucket configuration
// client.
func (c *IbmConnection) CosConfig() (*resourceconfigurationv1.ResourceConfigurationV1, error) {
	v, err := c.Memo("cosConfig", func() (any, error) {
		svc, err := resourceconfigurationv1.NewResourceConfigurationV1(&resourceconfigurationv1.ResourceConfigurationV1Options{Authenticator: c.auth})
		if err != nil {
			return nil, err
		}
		configure(svc.Service)
		return svc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*resourceconfigurationv1.ResourceConfigurationV1), nil
}

// KeyProtect returns the key management client for an instance's API
// endpoint, such as https://us-south.kms.cloud.ibm.com. Key Protect and Hyper
// Protect Crypto Services share the API; each call names its instance.
func (c *IbmConnection) KeyProtect(url string) (*ibmkeyprotectapiv2.IbmKeyProtectApiV2, error) {
	v, err := c.Memo("kms/"+url, func() (any, error) {
		svc, err := ibmkeyprotectapiv2.NewIbmKeyProtectApiV2(&ibmkeyprotectapiv2.IbmKeyProtectApiV2Options{Authenticator: c.auth, URL: url})
		if err != nil {
			return nil, err
		}
		configure(svc.Service)
		return svc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*ibmkeyprotectapiv2.IbmKeyProtectApiV2), nil
}

// DatabasesEndpoint is the IBM Cloud Databases API of a region. The SDK's
// GetServiceURLForRegion supports no region, so it is built here.
func DatabasesEndpoint(region string) string {
	return "https://api." + region + ".databases.cloud.ibm.com/v5/ibm"
}

// Databases returns the IBM Cloud Databases client for a region. A deployment
// only answers in its own region.
func (c *IbmConnection) Databases(region string) (*clouddatabasesv5.CloudDatabasesV5, error) {
	v, err := c.Memo("databases/"+region, func() (any, error) {
		svc, err := clouddatabasesv5.NewCloudDatabasesV5(&clouddatabasesv5.CloudDatabasesV5Options{Authenticator: c.auth, URL: DatabasesEndpoint(region)})
		if err != nil {
			return nil, err
		}
		configure(svc.Service)
		return svc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*clouddatabasesv5.CloudDatabasesV5), nil
}

// Atracker returns the Activity Tracker Event Routing client. Routing
// settings, targets, and routes are account-wide and every regional endpoint
// answers for them, so the default endpoint serves.
func (c *IbmConnection) Atracker() (*atrackerv2.AtrackerV2, error) {
	v, err := c.Memo("atracker", func() (any, error) {
		svc, err := atrackerv2.NewAtrackerV2(&atrackerv2.AtrackerV2Options{Authenticator: c.auth})
		if err != nil {
			return nil, err
		}
		configure(svc.Service)
		return svc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*atrackerv2.AtrackerV2), nil
}

// UserManagement returns the User Management client, which lists the users of
// the account.
func (c *IbmConnection) UserManagement() (*usermanagementv1.UserManagementV1, error) {
	v, err := c.Memo("userManagement", func() (any, error) {
		svc, err := usermanagementv1.NewUserManagementV1(&usermanagementv1.UserManagementV1Options{Authenticator: c.auth})
		if err != nil {
			return nil, err
		}
		configure(svc.Service)
		return svc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*usermanagementv1.UserManagementV1), nil
}

// AccountManagement returns the Account Management client, which reads the
// account itself, such as its owner.
func (c *IbmConnection) AccountManagement() (*accountmanagementv4.AccountManagementV4, error) {
	v, err := c.Memo("accountManagement", func() (any, error) {
		svc, err := accountmanagementv4.NewAccountManagementV4(&accountmanagementv4.AccountManagementV4Options{Authenticator: c.auth})
		if err != nil {
			return nil, err
		}
		configure(svc.Service)
		return svc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*accountmanagementv4.AccountManagementV4), nil
}

// KubernetesServiceURL is the global IBM Cloud Kubernetes Service API. It
// answers for the clusters of every region, Kubernetes and OpenShift alike.
const KubernetesServiceURL = "https://containers.cloud.ibm.com/global"

// KubernetesService returns a client for the IBM Cloud Kubernetes Service
// API. IBM's Go SDK for it drops a cluster's KMS configuration and the list's
// service endpoints, so resources read the API's JSON through this client,
// which shares the connection's authentication, retries, and timeout.
func (c *IbmConnection) KubernetesService() (*core.BaseService, error) {
	v, err := c.Memo("kubernetes", func() (any, error) {
		svc, err := core.NewBaseService(&core.ServiceOptions{Authenticator: c.auth, URL: KubernetesServiceURL})
		if err != nil {
			return nil, err
		}
		configure(svc)
		return svc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*core.BaseService), nil
}
