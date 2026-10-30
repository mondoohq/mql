// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package auth

import (
	"strings"

	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/google/go-containerregistry/pkg/authn"
	"go.mondoo.com/mql/providers/os/connection/container/acr"
)

const (
	acrIndicator = ".azurecr.io"
	ecrIndicator = ".ecr."
)

func getKeychains(name string) []authn.Keychain {
	kcs := []authn.Keychain{
		authn.DefaultKeychain,
	}
	if strings.Contains(name, ecrIndicator) {
		kcs = append(kcs, authn.NewKeychainFromHelper(ecr.NewECRHelper()))
	}
	if strings.Contains(name, acrIndicator) {
		kcs = append(kcs, authn.NewKeychainFromHelper(acr.NewAcrAuthHelper()))
	}
	return kcs
}

// ConstructKeychain creates a keychain for the given registry name
// It will add the default docker keychain and additional keychains for ECR and ACR, if those are determined to be used
func ConstructKeychain(name string) authn.Keychain {
	return authn.NewMultiKeychain(getKeychains(name)...)
}
