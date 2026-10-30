// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/aws/connection"
)

const (
	testSecretArn = "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod-db-AbCdEf"
	testEc2Arn    = "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0"
)

// The scanned asset is the resource the caller asked for, so its ARN is adopted.
func TestGetAssetIdentifier_MatchingPlatform(t *testing.T) {
	runtime := testAwsIdentifierRuntime(connection.PlatformSecretsmanagerSecret, "prod-db", []string{testSecretArn})
	assert.Equal(t, testSecretArn, getAssetIdentifier(runtime, connection.PlatformSecretsmanagerSecret))
}

// The case this guard exists for. cnspec evaluates every policy filter against
// every asset, so a filter like `aws.secretsmanager.secret.lastChangedDate !=
// null` reaches this init while an EC2 instance is being scanned. Adopting the
// instance's ARN made the provider call DescribeSecret with it -- 1,494 such
// calls in one measured scan, none of which could ever resolve.
func TestGetAssetIdentifier_ForeignPlatformIsNotAdopted(t *testing.T) {
	runtime := testAwsIdentifierRuntime(connection.PlatformEc2Instance, "web-01", []string{testEc2Arn})
	assert.Empty(t, getAssetIdentifier(runtime, connection.PlatformSecretsmanagerSecret),
		"an EC2 instance's ARN must never be adopted as a secret's ARN")
}

// An account asset is not any individual resource, so nothing is adopted.
func TestGetAssetIdentifier_AccountAssetIsNotAResource(t *testing.T) {
	runtime := testAwsIdentifierRuntime(connection.PlatformAccount, "AWS Account 123456789012",
		[]string{"//platformid.api.mondoo.app/runtime/aws/accounts/123456789012"})
	assert.Empty(t, getAssetIdentifier(runtime, connection.PlatformSecretsmanagerSecret))
}

// An asset with no platform cannot be shown to be the right kind of thing, so
// it fails closed rather than adopting on the strength of the ARN alone.
func TestGetAssetIdentifier_MissingPlatformFailsClosed(t *testing.T) {
	runtime := testAwsIdentifierRuntime("", "prod-db", []string{testSecretArn})
	assert.Empty(t, getAssetIdentifier(runtime, connection.PlatformSecretsmanagerSecret))
}

// Guards the one failure this design cannot catch by itself: a platform string
// spelled wrong matches no asset, which disables asset-scoped resolution for
// that resource silently -- no error, just a resource that never resolves.
// Every platform handed to getAssetIdentifier has to exist in the registry.
func TestEveryPlatformPassedToGetAssetIdentifierIsRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, p := range connection.Platforms {
		registered[p.Name] = true
	}

	// connection.PlatformFooBar -> the literal it is declared as
	constToValue := map[string]string{}
	platformsSrc, err := os.ReadFile(filepath.Join("..", "connection", "platforms.go"))
	require.NoError(t, err)
	for _, m := range regexp.MustCompile(`(Platform[A-Za-z0-9]+)\s*=\s*"([a-z0-9-]+)"`).
		FindAllStringSubmatch(string(platformsSrc), -1) {
		constToValue[m[1]] = m[2]
	}
	require.NotEmpty(t, constToValue, "no platform constants found")

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	callRe := regexp.MustCompile(`getAssetIdentifier\(runtime,\s*connection\.(Platform[A-Za-z0-9]+)\)`)

	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		require.NoError(t, err)
		for _, m := range callRe.FindAllStringSubmatch(string(src), -1) {
			seen++
			value, ok := constToValue[m[1]]
			require.True(t, ok, "%s: connection.%s is not a declared platform constant", f, m[1])
			assert.True(t, registered[value],
				"%s: platform %q (connection.%s) is not in connection.Platforms", f, value, m[1])
		}
	}
	assert.NotZero(t, seen, "found no getAssetIdentifier call sites to check")
}

// Every platform discovery can stamp on an asset must be in the registry, so
// the constants stay a complete picture of what a scanned asset can be. A
// platform returned here but missing from the registry would be unmatchable by
// any init.
func TestDiscoveryPlatformNamesAreRegistered(t *testing.T) {
	registered := map[string]bool{}
	for _, p := range connection.Platforms {
		registered[p.Name] = true
	}

	src, err := os.ReadFile("discovery_conversion.go")
	require.NoError(t, err)

	matches := regexp.MustCompile(`return "(aws-[a-z0-9-]+)"`).FindAllStringSubmatch(string(src), -1)
	require.NotEmpty(t, matches, "no platform names found in getPlatformName")
	for _, m := range matches {
		assert.True(t, registered[m[1]],
			"getPlatformName returns %q, which is not in connection.Platforms", m[1])
	}
}

// getAssetName is gated the same way, for the same reason: a bare
// aws.iam.user query on an EBS volume asset used to call GetUser with the
// volume id as the user name.
func TestGetAssetName_ForeignPlatformIsNotAdopted(t *testing.T) {
	runtime := testAwsIdentifierRuntime(connection.PlatformEbsVolume, "vol-0eacce2fc0d0612e3", nil)
	assert.Empty(t, getAssetName(runtime, connection.PlatformIamUser),
		"a volume's name must never be adopted as an IAM user name")
}

func TestGetAssetName_MatchingPlatform(t *testing.T) {
	runtime := testAwsIdentifierRuntime(connection.PlatformIamUser, "alice", nil)
	assert.Equal(t, "alice", getAssetName(runtime, connection.PlatformIamUser))
}
