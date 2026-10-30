// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/api/cloudresourcemanager/v3"
	"google.golang.org/api/iam/v1"
)

// TestIamServiceUsesFullCloudPlatformScope pins the OAuth scope every
// iam.googleapis.com call in this package is built with.
//
// Most Google APIs accept https://www.googleapis.com/auth/cloud-platform.read-only,
// and this provider reaches for it by default because it is a read-only tool.
// The IAM API does not: its reference lists cloud-platform as the ONLY accepted
// scope for the workload-identity and workforce pool methods, and a read-only
// token is rejected with
//
//	Error 403: Request had insufficient authentication scopes.
//	reason = ACCESS_TOKEN_SCOPE_INSUFFICIENT
//
// The rejection happens in the token check, before any IAM permission is
// consulted, so granting roles does not fix it and the failure looks like a
// permission gap. Verified against a live project: the same list call returns
// the pools under cloud-platform and 403s under cloud-platform.read-only.
//
// gcp.project.iamService.workloadIdentityPools (and its providers) and
// gcp.organization.workforcePools (and its providers) all failed this way on
// every scan authenticated with a service-account key -- the entire federated
// trust surface, which is exactly the data a "who can assume an identity in
// this project from outside it" audit reads.
// fullScopeConstant matches a package-qualified reference to the SDK's
// CloudPlatformScope constant.
//
// The trailing boundary is what makes this a token match rather than a
// substring one: `CloudPlatformReadOnlyScope` never matched, but a constant
// named `CloudPlatformScopeReadOnly` would have satisfied a plain
// strings.Contains and been accepted as the full scope. No such constant
// exists in google.golang.org/api today; this keeps the guard honest if one
// ever appears.
//
// The package qualifier is deliberately left open. Every generated package
// spells this constant identically and gives it the same value, and the
// provider legitimately reaches for whichever one is already imported --
// iam.CloudPlatformScope, compute.CloudPlatformScope,
// sqladmin.CloudPlatformScope. Requiring `iam.` specifically would reject
// call sites that are already correct. TestCloudPlatformScopeConstants pins
// the values, which is the property the match actually stands in for.
var fullScopeConstant = regexp.MustCompile(`\.CloudPlatformScope\b`)

// TestCloudPlatformScopeConstants pins the two constant values the guard above
// reasons about.
//
// That guard matches on a NAME, which is only meaningful while the name still
// carries the value it does today. If the SDK renamed these, or gave
// CloudPlatformScope the read-only URL, the guard would keep passing while
// checking nothing -- the vacuous-pass failure mode. Assert the values.
func TestCloudPlatformScopeConstants(t *testing.T) {
	assert.Equal(t, "https://www.googleapis.com/auth/cloud-platform", iam.CloudPlatformScope,
		"the guard treats CloudPlatformScope as the full cloud-platform scope")
	assert.Equal(t, "https://www.googleapis.com/auth/cloud-platform", cloudresourcemanager.CloudPlatformScope,
		"every generated package spells the full scope the same way, which is why the guard does not pin a package")
	assert.NotEqual(t, iam.CloudPlatformScope, cloudresourcemanager.CloudPlatformReadOnlyScope,
		"the read-only scope must stay distinguishable from the one the IAM API accepts")
	assert.False(t, fullScopeConstant.MatchString("cloudresourcemanager.CloudPlatformReadOnlyScope"),
		"the read-only constant must not satisfy the guard")
	assert.False(t, fullScopeConstant.MatchString("iam.CloudPlatformScopeReadOnly"),
		"a suffixed constant must not satisfy the guard by substring")
	assert.True(t, fullScopeConstant.MatchString("iam.CloudPlatformScope"))
	assert.True(t, fullScopeConstant.MatchString("sqladmin.CloudPlatformScope, iam.CloudPlatformScope"))
}

func TestIamServiceUsesFullCloudPlatformScope(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	fset := token.NewFileSet()
	checked := 0

	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".lr.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}

		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			body := render(fset, fn.Body)
			if !strings.Contains(body, "iam.NewService(") {
				return true
			}
			checked++
			for line := range strings.SplitSeq(body, "\n") {
				if !strings.Contains(line, "conn.Client(") {
					continue
				}
				if fullScopeConstant.MatchString(line) {
					continue
				}
				t.Errorf("%s: %s builds an iam.googleapis.com service from %s\n"+
					"the IAM API accepts only cloud-platform; a read-only token is rejected with "+
					"ACCESS_TOKEN_SCOPE_INSUFFICIENT before permissions are checked",
					fset.Position(fn.Pos()), fn.Name.Name, strings.TrimSpace(line))
			}
			return true
		})
	}

	if checked == 0 {
		t.Fatal("no iam.NewService call sites found; this guard has stopped guarding anything")
	}
}

func render(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, n); err != nil {
		return ""
	}
	return b.String()
}
