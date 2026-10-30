// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// validate answers one question about the provider permission manifests (aws,
// gcp and azure *.permissions.json): can they be used to build a role or
// policy that lets the scan run.
//
// The manifests are derived from provider source by permissions.go, which maps
// SDK method names onto IAM permission strings heuristically. That derivation
// is wrong whenever an SDK name and the IAM name disagree (a missing parent
// resource, a different plural, a renamed service prefix), and nothing in the
// build notices: the manifest is valid JSON and the provider runs fine. The
// customer notices, when the role they built from the manifest is refused or
// does not grant what the scan needs. This tool is the check the build lacks.
// It asks each cloud's own list of permissions (aws.go, gcp.go and azure.go
// say what each one is and why) about every manifest entry and reports the
// ones that cannot be used (✗) and the ones that can but with a caveat (!).
//
//	go run ./providers-sdk/v1/util/permissions/validate            # all three providers
//	go run ./providers-sdk/v1/util/permissions/validate providers/aws
//
// AWS's list is public. GCP needs a Google identity (GCP_ACCESS_TOKEN, or a
// gcloud login) plus -gcp-project and -gcp-organization; Azure needs an Azure
// identity (AZURE_ACCESS_TOKEN, or an az login).
//
// Exit status is 0 when every entry can be used, 1 when any entry cannot, and
// 2 when a cloud's list could not be fetched or parsed.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	gcpProject := fs.String("gcp-project", os.Getenv("GCP_PROJECT"), "GCP project id to query testable permissions on")
	gcpOrganization := fs.String("gcp-organization", os.Getenv("GCP_ORGANIZATION"), "GCP organization id to query testable permissions on")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "usage: validate [flags] [provider-dir ...]\n\n"+
			"Checks each provider's resources/<name>.permissions.json against the cloud's\n"+
			"IAM catalog. With no provider directories, checks providers/aws, providers/gcp\n"+
			"and providers/azure relative to the current directory (the repository root).\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	dirs := fs.Args()
	if len(dirs) == 0 {
		dirs = []string{"providers/aws", "providers/gcp", "providers/azure"}
	}
	fetch := newFetcher(os.Stdout)
	annotate := os.Getenv("GITHUB_ACTIONS") != ""
	failed := false
	for _, dir := range dirs {
		name := filepath.Base(dir)
		path := filepath.Join(dir, "resources", name+".permissions.json")
		fmt.Printf("==> %s\n", path)

		m, err := readManifest(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		cat, err := loadCatalog(m, fetch, *gcpProject, *gcpOrganization)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		r := checkManifest(m, cat)
		report(r, path, len(cat.exact), annotate)
		if !r.ok() {
			failed = true
		}
	}
	if failed {
		return 1
	}
	return 0
}

// report prints one manifest's result. Under GitHub Actions each problem is
// also emitted as a workflow annotation on the manifest file.
func report(r result, path string, catalogSize int, annotate bool) {
	fmt.Printf("  %d permissions checked against %d the cloud knows: %d usable, %d not usable\n",
		r.Total, catalogSize, r.Valid, r.Total-r.Valid)
	for _, p := range r.Notes {
		fmt.Printf("  ! %s: %s\n", p.Permission, p.Message)
	}
	for _, p := range r.Problems {
		fmt.Printf("  ✗ %s: %s\n", p.Permission, p.Message)
		if annotate {
			fmt.Printf("::error file=%s,title=unusable %s permission::%s: %s\n", path, r.Provider, p.Permission, p.Message)
		}
	}
	if r.ok() {
		fmt.Println("  ✓ ok")
	}
}
