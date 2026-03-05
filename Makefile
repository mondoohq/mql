NAMESPACE=mondoo

ifndef LATEST_VERSION_TAG
# echo "read LATEST_VERSION_TAG from git"
LATEST_VERSION_TAG=$(shell git describe --abbrev=0 --tags)
endif

ifndef MANIFEST_VERSION
# echo "read MANIFEST_VERSION from git"
MANIFEST_VERSION=$(shell git describe --abbrev=0 --tags)
endif

ifndef VERSION
# echo "read VERSION from git"
VERSION=${LATEST_VERSION_TAG}+$(shell git rev-list --count HEAD)
endif
MAJOR_VERSION=v13

ifndef TARGETOS
	TARGETOS = $(shell go env GOOS)
endif

ifndef TARGETARCH
	TARGETARCH = $(shell go env GOARCH)
endif

BIN_SUFFIX = ""
ifeq ($(TARGETOS),windows)
	BIN_SUFFIX=".exe"
endif

LDFLAGS=-ldflags "-s -w -X go.mondoo.com/mql/${MAJOR_VERSION}.Version=${VERSION}" # -linkmode external -extldflags=-static
LDFLAGSDIST=-tags production -ldflags "-s -w -X go.mondoo.com/mql/${MAJOR_VERSION}.Version=${LATEST_VERSION_TAG} -s -w"

.PHONY: info/ldflags
info/ldflags:
	$(info go run ${LDFLAGS} apps/mql/mql.go)
	@:

#   🧹 CLEAN   #

clean/proto:
	find . -not -path './.*' \( -name '*.ranger.go' -or -name '*.pb.go' -or -name '*.actions.go' -or -name '*-packr.go' -or -name '*.swagger.json' \) -delete

.PHONY: version
version:
	@echo $(VERSION)

#   🔨 TOOLS       #

prep: prep/tools

prep/tools/windows:
	go get -u google.golang.org/protobuf
	go get -u gotest.tools/gotestsum


prep/tools/protolint:
	# protobuf linting
	go install github.com/yoheimuta/protolint/cmd/protolint@latest

prep/tools: prep/tools/protolint prep/tools/mockgen
	# additional helper
	go install gotest.tools/gotestsum@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install github.com/hashicorp/copywrite@latest

prep/tools/mockgen:
	go install go.uber.org/mock/mockgen@latest

#   🌙 MQL/MOTOR   #

mql/generate: clean/proto llx/generate shared/generate sbom/generate reporter/generate providers

mql/generate/core: clean/proto llx/generate shared/generate providers/proto providers/build/mock providers/build/core sbom/generate reporter/generate

define buildProvider
	$(eval $@_HOME = $(1))
	$(eval $@_NAME = $(shell basename ${$@_HOME}))
	$(eval $@_DIST = "${$@_HOME}"/dist)
	$(eval $@_DIST_BIN = "./dist/${$@_NAME}")
	$(eval $@_BIN = "${$@_DIST}"/"${$@_NAME}")
	echo "--> [${$@_NAME}] process resources"
	./lr go ${$@_HOME}/resources/${$@_NAME}.lr --dist ${$@_DIST}
	./lr versions ${$@_HOME}/resources/${$@_NAME}.lr
	echo "--> [${$@_NAME}] generate CLI json"
	cd ${$@_HOME} && go run ./gen/main.go .
	@if [ "$(SKIP_COMPILE)" = "yes" ]; then \
		echo "--> [${$@_NAME}] skipping compile"; \
	else \
		echo "--> [${$@_NAME}] creating ${$@_BIN}"; \
		cd ${$@_HOME} && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o ${$@_DIST_BIN}${BIN_SUFFIX} ./main.go; \
	fi
endef

define buildProviderDist
	$(eval $@_HOME = $(1))
	$(eval $@_NAME = $(shell basename ${$@_HOME}))
	$(eval $@_DIST = "${$@_HOME}"/dist)
	$(eval $@_DIST_BIN = "./dist/${$@_NAME}")
	$(eval $@_BIN = "${$@_DIST}"/"${$@_NAME}")
	echo "--> [${$@_NAME}] process resources"
	./lr go ${$@_HOME}/resources/${$@_NAME}.lr --dist ${$@_DIST}
	./lr versions ${$@_HOME}/resources/${$@_NAME}.lr
	echo "--> [${$@_NAME}] generate CLI json"
	cd ${$@_HOME} && go run ./gen/main.go .
	echo "--> [${$@_NAME}] creating ${$@_BIN}"
	cd ${$@_HOME} && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build ${LDFLAGSDIST} -o ${$@_DIST_BIN}${BIN_SUFFIX} ./main.go
endef

define installProvider
	$(eval $@_HOME = $(1))
	$(eval $@_NAME = $(shell basename ${$@_HOME}))
	$(eval $@_DIST = "${$@_HOME}"/dist)
	$(eval $@_BIN = "${$@_DIST}"/"${$@_NAME}")
	$(eval $@_DST = "$(HOME)/.config/mondoo/providers/${$@_NAME}")
	echo "--> install ${$@_NAME}"
	install -d "${$@_DST}"
	install -m 755 ./${$@_DIST}/${$@_NAME} ${$@_DST}/
	install -m 644 ./${$@_DIST}/${$@_NAME}.json ${$@_DST}/
	install -m 644 ./${$@_DIST}/${$@_NAME}.resources.json ${$@_DST}/
endef

define bundleProvider
	$(eval $@_HOME = $(1))
	$(eval $@_NAME = $(shell basename ${$@_HOME}))
	$(eval $@_DIST = "${$@_HOME}"/dist)
	$(eval $@_DST = "${$@_DIST}/${$@_NAME}.tar.xz")
	echo "--> bundle ${$@_NAME} to ${$@_DST} (this may take a while)"
	tar -cf ${$@_DST} --no-same-owner \
		--use-compress-program='xz -9v' \
		-C ${$@_DIST} \
		${$@_NAME} ${$@_NAME}.json ${$@_NAME}.resources.json
	ls -lha ${$@_DST}
endef

define testProvider
	$(eval $@_HOME = $(1))
	$(eval $@_NAME = $(shell basename ${$@_HOME}))
	$(eval $@_PKGS = $(shell go list ./${$@_HOME}/...))
	echo "--> test ${$@_NAME} in ${$@_HOME}"
	gotestsum --junitfile ./report_${$@_NAME}.xml --format pkgname -- -cover ${$@_PKGS}
endef

define testGoModProvider
	$(eval $@_HOME = $(1))
	$(eval $@_NAME = $(shell basename ${$@_HOME}))
	$(eval $@_PKGS = $(shell bash -c "cd ${$@_HOME} && go list ./..."))
	echo "--> test ${$@_NAME} in ${$@_HOME}"
	cd ${$@_HOME} && gotestsum --junitfile ../../report_${$@_NAME}.xml --format pkgname -- -cover ${$@_PKGS}
endef

.PHONY: providers
providers: providers/proto providers/config providers/build

.PHONY: providers/proto
providers/proto:
	go generate .
	go generate ./providers-sdk/v1/vault
	go generate ./providers-sdk/v1/resources
	go generate ./providers-sdk/v1/inventory
	go generate ./providers-sdk/v1/plugin
	go generate ./providers-sdk/v1/recording

.PHONY: providers/config
providers/config:
	go run ./providers-sdk/v1/util/configure -f providers.yaml -o providers/builtin_dev.go

.PHONY: providers/defaults
providers/defaults:
	go run ./providers-sdk/v1/util/defaults/defaults.go -o providers/defaults.go

.PHONY: providers/lr
providers/lr:
	go build -o lr ./providers-sdk/v1/mqlr/main.go

providers/lr/install: providers/lr
	cp ./lr ${GOPATH}/bin

.PHONY: providers/mqlr
providers/mqlr:
	go build -o mqlr ./providers-sdk/v1/mqlr/main.go

providers/mqlr/install: providers/mqlr
	cp ./mqlr ${GOPATH}/bin

.PHONY: providers/build
# Note we need \ to escape the target line into multiple lines
providers/build: \
	providers/build/mock \
	providers/build/core \
	providers/build/network \
	providers/build/os \
	providers/build/ipmi \
	providers/build/ipinfo \
	providers/build/oci \
	providers/build/slack \
	providers/build/github \
	providers/build/gitlab \
	providers/build/terraform \
	providers/build/vsphere \
	providers/build/opcua \
	providers/build/okta \
	providers/build/google-workspace \
	providers/build/arista \
	providers/build/equinix \
	providers/build/vcd \
	providers/build/gcp \
	providers/build/k8s \
	providers/build/azure \
	providers/build/ms365 \
	providers/build/aws \
	providers/build/atlassian \
	providers/build/cloudformation \
	providers/build/shodan \
	providers/build/ansible \
	providers/build/snowflake \
	providers/build/mondoo \
	providers/build/cloudflare \
	providers/build/nmap \
	providers/build/tailscale \
	providers/build/depsdev

.PHONY: providers/install
# Note we need \ to escape the target line into multiple lines
providers/install: \
	providers/install/network \
	providers/install/os \
	providers/install/ipmi \
	providers/install/ipinfo \
	providers/install/oci \
	providers/install/slack \
	providers/install/github \
	providers/install/gitlab \
	providers/install/terraform \
	providers/install/vsphere \
	providers/install/opcua \
	providers/install/okta \
	providers/install/google-workspace \
	providers/install/arista \
	providers/install/equinix \
	providers/install/vcd \
	providers/install/gcp \
	providers/install/k8s \
	providers/install/azure \
	providers/install/ms365 \
	providers/install/atlassian \
	providers/install/aws \
	providers/install/cloudformation \
	providers/install/shodan \
	providers/install/ansible \
	providers/install/snowflake \
	providers/install/mondoo \
	providers/install/cloudflare \
	providers/install/nmap \
	providers/install/tailscale \
	providers/install/depsdev

providers/build/mock: providers/lr
	./lr go providers-sdk/v1/testutils/mockprovider/resources/mockprovider.lr

providers/build/core: providers/lr
	@$(call buildProvider, providers/core)

providers/build/network: providers/lr
	@$(call buildProvider, providers/network)
providers/install/network:
	@$(call installProvider, providers/network)

providers/build/os: providers/lr
	@$(call buildProvider, providers/os)
providers/install/os:
	@$(call installProvider, providers/os)

providers/build/ipmi: providers/lr
	@$(call buildProvider, providers/ipmi)
providers/install/ipmi:
	@$(call installProvider, providers/ipmi)

providers/build/oci: providers/lr
	@$(call buildProvider, providers/oci)
providers/install/oci:
	@$(call installProvider, providers/oci)

providers/build/slack: providers/lr
	@$(call buildProvider, providers/slack)
providers/install/slack:
	@$(call installProvider, providers/slack)

providers/build/github: providers/lr
	@$(call buildProvider, providers/github)
providers/install/github:
	@$(call installProvider, providers/github)

providers/build/cloudflare: providers/lr
	@$(call buildProvider, providers/cloudflare)
providers/install/cloudflare:
	@$(call installProvider, providers/cloudflare)

providers/build/gitlab: providers/lr
	@$(call buildProvider, providers/gitlab)
providers/install/gitlab:
	@$(call installProvider, providers/gitlab)

providers/build/terraform: providers/lr
	@$(call buildProvider, providers/terraform)
providers/install/terraform:
	@$(call installProvider, providers/terraform)

providers/build/vsphere: providers/lr
	@$(call buildProvider, providers/vsphere)
providers/install/vsphere:
	@$(call installProvider, providers/vsphere)

providers/build/opcua: providers/lr
	@$(call buildProvider, providers/opcua)
providers/install/opcua:
	@$(call installProvider, providers/opcua)

providers/build/okta: providers/lr
	@$(call buildProvider, providers/okta)
providers/install/okta:
	@$(call installProvider, providers/okta)

providers/build/google-workspace: providers/lr
	@$(call buildProvider, providers/google-workspace)
providers/install/google-workspace:
	@$(call installProvider, providers/google-workspace)

providers/build/arista: providers/lr
	@$(call buildProvider, providers/arista)
providers/install/arista:
	@$(call installProvider, providers/arista)

providers/build/equinix: providers/lr
	@$(call buildProvider, providers/equinix)
providers/install/equinix:
	@$(call installProvider, providers/equinix)

providers/build/vcd: providers/lr
	@$(call buildProvider, providers/vcd)
providers/install/vcd:
	@$(call installProvider, providers/vcd)

providers/build/k8s: providers/lr
	@$(call buildProvider, providers/k8s)
providers/install/k8s:
	@$(call installProvider, providers/k8s)

providers/build/gcp: providers/lr
	@$(call buildProvider, providers/gcp)
providers/install/gcp:
	@$(call installProvider, providers/gcp)

providers/build/azure: providers/lr
	@$(call buildProvider, providers/azure)
providers/install/azure:
	@$(call installProvider, providers/azure)

providers/build/aws: providers/lr
	@$(call buildProvider, providers/aws)
providers/install/aws:
	@$(call installProvider, providers/aws)

providers/build/atlassian: providers/lr
	@$(call buildProvider, providers/atlassian)
providers/install/atlassian:
	@$(call installProvider, providers/atlassian)

providers/build/ms365: providers/lr
	@$(call buildProvider, providers/ms365)
providers/install/ms365:
	@$(call installProvider, providers/ms365)

providers/build/cloudformation: providers/lr
	@$(call buildProvider, providers/cloudformation)
providers/install/cloudformation:
	@$(call installProvider, providers/cloudformation)

providers/build/shodan: providers/lr
	@$(call buildProvider, providers/shodan)
providers/install/shodan:
	@$(call installProvider, providers/shodan)

providers/build/ansible: providers/lr
	@$(call buildProvider, providers/ansible)
providers/install/ansible:
	@$(call installProvider, providers/ansible)

providers/build/snowflake: providers/lr
	@$(call buildProvider, providers/snowflake)
providers/install/snowflake:
	@$(call installProvider, providers/snowflake)

providers/build/mondoo: providers/lr
	@$(call buildProvider, providers/mondoo)
providers/install/mondoo:
	@$(call installProvider, providers/mondoo)

providers/build/nmap: providers/lr
	@$(call buildProvider, providers/nmap)
providers/install/nmap:
	@$(call installProvider, providers/nmap)

providers/build/tailscale: providers/lr
	@$(call buildProvider, providers/tailscale)
providers/install/tailscale:
	@$(call installProvider, providers/tailscale)

providers/build/depsdev: providers/lr
	@$(call buildProvider, providers/depsdev)
providers/install/depsdev:
	@$(call installProvider, providers/depsdev)

providers/build/ipinfo: providers/lr
	@$(call buildProvider, providers/ipinfo)
providers/install/ipinfo:
	@$(call installProvider, providers/ipinfo)

providers/dist:
	@$(call buildProviderDist, providers/network)
	@$(call buildProviderDist, providers/os)
	@$(call buildProviderDist, providers/ipmi)
	@$(call buildProviderDist, providers/ipinfo)
	@$(call buildProviderDist, providers/oci)
	@$(call buildProviderDist, providers/slack)
	@$(call buildProviderDist, providers/github)
	@$(call buildProviderDist, providers/gitlab)
	@$(call buildProviderDist, providers/terraform)
	@$(call buildProviderDist, providers/vsphere)
	@$(call buildProviderDist, providers/opcua)
	@$(call buildProviderDist, providers/okta)
	@$(call buildProviderDist, providers/google-workspace)
	@$(call buildProviderDist, providers/arista)
	@$(call buildProviderDist, providers/equinix)
	@$(call buildProviderDist, providers/vcd)
	@$(call buildProviderDist, providers/gcp)
	@$(call buildProviderDist, providers/k8s)
	@$(call buildProviderDist, providers/azure)
	@$(call buildProviderDist, providers/ms365)
	@$(call buildProviderDist, providers/aws)
	@$(call buildProviderDist, providers/atlassian)
	@$(call buildProviderDist, providers/cloudformation)
	@$(call buildProviderDist, providers/shodan)
	@$(call buildProviderDist, providers/ansible)
	@$(call buildProviderDist, providers/snowflake)
	@$(call buildProviderDist, providers/mondoo)
	@$(call buildProviderDist, providers/nmap)
	@$(call buildProviderDist, providers/tailscale)

providers/bundle:
	@$(call bundleProvider, providers/network)
	@$(call bundleProvider, providers/os)
	@$(call bundleProvider, providers/ipmi)
	@$(call bundleProvider, providers/ipinfo)
	@$(call bundleProvider, providers/oci)
	@$(call bundleProvider, providers/slack)
	@$(call bundleProvider, providers/github)
	@$(call bundleProvider, providers/gitlab)
	@$(call bundleProvider, providers/terraform)
	@$(call bundleProvider, providers/vsphere)
	@$(call bundleProvider, providers/opcua)
	@$(call bundleProvider, providers/okta)
	@$(call bundleProvider, providers/google-workspace)
	@$(call bundleProvider, providers/arista)
	@$(call bundleProvider, providers/equinix)
	@$(call bundleProvider, providers/vcd)
	@$(call bundleProvider, providers/gcp)
	@$(call bundleProvider, providers/k8s)
	@$(call bundleProvider, providers/azure)
	@$(call bundleProvider, providers/ms365)
	@$(call bundleProvider, providers/aws)
	@$(call bundleProvider, providers/atlassian)
	@$(call bundleProvider, providers/cloudformation)
	@$(call bundleProvider, providers/shodan)
	@$(call bundleProvider, providers/ansible)
	@$(call bundleProvider, providers/snowflake)
	@$(call bundleProvider, providers/mondoo)
	@$(call bundleProvider, providers/nmap)
	@$(call bundleProvider, providers/tailscale)

providers/test:
	@$(call testProvider, providers/core)
	@$(call testProvider, providers/network)
	@$(call testProvider, providers/os)
	@$(call testGoModProvider, providers/ipmi)
	@$(call testGoModProvider, providers/ipinfo)
	@$(call testGoModProvider, providers/oci)
	@$(call testGoModProvider, providers/slack)
	@$(call testGoModProvider, providers/github)
	@$(call testGoModProvider, providers/gitlab)
	@$(call testGoModProvider, providers/terraform)
	@$(call testGoModProvider, providers/vsphere)
	@$(call testGoModProvider, providers/opcua)
	@$(call testGoModProvider, providers/okta)
	@$(call testGoModProvider, providers/google-workspace)
	@$(call testGoModProvider, providers/arista)
	@$(call testGoModProvider, providers/equinix)
	@$(call testGoModProvider, providers/vcd)
	@$(call testGoModProvider, providers/gcp)
	@$(call testGoModProvider, providers/k8s)
	@$(call testGoModProvider, providers/azure)
	@$(call testGoModProvider, providers/ms365)
	@$(call testGoModProvider, providers/aws)
	@$(call testGoModProvider, providers/atlassian)
	@$(call testGoModProvider, providers/cloudformation)
	@$(call testGoModProvider, providers/shodan)
	@$(call testGoModProvider, providers/ansible)
	@$(call testGoModProvider, providers/snowflake)
	@$(call testGoModProvider, providers/mondoo)
	@$(call testGoModProvider, providers/nmap)
	@$(call testGoModProvider, providers/tailscale)

lr/test:
	go test ./providers-sdk/v1/mqlr/...

# TODO: migrate
.PHONY: lr/docs/serve
lr/docs/serve:
	cd resources/docs && yarn
	cd resources/docs && $(shell cd resources/docs && npm bin)/parcel -p 1235 index.html

# TODO: migrate
.PHONY: lr/docs/markdown
lr/docs/markdown: providers/lr
	./lr markdown providers/ansible/resources/ansible.lr \
		--pack-name "Ansible" \
		--description "The Ansible resource pack lets you use MQL to query and assess the security of your Ansible playbooks." \
		--output ../docs/docs/mql/resources/ansible-pack
	./lr markdown providers/arista/resources/arista.lr \
		--pack-name "Arista EOS" \
		--description "The Arista EOS resource pack lets you use MQL to query and assess the security of your Arista EOS network devices." \
		--output ../docs/docs/mql/resources/arista-pack
	./lr markdown providers/atlassian/resources/atlassian.lr \
		--pack-name "Atlassian" \
		--description "The Atlassian resource pack lets you use MQL to query and assess the security of your Atlassian services." \
		--output ../docs/docs/mql/resources/atlassian-pack
	./lr markdown providers/aws/resources/aws.lr \
    	--pack-name "Amazon Web Services (AWS)" \
		--description "The Amazon Web Services (AWS) resource pack lets you use MQL to query and assess the security of your AWS cloud services." \
		--output ../docs/docs/mql/resources/aws-pack
	./lr markdown providers/azure/resources/azure.lr \
		--pack-name "Azure" \
		--description "The Azure resource pack lets you use MQL to query and assess the security of your Azure cloud services." \
		--output ../docs/docs/mql/resources/azure-pack
	./lr markdown providers/cloudflare/resources/cloudflare.lr \
		--pack-name "Cloudflare" \
		--description "The Cloudflare resource pack lets you use MQL to query and assess the security of your Cloudflare configuration." \
		--output ../docs/docs/mql/resources/cloudflare-pack
	./lr markdown providers/cloudformation/resources/cloudformation.lr \
		--pack-name "AWS CloudFormation" \
		--description "The AWS CloudFormation resource pack lets you use MQL to query and assess the security of your AWS CloudFormation." \
		--output ../docs/docs/mql/resources/cloudformation-pack
	./lr markdown providers/core/resources/core.lr \
		--pack-name "Core" \
		--description "The Core pack provides basic MQL resources that let you query and assess the security of assets in your infrastructure." \
		--output ../docs/docs/mql/resources/core-pack
	./lr markdown providers/equinix/resources/equinix.lr \
		--pack-name "Equinix Metal" \
		--description "The Equinix Metal resource pack lets you use MQL to query and assess the security of your Equinix Metal assets." \
		--output ../docs/docs/mql/resources/equinix-pack
	./lr markdown providers/gcp/resources/gcp.lr \
		--pack-name "Google Cloud Platform (GCP)" \
		--description "The Google Cloud Platform (GCP) resource pack lets you use MQL to query and assess the security of your Google cloud services." \
		--output ../docs/docs/mql/resources/gcp-pack
	./lr markdown providers/github/resources/github.lr \
		--pack-name "GitHub" \
		--description "The GitHub resource pack lets you use MQL to query and assess the security of your GitHub organizations and repositories." \
		--output ../docs/docs/mql/resources/github-pack
	./lr markdown providers/gitlab/resources/gitlab.lr \
		--pack-name "GitLab" \
		--description "The GitLab resource pack lets you use MQL to query and assess the security of your GitLab groups and projects." \
		--output ../docs/docs/mql/resources/gitlab-pack
	./lr markdown providers/google-workspace/resources/google-workspace.lr \
		--pack-name "Google Workspace" \
		--description "The Google Workspace resource pack lets you use MQL to query and assess the security of your Google Workspace identities and configuration." \
		--output ../docs/docs/mql/resources/google-workspace-pack
	./lr markdown providers/ipmi/resources/ipmi.lr \
		--pack-name "IPMI" \
		--description "The IPMI resource pack lets you use MQL to query and assess the security of your IPMI devices." \
		--output ../docs/docs/mql/resources/ipmi-pack
	./lr markdown providers/ipinfo/resources/ipinfo.lr \
		--pack-name "IPinfo" \
		--description "The IPinfo resource pack lets you use MQL to query IP address information from ipinfo.io." \
		--output ../docs/docs/mql/resources/ipinfo-pack
	./lr markdown providers/k8s/resources/k8s.lr \
		--pack-name "Kubernetes (K8s)" \
		--description "The Kubernetes resource pack lets you use MQL to query and assess the security of your Kubernetes clusters and workloads." \
		--output ../docs/docs/mql/resources/k8s-pack
	./lr markdown providers/mondoo/resources/mondoo.lr \
		--pack-name "Mondoo Platform" \
		--description "The Mondoo resource pack lets you interact with Mondoo Platform and its assets and resources." \
		--output ../docs/docs/mql/resources/mondoo-pack
	./lr markdown providers/ms365/resources/ms365.lr \
		--pack-name "Microsoft 365 (M365)" \
		--description "The Microsoft 365 (M365) resource pack lets you use MQL to query and assess the security of your Microsoft 365 identities and configuration." \
		--output ../docs/docs/mql/resources/m365-pack
	./lr markdown providers/network/resources/network.lr \
		--pack-name "Network" \
		--description "The Network resource pack lets you use MQL to query and assess the security of domains and network services." \
		--output ../docs/docs/mql/resources/network-pack
	./lr markdown providers/nmap/resources/nmap.lr \
		--pack-name "Nmap" \
		--description "The Nmap resource pack lets you use MQL to query and assess the network devices with Nmap." \
		--output ../docs/docs/mql/resources/nmap-pack
	./lr markdown providers/oci/resources/oci.lr \
		--pack-name "Oracle Cloud Infrastructure (OCI)" \
		--description "The Oracle Cloud Infrastructure (OCI) resource pack lets you use MQL to query and assess the security of your OCI services." \
		--output ../docs/docs/mql/resources/oci-pack
	./lr markdown providers/okta/resources/okta.lr \
		--pack-name "Okta" \
		--description "The Okta resource pack lets you use MQL to query and assess the security of your Okta identities and configuration." \
		--output ../docs/docs/mql/resources/okta-pack
	./lr markdown providers/opcua/resources/opcua.lr \
		--pack-name "OPC UA" \
		--description "The OPC UA resource pack lets you use MQL to query and assess the security of your OPC UA assets." \
		--output ../docs/docs/mql/resources/opcua-pack
	./lr markdown providers/os/resources/os.lr \
		--pack-name "Operating Systems (OS)" \
		--description "The Operating Systems (OS) resource pack lets you use MQL to query and assess the security of your operating system packages and configuration." \
		--output ../docs/docs/mql/resources/os-pack
	./lr markdown providers/shodan/resources/shodan.lr \
		--pack-name "Shodan" \
		--description "The Shodan resource pack lets you use MQL to query and assess IP and DNS information via Shodan service." \
		--output ../docs/docs/mql/resources/shodan-pack
	./lr markdown providers/slack/resources/slack.lr \
		--pack-name "Slack" \
		--description "The Slack resource pack lets you use MQL to query and assess the security of your Slack identities and configuration." \
		--output ../docs/docs/mql/resources/slack-pack
	./lr markdown providers/snowflake/resources/snowflake.lr \
		--pack-name "Snowflake" \
		--description "The Snowflake resource pack lets you use MQL to query and assess the security of your Snowflake identities and configuration." \
		--output ../docs/docs/mql/resources/snowflake-pack
	./lr markdown providers/tailscale/resources/tailscale.lr \
		--pack-name "Tailscale" \
		--description "The Tailscale resource pack lets you use MQL to query devices, users, DNS nameservers, and more information about a Tailscale network." \
		--output ../docs/docs/mql/resources/tailscale-pack
	./lr markdown providers/terraform/resources/terraform.lr \
		--pack-name "Terraform IaC" \
		--description "The Terraform IaC resource pack lets you use MQL to query and assess the security of your Terraform HCL, plan, and state resources." \
		--output ../docs/docs/mql/resources/terraform-pack
	./lr markdown providers/vcd/resources/vcd.lr \
		--pack-name "VMware Cloud Director" \
		--description "The VMware Cloud Director resource pack lets you use MQL to query and assess the security of your VMware Cloud Director configuration." \
		--output ../docs/docs/mql/resources/vcd-pack
	./lr markdown providers/vsphere/resources/vsphere.lr \
		--pack-name "VMware vSphere" \
		--description "The VMware vSphere resource pack lets you use MQL to query and assess the security of your VMware vSphere hosts and services." \
		--output ../docs/docs/mql/resources/vsphere-pack

lr/docs/stats:
	@echo "Please remember to re-run before using this:"
	@echo "  make providers/build"
	@echo ""
	go run providers-sdk/v1/util/docs/summarize.go ${PWD}/providers

llx/generate:
	go generate ./llx

.PHONY: llx
llx: | llx/generate llx/test

llx/test:
	go test -timeout 5s $(shell go list ./llx/... | grep -v '/vendor/')

.PHONY: mqlc
mqlc: | llx mqlc/test

mqlc/test:
	go test -timeout 5s $(shell go list ./mqlc/... | grep -v '/vendor/')

sbom/generate:
	go generate ./sbom

reporter/generate:
	go generate ./cli/reporter

#   🏗 Binary / Build   #

.PHONY: mql/build
mql/build:
	go build ${LDFLAGSDIST} apps/mql/mql.go

.PHONY: mql/build/linux
mql/build/linux:
	GOOS=linux GOARCH=amd64 go build ${LDFLAGSDIST} apps/mql/mql.go

.PHONY: mql/build/windows
mql/build/windows:
	GOOS=windows GOARCH=amd64 go build ${LDFLAGSDIST} apps/mql/mql.go

mql/build/darwin:
	GOOS=darwin go build ${LDFLAGSDIST} apps/mql/mql.go

.PHONY: mql/install
mql/install:
	GOBIN=${GOPATH}/bin go install ${LDFLAGSDIST} apps/mql/mql.go

mql/dist/goreleaser/stable:
	goreleaser release --clean --skip=validate,publish -f .goreleaser.yml --timeout 120m

mql/dist/goreleaser/edge:
	goreleaser release --clean --skip=validate,publish -f .goreleaser.yml --timeout 120m --snapshot

shared/generate:
	go generate ./shared/proto/.
	go generate ./providers-sdk/v1/upstream/
	go generate ./providers-sdk/v1/upstream/health
	go generate ./providers-sdk/v1/upstream/mvd/cvss
	go generate ./providers-sdk/v1/upstream/mvd
	go generate ./providers-sdk/v1/upstream/etl

#   ⛹🏽‍ Testing   #

test/lint: test/lint/golangci-lint/run

test: test/go test/lint

race/go:
	go test -race go.mondoo.com/mql/${MAJOR_VERSION}/internal/workerpool

test/generate: prep/tools/mockgen
	go generate ./providers/...

test/go: mql/generate test/generate test/go/plain

test/go/plain:
	go test -cover $(shell go list ./... | grep -v '/providers/' | grep -v '/test/')

test/go/plain-ci: prep/tools test/generate providers/build
	gotestsum --junitfile report.xml --format pkgname -- -cover $(shell go list ./... | grep -v '/vendor/' | grep -v '/providers/' | grep -v '/test/')

test/integration:
	go test -cover -p 1 $(shell go list ./... | grep '/test/')

test/go-cli/plain-ci: prep/tools test/generate providers/build
	gotestsum --junitfile report.xml --format pkgname -- -cover -p 1 $(shell go list ./... | grep '/test/')

.PHONY: test/lint/staticcheck
test/lint/staticcheck:
	staticcheck $(shell go list ./... | grep -v /providers/slack)

.PHONY: test/lint/govet
test/lint/govet:
	go vet $(shell go list ./... | grep -v /providers/slack)

.PHONY: test/lint/golangci-lint/run
test/lint/golangci-lint/run: prep/tools
	golangci-lint --version
	golangci-lint run

test/lint/extended: prep/tools test/generate
	golangci-lint run --config=.github/.golangci.yaml --timeout=30m

test/lint/proto: prep/tools/protolint
	protolint lint .

license: license/headers/check

license/headers/check:
	copywrite headers --plan

license/headers/apply:
	copywrite headers

#   📈 METRICS       #

metrics/start: metrics/grafana/start metrics/prometheus/start

metrics/prometheus/start:
	APP_NAME=mql VERSION=${VERSION} prometheus --config.file=prometheus.yml

metrics/grafana/start:
	docker run -d --name=grafana \
		-p 3000:3000               \
		grafana/grafana

metrics/grafana/stop:
	docker stop grafana
