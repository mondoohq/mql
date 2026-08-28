# ADR-036: Jenkins Provider Implementation

**Status:** Proposed
**Date:** 2026-08-08
**Author:** (Engineering Team)

---

## Context

Jenkins is a self-hosted automation server that runs CI/CD pipelines, and its security posture (who can administer it, which plugins are current, how agents authenticate to the controller, whether CSRF protection is on) is a common target for compliance audits. Unlike the cloud SaaS providers already in the fleet (DigitalOcean, Shodan), a Jenkins instance has no fixed API host: the connection must target a customer-supplied base URL, the same way an SSH or host-based connection targets an address rather than a bearer token alone. Authentication is HTTP Basic auth using a Jenkins username paired with a per-user API token, verified against the Jenkins Remote Access API (`/api/json` and its sub-trees) via the Go SDK `github.com/bndr/gojenkins`.

Jenkins exposes a rich, code-oriented data model (jobs, builds, plugins, nodes, credentials) entirely through this REST/JSON tree API, with no pagination: every list endpoint returns its full result and callers narrow the payload with a `tree=` query parameter instead of paging through it. This makes Jenkins a good test of the "single deep fetch" implementation pattern, distinct from the page-based list APIs used by DigitalOcean and most cloud providers.

Credentials stored in Jenkins (via the Credentials plugin) are modeled for inventory purposes only: this provider reads credential identifiers, scope, type, and description so audits can assess exposure and scoping, but it deliberately never requests or stores secret material (passwords, private keys, tokens). The Credentials plugin's REST API does not return secret values to unprivileged read calls, and this provider does not attempt to elevate that boundary.

**Client selection.** Following the client-selection priority ladder (vendor SDK, then Terraform-provider-aligned generated client, then hand-written/community client), Jenkins lands on the third rung. There is no official Jenkins Go SDK published by the Jenkins project. There is also no canonical OpenAPI/Swagger spec to generate a client from: the Jenkins project has run multiple GSoC efforts toward standardizing REST API documentation as OpenAPI, but as of this writing has not shipped one, and the community `swaggy-jenkins` description is unofficial and partial, not a vendor artifact. `github.com/bndr/gojenkins` is the de-facto community Go client (widely used, including by the community Terraform provider below) and is the client this ADR selects, with this justification recorded explicitly per the ladder's rung-3 requirement rather than left implicit.

**Terraform provider alignment.** Rung 2's harmonization step still applies for schema modeling even though the client itself falls to rung 3: this ADR aligns resource and field naming with the community `taiidani/terraform-provider-jenkins` (github.com/taiidani/terraform-provider-jenkins), which is itself built on `gojenkins` and is the most actively referenced Jenkins Terraform provider on the registry. Its `jenkins_job`, `jenkins_folder`, and `jenkins_credential` resources map directly to this ADR's `jenkins.job` and `jenkins.credential`, and its credential resource likewise exposes only identifying fields (id, scope, type) and never round-trips secret material through state in a readable form, matching this provider's read-only, metadata-only stance.

---

## Provider Metadata

| Attribute | Value |
|-----------|-------|
| **Provider Name** | `jenkins` |
| **Provider ID** | `go.mondoo.com/mql/providers/jenkins` |
| **Initial Version** | `13.0.0` |
| **Connection Type** | `jenkins` |
| **Go SDK** | `github.com/bndr/gojenkins` (community client; rung-3 fallback, no vendor SDK or canonical OpenAPI spec exists, see Context) |
| **API Type** | REST/JSON (Jenkins Remote Access API, `/api/json`) |
| **Auth** | Base URL + username + API token, HTTP Basic auth (`JENKINS_URL` / `JENKINS_USER` / `JENKINS_TOKEN` env vars, or `--url` / `--user` / `--token` flags) |

---

## Directory Structure

```
providers/jenkins/
├── main.go
├── go.mod
├── go.sum
├── gen/
│   └── main.go
├── config/
│   └── config.go
├── connection/
│   └── connection.go
├── provider/
│   └── provider.go
└── resources/
    ├── jenkins.lr
    ├── jenkins.lr.go              # generated
    ├── jenkins.lr.versions        # generated
    ├── discovery.go
    ├── jenkins.go                 # root resource
    ├── jenkins_security.go        # instance security configuration
    ├── jenkins_plugin.go
    ├── jenkins_job.go
    ├── jenkins_node.go
    └── jenkins_credential.go
```

---

## Resource Schema (`jenkins.lr`)

```lr
option provider = "go.mondoo.com/mql/providers/jenkins"
option go_package = "go.mondoo.com/mql/v13/providers/jenkins/resources"

// Jenkins automation server
//
// The Jenkins controller reachable at the configured base URL. Exposes
// instance-level metadata (version, operating mode) alongside the
// security configuration, installed plugins, jobs, agents, and stored
// credential metadata that make up a Jenkins security audit.
jenkins {
  // Base URL the connection targets, for example "https://jenkins.example.com"
  url string
  // Jenkins core version reported by the controller
  version string
  // Operating mode, either NORMAL (builds run anywhere) or EXCLUSIVE (builds only run on labeled agents)
  mode string
  // Whether the controller is in the process of shutting down for maintenance
  quietingDown bool
  // Instance security configuration
  security() jenkins.security
  // Installed plugins
  plugins() []jenkins.plugin
  // Configured jobs, including folders and pipelines
  jobs() []jenkins.job
  // Build agents and the built-in controller node
  nodes() []jenkins.node
  // Stored credential metadata, never the secret material itself
  credentials() []jenkins.credential
}

// Jenkins instance security configuration
//
// The controller-wide security posture: which authorization strategy and
// security realm are active, whether CSRF protection (the crumb issuer)
// is enabled, and how agents are permitted to connect to the controller.
// This is a singleton, queried as `jenkins.security` directly.
jenkins.security @defaults("authorizationStrategy securityRealm") {
  // Class name of the active authorization strategy, for example "hudson.security.GlobalMatrixAuthorizationStrategy"
  authorizationStrategy string
  // Class name of the active security realm, for example "hudson.security.HudsonPrivateSecurityRealm"
  securityRealm string
  // Whether access control (authentication and authorization) is enabled at all
  securityEnabled bool
  // Whether CSRF protection (the crumb issuer) is enabled
  csrfProtectionEnabled bool
  // Whether the instance allows unauthenticated administration
  //
  // True when securityEnabled is false, or the authorization strategy is
  // the legacy unsecured strategy that grants every user, including
  // anonymous ones, full administrative rights ("anyone can do anything").
  allowsAnonymousAdmin bool
  // Whether agent-to-controller access control (the Agent Access Control subsystem) is enabled
  agentToControllerAccessControlEnabled bool
  // TCP protocols accepted from inbound agents, for example "JNLP4-connect"
  agentProtocols []string
  // TCP port accepting inbound agent connections, -1 when disabled and 0 when a random port is used
  slaveAgentPort int
  // Class name of the configured markup formatter for job descriptions
  markupFormatter string
}

// Plugin installed on the Jenkins controller
//
// One entry per plugin returned by the plugin manager. The `shortName`
// field is the plugin's install identifier, for example "git" or
// "credentials-binding". `hasUpdate` reflects whether the Jenkins update
// center has a newer release available for this plugin.
jenkins.plugin @defaults("shortName version") {
  // Plugin install identifier, for example "git"
  shortName string
  // Human-readable plugin name
  longName string
  // Installed plugin version
  version string
  // Whether the plugin is enabled
  enabled bool
  // Whether the plugin is active (enabled and all its dependencies are active)
  active bool
  // Whether a newer version is available from the configured update center
  hasUpdate bool
  // Plugin homepage URL
  url string
  // Minimum Jenkins core version this plugin requires
  requiredCoreVersion string
}

// Jenkins job
//
// A configured job, pipeline, or folder. The `fullName` field is the
// job's path-qualified name, for example "team-a/deploy-service", and is
// stable across folder reorganizations of the same job. The `class`
// field distinguishes job types, such as "hudson.model.FreeStyleProject",
// "org.jenkinsci.plugins.workflow.job.WorkflowJob" (pipeline), or
// "com.cloudbees.hudson.plugins.folder.Folder".
jenkins.job @defaults("fullName class") {
  // Job name
  name string
  // Path-qualified job name, for example "team-a/deploy-service"
  fullName string
  // Job URL
  url string
  // Job class, identifying the job or folder type
  class string
  // Whether the job can currently be built
  buildable bool
  // Whether the job is disabled
  disabled bool
  // Last build number, 0 when the job has never built
  lastBuildNumber int
  // Last successful build number, 0 when the job has never succeeded
  lastSuccessfulBuildNumber int
  // Last failed build number, 0 when the job has never failed
  lastFailedBuildNumber int
  // Job description
  description string
  // Node the last build ran on
  node() jenkins.node
}

// Jenkins node
//
// A build agent, or the built-in controller node itself (`isController`
// distinguishes the two). Agents are keyed by their `name` as reported
// by the controller, for example "linux-agent-01"; the built-in node's
// name is the empty string internally and is surfaced here as
// "Built-In Node".
jenkins.node @defaults("name offline") {
  // Node name, "Built-In Node" for the controller itself
  name string
  // Node description
  description string
  // Whether this is the built-in controller node rather than an agent
  isController bool
  // Whether the node is currently offline
  offline bool
  // Whether the node was taken offline manually rather than due to a failure
  temporarilyOffline bool
  // Reason given for the node being offline
  offlineCauseReason string
  // Class name of the agent launch method, for example "hudson.slaves.JNLPLauncher"
  launchMethod string
  // Number of concurrent build executors configured on this node
  numExecutors int
  // Labels assigned to this node
  labels []string
}

// Jenkins stored credential
//
// Metadata for a credential stored in the Jenkins Credentials plugin,
// scoped to the system domain. Only identifying metadata is exposed:
// `id`, `typeName`, `scope`, `description`, and the owning `domain`.
// The credential's secret material (passwords, private keys, tokens) is
// never fetched or exposed by this resource.
jenkins.credential @defaults("id typeName scope") {
  // Credential ID, as referenced by jobs and pipelines
  id string
  // Credential implementation class, for example "com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl"
  typeName string
  // Credential scope, either GLOBAL (available to jobs) or SYSTEM (available only to the controller itself)
  scope string
  // Credential description
  description string
  // Credentials domain the credential belongs to, "_" for the global domain
  domain string
}
```

---

## Authentication

Base URL plus username and API token, HTTP Basic auth, built on `gojenkins` (the rung-3 community client selected in Context). This is closer to a host-target connection (SSH, a device address) than to the single-token pattern in `providers/shodan/connection/connection.go`: Jenkins has no fixed API endpoint, so the base URL is a required connection input, not just an auth secret.

```go
type JenkinsConnection struct {
    plugin.Connection
    Conf  *inventory.Config
    asset *inventory.Asset

    baseUrl string
    client  *gojenkins.Jenkins
}

func NewJenkinsConnection(id uint32, asset *inventory.Asset, conf *inventory.Config) (*JenkinsConnection, error) {
    conn := &JenkinsConnection{
        Connection: plugin.NewConnection(id, asset),
        Conf:       conf,
        asset:      asset,
    }

    baseUrl := conf.Host
    if baseUrl == "" {
        baseUrl = os.Getenv("JENKINS_URL")
    }
    if conf.Options != nil && conf.Options["url"] != "" {
        baseUrl = conf.Options["url"]
    }
    if baseUrl == "" {
        return nil, errors.New("a Jenkins base URL is required, pass --url 'https://jenkins.example.com' or set JENKINS_URL")
    }
    baseUrl = strings.TrimRight(baseUrl, "/")

    user := os.Getenv("JENKINS_USER")
    token := os.Getenv("JENKINS_TOKEN")
    if len(conf.Credentials) > 0 {
        for i := range conf.Credentials {
            cred := conf.Credentials[i]
            switch cred.Type {
            case vault.CredentialType_password:
                if cred.User != "" {
                    user = cred.User
                }
                token = string(cred.Secret)
            default:
                log.Warn().Str("credential-type", cred.Type.String()).Msg("unsupported credential type for Jenkins provider")
            }
        }
    }
    if user == "" || token == "" {
        return nil, errors.New("a Jenkins username and API token are required, pass --user/--token or set JENKINS_USER/JENKINS_TOKEN")
    }

    client, err := gojenkins.CreateJenkins(nil, baseUrl, user, token).Init(context.Background())
    if err != nil {
        return nil, errors.New("failed to connect to Jenkins at " + baseUrl + ": " + err.Error())
    }

    conn.baseUrl = baseUrl
    conn.client = client

    return conn, nil
}

func (c *JenkinsConnection) Name() string {
    return "jenkins"
}

func (c *JenkinsConnection) Asset() *inventory.Asset {
    return c.asset
}

func (c *JenkinsConnection) Client() *gojenkins.Jenkins {
    return c.client
}

func (c *JenkinsConnection) BaseUrl() string {
    return c.baseUrl
}

func (c *JenkinsConnection) Identifier() string {
    return "//platformid.api.mondoo.app/runtime/jenkins/url/" + strings.ToLower(c.baseUrl)
}
```

---

## Implementation Patterns

### Single Deep Fetch (no pagination)

Jenkins list endpoints return their full result set in one response; there is no cursor or page token to iterate. Use the `tree=` query parameter to scope the payload to only the fields a query needs, rather than paginating:

```go
func (j *mqlJenkins) populate() error {
    conn := j.MqlRuntime.Connection.(*connection.JenkinsConnection)

    var root struct {
        Mode         string `json:"mode"`
        Version      string `json:"-"` // reported via X-Jenkins response header, not the tree
        QuietingDown bool   `json:"quietingDown"`
        Jobs         []struct {
            Name  string `json:"name"`
            Class string `json:"_class"`
        } `json:"jobs"`
    }

    err := conn.Client().Requester.GetJSON(context.Background(),
        "/api/json?tree=mode,quietingDown,jobs[name,_class]", &root, nil)
    if err != nil {
        return err
    }
    // ... map root into the mqlJenkins fields
    return nil
}
```

Plugin update availability is similarly a single call, not a per-plugin fetch: `/pluginManager/api/json?tree=plugins[shortName,longName,version,enabled,active,hasUpdate,requiredCoreVersion,url]` returns every installed plugin's `hasUpdate` flag already computed against the configured update center in one response.

### Instance Security (single resource, several config surfaces)

`jenkins.security` is a singleton assembled from a handful of root-tree fields plus the crumb issuer and agent protocol endpoints, all fetched once and cached on the `Internal` struct:

```go
type mqlJenkinsSecurityInternal struct {
    fetched bool
    lock    sync.Mutex
}

func (s *mqlJenkinsSecurity) authorizationStrategy() (string, error) {
    return s.fetchAll()
}

func (s *mqlJenkinsSecurity) fetchAll() (string, error) {
    conn := s.MqlRuntime.Connection.(*connection.JenkinsConnection)
    var resp struct {
        AuthorizationStrategy struct {
            Class string `json:"_class"`
        } `json:"authorizationStrategy"`
        SecurityRealm struct {
            Class string `json:"_class"`
        } `json:"securityRealm"`
        UseSecurity  bool   `json:"useSecurity"`
        UseCrumbs    bool   `json:"useCrumbs"`
        SlaveAgentPort int  `json:"slaveAgentPort"`
    }
    err := conn.Client().Requester.GetJSON(context.Background(),
        "/api/json?tree=useSecurity,useCrumbs,slaveAgentPort,authorizationStrategy[_class],securityRealm[_class]",
        &resp, nil)
    if err != nil {
        return "", err
    }

    unsecuredStrategy := resp.AuthorizationStrategy.Class == "hudson.security.AuthorizationStrategy$Unsecured"
    allowsAnonymousAdmin := !resp.UseSecurity || unsecuredStrategy

    s.SecurityEnabled = plugin.TValue[bool]{Data: resp.UseSecurity, State: plugin.StateIsSet}
    s.CsrfProtectionEnabled = plugin.TValue[bool]{Data: resp.UseCrumbs, State: plugin.StateIsSet}
    s.AllowsAnonymousAdmin = plugin.TValue[bool]{Data: allowsAnonymousAdmin, State: plugin.StateIsSet}
    s.AuthorizationStrategy = plugin.TValue[string]{Data: resp.AuthorizationStrategy.Class, State: plugin.StateIsSet}
    s.SecurityRealm = plugin.TValue[string]{Data: resp.SecurityRealm.Class, State: plugin.StateIsSet}
    s.SlaveAgentPort = plugin.TValue[int64]{Data: int64(resp.SlaveAgentPort), State: plugin.StateIsSet}

    return resp.AuthorizationStrategy.Class, nil
}
```

### Typed Resource Reference (job to node)

A job's last build records which node ran it. Cache the raw node name on the job's `Internal` struct at creation time, and resolve it lazily to a typed `jenkins.node` rather than exposing a raw `builtOn string` field:

```go
type mqlJenkinsJobInternal struct {
    cacheBuiltOn string
}

func (j *mqlJenkinsJob) node() (*mqlJenkinsNode, error) {
    if j.cacheBuiltOn == "" {
        j.Node.State = plugin.StateIsNull | plugin.StateIsSet
        return nil, nil
    }
    r, err := NewResource(j.MqlRuntime, "jenkins.node",
        map[string]*llx.RawData{"name": llx.StringData(j.cacheBuiltOn)})
    if err != nil {
        return nil, err
    }
    return r.(*mqlJenkinsNode), nil
}
```

### Credentials Metadata Without Secrets

The Credentials plugin's REST endpoint never returns secret material to a metadata read, so no redaction logic is required in the provider itself; the fetch simply never asks for it:

```go
func (conn *connection.JenkinsConnection) fetchCredentials() ([]jenkinsCredentialData, error) {
    var resp struct {
        Credentials []struct {
            Id          string `json:"id"`
            TypeName    string `json:"typeName"`
            Description string `json:"description"`
        } `json:"credentials"`
    }
    // tree= is scoped to id/typeName/description; no "secret" or "password" field is requested
    err := conn.Client().Requester.GetJSON(context.Background(),
        "/credentials/store/system/domain/_/api/json?tree=credentials[id,typeName,description]",
        &resp, nil)
    if err != nil {
        return nil, err
    }
    out := make([]jenkinsCredentialData, 0, len(resp.Credentials))
    for _, c := range resp.Credentials {
        out = append(out, jenkinsCredentialData{Id: c.Id, TypeName: c.TypeName, Description: c.Description, Domain: "_", Scope: "GLOBAL"})
    }
    return out, nil
}
```

### Controller Node Detection

The built-in controller node has an empty internal name; detect it explicitly rather than relying on ordering:

```go
func isControllerNode(nodeName string) bool {
    return nodeName == "" || nodeName == "master" || nodeName == "(built-in)"
}
```

---

## Security Policies (MVP)

Ship as `mondoo-jenkins-security.mql.yaml`:

**Instance Security:**
- CSRF protection (crumb issuer) must be enabled: `jenkins.security.csrfProtectionEnabled == true`
- The instance must not allow anonymous administration: `jenkins.security.allowsAnonymousAdmin == false`
- The security realm must not be disabled: `jenkins.security.securityEnabled == true && jenkins.security.securityRealm != empty`
- Agent-to-controller access control must be enabled: `jenkins.security.agentToControllerAccessControlEnabled == true`

**Plugin Security:**
- No installed plugin should have an available update: `jenkins.plugins.all(hasUpdate == false)`
- Every enabled plugin should be active (no broken dependency chains): `jenkins.plugins.where(enabled == true).all(active == true)`

**Credential Security:**
- Credentials should be scoped as narrowly as their use requires: flag `jenkins.credentials.where(scope == "GLOBAL")` for review rather than blanket denial, since some global credentials are intentional
- Every credential should carry a description identifying its owner or purpose: `jenkins.credentials.all(description != empty)`

**Agent Security:**
- Builds must not be schedulable on the controller node: `jenkins.nodes.where(isController == true).all(numExecutors == 0)`
- No agent should be offline for an unexplained reason: `jenkins.nodes.where(offline == true && temporarilyOffline == false).all(offlineCauseReason != empty)`

---

## Registration

Add to these files (alphabetically):

1. **`providers/defaults.go`** — Provider entry with connection type and flags
2. **`README.md`** — Row in provider table
3. **`DEVELOPMENT.md`** — `providers/jenkins` in `go.work` list
4. **`Makefile`** — `jenkins` in `PROVIDERS` list

---

## Build & Test

```bash
# Generate resource code
make providers/mqlr
./mqlr generate providers/jenkins/resources/jenkins.lr \
  --dist providers/jenkins/resources

# Build and install
make providers/build/jenkins && make providers/install/jenkins

# Test
export JENKINS_URL="https://jenkins.example.com"
export JENKINS_USER="svc-mondoo"
export JENKINS_TOKEN="11a2b3c4d5e6f7890abcdef1234567890"
mql shell jenkins
> jenkins.version
> jenkins.security { authorizationStrategy securityRealm csrfProtectionEnabled allowsAnonymousAdmin }
> jenkins.plugins.where(hasUpdate == true) { shortName version }
> jenkins.jobs { fullName class buildable disabled }
> jenkins.nodes { name isController offline numExecutors }
> jenkins.credentials { id typeName scope description }
```

---

## Implementation Order

1. Scaffold via `go run apps/provider-scaffold/provider-scaffold.go --path providers/jenkins --provider-id jenkins --provider-name "Jenkins"` then `cd providers/jenkins && go mod tidy`
2. Root + connection (base URL, Basic auth, validates against `/api/json`)
3. `jenkins.security` (crumb issuer, authorization strategy, security realm; highest audit value, no dependencies on other resources)
4. `jenkins.plugin` (single-fetch list, `hasUpdate` from the plugin manager tree)
5. `jenkins.node` (agents and controller, `isController` detection)
6. `jenkins.job` (jobs list, typed `node()` reference back to step 5)
7. `jenkins.credential` (metadata-only fetch from the Credentials plugin endpoint)
8. Security policies (`mondoo-jenkins-security.mql.yaml`)
9. Discovery
10. Registration (`defaults.go`, `README.md`, `DEVELOPMENT.md`, `Makefile`)

---

## References

- [Jenkins Remote Access API](https://www.jenkins.io/doc/book/using/remote-access-api/)
- [Authenticating scripted clients (API tokens)](https://www.jenkins.io/doc/book/system-administration/authenticating-scripted-clients/)
- [gojenkins Go SDK](https://github.com/bndr/gojenkins) — community client, rung-3 selection (no vendor SDK, no canonical OpenAPI spec; see Context)
- [taiidani/terraform-provider-jenkins](https://github.com/taiidani/terraform-provider-jenkins) — community Terraform provider this ADR's resource/field modeling aligns with (also built on `gojenkins`)
- [Swagger / OpenAPI standardization for Jenkins REST API (GSoC project idea)](https://www.jenkins.io/projects/gsoc/2025/project-ideas/swagger-openapi-for-jenkins-rest-api/) — confirms no official spec exists yet
- [Jenkins Credentials plugin](https://plugins.jenkins.io/credentials/)
- [Jenkins Security](https://www.jenkins.io/doc/book/security/)
- Reference providers: `providers/shodan/` (token auth shape, adapted here to base URL + Basic auth), `providers/digitalocean/` (single-token REST provider scaffolding)
