# Provider scan performance

Work to remove redundant API calls from cloud provider scans. Same data, same
scores, far fewer requests — which matters most where APIs throttle.

Status: **Azure, AWS, GCP, GitLab, Okta and ms365 all merged to main**, with
Okta and ms365 also backported to the **v13** release branch. **GitHub is in
review**. **vSphere is in draft** (#10049) pending a decision — it is the one
change with no measured user-visible benefit. Each provider has a *What is not
covered* note where a test environment could not exercise everything.

---

## Headline

| provider | before | after | change |
|---|---|---|---|
| **AWS** | 9,558 calls | **1,833** | **−80.8%** |
| **GCP** | 2,651 calls | **1,113** | **−58.0%** |
| **Azure** (per reference query) | 67 ARM calls | **9** | **−87%** |
| **GitLab** | 149 calls | **5** | **−96.6%** |
| **ms365** (worst-path query) | 123s | **24s** | **−80%** |
| **ms365** (registration details) | 58 calls | **10** | **−83%** |
| **Okta** | 7 calls | **3** | **−57%** |
| **GitHub** | 1,291 calls | **1,049** | **−18.7%** |

AWS was measured end to end on a 169-asset scan and GCP on a 71-asset project,
both with server policies. Azure was measured per change on a live subscription,
and ms365 by timing the query that exercised its worst path on a 72-application
tenant. Calls per asset now: **Azure 1.9, AWS 10.8, GCP 15.7** — before the work GCP was
37.

**Correctness was verified, not assumed.** For AWS, all 14,557 per-check score
tuples are byte-identical before and after, and the run produced 34 *fewer*
"provider returned no data" warnings. For GCP, 4 of 6,996 tuples changed and
every one is a baseline *error* that now resolves. GCP determinism was checked
by running the fixed build twice and confirming byte-identical scores.

---

## Four root causes

All four come from shared machinery, so they recur in every provider.

**1. The resource cache is per connection.** Every discovered asset gets its own
runtime. Unless a provider opts in, data belonging to a subscription or account
is re-fetched once per asset beneath it.

**2. `init` runs before the cache is read.** `NewResource` calls the init first
and only then checks the cache — it has to, because the cache key is the
resolved resource's id. So an init that fetches unconditionally pays for a
resource the runtime is already holding, then throws its result away.

**3. Calls that can never succeed.** An init with no arguments adopts the
*scanned asset's* identity without checking what kind of asset it is. Since
policy filters are evaluated against every asset, a Secrets Manager init would
run while an EC2 instance was being scanned, adopt the instance's ARN, and call
`DescribeSecret` with it. The call fails, failures are not cached, so it retries
per referrer. This was the largest single cause in AWS and was invisible in
normal output — it surfaces only in a request trace.

**4. Two fields, one request.** The cache stores resolved values *per field*,
and nothing in it knows that two different fields issue the same HTTP request.
Each field is computed exactly once, correctly, and the API is still asked
twice. This is not a caching failure and no amount of cache sharing fixes it:
the duplication lives below the resource layer, where only the request URL is
visible. GitHub is the worked example — `files` read the repository root and
`findSpecialFiles` read the same directory as `"."`.

---

## Azure

Four changes, all merged.

| PR | change | measured |
|---|---|---|
| #9847 | Stage discovery by subscription so assets share one resource cache | 21 assets resolving `web.apps`: 21 → 1 calls; 44 → 3 ARM calls total |
| #9848 | Resolve asset-scoped resources from the service list instead of a per-resource GET (9 resources) | compute VM 4 → 0 GETs across 5 assets; function app 3 → 0; key vault 1+N → one paged list |
| #9850 | Resolve typed references from the service list before fetching (4 resources) | `securityGroups { interfaces { name } }`: 60 GETs on 30 interfaces → 0; **67 → 9 ARM calls** |
| #9851 | Answer a repeated reference from the resource cache instead of refetching | — |

For context, a customer scan had been showing **42,590 ARM calls against 9,448
distinct URLs**.

Azure turned out to be immune to root cause 3: its inits resolve ids by scanning
an already-fetched list, so a mismatched id finds nothing and costs no call.

**What is not covered.** Of 33 inits that make a per-resource call, 23 consult a
list or the cache first and **10 go straight to the API**. They are latent rather
than bleeding — the measured tenant runs at 1.9 calls per asset with zero 404s,
the healthiest of the three clouds — and the GCP failure mode cannot occur here,
since ARM has no service-enablement concept to get wrong. Some of the ten are also
per-resource by nature: a Key Vault secret's value is in no list. The open
question for azure is only whether the rest should resolve from a list like the
23 that already do.

---

## AWS

| PR | change |
|---|---|
| #9996 | Answer a repeated reference from the resource cache |
| #9998 | Cache-first for security group, VPC and reference lookups |
| #9999 | Only adopt a scanned asset's ARN when the asset *is* that resource |
| #10044 | Resolve IAM users and groups from the account list |

Effect by service on a 169-asset scan:

| service | before | after |
|---|---|---|
| `DescribeSecurityGroups` | 2,862 | 1 |
| Secrets Manager | 1,534 | 40 |
| OpenSearch | 718 | 2 |
| ECR | 1,026 | 30 |
| MSK, transfer, memorydb, cognito, codebuild, appstream | 436–505 each | 1 each |
| IAM | 777 | 282 |

Of the 1,534 Secrets Manager calls, only **39 asked for an actual secret**. The
rest carried the ARNs of EC2 instances, S3 buckets, KMS keys and log groups.

#10044 closed the last measured repetition: `initAwsIamUser` looked users up by
name while its cache check keyed on ARN, so the check could never fire and one
scan spent **59 `GetUser` calls on 4 distinct users** — now **0**, resolved from
the account list that is fetched once anyway. Safe despite `ListUsers` omitting
`Tags` and `PermissionsBoundary`, because both are already lazy computed fields.

#9999 fixes this by gating on the asset's *platform* — the exact discriminator,
one registry entry per resource type — rather than by parsing identifiers. The
platform argument is **required**, so the compiler forced all 61 call sites to
declare one; only 3 were actively wrong, but the other 47 were one policy filter
away from joining them.

---

## GCP

**2,651 → 1,113 calls (−58.0%)** on a 71-asset project, across three merged PRs.

| change | measured |
|---|---|
| Gate six inits behind the existing service-enablement check | failing `Get`s **1,050 → 0** |
| Cache-first check in `initGcpProject` | project refetch **452 → 3** |
| Cloud Run `locations/-` wildcard instead of a 43-region fan-out | `ListServices` **43 → 1** |
| Pass `regionUrl` into the subnetwork init | empty-region `Get`s **3 → 0** |

The 1,050 failing calls were five gRPC `Get` methods at exactly 210 each, against
Vertex AI and Memcache APIs that were not enabled on the project. GCP already had
a `serviceGate` for this, used by 29 files — but it is embedded in a service
resource's struct, and init functions have no receiver to hold it, so those six
inits skipped the check and went straight to a per-resource `Get`.

The wildcard was verified against the live API, not assumed: `ListServices`
accepts `locations/-`, `ListJobs` rejects it, so the jobs lister still fans out.

The fourth item was a **pre-existing bug the others exposed**: `getSubnetworkByUrl`
computed a region URL and never passed it into the args, so the init ran with an
empty region and fell through to `GET .../regions//subnetworks/{name}` — note the
empty path segment — which GCP rejects. The same shape explains one of the
improvements: a baseline failure reading `The resource id projects/ is invalid`,
an empty *project* id. One defect, two spellings: an identifier computed and then
not threaded through.

Three follow-ups:

**Ten more inits gated**, across two follow-ups. The six above were the ones one
project could measure; an audit found ten more with the identical shape. All ten
are now gated, taking coverage from **6 of 17 to 16**. The one still ungated is
`initGcpService`, which must never be gated — it is the resource that *answers*
whether a service is enabled. These ten are gated on a proven pattern rather than
on measurement: the test project has none of those resources with their APIs off,
which is the condition that makes the bug cost anything.

**A husk in the project cache.** Found by review, and older and wider than the
work that surfaced it. Both service-enablement helpers built `gcp.project` with
`CreateResource`, which caches a project holding nothing but an id — and
`NewResource` returns whatever is cached even after building the full record, so
that husk won for every later caller. It never fills itself in: `name`, `state`,
`parentId`, `labels`, `createTime` and `number` are declared as computed fields
but implemented as placeholders returning "not implemented". Whether it bit
depended purely on ordering. `resolveEnabled` had carried this since it was
written and is used by 29 files.

### What is not covered

One project, 71 assets, 13 API hosts — against **485 declared resources**. Two
services with per-resource-`Get` inits (`certificatemanager`, `documentai`) do not
appear in its traffic at all.

The *audit* is complete — 16 of 17, with the seventeenth correctly excluded — but
only six of those sixteen are backed by a before/after measurement. The other ten
are gated on the pattern the six proved. Confirming them needs projects that
contain those resources **with their APIs disabled**, which is the condition that
makes the bug cost anything; the gate is a no-op wherever the API is on.

## ms365

Two changes. **123s → 24s** on the query that exercised the worst path, and
**58 → 10 calls / 47s → 18s** on the registration-details path.

`microsoft.application.servicePrincipal` ran one filtered Graph query per
application, while `microsoft.serviceprincipals` already fetches the whole set in
a single paginated call. On a 72-application tenant, reading `servicePrincipal`
across all of them took **123s**; resolving from the list takes **24s** and
returns the same 134 service principal ids, byte-identical. Graph throttles on
request volume, so the gap widens with tenant size.

Review also caught that an application with no service principal was returning an
error. Not every registration has one — a multi-tenant app nobody has consented to
has none — so it is now a proper null. That was wrong before this work too.

**Registration details, read once for the tenant instead of once per user.**
`user.authMethods.registrationDetails` fetched its own record per user, while its
parent `authMethods` is already batched at 19 requests per Graph `$batch` call —
so the child cost roughly **twelve times its parent** and 86% of that query's
traffic. It now reads the tenant-wide report once, paginated and indexed by user
id. A user with no registration record is a legitimate state (the report omits
people who never registered a method) and now returns null rather than a 404.
Measured: 58 → 10 calls, 47s → 18s, the same 24 ids byte-identical, and both 404s
gone. Unlike vSphere this is a real wall-clock win — these requests were
serialised, not parallelised. (#10055.)

ms365 is structurally among the healthiest: no init adopts the scanned
asset's identity, so root cause 3 cannot occur, and only 3 of its 23 inits reach
the API at all. Several patterns that looked like N+1s turned out to be already
optimised — `user.job`/`user.contact` are selected in bulk on the users list,
`application.owners()` uses `$select` to avoid a second-level N+1, and `mfaEnabled`
fetches tenant-wide behind a `sync.Once`.

### What is not covered

`loadMfaResp()` still reads the same registration report through the **beta**
client, keeping only `IsMfaRegistered` for `mfaEnabled`, while the fix above reads
it through v1. Unifying them means moving a shipped field's data source from beta
to v1 — a behaviour change that deserves its own change rather than riding along
with a performance fix.

Reaching that path at all needed a dedicated app registration with **application**
permissions. Granting `UserAuthenticationMethod.Read.All` to the Azure CLI app
does not work: Azure CLI is a Microsoft first-party application whose token scopes
come from Microsoft's pre-authorization list, so a tenant `oauth2PermissionGrant`
never reaches the issued token.

The remaining per-item calls are genuinely per-item: `group.members()`/`owners()`,
the Intune per-device collections, and per-parent child collections have no
tenant-wide equivalent in Graph. The tenant-wide `DeviceManagement().DetectedApps()`
looks like a substitute for the per-device one but returns a device *count*, not
the device-to-app mapping.

The tenant measured is small — 72 applications, 25 users, 9 groups, 3 devices. On
an Intune tenant with thousands of managed devices the per-device collections
would dominate regardless of whether a bulk API exists.

## GitLab

**149 → 5 calls (−96.6%)** on a 36-project group, 37 assets. Two changes, and a
static audit found neither.

**Discovery re-ran for every asset it produced.** `inventory.WithoutDiscovery()`
clones a config with `Discover` set to an empty `&Discovery{}` rather than nil,
and `discover()` guarded on the pointer being nil — so the guard never fired.
`discoverGroups` is called before anything reads `Targets`, so each of the 37
assets repeated a `GetGroup`, a `ListSubGroups` and a `ListDescendantGroups` for
a group already resolved. Those three URLs were **110 of the original 149 calls**.
Guarding on `Targets` — which the azure provider already does — took them to one
each.

**Every asset then re-fetched its own project.** Discovery finds project assets
by listing a group's projects, and that listing returns the full project object;
each asset's connection then spent a `GetProject` for the record discovery
already had. Discovery now hands those projects to the connection package, keyed
by instance URL as well as id since ids are only unique within a GitLab. That
removed the remaining 36.

The MQL resource cache could not serve the second one, which is worth recording:
it is attached to a child runtime only *after* `Connect()` returns, so `detect()`
has nothing to read, and the `gitlab.project` MQL resources exist only if some
policy happened to query `gitlab.group.projects`. Discovery's listing is fetched
unconditionally, which is what makes it the reliable source.

The five remaining calls are each made once and all needed: the group, its
subgroups, its descendant groups, and two project listings.

**Correctness:** 1,262 score tuples and 49,470 query executions byte-identical.

### What is not covered

GitLab had **no API tracing** — no equivalent of azure's `apiTracePolicy` — so
none of this was measurable until one was added. That is now part of the change.

A static audit found *nothing*: zero API-CALL inits, zero INLINE accessors, no
asset-identity adoption, and the per-item fetches (`pipeline.loadDetails`,
`project.projectDetails`, `user.fetchUser`) are all correctly `sync.Once`-memoized
and shared across fields. Both real bugs were in the per-asset connection
lifecycle, which only shows up when watching a real scan. That is the second time
measurement overturned a clean static reading, after GCP.

`group.projects { … }` still fans out one call per project per collection. That is
inherent to GitLab's API — there are no bulk endpoints for per-project settings.

## Okta

**7 → 3 calls** on a single-org scan, one change.

`initOktaOrganization` fetched `GET /api/v1/org` unconditionally, and
`NewResource` runs an init before it consults the resource cache — so every
query referencing `okta.organization` spent its own fetch, and `Identifier()`
fetched it a second way. Five of the scan's seven calls were that one record.

The resource cache could not serve it: the org's id arrives *in* the response,
so there is no key to look it up by beforehand — unlike the gcp project refetch,
where the id was already known from the connection config. There is exactly one
organization per connection, so the connection memoizes it.

The saving follows how many checks mention the organization, not org size, so it
grows with policy breadth rather than staying fixed at four calls.

**Correctness:** 34 score tuples and 1,337 query executions identical.

### What is not covered

The eight per-user accessors (`roles`, `groups`, `factors`, `blocks`,
`appLinks`, `grants`, `clients`, `identityProviders`) are genuinely N+1 —
measured, 8 users produced 8 `roles` and 8 `groups` calls. Okta has **no bulk
endpoint** for any of them, so that is the API's design rather than a provider
defect, and on a large org it is the cost that would dominate. The accessors are
lazy, so nothing is fetched unless a policy asks.

The test org has **8 users, 2 groups and 0 applications**. The six
per-application accessors never executed and the per-user fan-out was too small
to stress, so "otherwise clean" is a weaker claim here than for GitLab, where 36
projects exercised the fan-out properly.

## GitHub

**1,291 → 1,049 calls (−18.7%)** on the mondoohq organization, 226 repositories,
both runs stopped at the same 97 asset blocks. The 159 redundant calls went to
**zero**, and 404s fell from 375 to 289.

This is the worked example of root cause 4, and it is the one provider where the
resource cache was working perfectly and the duplication happened anyway.

`repository.files` reads the repository root. `findSpecialFiles`, which resolves
`securityFile`, `supportFile` and `codeOfConductFile`, read the same directory as
`"."`. Those normalize to the identical request. Scanning an organization paid
it twice per repository: once while the organization asset resolved the
repository, once while that repository was scanned as its own asset.

The cache could not help, and this was verified rather than assumed. Discovery
sets `WithParentConnectionId`, so a repository asset inherits the organization's
`runtime.Resources`; instrumenting the resource showed **the same
`github.repository` object, at the same address, serving both assets**. Across
226 repositories: zero resolved to more than one instance, and
`findSpecialFiles` never ran twice. Both fields computed exactly once. The cache
stores values per field, so two fields wanting one request is simply outside
what it can see.

The fix reads the root from the `files` field instead of fetching it, so
whichever caller arrives second reuses the cached field, and reaches `.github`
by descending through its entry in that listing rather than requesting it
outright. That second part was unplanned and turned out to be the larger win: a
repository with no `.github` directory now costs **no request at all**, where
before it bought a 404. That is the 86 vanished 404s.

| | before | after |
|---|---|---|
| root `contents/` | 321 for 226 repos | **226** |
| `contents/.github` | 290 for 226 repos | **140** |
| redundant calls | 159 | **0** |

An earlier attempt cached directory listings in the connection layer with
single-flighting. It also reached zero redundancy but only −12.0%, because it
still paid the `.github` 404s, and it cost ~205 lines and a new dependency
against 68 net lines and none. It is recorded here because it is the fix that
generalizes: it holds under parallel scanning, where the field approach does not
(see below).

**Correctness:** all 13,480 per-check score tuples identical, none missing.

### What is not covered

The field approach relies on GitHub scans running **sequentially**, which they
currently do. `GetOrCompute` (`providers-sdk/v1/plugin/runtime.go:263`) checks
`IsSet` and computes with no lock between the two, so under `--parallelism > 1`
two assets could resolve `files` on the same shared resource at once and both
fetch. That degrades to an occasional duplicate, never to wrong data, and it is
the same exposure as **server#18630**. Fixing that guard upstream would make the
field approach airtight and benefit every provider.

No repository in the measured organization keeps a `SECURITY.md`,
`SUPPORT.md` or `CODE_OF_CONDUCT.md` **inside `.github/`** — a code search across
the org returns zero. The descent path is therefore the one part of the change
with no measurement behind it, and carries unit tests instead. The positive root
path was confirmed live against `mondoohq/.github`, which returns all three with
their real uppercase names.

`allFiles` never ran in either scan: no policy in the bundle asks for it. It is
backed by the Git Trees API rather than `contents/`, so it neither benefits from
nor contributes to this change. Serving `files` and the special files from one
recursive tree call would cut 2–3 requests per repository to 1, but it changes
which API backs a shipped field and would truncate on large repositories, so it
belongs in its own change.

The scan was stopped at 97 of 227 assets, so the percentage is measured at 43%
completion. The redundancy share grew with completion, so a full scan would have
saved somewhat more.

## vSphere — in draft, undecided

**1,529 → 695 SOAP calls (−55%)**, 568 score tuples identical — but **wall-clock
is unchanged** at ~12s, so this one is filed as a draft (#10049) for a decision
rather than merged.

`esx.NewExecutor` costs two SOAP round trips of its own, and all 23 esxcli
helpers built a fresh one per command; `esxiClient()` returned a new client per
accessor call on top. That was 275 executor constructions — 550 setup calls, 36%
of the scan's traffic.

The reason it is not simply a win: the calls were already heavily parallelised,
so removing 834 of them changed no timings, and `Executor.Run` mutates a shared
`CommandInfo` map, so sharing an executor required a mutex that serialises
esxcli commands within a host. Fewer calls, less concurrency, same duration.
Worth deciding against a larger inventory than the four-asset one available.

## Still open

- **mondoohq/server#18630** — no in-flight deduplication in the resource layer.
  Concurrent resolution of the same resource spends N identical calls; a
  cache-first check cannot fix it. Worth ~7% of the post-fix AWS scan and applies
  to every provider.
- **mondoohq/mql#10000** — the provider update check fetches
  `releases.mondoo.com/providers/latest.json` **once per asset** and blocks on it
  (~17s added to a 169-asset scan). The one-hour throttle only re-arms after an
  update actually installs, so in steady state it never fires.

## Reference

The recurring patterns, how to detect them, and the measurement traps that
produced wrong conclusions along the way are written up in the
`provider-api-call-dedup` skill:
[`.claude/skills/provider-api-call-dedup/SKILL.md`](../.claude/skills/provider-api-call-dedup/SKILL.md).

Read that skill to *do* this work on a new provider; read this document for what
each provider's defect turned out to be and what the fix measured.
