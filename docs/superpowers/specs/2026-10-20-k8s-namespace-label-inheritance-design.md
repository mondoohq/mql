# Kubernetes namespace label inheritance for discovered assets — design (draft)

- **Status:** design settled 2026-10-22 (D3, D5, D6 and the Phase 4 scope decided by Mikita). Next step: implementation plan for Phases 1 and 2.
- **Repos:** mql (k8s provider), mondoo-operator. cnspec needs no change. Server needs no change for the core; Phase 4 (Console/server parity) is a non-blocking follow-up.
- **Author's notes:** decisions marked *(my call)* were made by the drafter and are open to override; *(decided)* records Mikita's answer.

**Customer context (from Mikita):** namespaces are labeled with team ids, every team has its own space, and the scans report at org scope so routing rules place workloads by team.

## Intent

Workloads discovered under a Kubernetes namespace should carry selected labels of that namespace, so that a namespace labeled `my.company.com/team: aaabbbccc` yields pods, deployments, jobs, etc. that carry `my.company.com/team: aaabbbccc` too. The keys to inherit are chosen by the operator of the scan, by adding them to the scan inventory. The immediate purpose is **asset routing**: an org-level routing rule on `LABEL my.company.com/team` should send every workload of a team's namespaces to that team's space.

## What exists today (verified in code)

**mql k8s provider** (`providers/k8s/resources/discovery.go`)
- A workload asset's labels are the k8s object's own labels plus `k8s.mondoo.com/{namespace,name,uid,kind,apiVersion,resource-version,cluster-id,owner-*}` (`addMondooAssetLabels`, l.1300). The Mondoo keys overwrite object keys of the same name.
- A namespace asset's labels are the namespace's own labels plus the same Mondoo keys (`discoverNamespaces`, l.1177).
- The namespace object is already in hand wherever workloads are discovered: the staged path fetches it (`discoverNamespaceStage`, l.380–390, `conn.Namespace(nsName)`); the legacy path loops over the namespace assets it built (`discoverLegacy`, l.226–249). cnspec always enables staged discovery (`policy/scan/local_scanner.go:520`).
- Container-image assets are emitted bare: a `registry-image` connection, no labels, no name, no platform IDs (`discoverContainerImages`, l.1246–1297). They are deduplicated per namespace stage by resolved image reference. The os provider later merges its own labels into whatever labels the asset already has (`providers/os/connection/container/image_connection.go:197–204`), so labels set at discovery survive.
- Precedent for stamping a parent-level fact on every discovered asset: `addDistroMetadata` (l.144) puts the cluster's cloud account on every asset as an annotation.
- Inventory `options` are an opaque `map<string,string>` passed through untouched by cnspec. Existing option keys live in `providers/k8s/connection/shared/connection.go:21–33`; CLI flags in `providers/k8s/config/config.go:76–130`; the flag→option mapping in `providers/k8s/provider/provider.go` `ParseCLI`. Stage 1 clones the options into every namespace's stage-2 config, so a new option reaches stage 2 for free.
- Under staged discovery the provider emits **no** `RelatedAssets` links at all (`setRelatedAssets` is only called from the legacy path, l.246). Every cluster, namespace, workload and image is uploaded as an independent top-level asset.

**mql client discovery** (`discovery/asset_explorer.go`, `discovery/discovery.go`)
- Children inherit from the *root* asset (the cluster, never the namespace) only labels matching `*mondoo.com/*` and all annotations (`prepareAsset`, l.102; `findRootAsset`, l.429). Arbitrary keys like `my.company.com/team` do not propagate this way.
- The first connected copy of an image digest wins; later copies from other namespaces are closed as duplicates (`dedup`, l.361). Because cnspec flushes and drains each namespace subtree before the next, namespace A's copy of an image is uploaded before namespace B is even discovered.

**server**
- Asset routing (ADR-020, `policy/asset_routing.go`) runs only when an agent syncs at org or platform scope. It evaluates each top-level asset in the request on the **incoming payload**, never on stored state. `LABEL` conditions read annotations first, then labels, then platform labels (`extractField`, l.171–180).
- On every sync, labels are **replaced** (`replaceLabels`, `policy/datalakes/db/assetstore.go:3206`, a few `mondoo.com/*` and third-party keys excepted) while annotations are **merged** (`mergeAnnotations`, l.3244).
- The server stores no link between a workload and the images it runs.
- The k8s integration can exist at org scope: `Type_K8S` is in `OrgIntegrationTypes` (`nexus/integrations/integrations.go:105`), and an org-scoped one mints its registration token at the integration's own scope (`integrationsservice/engine_ent_common.go:333–341`). Space-scoped ones additionally have a `space_id` override (`integrations.proto:1550`). What is **not** verified: whether the operator tolerates an org-scoped service account (`pkg/utils/mondoo/gc.go:133–142` and `integration_provision.go:109–117` read `sa.SpaceMrn` as a space), and whether the console offers the org-scoped form.

**mondoo-operator**
- Every inventory option is mapped explicitly; there is no raw pass-through. Four builders produce k8s inventories: `controllers/k8s_scan/resources.go` `Inventory()` (l.1053) and `ExternalClusterInventory()` (l.1125), `controllers/container_image/resources.go` `containerImageOptions()` (l.425), and the resource watcher `controllers/resource_watcher/scanner.go` (l.142–211), which receives its settings as Deployment args (`resources.go:43–112`, `cmd/mondoo-operator/resource_watcher/cmd.go:53–67`).
- The container-image scan is a separate CronJob and process, but it runs the **same k8s provider discovery** with `discover: [container-images]`. A provider-side change therefore covers it.
- `pkg/utils/k8s/label_selectors.go` is the pattern for turning a CRD field into provider options shared by all four builders.
- Remote-managed mode rebuilds the whole spec from the server's `K8sConfigurationOptions` (`pkg/utils/k8s/effective_config.go:40`) and preserves only credentials, `consoleIntegration`, `remoteManaged` and three scanner fields from the local CR (`preserveLocalFields`, l.138–146). Any other locally set field, `spec.annotations` included, is discarded on a remote-managed CR.
- The scanner image is the floating `14-rootless` tag with providers installed at build time; a provider change reaches scheduled scans once a new cnspec 14.x image is published, unless `spec.scanner.image` is pinned.

## Goals

- One opt-in setting, expressed as inventory option keys, that copies the listed namespace label keys onto every namespaced asset discovered under that namespace.
- Works on both scheduled k8s scans and the resource-watcher rescans, so a watcher rescan does not strip the inherited label.
- Routing rules of the form `LABEL <key> EQUAL <value>` work on workloads with no server change.
- Container images get the same treatment where it is unambiguous (see D5).

## Non-goals

- Inheriting from anything other than the namespace (no cluster-level or owner-workload inheritance; the root-annotation mechanism already covers cluster-level facts).
- Inheriting namespace *annotations*. Same mechanism would work; out of scope until asked.
- Moving an already-routed asset between spaces when its label changes. Routing creates a new asset in the new target space and leaves the old one to go stale; that is routing's existing behaviour, not this feature's.
- Admission-review assets (`k8s-admission-review` connection). They have no namespace object at hand and the path is deprecated.
- Node assets and other cluster-scoped objects. Nothing to inherit from.

## Anti-goals (would make this a failure even if it works)

- Making image labels flip between teams from scan to scan, or attributing a shared base image to one team because of iteration order.
- Adding per-asset API calls to discovery (one namespace lookup per namespace is fine; one per pod is not).
- A second, operator-only mechanism that differs from what `cnspec scan k8s --inherit-namespace-labels` does.

## Decisions

### D1. Configuration surface *(my call on shape; name open to bikeshedding)*

- New k8s connection option `inherit-namespace-labels`, a comma-separated list of label keys. Globs are accepted with the same matcher the `images`/`namespaces` filters use (`newFilterOpts`/`matchesAny`), so `my.company.com/*` inherits a whole prefix. Constant `OPTION_INHERIT_NAMESPACE_LABELS` next to the others.
- Matching CLI flag `--inherit-namespace-labels` so `cnspec scan k8s` and the operator behave identically. cnspec attaches provider flags generically; nothing to do there.
- Operator CRD: `spec.inheritNamespaceLabels: []string`, a sibling of `spec.annotations` (it is asset-metadata configuration, not filtering). One global list; a per-external-cluster override is not needed until a customer has clusters with different conventions. The operator joins it with commas into the option in all four inventory builders and passes it to the watcher as a new Deployment arg.

### D2. Inherited values are **labels**, not annotations *(my call)*

Labels are what the user asked for and what the k8s object's own labels already are. Their replace-on-every-sync semantics are the right lifecycle for workloads: relabel or unlabel the namespace, and the next scan updates every workload. Every path that scans a workload is the k8s provider fed from the same CRD, so nothing else ever strips the key. Annotations (ADR-271's choice for the AWS account id) exist for values that must survive scans by paths that do not know them; they also never clear. Routing reads both, so routing is indifferent.

Consequence: the resource watcher **must** receive the option, otherwise its rescans replace the labels without the inherited key.

### D3. Collision: the namespace only fills gaps *(decided)*

The workload's own value wins; the namespace supplies a listed key only when the workload does not carry it. Nothing is ever removed. This is the k8s-conventional reading (more specific overrides more general) and keeps a workload's deliberate own label intact. Known consequence, accepted: a pod author can set a listed key on the pod and route it elsewhere. The alternative, where the namespace is the authority and keys it lacks are stripped from workloads, was considered and rejected for being a visible, destructive change to existing labels.

### D4. Which assets inherit

Every namespaced asset returned by `discoverAssets` for that namespace: pods, jobs, cronjobs, services, statefulsets, deployments, replicasets, daemonsets, ingresses. Namespace assets already carry their own labels. Container images are handled by D5. Applied once per namespace in a single helper called from both `discoverLegacy` and `discoverNamespaceStage`, the same shape as `addDistroMetadata`. No new failure mode: stage 2 already fails the namespace stage when the namespace cannot be fetched (`discovery.go:384–387`), the legacy path reuses the namespace assets it built, and manifest scans synthesize a bare namespace for any referenced name (`connection/shared/manifest_parser.go:154–200`), which simply has nothing to inherit.

### D5. Container images: inherit when unambiguous, mark when shared *(decided, with the caveat below accepted)*

An image is one asset per digest shared by every namespace, cluster and registry that scans it, and routing places an asset in exactly one space. A single-valued label on a shared image is therefore a heuristic, and the naive version (stamp whatever the current namespace says) is unacceptable: it attributes `istio-proxy` to the alphabetically first namespace and flips as namespaces come and go.

Rule, per inherited key, over the in-scope namespaces that run the image and **carry the key** (namespaces without the key do not vote, consistent with D3's fill semantics; infra namespaces without a team id therefore never block attribution) *(my call)*:
- all voters agree on one value → the image gets `key=value`;
- voters disagree → the key stays unset and the image gets the marker label `k8s.mondoo.com/namespace-label-conflict`, whose value is the comma-separated list of conflicting keys *(my call on name and value)*. A customer routes shared images with a rule such as `LABEL k8s.mondoo.com/namespace-label-conflict CONTAINS my.company.com/team` ahead of the catch-all. The value is the key rather than `true` so that `CONTAINS`/`EQUAL` work; an absent label reads as the empty string, which `MATCHES *` would also match, so the docs must steer users away from that form;
- no voters → nothing is stamped.

In-scope means namespaces that pass the scan's namespace and label-selector filters; namespaces the admin excluded from scanning do not vote. App images built and run by one team get the team label; images run by several teams get the marker.

Mechanism: stage 2 sees only its own namespace, so it cannot judge ambiguity. Stage 1 (`discoverClusterStage`), when the option is set and `container-images` is a target, lists pods cluster-wide once (paginated, keeping only image reference → per-key value sets), computes the set of **ambiguous image references**, and passes that set to every namespace's stage-2 config as an internal option, the same way `OPTION_NAMESPACE` is passed. Stage 2 stamps inherited labels on every image not in the set. The set is small in practice (shared infra images); the builder should cap it and log if it grows beyond a sane size. The legacy path has all namespaces in one pass and computes the same thing directly. When discovery starts directly at stage 2 (operator passes exactly one literal namespace), no other namespace is in scope, so stamping is unconditional.

The unanimity is judged within one scan run of one cluster. Across clusters it holds up **only under org routing**: the label value selects the target space, so two clusters that disagree about a digest produce two assets in two spaces and never touch each other, and a marked image lands in the shared-images or catch-all space as a third. In a **single space fed by several clusters** (no routing), or a space that also runs a registry integration, the one shared image asset takes whichever scan synced last, and the label flips between teams. The client cannot compute cross-cluster unanimity. **Accepted (Mikita, 2026-10-22):** this is a routing-oriented feature and the single-space behaviour is documented as a known limit rather than gated.

Other known limits, to be documented: the scan cache's `platformids-exclude` delays a label refresh by its TTL; the operator's scan-cache lookup has not been checked against routed images living in a different space than the integration. Builder note: the stage-1 index must read images from pod status directly (`ResolveUniqueContainerImagesFromStatus`), not via `UniqueImagesForPod`, which fetches each pod's pull secrets through the API (`container_utils.go:62–67`).

### D6. Scope: org-scoped scanning *(decided)*

The scans report at org scope and routing places assets per team. The server already allows an org-scoped k8s integration with an org-scoped token. Pre-check for the builder of Phase 2, not a design question: the operator reads the service account's scope as a space in two places (`gc.go:133–142`, `integration_provision.go:109–117`); confirm an org-scoped service account does not trip them, and fix if it does. Nothing in this design changes scope; it only guarantees the labels are on the wire.

### D7. No cnspec change, no server change for the core

cnspec passes options through and uploads the provider's labels unchanged. The server's routing engine already matches on incoming labels. Only the optional Phase 4 (console-managed configuration) touches the server.

## Phased plan

Each phase is one PR. Order matters only where stated. An older provider ignores an unknown option key, so the operator PR can merge before or after the provider PR without breaking anything; the feature just stays inert until both are deployed.

### Phase 1 — mql: inherit onto namespaced workloads

- Option constant, CLI flag, `ParseCLI` mapping, option parser reusing `newFilterOpts`.
- Helper that copies matching namespace labels onto a list of assets (collision rule D3), called per namespace from `discoverLegacy` and `discoverNamespaceStage`. Images excluded until Phase 3.
- Unit tests in `providers/k8s/resources/discovery_test.go` using the existing fake connection: listed key inherited; unlisted key not; glob; collision per the chosen D3 policy, including the namespace-lacks-key case; option unset leaves labels byte-identical to today; manifest scan with an undeclared namespace inherits nothing and does not error.
- mql ADR under `docs/adr/` (next free number after 050) recording D2–D5, since mql keeps ADRs for provider behaviour that other repos depend on.

### Phase 2 — mondoo-operator: plumb the setting

- CRD field `spec.inheritNamespaceLabels` with kubebuilder validation (non-empty strings); `make manifests` and the chart CRD copies.
- Shared helper in `pkg/utils/k8s/` producing the option, used by the k8s scan inventory, the external-cluster inventory, the container-image inventory, and the resource watcher (Deployment arg, cmd flag, `ScannerConfig`, scanner inventory).
- Docs: user-manual section next to "Filter Kubernetes objects based on labels", sample CR, README feature row, with the minimum cnspec/provider version stated the way the label-selector section does.
- Tests: existing inventory builder tests extended for the new option in all four builders.

### Phase 3 — mql: container images (depends on Phase 1)

- Stage-1 ambiguity index and the internal stage-2 option; legacy-path equivalent.
- Stamping in `discoverContainerImages`: the value for unambiguous images, the conflict marker for shared ones.
- Tests: two namespaces agreeing → value stamped; disagreeing → marker with the key, value absent; one namespace lacking the key, the other carrying it → value stamped; no namespace carrying it → nothing; single-namespace stage → value stamped; option unset → images byte-identical to today; excluded namespace does not vote; two keys where only one conflicts → one value and a marker naming only the conflicting key.
- Docs (operator user manual, Phase 2 section) gain the shared-image routing rule example and the single-space caveat.

### Phase 4 — follow-up, not blocking: Console/server parity for the CRD setting

A remote-managed CR is rebuilt from the server's integration config and discards local spec fields; that is how remote management is meant to work, so for those deployments the setting has to come from the server. Mikita's call (2026-10-22): do it later, as part of syncing CRD features with the Console and the server-side k8s integration, so the setting can be given on first connection and managed from the app. Until then the feature is available through the CR and `cnspec scan k8s`. Scope when it happens: `K8sConfigurationOptions.inherit_namespace_labels` in `nexus/integrations/integrations.proto`, the GraphQL input/output (additive, `graphql-api` skill), integration validation, the JSON config handed to the operator, and `mapRemoteConfig`. This changes the server↔operator config contract, so it needs a server ADR per the server's CLAUDE.md.

### Phase 5 — direction, not scheduled: workload → image relations

The structurally right answer for images is for the server to know which workloads run which image, so ownership can be derived from the union of running workloads and shown as such, and routing could one day consult relations. The provider can emit this cheaply: a pod's `imageID` carries the digest, and `containerid.MondooContainerImageID(digest)` yields the image's platform ID without pulling, so each workload can carry an ADR-030 anchored relationship to its images. This is a separate ADR and does not block Phases 1–3.

## Risks

- **Watcher path missed** → inherited labels vanish on every watcher rescan. Mitigated by the shared helper and a test per builder.
- **Routing moves nothing**: a namespace relabel produces a new asset in the new team's space and a stale one in the old. Existing routing behaviour; document it in the user manual section.
- **Stage-1 pod list on very large clusters**: only when the option is set and images are targeted; paginated; retains an index, not pods. Legacy discovery listed all pods anyway.
- **Scan cache and routed images**: not analysed; flagged for the builder of Phase 3 to check `RefreshAssetScores` against assets that routing placed in another space.

## Settled (2026-10-22)

- Org-scoped scanning with one space per team (D6).
- Images ship with the unanimity rule and the conflict marker; the single-space caveat is accepted (D5).
- The namespace fills gaps only (D3).
- Remote-managed deployments get the setting once CRD features are synced with the Console and the server-side integration (Phase 4); not blocking, noted as a follow-up so it can be set on first connection as well as managed from the app.

No open questions remain.

## Left to the builder

- Exact option parsing and error text; whether an invalid glob fails the scan (the existing filters do) — follow the existing filters.
- How the legacy path gets the raw namespace labels: the namespace assets already hold them, but `k8s.mondoo.com/*` keys have been added on top, so either keep the raw objects from `conn.Namespaces()` or exclude the Mondoo prefix when copying.
- Encoding of the stage-2 ambiguity set and its cap.
- Log levels and wording.
