# Runtime Cache Image Scanner Model Plan

## Scope

Add the MQL provider model required for scanning container images that are already present on Kubernetes nodes. This plan belongs in `mql` because it defines the data model, provider options, runtime-cache image discovery semantics, and scanner handoff contract. Operator deployment and policy content are handled in separate PRs.

## Goals

- Discover images that are actually in use on a node from local runtime state.
- Reuse cached image content from containerd, CRI-O, Docker, or compatible CRI daemons without pulling from a registry.
- Represent runtime delegates, runtime images, cached layers, and pod-to-image links in MQL.
- Allow scans of protected-registry images without reading Kubernetes `imagePullSecrets` or registry credentials.
- Make no-pull behavior explicit and testable: missing local images are reported as `notPresent`, never fetched.
- Keep memory bounded by streaming image/layer content and deduplicating image scans by immutable image identity.

## Non-goals

- Do not replace registry scanning. Existing registry and `container.image` flows remain valid for registry inventory and out-of-cluster image scans.
- Do not add operator CRD fields in this repo.
- Do not implement admission-time decisions. This is scan-time inventory and assessment only.
- Do not expose host filesystem paths or runtime socket paths as policy-facing secrets.

## Current implementation anchors

- Existing `providers/os/resources/containerd.go` discovers containerd containers through `ctr` commands and exposes `containerd.container`; the runtime-cache scanner handoff below uses containerd image/content services instead.
- `providers/os/resources/container.go` exposes `container.image` from a registry-style reference.
- `providers/k8s/resources/pod.go` and `providers/k8s/resources/container.go` already know Kubernetes pod containers and their declared images.
- `providers/k8s/resources/node.go` exposes node assets, which is the natural parent for node-local runtime-image inventory.
- `docs/adr/002-staged-discovery.md` describes the memory pattern this feature must preserve: discover a bounded scope, scan it, close it, then move on.

## Implemented in this draft

- `container.runtimeDelegate`, `container.runtimeImage`, and `container.runtimeImageLayer` model runtime-cache delegates and images.
- `k8s.node.runtimeDelegates`, `k8s.node.runtimeImages`, `k8s.containerStatus.runtimeImage`, and `k8s.containerStatus.runtimeImageStatus` expose Kubernetes-to-runtime-image links.
- Kubernetes discovery accepts the explicit `runtime-cache-images` target and emits `runtime-image` scan assets for images used by pods on the configured node.
- `runtime-cache-images` reads the operator-provided `runtime-cache-delegates-file`, respects `runtime-cache-node-name`, rejects pull-enabled configs, deduplicates scan targets by delegate plus immutable digest, and keeps normal `container-images` discovery on the existing `registry-image` path.
- `k8s.containerStatus.runtimeImageStatus` now reports `matched` only when the scheduled node exposes a compatible runtime delegate and the runtime image exists in that node cache. Images absent from the node cache report `notPresent`; missing runtime delegation reports `runtimeUnavailable`.
- The OS provider registers a no-pull `runtime-image` connection. The initial implementation supports read-only containerd delegates by using containerd's image/content services on the configured mounted socket, exporting a local OCI archive, loading the exported OCI layout locally, and handing it to the existing tar-based container scanner.

Remaining runtime implementations are still future work: CRI-O, Docker, Podman, native CRI clients, richer `notPresent` result modeling, and cross-node scan-result dedupe across discovered assets.

## Proposed resource model

Add resources behind the OS and Kubernetes providers. Names can change during implementation, but the model should stay stable.

### `container.runtimeDelegate`

Represents a configured local runtime endpoint that may serve image metadata and content.

Fields:

- `id`: Stable delegate id from inventory or operator config.
- `kind`: `cri`, `containerd`, `crio`, `docker`, or `podman`.
- `endpoint`: Sanitized endpoint identifier. Return `unix:///run/containerd/containerd.sock`, but do not include credentials.
- `priority`: Lower values are tried first.
- `nodeName`: Node where the delegate is valid.
- `namespaces`: Runtime namespaces to inspect, for example `k8s.io` for containerd.
- `snapshotters`: Snapshotters observed on this delegate.
- `readonly`: Whether the scanner promises read-only operations.
- `allowPull`: Always false for this feature.
- `status`: `ready`, `unavailable`, `permissionDenied`, or `unsupported`.
- `statusMessage`: Short diagnostic safe for UI display.
- `lastChecked`: Probe timestamp.

### `container.runtimeImage`

Represents an image known to a node-local runtime cache.

Fields:

- `id`: Stable node-scoped id derived from node name plus runtime image ID, digest, or content descriptor. The same digest cached on two nodes must produce two `container.runtimeImage` resources so node-local cache state, delegate ownership, and scan status do not collapse across nodes.
- `nodeName`: Kubernetes node name when known.
- `delegateId`: Owning runtime delegate.
- `runtimeKind`: Runtime kind that reported the image.
- `imageId`: Runtime image ID.
- `repoTags`: Tags reported by the runtime.
- `repoDigests`: Digests reported by the runtime.
- `resolvedDigest`: Preferred immutable digest used for scan deduplication.
- `chainId`: Layer chain ID when available.
- `targetDigest`: OCI manifest or index digest used for content access.
- `mediaType`: OCI/Docker media type.
- `platform`: OS, architecture, variant.
- `sizeBytes`: Runtime-reported size.
- `created`: Image creation timestamp when available.
- `labels`: Sanitized runtime labels.
- `namespaces`: Runtime namespaces that reference the image.
- `inUse`: True if at least one running or recently observed container references it.
- `containers`: Links to `containerd.container`, Docker containers, or Kubernetes pod containers.
- `scanStatus`: `pending`, `scanned`, `notPresent`, `unsupported`, `permissionDenied`, or `failed`.
- `scanStatusMessage`: Short non-secret diagnostic.

### `container.runtimeImageLayer`

Represents layer metadata needed for vulnerability, package, and SBOM scans.

Fields:

- `digest`: Compressed layer digest.
- `diffId`: Uncompressed layer digest when available.
- `sizeBytes`: Layer size.
- `mediaType`: Layer media type.
- `annotations`: OCI annotations filtered for non-secret values.
- `cachePresent`: Whether the layer content is locally available.

### Kubernetes links

Add links rather than duplicating image state:

- `k8s.node.runtimeDelegates`: Local runtime delegates known on the node.
- `k8s.node.runtimeImages`: Cached images known on the node.
- `k8s.pod.containers[].runtimeImage`: Runtime image matched by `imageID`, digest, or container runtime ID.
- `k8s.pod.containers[].runtimeImageStatus`: `matched`, `notPresent`, `ambiguous`, or `runtimeUnavailable`.

## Runtime delegation list

The provider should consume a central delegation list from inventory options. The operator PR will generate this list; local CLI users can provide it directly.

Example inventory shape:

```yaml
runtimeImageCache:
  allowPull: false
  scanOnlyInUse: true
  maxConcurrentImageScans: 1
  maxConcurrentLayerReaders: 2
  delegates:
    - id: containerd-cri
      kind: containerd
      endpoint: unix:///run/containerd/containerd.sock
      priority: 10
      namespaces: ["k8s.io"]
      readonly: true
    - id: crio-cri
      kind: cri
      endpoint: unix:///var/run/crio/crio.sock
      priority: 20
      readonly: true
```

Rules:

- `allowPull` must default to false and must not be overridden by image references.
- Delegates are tried in ascending `priority`.
- A delegate can fail independently. Other delegates continue.
- Runtime endpoint probing must produce per-delegate status resources instead of failing the whole scan.
- Unknown delegate kinds are ignored with `status=unsupported`.

## Discovery algorithm

1. Read the Kubernetes node name from inventory, environment, or node asset context.
2. Load runtime delegates for that node.
3. Probe delegates with read-only calls.
4. Query Kubernetes pods scheduled to the node when a Kubernetes connection is available.
5. Build desired image keys from pod `image`, `imageID`, container ID, runtime name, and node name.
6. Query runtime image metadata through CRI `ListImages` and `ImageStatus` first.
7. If the CRI path does not expose enough content metadata, use native runtime clients:
   - containerd content and image services for containerd
   - CRI-O image service and storage metadata where available
   - Docker or Podman image inspect APIs where explicitly configured
8. Join pod containers to runtime images by immutable digest first. If Kubernetes reports an immutable `imageID`, tag equality must not override a digest mismatch. Runtime image ID and normalized tag matching are only fallbacks when no immutable digest is available from pod status.
9. Emit `notPresent` for pod images absent from the local cache.
10. Deduplicate scan jobs by `resolvedDigest`, then by `imageId`, then by `chainId`.

## Scanner handoff contract

The scanner needs an image source that can read from local runtime content without registry auth. The draft connection type is `runtime-image`.

Connection options:

- `runtime-cache-delegate-id`
- `runtime-cache-kind`
- `runtime-cache-endpoint`
- `runtime-cache-namespaces`
- `runtime-cache-image-ref`
- `runtime-cache-image-digest`
- `runtime-cache-allow-pull=false`
- `runtime-cache-node-name`

Required behavior:

- Never call registry pull APIs when `allowPull=false`.
- Prefer direct OCI descriptor and blob reads from the runtime content store.
- If a runtime cannot stream blobs directly, export a bounded temporary OCI layout and scan that layout.
- Temporary exports must honor configured size limits and be removed on success, failure, and context cancellation.
- A missing blob is a scan result state, not a registry fallback.

## Resource usage requirements

- Stream layer content; do not load full image layers into memory.
- Bound image scan concurrency separately from layer reader concurrency.
- Use a per-node dedupe cache so multiple pods using the same digest scan once.
- Respect context cancellation before opening each image, layer, and temp file.
- Record skipped images with a reason so coverage policies can distinguish `notPresent`, `runtimeUnavailable`, and `unsupported`.

## Security requirements

- Do not read Kubernetes Secrets.
- Do not read Docker config files unless the user explicitly invokes the existing registry scanner path.
- Treat runtime socket access as privileged host access and keep it operator-configured, not auto-discovered from arbitrary paths.
- Only use read-only runtime APIs for inventory and content reads.
- Do not expose raw host paths to policy results.
- Redact endpoint diagnostics that include credentials or query parameters.

## Implementation phases

### Phase 1: Model and fakeable interfaces

- Add delegate and runtime-image resource definitions to the relevant `.lr` files.
- Generate resource code and JSON metadata.
- Add Go interfaces for runtime image clients:
  - `Probe(ctx) DelegateStatus`
  - `ListImages(ctx) []RuntimeImage`
  - `ImageContent(ctx, image) OCIContentReader`
- Add fake implementations for unit tests.
- Add parser tests for image IDs, digests, runtime names, and weak tag fallback behavior.

### Phase 2: CRI and containerd support

- Implement CRI `ListImages` and `ImageStatus`.
- Implement containerd native metadata and content streaming.
- Replace new shell-based runtime inspection with Go clients where possible. Keep shell helpers only for existing resources until migrated.
- Add negative tests that verify no registry client is called when images are missing locally.

### Phase 3: Kubernetes join

- Join `k8s.pod` containers to node-local runtime images.
- Add `runtimeImageStatus` so policies can assert coverage.
- Keep namespace-scoped staged discovery behavior intact; do not load all pods across the cluster from a node-local scan unless explicitly requested.

### Phase 4: Scanner connection

- Add the `runtime-image` connection type or equivalent option path.
- Wire scan assets from runtime images with immutable platform IDs.
- Ensure duplicate pod references collapse into one image scan result with many workload references.

### Phase 5: CRI-O, Docker, and Podman

- Add CRI-O support through CRI first, then native metadata if required for content reads.
- Add Docker and Podman support only when an endpoint is configured in the delegation list.
- Mark partial support explicitly when a daemon can list images but cannot expose content without an export step.

## Test plan

Focused tests:

- `cd providers/os && go test ./...`
- `cd providers/k8s && go test ./...`
- Unit tests for delegate priority, unavailable delegates, and unsupported delegate kinds.
- Fake CRI tests for `ListImages`, `ImageStatus`, missing image, and permission denied.
- Containerd integration test behind an opt-in build tag or environment flag.
- Tests proving a missing local image does not trigger registry pull or secret lookup.
- Tests proving two pods using the same digest create one scan target.
- Cancellation tests for layer streaming and temporary OCI export cleanup.

Full repo verification:

- `make providers/test`
- `make test`

## Acceptance criteria

- A node-local scan can inventory cached images without registry credentials.
- A protected-registry image already present in containerd can be scanned without reading pull secrets.
- An image referenced by a pod but absent from the node cache is reported as `notPresent`.
- Runtime delegate status is visible in MQL.
- Scan memory remains bounded by the configured concurrency and streaming limits.
- Existing registry and container-image scan behavior remains unchanged.
