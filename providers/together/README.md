# Together AI Provider

Query and assess your Together AI account, including models, fine-tuning jobs, dedicated endpoints, container deployments, files, GPU clusters, secrets, batch jobs, evaluation jobs, and persistent volumes.

## Prerequisites

You need a Together AI **API key**:

1. Go to [Together AI Settings > API Keys](https://api.together.ai/settings/api-keys)
2. Create or copy an API key

## Authentication

### Environment Variable (recommended)

```bash
export TOGETHER_API_KEY="<your-api-key>"
```

### CLI Flag

```bash
mql shell together --token <api-key>
```

### Project Identifier

Together AI API keys are scoped to a project. Pass `--project` to set a stable platform identifier for the asset:

```bash
mql shell together --project proj_CbM93CwtkjHJX79ygxahE
```

The project ID appears in the Together AI dashboard URL when you select a project. Without `--project`, the platform ID is a generic `//platformid.api.mondoo.app/runtime/together`.

### Custom Base URL

For self-hosted or proxy setups:

```bash
mql shell together --token <api-key> --base-url https://my-proxy.example.com
```

The base URL is the API root: the provider calls versioned paths below it (`v1/files`, `v2/projects/...`, `v3/whoami`). A base URL ending in `/v1` is accepted and cut back to the root.

## Examples

**List all available models**

```bash
mql> together.models { id type organization contextLength }
```

**Find chat models from a specific organization**

```bash
mql> together.models.where(type == "chat" && organization == "Meta") { id contextLength license }
```

**Check model pricing**

```bash
mql> together.models.where(type == "chat") { id pricingInput pricingOutput }
```

**Inspect AIBOM model metadata**

Fields `family`, `parameterSize`, `quantization`, and `description` are parsed from the model identifier for AI Bill of Materials (AIBOM) use cases:

```bash
mql> together.models.where(type == "chat") { id family parameterSize quantization description }
```

**List active endpoints**

```bash
mql> together.endpoints.where(state == "STARTED") { name model type owner }
```

**Find dedicated endpoints**

```bash
mql> together.endpoints.where(type == "dedicated") { name model state }
```

**List fine-tuning jobs and their status**

```bash
mql> together.fineTunes { id status model modelOutputName totalPrice }
```

**Find running fine-tune jobs**

```bash
mql> together.fineTunes.where(status == "running") { id model trainingFile epochs }
```

**Inspect container deployments**

```bash
mql> together.deployments { name image status gpuType gpuCount }
```

**Audit deployment environment variables**

```bash
mql> together.deployments { name environmentVariableNames }
```

**Find running deployments with their resource allocation**

```bash
mql> together.deployments.where(status == "Ready") { name image cpu memory gpuType gpuCount healthCheckPath }
```

**List uploaded files**

```bash
mql> together.files { id filename purpose fileType bytes }
```

**Inspect GPU clusters**

```bash
mql> together.clusters { name gpuType numGpus region status billingType }
```

**Audit cluster OIDC configuration**

```bash
mql> together.clusters { name oidcIssuer oidcClientId }
```

**Check cluster storage**

```bash
mql> together.clusters { name storageVolumes { volumeName sizeTib status } }
```

**List managed secrets**

```bash
mql> together.secrets { name description createdBy createdAt }
```

**List batch inference jobs**

```bash
mql> together.batches { id status modelId progress endpoint }
```

**Find in-progress batch jobs**

```bash
mql> together.batches.where(status == "IN_PROGRESS") { id modelId progress }
```

**List evaluation jobs**

```bash
mql> together.evals { workflowId type status createdAt }
```

**List persistent volumes**

```bash
mql> together.volumes { name type currentVersion mountedBy }
```

**Account overview**

```bash
mql> together { models.length endpoints.length fineTunes.length deployments.length batches.length files.length }
```

## Resources

| Resource | Description |
|---|---|
| `together.models` | Available models in the Together AI catalog |
| `together.endpoints` | Dedicated and serverless endpoint deployments |
| `together.fineTunes` | Fine-tuning jobs |
| `together.deployments` | Container deployments (Jig) with GPU allocation |
| `together.files` | Uploaded files for fine-tuning, eval, or batch |
| `together.clusters` | GPU compute clusters |
| `together.cluster.storageVolumes` | Persistent storage attached to clusters |
| `together.secrets` | Managed secrets for deployments |
| `together.batches` | Batch inference jobs |
| `together.evals` | Evaluation jobs |
| `together.volumes` | Persistent volumes for deployments |

### Enterprise-Only Resources

The following resources require an enterprise Together AI account. On non-enterprise accounts, they return empty lists:

- `together.deployments`
- `together.clusters` (and `cluster.storageVolumes`)
- `together.secrets`
- `together.volumes`
