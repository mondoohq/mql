# Mistral AI Provider

Query models, fine-tuning jobs, files, and batch inference jobs in a Mistral AI workspace for security posture assessment and AI Bill of Materials (AIBOM) generation.

## Prerequisites

- A Mistral AI account at [console.mistral.ai](https://console.mistral.ai)
- An API key generated at [console.mistral.ai/api-keys](https://console.mistral.ai/api-keys)
- Activated billing (Experiment tier or Scale plan)

## Authentication

Mistral AI API keys are **scoped to a single workspace**. To scan all workspaces in an organization, add each workspace as a separate asset with its own API key.

Set the API key via environment variable:

```bash
export MISTRAL_API_KEY=<your-api-key>
```

Or pass it directly:

```bash
mql shell mistral --token <your-api-key>
```

The provider also accepts `MISTRAL_KEY` as a fallback environment variable.

## Usage

```bash
# Connect to a workspace
mql shell mistral --token <api-key> --workspace my-workspace

# Using environment variable
export MISTRAL_API_KEY=<api-key>
mql shell mistral
```

## Examples

### List all models with capabilities

```coffeescript
mistral.models { id type maxContextLength capabilityChat capabilityVision capabilityFunctionCalling }
```

### Find vision-capable models

```coffeescript
mistral.models.where(capabilityVision == true) { id name description }
```

### AIBOM: model inventory with family and parameter size

```coffeescript
mistral.models { id name family parameterSize description ownedBy }
```

### Find fine-tuned models and their lineage

```coffeescript
mistral.models.where(type == "fine-tuned") { id root job archived }
```

### Audit fine-tuning jobs

```coffeescript
mistral.fineTuningJobs { id status model fineTunedModel trainedTokens cost costCurrency }
```

### Audit uploaded training data

```coffeescript
mistral.files { id filename purpose bytes source createdAt }
```

### Check batch inference jobs

```coffeescript
mistral.batchJobs { id status model endpoint totalRequests succeededRequests failedRequests }
```

### Security posture: deprecated models still in use

```coffeescript
mistral.models.where(deprecation != null) { id name deprecation }
```

### Security posture: models with function calling enabled

```coffeescript
mistral.models.where(capabilityFunctionCalling == true) { id name type }
```

## Resources

| Resource | Description |
|---|---|
| `mistral` | Root namespace — workspace overview |
| `mistral.model` | Available models (base and fine-tuned) with AIBOM fields |
| `mistral.fineTuningJob` | Fine-tuning jobs with status, cost, and model lineage |
| `mistral.file` | Uploaded files for fine-tuning, batch, and OCR |
| `mistral.batchJob` | Batch inference jobs with progress tracking |

## Workspace Scoping

Mistral AI organizes resources into **workspaces**. Each API key is bound to exactly one workspace and can only access resources within that workspace. This means:

- Models listed via `mistral.models` include both platform-wide base models and workspace-specific fine-tuned models
- Fine-tuning jobs, files, and batch jobs are workspace-scoped
- To get a complete view of an organization, create a separate API key for each workspace and add each as a separate asset in Mondoo

Use the `--workspace` flag to label each connection for easier identification:

```bash
mql shell mistral --token <key-for-prod> --workspace production
mql shell mistral --token <key-for-dev> --workspace development
```

## Provider Development

```bash
# Build and install
make providers/build/mistral && make providers/install/mistral

# Test interactively
mql shell mistral

# Regenerate after .lr changes
./mqlr generate providers/mistral/resources/mistral.lr --dist providers/mistral/resources
```
