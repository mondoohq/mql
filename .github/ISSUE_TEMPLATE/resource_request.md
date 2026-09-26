---
name: Resource request
about: Request a new MQL resource or new fields on an existing one
title: '<provider>: add a <resource> resource'
labels: 'feature'
assignees: ''

---

<!--
Title examples:
  aws: add an aws.fsx.fileSystem resource
  azure: add fields for container app ingress
  os: add a firefox.policies resource
-->

**Before you file**

- [ ] The resource or field does not exist yet: `mql providers resources <provider> --json`, or `help` in `mql shell <provider>`
- [ ] I read the provider's `.lr` schema (`providers/<provider>/resources/<provider>.lr`) and none of its resources or fields covers this

**Summary**
One sentence: what the resource represents and what it lets you check.

**API reference**
Links to the official API documentation for the list/describe/get operations that return the data, and the permissions they need.

- [`<Operation>`](<link>): what it returns

**Proposed fields**

`<provider>.<service>.<resource>`

| Field | Type | Description |
|---|---|---|
| `arn` / `id` | `string` | Unique identifier |
| `name` | `string` | |
| `tags` | `map[string]string` | |

Map API types to MQL types:

| API type | MQL type |
|---|---|
| string | `string` |
| boolean | `bool` |
| integer, long | `int` |
| float, double | `float` |
| timestamp, date-time | `time` |
| array of strings | `[]string` |
| tags, string map | `map[string]string` |
| nested object | `dict` |
| ID or ARN of another modeled resource | that resource, for example `vpc() aws.vpc` |
| list of child objects with their own ID | `[]<provider>.<service>.<child>` |

**Example MQL**

```coffee
<provider>.<service>.<resources>.all(<field> == <value>)
```

**Additional context**
What you want to audit with it, and anything unusual about the API (regional, paginated, preview-only, requires a paid tier).
