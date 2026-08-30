# Ansible Provider

The Ansible provider enables security and compliance verification of Ansible infrastructure as code using cnquery.

Point the provider at a **single playbook file** to analyze its plays, tasks,
handlers, and variables. Point it at an **Ansible project directory** to analyze
the whole codebase — its playbooks, roles (tasks, handlers, defaults, variables,
metadata, and dependencies), static inventory and host/group variables, Galaxy
requirements, `ansible.cfg`, and vault-encrypted files. Nothing is executed
against an inventory; the analysis is entirely static.

## Usage

```shell
±> mql shell ansible providers/ansible/play/testdata/play_cert_validation.yaml
→ connected to Ansible Playbook
 _ __ ___   __ _| |
| '_ ` _ \ / _` | |
| | | | | | (_| | |
|_| |_| |_|\__, |_|
  mondoo™     |_|
 interactive shell

mql> ansible.plays
ansible.plays: [
  0: ansible.play name="Install packages"
]
```

## Examples

Query all plays in a playbook:

```javascript
ansible.plays
```

Access specific play details:

```javascript
ansible.plays.first.name
```

Assume the following ansible tasks where we install httpd
with [yum](https://github.com/ansible/ansible/blob/devel/lib/ansible/modules/dnf.py):

```yaml
- name: Install packages
  hosts: all
  gather_facts: false
  tasks:
    - name: Install httpd server
      ansible.builtin.yum:
        name: httpd>=2.4
        state: present
        validate_certs: false
```

You can easily query all tasks for all plays in the playbook:

```shell
mql> ansible.plays.map(tasks)
ansible.plays.map: [
  0: [
    0: {
      name: "Install httpd server"
    }
  ]
]
```

You can also query for all tasks that use `ansible.builtin.yum`:

```shell
mql> ansible.plays { tasks.where (action["ansible.builtin.yum"] != empty) }
ansible.plays: [
  0: {
    tasks.where: [
      0: ansible.task name="Install httpd server"
    ]
  }
]
```

To enforce that no `ansible.builtin.yum` is using `validate_certs: false`, you write the following MQL:

```shell
ansible.plays.all(
  tasks.where(action["ansible.builtin.yum"] != empty).all(
    action["ansible.builtin.yum"]["validate_certs"] != false 
  )
)
```

Query packs allow you to collect information from your Ansible playbooks without enforcing compliance. Create a query
pack to identify tasks that disable certificate validation:

```yaml
packs:
  - uid: ansible-example-pack
    name: Ansible Example Pack
    version: 1.0.0
    license: BUSL-1.1
    authors:
      - name: Mondoo, Inc
        email: hello@mondoo.com
    groups:
      - title: Query tasks that use insecure yum
        filters: asset.platform == 'ansible-playbook'
        queries:
          - uid: ansible-example-pack-yum-validate-certs
            title: Ansible tasks that do not validate yum certificates
            mql: |
              ansible.plays { 
                tasks.where (action["ansible.builtin.yum"]["validate_certs"] == false )
              }
```

Execute the query pack and format the output with `jq`:

```shell
cnquery scan ansible providers/ansible/play/testdata/play_cert_validation.yaml -f providers/ansible/examples/querypack.mql.yaml --output json | jq .
```

Policies enforce security and compliance standards by defining checks that must pass. Create a policy to ensure
`validate_certs` is always enabled for yum tasks:

```yaml
policies:
  - uid: ansible-example-policy
    name: Ansible Example Policy
    version: 1.0.0
    license: BUSL-1.1
    require:
      - provider: ansible
    authors:
      - name: Mondoo, Inc
        email: hello@mondoo.com
    groups:
      - title: Insecure permissions
        filters: |
          asset.platform == 'ansible-playbook'
        checks:
          - uid: ansible-example-policy-yum-validate-cert
            title: Ensure `validate_certs` is enabled for `ansible.builtin.yum`
            mql: |
              ansible.plays.all(
                tasks.where(action["ansible.builtin.yum"] != empty).all(
                  action["ansible.builtin.yum"]["validate_certs"] != false 
                )
              )
```

Execute the policy scan:

```shell
cnspec scan ansible providers/ansible/play/testdata/play_cert_validation.yaml -f providers/ansible/examples/policy.mql.yaml
```

## Project analysis

Connect to a project directory to analyze the whole codebase through the
`ansible.project` resource:

```shell
mql shell ansible ./my-ansible-project
```

```javascript
// Roles defined in the project, with the roles they depend on
ansible.project.roles { name dependencies { name } }

// External roles and collections pulled in from Galaxy, and what is vendored
ansible.project.requirements { roles collections }
ansible.project.collections { name version }

// Custom modules and plugins shipped in the project (supply chain)
ansible.project.plugins { name type }

// Security-relevant ansible.cfg settings
ansible.project.config { hostKeyChecking become }

// Vault-encrypted files and inline encrypted variables
ansible.project.vault { files { cipher } variables { key file } }

// Test/quality signals
ansible.project { lintConfig moleculeScenarios }
```

Tasks expose the module they invoke directly, so audits can select by module
without knowing the exact key in `action`:

```javascript
// Flag any task that shells out
ansible.project.playbooks.all(
  plays.all(tasks.all(module != /command|shell/))
)
```

The single-playbook queries above continue to work unchanged when the provider
is pointed at a file rather than a directory.
