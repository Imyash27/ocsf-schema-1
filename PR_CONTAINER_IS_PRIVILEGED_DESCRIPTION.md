This adds an optional `is_privileged` boolean to the `container` object, so a container running in privileged mode can be flagged in normalized events.

### The problem

The `container` object today has the name, id, image, runtime, orchestrator, labels and so on, but nothing that says how the container is confined. The one setting that matters most for that is privileged mode. A privileged container is not really isolated from the host:

- Docker's `--privileged` flag "Enables all Linux kernel capabilities", "Disables the default seccomp profile", "Disables the default AppArmor profile", "Disables the SELinux process label", "Grants access to all host devices" and makes `/sys` and the cgroup mounts read-write. The Docker docs put it plainly: "A container with `--privileged` is not a securely sandboxed process."
- Kubernetes sets the same thing per container with `securityContext.privileged`. The Pod Security Standards Baseline policy says "Privileged Pods disable most security mechanisms and must be disallowed", and only allows the field to be unset or `false`.

When a runtime security tool reports activity inside a privileged container, the flag has nowhere to go in OCSF, so it ends up in `unmapped`.

### Where the data comes from

| source | field | example |
|---|---|---|
| Falco (any rule with container context) | `container.privileged` ("'true' for containers running as privileged, 'false' otherwise") | `"container.privileged": true` |
| Docker Engine (`docker inspect`, events API) | `HostConfig.Privileged` | `"Privileged": true` |
| Kubernetes (pod spec, and the audit log `requestObject` for pod create) | `spec.containers[*].securityContext.privileged` (also `initContainers`, `ephemeralContainers`) | `"privileged": true` |

### Why it matters

Privileged containers are the most common starting point for container escape.

- MITRE ATT&CK T1611 (Escape to Host) lists "utilizing a privileged container to run commands or load a malicious kernel module on the underlying host" as an example, and T1610 (Deploy Container) notes that an adversary "may attempt to deploy a privileged or vulnerable container into a specific node in order to Escape to Host".
- Falco's default ruleset keys on the flag directly. "Debugfs Launched in Privileged Container" (tagged T1611) fires on `spawned_process and container and container.privileged=true and proc.name=debugfs`, and "Launch Privileged Container" (T1610) fires when a container starts with `container.privileged=true`.
- It is also useful as context. As the Falco rule description says, if another rule triggers inside a privileged container, "it could be seen as more suspicious, prompting a closer inspection." With the flag normalized, any detection can be scored higher when `process.container.is_privileged = true`.

An example query on normalized data: `class_uid = 1007 AND activity_id = 1 AND process.container.is_privileged = true AND process.name IN ("debugfs", "insmod", "nsenter", "mount")`.

### Design

- **A boolean on `container`.** Privileged mode is an on or off setting in every runtime, so a boolean is the simplest shape and matches the other `is_*` flags in the schema.
- **Generic dictionary entry, specific usage on `container`.** Following the review feedback on #1792, the dictionary description is generic ("Indicates that the object runs with privileges that remove most of the isolation normally applied to it. See specific usage."), and the container specific description and the Docker and Kubernetes references are on the `container` object. That leaves room to reuse it later, for example for a privileged pod or a privileged virtual machine, without changing the dictionary.
- **Optional.** Not every source knows the container configuration, so it is optional.
- **Out of scope.** Other confinement settings (added capabilities, host namespaces such as `hostPID` and `hostNetwork`, `allowPrivilegeEscalation`) are related but separate. They could follow the same pattern if there is demand.

### What changes

- `dictionary.json`: adds `is_privileged` (`boolean_t`) with the generic description.
- `objects/container.json`: adds `is_privileged` as `optional`, with the container specific description and references.
- `CHANGELOG.md`: entries under Dictionary Attributes and Objects.

### Example

Falco alert from the default rule "Debugfs Launched in Privileged Container" (JSON output):

```json
{
  "hostname": "node-1",
  "priority": "Warning",
  "rule": "Debugfs Launched in Privileged Container",
  "source": "syscall",
  "tags": ["T1611", "cis", "container", "maturity_stable", "mitre_privilege_escalation", "process"],
  "time": "2026-11-09T10:21:04.123456789Z",
  "output": "Debugfs launched started in a privileged container | evt_type=execve user=root user_uid=0 process=debugfs proc_exepath=/usr/sbin/debugfs parent=bash command=debugfs /dev/sda1",
  "output_fields": {
    "container.id": "3ad7b26ded6d",
    "container.name": "debug-shell",
    "container.image.repository": "docker.io/library/ubuntu",
    "container.image.tag": "22.04",
    "container.privileged": true,
    "evt.type": "execve",
    "proc.name": "debugfs",
    "proc.exepath": "/usr/sbin/debugfs",
    "proc.cmdline": "debugfs /dev/sda1",
    "proc.pname": "bash",
    "user.name": "root",
    "user.uid": 0
  }
}
```

Field mapping:

| Falco field | OCSF |
|---|---|
| `rule` | `metadata.event_code`, and the alert text in `message` |
| `evt.type` (`execve`) | `activity_id` = 1 (Launch) |
| `proc.name`, `proc.exepath`, `proc.cmdline` | `process.name`, `process.file.path`, `process.cmd_line` |
| `proc.pname` | `actor.process.name` |
| `user.name`, `user.uid` | `process.user.name`, `process.user.uid` |
| `container.id`, `container.name` | `process.container.uid`, `process.container.name` |
| `container.image.repository`, `container.image.tag` | `process.container.image.name`, `process.container.image.tag` |
| **`container.privileged` (`true`)** | **`process.container.is_privileged` = `true`**, no place for it today |

Result, Process Activity (1007), Launch:

```json
{
  "activity_id": 1,
  "category_uid": 1,
  "class_uid": 1007,
  "type_uid": 100701,
  "severity_id": 3,
  "time": 1794219664123,
  "message": "Debugfs launched started in a privileged container",
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Falco", "vendor_name": "The Falco Project" },
    "event_code": "Debugfs Launched in Privileged Container"
  },
  "device": { "type_id": 1, "hostname": "node-1", "os": { "name": "Linux", "type_id": 200 } },
  "actor": {
    "process": { "pid": 48211, "name": "bash" }
  },
  "process": {
    "pid": 48377,
    "name": "debugfs",
    "cmd_line": "debugfs /dev/sda1",
    "file": { "name": "debugfs", "path": "/usr/sbin/debugfs", "type_id": 1 },
    "user": { "name": "root", "uid": "0" },
    "container": {
      "uid": "3ad7b26ded6d",
      "name": "debug-shell",
      "image": { "uid": "sha256:97271d29cb7956f0908cfb1449610a2cd9cb46b004ac8af25f0255663eb364ba", "name": "docker.io/library/ubuntu", "tag": "22.04" },
      "is_privileged": true
    }
  }
}
```

The same flag from the other sources: `docker inspect` with `"HostConfig": { "Privileged": true }`, or a Kubernetes pod create in the audit log with `securityContext.privileged: true`, both map to `container.is_privileged` = `true`.

### Testing

- The sample event validates against the Process Activity class compiled from this branch. On current `main` the only error is `process.container.is_privileged` being an unknown attribute.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- Docker, `docker container run`, `--privileged`: https://docs.docker.com/reference/cli/docker/container/run/
- Kubernetes Pod Security Standards, Baseline, Privileged Containers: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Falco supported fields, `container.privileged`: https://falco.org/docs/reference/rules/supported-fields/
- Falco default rules, "Debugfs Launched in Privileged Container": https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
- Falco incubating rules, "Launch Privileged Container": https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml
- MITRE ATT&CK T1611, Escape to Host: https://attack.mitre.org/techniques/T1611/
- MITRE ATT&CK T1610, Deploy Container: https://attack.mitre.org/techniques/T1610/

The Docker and Kubernetes links are also in the attribute `references`.
