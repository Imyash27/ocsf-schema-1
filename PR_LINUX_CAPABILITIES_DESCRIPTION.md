This adds an optional `effective_capabilities` attribute to the Linux `process` object, a list of capability names, so the effective capability set of a process can be normalized instead of going to `unmapped`.

### The problem

On Linux, root is not a single privilege. The kernel splits it into capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_DAC_OVERRIDE`, `CAP_NET_RAW` and so on), and each thread has several capability sets. The one that decides what a process can actually do is the effective set. The capabilities(7) man page describes it as "the set of capabilities used by the kernel to perform permission checks for the thread."

So the user ID alone does not tell you what a process is allowed to do. A process running as uid 0 inside a container usually has a reduced set, and a process running as a normal user can still hold extra capabilities through file capabilities or the container configuration.

OCSF has the Linux user fields (`auid`, `euid`, `egid`, through the Linux extension) but nothing for capabilities. Runtime security tools report them, and today they end up in `unmapped`.

### Where the data comes from

| source | field | example |
|---|---|---|
| Falco | `thread.cap_effective` ("The effective capabilities set"), also `thread.cap_permitted` and `thread.cap_inheritable` | `CAP_CHOWN CAP_DAC_OVERRIDE ... CAP_SYS_ADMIN` |
| Tetragon | `process.cap.effective`, a repeated `CapabilitiesType` ("Effective set indicates what capabilities are active in a process. This is the set used by the kernel to perform permission checks for the thread."), also `permitted` and `inheritable` | `["CAP_SYS_ADMIN", "CAP_NET_RAW"]` |
| Linux kernel | `CapEff` in `/proc/[pid]/status`, as a hex mask | `CapEff: 000001ffffffffff` |

### Why it matters

Several of Falco's default rules check the effective set as part of their condition, because the capability, not the user ID, is what makes the activity possible:

- "Linux Kernel Module Injection Detected" requires `thread.cap_effective icontains sys_module` for module loads from a container.
- "Detect release_agent File Container Escapes" (tagged MITRE ATT&CK T1611, Escape to Host) requires `thread.cap_effective contains CAP_SYS_ADMIN`.

Capabilities are also useful as context on any process event. A process in a container that holds `CAP_SYS_ADMIN` or `CAP_SYS_MODULE` is much more interesting than one with the default set, so detections can raise severity based on it. With the attribute normalized, that is one query across sources, for example `class_uid = 1007 AND process.container.uid IS NOT NULL AND "CAP_SYS_ADMIN" IN process.effective_capabilities`.

### Design

- **Linux extension.** Capabilities are a Linux kernel feature, so the attribute is added to the Linux `process` object, next to the Linux user fields.
- **Base dictionary.** Following #1538, which moved the Linux extension attributes into the base dictionary so both the Linux and macOS extensions can use them, the dictionary entry is in `dictionary.json` and the Linux `process` object only sets the requirement.
- **List of names, not a mask.** The value is an array of capability names as the man page defines them (`CAP_SYS_ADMIN` and so on). Falco and Tetragon already give names, and the names are the same on every kernel. A producer reading `CapEff` from `/proc` converts the mask to names.
- **Effective set only.** The effective set is the one the kernel checks and the one detections use. The permitted, inheritable, bounding and ambient sets could be added the same way if there is demand.
- **Name.** `capabilities` is already used in the dictionary for RDP capabilities, so this uses `effective_capabilities`, which also says which set it is.

### What changes

- `dictionary.json`: adds `effective_capabilities` (array of `string_t`) with the description and a reference to capabilities(7).
- `extensions/linux/objects/process.json`: adds `effective_capabilities` as `optional`.
- `CHANGELOG.md`: entries under Dictionary Attributes and Platform Extensions.

### Example

Tetragon `process_exec` for `mount` started by a shell inside a container that was given `CAP_SYS_ADMIN` (trimmed):

```json
{
  "process_exec": {
    "process": {
      "pid": 51022,
      "uid": 0,
      "binary": "/usr/bin/mount",
      "arguments": "-t tmpfs none /mnt",
      "docker": "9f3c1a7e52b0",
      "cap": {
        "effective": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_ADMIN"]
      }
    },
    "parent": { "pid": 51010, "binary": "/usr/bin/bash" }
  },
  "node_name": "node-3",
  "time": "2026-11-09T11:21:51.540Z"
}
```

Field mapping:

| Tetragon field | OCSF |
|---|---|
| `process_exec` | `activity_id` = 1 (Launch) |
| `process.pid`, `process.binary`, `process.arguments` | `process.pid`, `process.file.path`, `process.cmd_line` |
| `process.uid` | `process.user.uid` |
| `process.docker` | `process.container.uid` |
| `parent.pid`, `parent.binary` | `actor.process.pid`, `actor.process.file.path` |
| **`process.cap.effective`** | **`process.effective_capabilities`**, no place for it today |

Result, Process Activity (1007), Launch:

```json
{
  "activity_id": 1,
  "category_uid": 1,
  "class_uid": 1007,
  "type_uid": 100701,
  "severity_id": 1,
  "time": 1794223311540,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Tetragon", "vendor_name": "Cilium" },
    "event_code": "process_exec",
    "extensions": [{ "name": "linux", "uid": "1", "version": "1.10.0" }]
  },
  "device": { "type_id": 1, "hostname": "node-3", "os": { "name": "Linux", "type_id": 200 } },
  "actor": {
    "process": { "pid": 51010, "name": "bash", "file": { "name": "bash", "path": "/usr/bin/bash", "type_id": 1 } }
  },
  "process": {
    "pid": 51022,
    "name": "mount",
    "cmd_line": "mount -t tmpfs none /mnt",
    "file": { "name": "mount", "path": "/usr/bin/mount", "type_id": 1 },
    "user": { "uid": "0" },
    "effective_capabilities": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_ADMIN"],
    "container": {
      "uid": "9f3c1a7e52b0",
      "name": "web-frontend",
      "image": { "uid": "sha256:4f53e9c8ad1d0e1f9b1c4f1f8b8d0a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f", "name": "docker.io/library/nginx", "tag": "1.27" }
    }
  }
}
```

A Falco event maps the same way: `thread.cap_effective` is a space separated list, so the producer splits it into the array.

### Testing

- The sample event validates against the Process Activity class compiled from this branch. On current `main` the only error is `process.effective_capabilities` being an unknown attribute.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled `process` object has `effective_capabilities` as an optional string array.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- capabilities(7) man page, thread capability sets: https://man7.org/linux/man-pages/man7/capabilities.7.html
- Falco supported fields, `thread.cap_effective`: https://falco.org/docs/reference/rules/supported-fields/
- Falco default rules: https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
- Tetragon gRPC API, `Process.cap` and `Capabilities`: https://tetragon.io/docs/reference/grpc-api/
- MITRE ATT&CK T1611, Escape to Host: https://attack.mitre.org/techniques/T1611/

The capabilities(7) link is also in the attribute `references`.
