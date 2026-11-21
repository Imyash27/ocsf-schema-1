This adds `is_host_network`, `is_host_pid` and `is_host_ipc` to the `container` object, for containers that share the network, PID or IPC namespace of their host. It is a follow-up to `is_privileged` (#1805), and covers the other host isolation settings that pod and container specs carry.

### The problem

Containers are isolated from their host mainly through Linux namespaces. A container can be told to share some of them with the host instead:

- **Host network**: the container uses the host's network interfaces, can bind to the host's ports, and can reach services that only listen on the host's loopback address.
- **Host PID**: the container sees every process on the host, and with enough privileges can signal, trace or enter them.
- **Host IPC**: the container can use the host's shared memory and other IPC objects.

The Kubernetes Pod Security Standards treat this the same way as privileged mode. The Baseline policy has a "Host Namespaces" control ("Sharing the host namespaces must be disallowed.") that restricts `spec.hostNetwork`, `spec.hostPID` and `spec.hostIPC` to unset or `false`.

The `container` object has `is_privileged`, but nothing for these three, so they end up in `unmapped`.

### Where the data comes from

| source | host network | host PID | host IPC |
|---|---|---|---|
| Kubernetes pod spec (in audit log `requestObject`, or the API) | `spec.hostNetwork` | `spec.hostPID` | `spec.hostIPC` |
| Container runtime, container inspect (`HostConfig`) | `NetworkMode` = `host` | `PidMode` = `host` | `IpcMode` = `host` |
| Falco Kubernetes audit fields | `ka.req.pod.host_network` | `ka.req.pod.host_pid` | `ka.req.pod.host_ipc` |

### Why it matters

Each of these is a known way to break out of a container (MITRE ATT&CK T1611, Escape to Host), and existing rules alert on them:

- **Elastic**: "Kubernetes Pod Created With HostNetwork" (`kubernetes.audit.requestObject.spec.hostNetwork:true`), "Kubernetes Pod Created With HostPID" (`spec.hostPID:true`) and "Kubernetes Pod Created With HostIPC" (`spec.hostIPC:true`). All three are mapped to T1611 and T1610 (Deploy Container).
- **Falco**: "Create HostNetwork Pod" (`ka.req.pod.host_network intersects (true)`, which the rules file notes corresponds to K8s CIS Benchmark 1.7.4), "Create HostPid Pod" and "Create HostIPC Pod".

With the attributes, these rules work on normalized data, whether the source is a Kubernetes audit log (`api.request.containers[]`) or a runtime sensor (`process.container`):

```
class_uid = 6003 AND api.operation = "create" AND resources.type = "pods"
  AND (api.request.containers.is_host_pid = true OR api.request.containers.is_host_network = true)
```

### Design

- **On `container`, next to `is_privileged`.** The same pod and runtime specs carry these settings, and #1805 put `is_privileged` on `container`. In Kubernetes they are set on the pod, so every container in the pod gets the same value. A producer reading a pod spec sets them on each container it maps.
- **Three booleans, not one list.** They match the three fields that Kubernetes, the container runtime and Falco expose, and they keep queries simple. I considered a single `host_namespaces` list (for example `["network", "pid"]`), but a list of strings is harder to query and validate, and there are only three namespaces a container can share this way. If reviewers prefer the list, I can switch.
- **Optional.** Most containers don't share host namespaces, and most sources don't report it.
- **Dictionary entries are generic** ("See specific usage"), and the container descriptions give the Kubernetes and runtime settings as examples. Each attribute references the Pod Security Standards and the container runtime API.

### What changes

- `dictionary.json`: adds `is_host_ipc`, `is_host_network` and `is_host_pid` (`boolean_t`).
- `objects/container.json`: adds the three attributes as `optional`, with specific descriptions and references.
- `changelog.d/1841.md`: the changelog entries for this PR, as described in `changelog.d/README.md`. The `changelog.py check --pr 1841` run passes.

### Example

Kubernetes audit event for a pod created with `hostPID` and `hostNetwork` (trimmed to the relevant parts of `requestObject`):

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "5d1c7e2a-4b9f-4a63-8e0d-2f7b6c1a9e54",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/ci/pods",
  "verb": "create",
  "user": { "username": "system:serviceaccount:ci:deployer" },
  "sourceIPs": ["10.40.7.51"],
  "userAgent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
  "objectRef": { "resource": "pods", "namespace": "ci", "name": "node-debug", "apiVersion": "v1" },
  "requestObject": {
    "kind": "Pod",
    "metadata": { "name": "node-debug", "namespace": "ci" },
    "spec": {
      "hostPID": true,
      "hostNetwork": true,
      "containers": [
        {
          "name": "debug",
          "image": "docker.io/library/alpine:3.20",
          "securityContext": { "privileged": true }
        }
      ]
    }
  },
  "responseStatus": { "metadata": {}, "code": 201 },
  "annotations": { "authorization.k8s.io/decision": "allow" }
}
```

Field mapping (other fields follow the `ocsf/examples` EKS audit mapping):

| Kubernetes field | OCSF |
|---|---|
| `verb` = `create` | `api.operation`, `activity_id` = 1 (Create) |
| `auditID` | `api.request.uid` |
| `objectRef.resource`, `name`, `namespace` | `resources[].type`, `resources[].name`, `resources[].namespace` |
| `spec.containers[].name`, `image` | `api.request.containers[].name`, `api.request.containers[].image` |
| `securityContext.privileged` | `api.request.containers[].is_privileged` |
| **`spec.hostPID`** | **`api.request.containers[].is_host_pid`**, no place for it today |
| **`spec.hostNetwork`** | **`api.request.containers[].is_host_network`**, no place for it today |
| **`spec.hostIPC`** (not set) | **`api.request.containers[].is_host_ipc`** = false |

Result, API Activity (6003), Create:

```json
{
  "activity_id": 1,
  "category_uid": 6,
  "class_uid": 6003,
  "type_uid": 600301,
  "severity_id": 1,
  "status_id": 1,
  "time": 1795268120544,
  "message": "ResponseComplete",
  "metadata": {
    "version": "1.11.0",
    "product": { "name": "Kubernetes API server", "vendor_name": "Kubernetes" },
    "log_name": "kube-apiserver-audit"
  },
  "cloud": { "provider": "AWS", "region": "us-east-1" },
  "api": {
    "operation": "create",
    "version": "v1",
    "request": {
      "uid": "5d1c7e2a-4b9f-4a63-8e0d-2f7b6c1a9e54",
      "containers": [
        {
          "name": "debug",
          "image": { "name": "docker.io/library/alpine", "tag": "3.20", "uid": "docker.io/library/alpine:3.20" },
          "is_host_pid": true,
          "is_host_network": true,
          "is_host_ipc": false,
          "is_privileged": true
        }
      ]
    },
    "response": { "code": 201 }
  },
  "actor": {
    "user": { "name": "system:serviceaccount:ci:deployer", "type_id": 4 },
    "authorizations": [{ "decision": "allow" }]
  },
  "src_endpoint": { "ip": "10.40.7.51" },
  "http_request": {
    "user_agent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
    "url": { "path": "/api/v1/namespaces/ci/pods" }
  },
  "resources": [{ "type": "pods", "name": "node-debug", "namespace": "ci" }]
}
```

`image.uid` is required by the `image` object, and a pod spec has no image ID, so the sample uses the image reference.

### Testing

- The sample event validates against the API Activity class compiled from this branch. On current `main` the only errors are the three new attributes being unknown.
- `python .github/scripts/format_schema.py --check` reports no files that need formatting, and every changed file ends with a newline.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- Kubernetes Pod Security Standards, Baseline policy, Host Namespaces: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Docker Engine API v1.47 (container create and inspect, `HostConfig.NetworkMode`, `PidMode`, `IpcMode`): https://docs.docker.com/reference/api/engine/version/v1.47/
- Elastic, Kubernetes Pod Created With HostNetwork: https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_hostnetwork.toml
- Elastic, Kubernetes Pod Created With HostPID: https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_hostpid.toml
- Elastic, Kubernetes Pod Created With HostIPC: https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_hostipc.toml
- Falco Kubernetes audit rules ("Create HostNetwork Pod", "Create HostPid Pod", "Create HostIPC Pod"): https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml
- MITRE ATT&CK T1611 Escape to Host: https://attack.mitre.org/techniques/T1611/
- MITRE ATT&CK T1610 Deploy Container: https://attack.mitre.org/techniques/T1610/
- Related: #1805 (`is_privileged` on `container`)
