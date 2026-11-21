This adds a `mount` object and an optional `mounts` list on the `container` object, so the file system mounts of a container (host paths, volumes and temporary file systems, and where they are attached) can be normalized. Today OCSF has no way to describe them.

### The problem

Mounting a sensitive host path into a container is one of the most common ways to escape from it. With a writable mount of the container runtime socket (`/var/run/docker.sock`), the host root (`/`), `/etc` or the kubelet directories, a container can start new privileged containers or change files on the host. The Kubernetes Pod Security Standards Baseline policy has a "HostPath Volumes" control for this reason: "HostPath volumes must be forbidden."

The `container` object has `image`, `is_privileged`, `labels`, `network_driver` and so on, but nothing for mounts. The EKS audit log mapping in `ocsf/examples` (AWS, v1.1.0) shows what that leads to. It puts `requestObject.spec.containers[].volumeMounts[].mountPath` into `api.request.containers[].image.path`, and joins the volume mount name into `image.uid`. Those are image attributes, so the mount information is still lost: a query cannot tell which host path is mounted, or whether it is writable.

### Where the data comes from

| source | host path | path in container | name | type | read only |
|---|---|---|---|---|---|
| Kubernetes pod spec (audit log `requestObject`, or the API) | `spec.volumes[].hostPath.path` | `spec.containers[].volumeMounts[].mountPath` | `volumes[].name` / `volumeMounts[].name` | the volume source (`hostPath`, `emptyDir`, `configMap`, `secret`, `persistentVolumeClaim`, ...) | `volumeMounts[].readOnly` |
| Container runtime, container inspect (`Mounts`) | `Source` ("Source location of the mount") | `Destination` | `Name` | `Type`: `bind`, `volume`, `tmpfs`, `npipe`, `cluster` | `RW` ("Whether the mount is mounted writable") |
| Falco container fields | `container.mount.source` | `container.mount.dest` | | | `container.mount.rdwr` |

### Why it matters

These detections all need the mount source and destination (MITRE ATT&CK T1611, Escape to Host):

- **Sigma**, "Container With A hostPath Mount Created" (tagged `attack.t1611`): "Attackers who have permissions to create a new pod in the cluster may create one with a writable hostPath volume and chroot to escape to the underlying node."
- **Elastic**, "Kubernetes Pod Created with a Sensitive hostPath Volume" (T1611, T1610): matches `kubernetes.audit.requestObject.spec.volumes.hostPath.path` against `/`, `/proc`, `/root`, `/var/run/docker.sock`, `/var/run/crio/crio.sock`, `/var/lib/kubelet`, `/etc/kubernetes` and others.
- **Falco**, "Create Sensitive Mount Pod" (Kubernetes audit, `ka.req.pod.volumes.hostpath intersects (/proc, /var/run/docker.sock, /, /etc, /root, ...)`), and the runtime rule "Launch Sensitive Mount Container", which checks `container.mount.dest[/proc*]`, `container.mount.dest[/var/run/docker.sock]` and similar on containers as they start.

With `mounts`, the Elastic and Falco checks become one normalized query for both Kubernetes audit logs and runtime sensors:

```
class_uid = 6003 AND api.operation = "create" AND resources.type = "pods"
  AND api.request.containers.mounts.type_id = 1
  AND api.request.containers.mounts.host_path IN ("/", "/etc", "/proc", "/var/run/docker.sock", "/var/lib/kubelet")
```

### Design

- **A new `mount` object, used from `container.mounts`.** A container usually has several mounts, and each one needs a few related fields (source, destination, type, read only), so they belong together in an object. I looked for an existing object to reuse. `file` describes one file, not a mapping between two paths, and `image.path` is the image's path, which is why the EKS mapping loses information.
- **Attributes:**
  - `path` (required): where the mount is attached inside the container. This reuses the generic `path`.
  - `host_path` (recommended): the host directory or file, for bind mounts and Kubernetes `hostPath` volumes. This is the field detections check.
  - `name` (optional): the volume name.
  - `is_read_only` (recommended): whether the container can write to it.
  - `type_id` / `type` (recommended): Bind, Volume, Temporary File System or Named Pipe, following the runtime mount types. Kubernetes `hostPath` is Bind, and the other Kubernetes volume sources (`emptyDir`, `configMap`, `secret`, persistent volume claims) are Volume.
- **New dictionary attributes** are `mounts`, `host_path` (`file_path_t`) and `is_read_only`, with generic descriptions. `name`, `path`, `type` and `type_id` are reused.
- **Left out for now.** Mount propagation and mount options (the runtime's `Propagation` and `Mode`, Falco's `container.mount.propagation` and `container.mount.mode`). They matter less for detection, and I'm happy to add them if reviewers want them.

If reviewers prefer a different name for the object (for example `volume_mount`) or for `host_path`, I can change them.

### What changes

- `objects/mount.json`: new `mount` object with `path`, `host_path`, `name`, `is_read_only`, `type` and `type_id`, and references to Kubernetes volumes, the Pod Security Standards and the container runtime API.
- `dictionary.json`: adds `mounts` (array of `mount`), `host_path` (`file_path_t`) and `is_read_only` (`boolean_t`).
- `objects/container.json`: adds `mounts` as `optional`.
- `changelog.d/<this PR>.md`: I'll add it once the PR has a number, as described in `changelog.d/README.md`.

### Example

Kubernetes audit event for a pod created with the runtime socket and the host root mounted (trimmed to the relevant parts of `requestObject`):

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "RequestResponse",
  "auditID": "9a4e1f0c-27d3-4b6e-a5c8-0e3f9d2b7c61",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/tools/pods",
  "verb": "create",
  "user": { "username": "dev-carol@example.com" },
  "sourceIPs": ["10.40.7.62"],
  "userAgent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
  "objectRef": { "resource": "pods", "namespace": "tools", "name": "agent-0", "apiVersion": "v1" },
  "requestObject": {
    "kind": "Pod",
    "spec": {
      "volumes": [
        { "name": "dockersock", "hostPath": { "path": "/var/run/docker.sock" } },
        { "name": "hostroot", "hostPath": { "path": "/" } }
      ],
      "containers": [
        {
          "name": "agent",
          "image": "registry.example.com/tools/agent:2.4.1",
          "volumeMounts": [
            { "name": "dockersock", "mountPath": "/var/run/docker.sock" },
            { "name": "hostroot", "mountPath": "/host", "readOnly": true },
            { "name": "kube-api-access-7x2kd", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount", "readOnly": true }
          ]
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
| `spec.containers[].name`, `image` | `api.request.containers[].name`, `api.request.containers[].image` |
| **`volumeMounts[].mountPath`** | **`mounts[].path`**, instead of `image.path` |
| **`volumes[].hostPath.path`** (joined on the volume name) | **`mounts[].host_path`**, with `type_id` = 1 (Bind) |
| **`volumeMounts[].name`** | **`mounts[].name`** |
| **`volumeMounts[].readOnly`** (unset means writable) | **`mounts[].is_read_only`** |
| a volume that is not a `hostPath` (the service account token) | `mounts[].type_id` = 2 (Volume) |

Result, API Activity (6003), Create:

```json
{
  "activity_id": 1,
  "category_uid": 6,
  "class_uid": 6003,
  "type_uid": 600301,
  "severity_id": 1,
  "status_id": 1,
  "time": 1795268744903,
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
      "uid": "9a4e1f0c-27d3-4b6e-a5c8-0e3f9d2b7c61",
      "containers": [
        {
          "name": "agent",
          "image": { "name": "registry.example.com/tools/agent", "tag": "2.4.1", "uid": "registry.example.com/tools/agent:2.4.1" },
          "mounts": [
            { "name": "dockersock", "type_id": 1, "type": "Bind", "host_path": "/var/run/docker.sock", "path": "/var/run/docker.sock", "is_read_only": false },
            { "name": "hostroot", "type_id": 1, "type": "Bind", "host_path": "/", "path": "/host", "is_read_only": true },
            { "name": "kube-api-access-7x2kd", "type_id": 2, "type": "Volume", "path": "/var/run/secrets/kubernetes.io/serviceaccount", "is_read_only": true }
          ]
        }
      ]
    },
    "response": { "code": 201 }
  },
  "actor": {
    "user": { "name": "dev-carol@example.com", "type_id": 1 },
    "authorizations": [{ "decision": "allow" }]
  },
  "src_endpoint": { "ip": "10.40.7.62" },
  "http_request": {
    "user_agent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
    "url": { "path": "/api/v1/namespaces/tools/pods" }
  },
  "resources": [{ "type": "pods", "name": "agent-0", "namespace": "tools" }]
}
```

The first mount, a writable `/var/run/docker.sock`, is what the Elastic, Falco and Sigma rules above are written to catch. A runtime sensor maps the same way into `process.container.mounts`, from the runtime's `Mounts` or Falco's `container.mount.*` fields.

### Testing

- The sample event validates against the API Activity class compiled from this branch. On current `main` the only error is `api.request.containers.mounts` being an unknown attribute.
- `python .github/scripts/format_schema.py --check` reports no files that need formatting (the new object is named `mount.json` after its `name`), and every changed file ends with a newline.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings. The compiled `mount` object has `path` required, `host_path` and `is_read_only` recommended, and `container.mounts` as an array of `mount`.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- Kubernetes, Volumes, hostPath: https://kubernetes.io/docs/concepts/storage/volumes/#hostpath
- Kubernetes Pod Security Standards, Baseline policy, HostPath Volumes: https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Docker Engine API v1.47 (container inspect, `Mounts`): https://docs.docker.com/reference/api/engine/version/v1.47/
- OCSF examples, EKS Audit Logs mapping (AWS v1.1.0): https://github.com/ocsf/examples/tree/main/mappings/markdown/AWS/v1.1.0/EKS%20Audit%20Logs
- Sigma, Container With A hostPath Mount Created: https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_hostpath_mount.yml
- Elastic, Kubernetes Pod Created with a Sensitive hostPath Volume: https://github.com/elastic/detection-rules/blob/main/rules/integrations/kubernetes/privilege_escalation_pod_created_with_sensitive_hostpath_volume.toml
- Falco Kubernetes audit rules ("Create Sensitive Mount Pod"): https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml
- Falco sandbox rules ("Launch Sensitive Mount Container"): https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml
- MITRE ATT&CK T1611 Escape to Host: https://attack.mitre.org/techniques/T1611/
- MITRE ATT&CK T1610 Deploy Container: https://attack.mitre.org/techniques/T1610/
