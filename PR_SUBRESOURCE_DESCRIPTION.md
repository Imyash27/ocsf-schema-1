This adds an optional `subresource` attribute to the `resource_details` object, so the part of a resource that an API request targets, such as the `exec` subresource of a Kubernetes pod, has its own place instead of being dropped or joined into `resources[].type`.

### The problem

Some APIs address a part of a resource, or an operation on it, separately from the resource itself. The Kubernetes API docs put it as "For some resource types, the API includes one or more sub-resources, which are represented as URI paths below the resource". Running a command in a pod is a `create` on `pods/exec`, attaching is `pods/attach`, port forwarding is `pods/portforward`, and reading logs is `pods/log`.

Kubernetes audit events report this in `objectRef.subresource`, next to `objectRef.resource`. `resource_details` has `type`, `name`, `namespace` and `uid`, but no subresource. That means two things today:

- The OCSF mapping for EKS audit logs in `ocsf/examples` (AWS, v1.1.0) fills `resources[].type` with `concat(objectRef.resource;objectRef.subresource)`. So `resources[].type` no longer says `pods` for an exec, and a query has to parse the type string to tell an exec from a pod creation.
- Other mappings drop the subresource, and then `create` on `pods` and `create` on `pods/exec` look the same, although one starts a workload and the other runs a shell inside one.

### Where the data comes from

| source | field | examples |
|---|---|---|
| Kubernetes audit event | `objectRef.subresource`, next to `objectRef.resource`, `objectRef.name` and `objectRef.namespace` | `exec`, `attach`, `portforward`, `log`, `status`, `eviction` |
| Kubernetes request URI | the path segment after the resource name | `/api/v1/namespaces/payments/pods/web-7d4b9c6f5-x2k8q/exec` |
| Falco Kubernetes audit fields | `ka.target.subresource` | used by the rules below |

### Why it matters

Exec into a pod is MITRE ATT&CK **T1609, Container Administration Command**, and the rules for it key on the subresource:

- **Sigma, "Potential Remote Command Execution In Pod Container"**: `verb: 'create'`, `objectRef.resource: 'pods'`, `objectRef.subresource: 'exec'`, tagged `attack.t1609`.
- **Elastic, "Kubernetes User Exec into Pod"** (T1609): `kubernetes.audit.objectRef.subresource == "exec"`. Its triage notes say to check `objectRef.resource` and `objectRef.subresource` "to verify that the action involved a pod and the 'exec' subresource".
- **Falco, "Attach/Exec Pod"**: `ka.target.subresource in (exec,attach)`. **Falco, "port-forward"**: `ka.target.subresource in (portforward)`.

With the attribute, the Sigma rule maps directly to normalized data:

```
class_uid = 6003 AND api.operation = "create"
  AND resources.type = "pods" AND resources.subresource = "exec"
```

### Design

- **On `resource_details`.** API Activity carries the target in `resources[]`, which is `resource_details`, and that object already has `namespace` for the same Kubernetes requests. The subresource belongs to the resource the request targets, so it sits next to `type` and `name`.
- **A string, not an enum.** Subresources are defined by each resource type, and new ones get added, so there is no fixed list to normalize to. The value is the name from the source, for example `exec`.
- **Kept generic.** The dictionary description does not mention Kubernetes, and the object description uses Kubernetes as the example, the same way `namespace` is described. Other APIs that address a part of a resource can use it too.
- **`resources[].type` stays the resource type.** With `subresource` available, a mapping can put `objectRef.resource` in `type` and `objectRef.subresource` here, and I'd suggest updating the EKS example mapping that way once this is in.
- **Optional.** Most requests do not target a subresource.

If reviewers would rather see this in a future Kubernetes extension (#1131), I'm open to that, but `resource_details` already carries `namespace` in core, and `subresource` fits next to it.

### What changes

- `dictionary.json`: adds `subresource` (`string_t`) with a generic description.
- `objects/resource_details.json`: adds `subresource` as `optional`, with the specific description.
- `.github/.project-words.txt`: adds `Subresource` and `subresource` for cspell.
- `changelog.d/<this PR>.md`: I'll add it once the PR has a number, as described in `changelog.d/README.md`.

### Example

Kubernetes audit event for `kubectl exec -it web-7d4b9c6f5-x2k8q -n payments -- sh` (trimmed):

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "0b7e2f41-9c55-4d1e-8a3a-5f6d2c9e1b77",
  "stage": "ResponseStarted",
  "requestURI": "/api/v1/namespaces/payments/pods/web-7d4b9c6f5-x2k8q/exec?command=sh&container=web&stdin=true&stdout=true&tty=true",
  "verb": "create",
  "user": { "username": "bob@example.com", "groups": ["dev-team", "system:authenticated"] },
  "sourceIPs": ["10.40.7.33"],
  "userAgent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
  "objectRef": {
    "resource": "pods",
    "namespace": "payments",
    "name": "web-7d4b9c6f5-x2k8q",
    "apiVersion": "v1",
    "subresource": "exec"
  },
  "responseStatus": { "metadata": {}, "code": 101 },
  "stageTimestamp": "2026-11-18T09:25:25.418204Z",
  "annotations": { "authorization.k8s.io/decision": "allow" }
}
```

Field mapping (following the `ocsf/examples` EKS mapping except for the subresource):

| Kubernetes field | OCSF |
|---|---|
| `verb` = `create` | `api.operation`, `activity_id` = 1 (Create) |
| `auditID` | `api.request.uid` |
| `stage` | `message` |
| `stageTimestamp` | `time` |
| `user.username`, `user.groups` | `actor.user.name`, `actor.user.groups` |
| `sourceIPs` | `src_endpoint.ip` |
| `userAgent`, `requestURI` | `http_request.user_agent`, `http_request.url` |
| `objectRef.resource` | `resources[].type` |
| **`objectRef.subresource`** | **`resources[].subresource`**, instead of being joined into `resources[].type` |
| `objectRef.name`, `objectRef.namespace` | `resources[].name`, `resources[].namespace` |
| `objectRef.apiVersion` | `api.version` |
| `responseStatus.code` | `api.response.code` |

Result, API Activity (6003), Create:

```json
{
  "activity_id": 1,
  "category_uid": 6,
  "class_uid": 6003,
  "type_uid": 600301,
  "severity_id": 1,
  "status_id": 1,
  "time": 1795080325418,
  "message": "ResponseStarted",
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Kubernetes API server", "vendor_name": "Kubernetes" },
    "log_name": "kube-apiserver-audit"
  },
  "cloud": { "provider": "AWS", "region": "us-east-1" },
  "api": {
    "operation": "create",
    "version": "v1",
    "request": { "uid": "0b7e2f41-9c55-4d1e-8a3a-5f6d2c9e1b77" },
    "response": { "code": 101 }
  },
  "actor": {
    "user": { "name": "bob@example.com", "type_id": 1, "groups": [{ "name": "dev-team" }, { "name": "system:authenticated" }] },
    "authorizations": [{ "decision": "allow" }]
  },
  "src_endpoint": { "ip": "10.40.7.33" },
  "http_request": {
    "user_agent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
    "url": { "path": "/api/v1/namespaces/payments/pods/web-7d4b9c6f5-x2k8q/exec", "query_string": "command=sh&container=web&stdin=true&stdout=true&tty=true" }
  },
  "resources": [
    { "type": "pods", "subresource": "exec", "name": "web-7d4b9c6f5-x2k8q", "namespace": "payments" }
  ]
}
```

### Testing

- The sample event validates against the API Activity class compiled from this branch. On current `main` the only error is `resources.subresource` being an unknown attribute.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled `resource_details` object has `subresource` as an optional string.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- Kubernetes, API concepts (sub-resources): https://kubernetes.io/docs/reference/using-api/api-concepts/
- Kubernetes, Audit event API (`objectRef`): https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- OCSF examples, EKS Audit Logs mapping (AWS v1.1.0): https://github.com/ocsf/examples/tree/main/mappings/markdown/AWS/v1.1.0/EKS%20Audit%20Logs
- Sigma, Potential Remote Command Execution In Pod Container: https://github.com/SigmaHQ/sigma/blob/master/rules/application/kubernetes/audit/kubernetes_audit_exec_into_container.yml
- Elastic, Kubernetes User Exec into Pod: https://www.elastic.co/guide/en/security/current/kubernetes-user-exec-into-pod.html
- Falco Kubernetes audit rules ("Attach/Exec Pod", "port-forward"): https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml
- MITRE ATT&CK T1609 Container Administration Command: https://attack.mitre.org/techniques/T1609/
