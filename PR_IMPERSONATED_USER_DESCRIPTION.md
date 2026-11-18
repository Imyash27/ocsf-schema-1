This adds an optional `impersonated_user` attribute (a `user` object) to the `actor` object, for requests that are made through impersonation, so the identity the request was authorized as no longer gets dropped or ends up in `unmapped`.

### The problem

With impersonation, two identities are involved in one request: the one that authenticated, and the one the request acts as. Authorization is decided on the second one. The `actor` object only has `user`, so a producer has to pick one of them and lose the other.

Kubernetes is the clearest case. The API server docs describe it as "Impersonation requests first authenticate as the requesting user, then switch to the impersonated user info", and "authorization acts on impersonated user info". Every audit event records both: `user` ("Authenticated user information") and `impersonatedUser` ("Impersonated user information").

The OCSF mapping for EKS audit logs in `ocsf/examples` (AWS, v1.1.0) shows what happens today. It maps `user.username` to `actor.user.name`, has no row for `impersonatedUser`, and states that "Any fields not present in an explicit mapping will be mapped to the unmapped object."

Cloud audit logs have the same shape. In Google Cloud audit logs, `authenticationInfo.principalEmail` is "The email address of the authenticated user (or service account on behalf of third party principal) making the request", and `serviceAccountDelegationInfo` is the "Identity delegation history of an authenticated service account that makes the request. It contains information on the real authorities that try to access GCP resources by delegating on a service account." When someone impersonates a service account, that is two identities again.

Today the only impersonation concept in OCSF is the `Impersonate` value of `account_switch_type_id` in the Authentication class (#1460), which reports the switch itself. Nothing on `actor` says that an API Activity or any other event was done as an impersonated identity.

### Where the data comes from

| source | authenticated identity | impersonated identity |
|---|---|---|
| Kubernetes audit event | `user` (`username`, `uid`, `groups`, `extra`) | `impersonatedUser` (same fields), set from the `Impersonate-User`, `Impersonate-Uid`, `Impersonate-Group` and `Impersonate-Extra-*` headers |
| Google Cloud audit log | `serviceAccountDelegationInfo[].firstPartyPrincipal.principalEmail` | `authenticationInfo.principalEmail`, the service account |

### Why it matters

Impersonation is a common way to use more privilege than an identity has on its own, and the detections need both identities:

- **Elastic, "Kubernetes Suspicious Self-Subject Review via Unusual User Agent"** (Discovery, T1069.003 Cloud Groups and T1613 Container and Resource Discovery) matches service accounts or nodes that look up their own permissions with `selfsubjectaccessreviews` or `selfsubjectrulesreviews`. It checks `kubernetes.audit.user.username` or `kubernetes.audit.impersonatedUser.username`, because the review can be sent as an impersonated user. Its triage notes tell the analyst to examine both fields.
- **Kubernetes impersonation in general.** A user who holds the `impersonate` verb can act as the users, service accounts and groups its RBAC rules allow, which can include powerful groups such as `system:masters`. Analysts want to know who really sent a request that was authorized as a powerful identity, and which identities a user is impersonating.
- **Service account impersonation in the cloud.** Granting the right to mint tokens for a service account and then using it is a common privilege escalation path. The interesting question is which human or workload was behind the service account at the time.

With the attribute, one query covers Kubernetes and cloud sources, for example:

```
class_uid = 6003
  AND actor.impersonated_user.name IS NOT NULL
  AND actor.impersonated_user.type_id = 4
  AND actor.user.name NOT LIKE "system:%"
```

This finds people acting as service accounts.

### Design

- **On `actor`, as a `user`.** The impersonated identity is a principal like `actor.user`, and both Kubernetes and cloud sources give a name, uid, groups or email for it, which the `user` object already models (a service account is `type_id` 4, Service).
- **`actor.user` stays the identity that authenticated.** I chose this direction because it matches how the sources name things: Kubernetes calls `user` the authenticated user, and Google Cloud lists the real principal in the delegation history. It also keeps `actor.user` meaning the same thing whether or not impersonation happened. The description says this so producers fill both the same way.
- **Optional.** Most requests do not use impersonation.
- **Not the `delegation` object.** `delegation` describes a durable grant of authority that can be correlated across events and carries its own identifiers. It does not identify the principal, and its description points to `actor.user` for that. Impersonation here is about the identity a single request acted as.
- **Related.** Issue #1462 asks to track who authorized an account switch or impersonation. This PR is narrower: it records the impersonated identity itself.

If people would prefer the other direction (`actor.user` is the effective identity, plus something like `actor.original_user` for the authenticated one), I can change it.

### What changes

- `dictionary.json`: adds `impersonated_user` (type `user`) with a generic description.
- `objects/actor.json`: adds `impersonated_user` as `optional`, with the specific description.
- `changelog.d/1828.md`: the changelog entries for this PR, as described in `changelog.d/README.md`. The `changelog.py check --pr 1828` run passes.

### Example

Kubernetes audit event, `alice@example.com` listing secrets in the `payments` namespace while impersonating the `deployer` service account (trimmed):

```json
{
  "kind": "Event",
  "apiVersion": "audit.k8s.io/v1",
  "level": "Metadata",
  "auditID": "6c1f6e9a-3f0b-4e55-9a51-2d1f0f8c7a10",
  "stage": "ResponseComplete",
  "requestURI": "/api/v1/namespaces/payments/secrets?limit=500",
  "verb": "list",
  "user": {
    "username": "alice@example.com",
    "groups": ["dev-team", "system:authenticated"]
  },
  "impersonatedUser": {
    "username": "system:serviceaccount:payments:deployer",
    "groups": ["system:serviceaccounts", "system:serviceaccounts:payments", "system:authenticated"]
  },
  "sourceIPs": ["10.40.7.21"],
  "userAgent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
  "objectRef": { "resource": "secrets", "namespace": "payments", "apiVersion": "v1" },
  "responseStatus": { "metadata": {}, "code": 200 },
  "stageTimestamp": "2026-11-18T08:41:07.131877Z",
  "annotations": {
    "authorization.k8s.io/decision": "allow",
    "authorization.k8s.io/reason": "RBAC: allowed by RoleBinding \"deployer-secrets/payments\" of Role \"secrets-reader\" to ServiceAccount \"deployer/payments\""
  }
}
```

Field mapping. Where the `ocsf/examples` EKS mapping covers a field I followed it. The authorization annotations are not in that mapping, so I mapped them to `actor.authorizations`:

| Kubernetes field | OCSF |
|---|---|
| `verb` = `list` | `api.operation`, `activity_id` = 5 (List) |
| `auditID` | `metadata.uid`, `api.request.uid` |
| `stage` | `message` |
| `stageTimestamp` | `time` |
| `user.username`, `user.groups` | `actor.user.name`, `actor.user.groups` |
| **`impersonatedUser.username`, `impersonatedUser.groups`** | **`actor.impersonated_user.name`, `actor.impersonated_user.groups`**, `type_id` = 4 (Service) because the name is a service account |
| `annotations` authorization decision and reason | `actor.authorizations[].decision`, `actor.authorizations[].policy.desc` |
| `sourceIPs` | `src_endpoint.ip` |
| `userAgent`, `requestURI` | `http_request.user_agent`, `http_request.url` |
| `objectRef.resource`, `objectRef.namespace` | `resources[].type`, `resources[].namespace` |
| `responseStatus.code` | `api.response.code` |

Result, API Activity (6003), List:

```json
{
  "activity_id": 5,
  "category_uid": 6,
  "class_uid": 6003,
  "type_uid": 600305,
  "severity_id": 1,
  "status_id": 1,
  "time": 1795077667131,
  "message": "ResponseComplete",
  "metadata": {
    "version": "1.10.0",
    "uid": "6c1f6e9a-3f0b-4e55-9a51-2d1f0f8c7a10",
    "product": { "name": "Kubernetes API server", "vendor_name": "Kubernetes" },
    "log_name": "kube-apiserver-audit"
  },
  "cloud": { "provider": "AWS", "region": "us-east-1" },
  "api": {
    "operation": "list",
    "request": { "uid": "6c1f6e9a-3f0b-4e55-9a51-2d1f0f8c7a10" },
    "response": { "code": 200 }
  },
  "actor": {
    "user": {
      "name": "alice@example.com",
      "type_id": 1,
      "groups": [{ "name": "dev-team" }, { "name": "system:authenticated" }]
    },
    "impersonated_user": {
      "name": "system:serviceaccount:payments:deployer",
      "type_id": 4,
      "groups": [{ "name": "system:serviceaccounts" }, { "name": "system:serviceaccounts:payments" }, { "name": "system:authenticated" }]
    },
    "authorizations": [
      {
        "decision": "allow",
        "policy": { "desc": "RBAC: allowed by RoleBinding \"deployer-secrets/payments\" of Role \"secrets-reader\" to ServiceAccount \"deployer/payments\"" }
      }
    ]
  },
  "src_endpoint": { "ip": "10.40.7.21" },
  "http_request": {
    "user_agent": "kubectl/v1.31.2 (linux/amd64) kubernetes/5864a46",
    "url": { "path": "/api/v1/namespaces/payments/secrets", "query_string": "limit=500" }
  },
  "resources": [{ "type": "secrets", "namespace": "payments" }]
}
```

A Google Cloud audit log entry works the same way: `authenticationInfo.principalEmail` (the service account) goes to `actor.impersonated_user.email_addr` with `type_id` 4, and `serviceAccountDelegationInfo[0].firstPartyPrincipal.principalEmail` goes to `actor.user.email_addr`.

### Testing

- The sample event validates against the API Activity class compiled from this branch. On current `main` the only error is `actor.impersonated_user` being an unknown attribute.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled `actor` object has `impersonated_user` as an optional `user`.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- Kubernetes, User impersonation: https://kubernetes.io/docs/reference/access-authn-authz/user-impersonation/
- Kubernetes, Audit event API (`user`, `impersonatedUser`): https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
- OCSF examples, EKS Audit Logs mapping (AWS v1.1.0): https://github.com/ocsf/examples/tree/main/mappings/markdown/AWS/v1.1.0/EKS%20Audit%20Logs
- Google Cloud, AuditLog `AuthenticationInfo` and `ServiceAccountDelegationInfo`: https://docs.cloud.google.com/logging/docs/reference/audit/auditlog/rest/Shared.Types/AuditLog
- Elastic, Kubernetes Suspicious Self-Subject Review via Unusual User Agent: https://www.elastic.co/guide/en/security/current/kubernetes-suspicious-self-subject-review.html
- MITRE ATT&CK T1069.003 Cloud Groups: https://attack.mitre.org/techniques/T1069/003/
- MITRE ATT&CK T1613 Container and Resource Discovery: https://attack.mitre.org/techniques/T1613/
- Related: #1460 (Account Switch in Authentication) and #1462 (track the authority for account switches and impersonation)
