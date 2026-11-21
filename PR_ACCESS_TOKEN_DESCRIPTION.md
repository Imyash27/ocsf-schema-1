This adds `Access Token` (8) to the `type_id` enum of the `token` object, for OAuth 2.0 access tokens. `authentication_token` extends `token`, so it gets the value too.

### The problem

The token type enum has the OIDC ID token (3) and the refresh token (4), but not the OAuth 2.0 access token. RFC 6749 section 1.4 describes it as "Access tokens are credentials used to access protected resources. An access token is a string representing an authorization issued to the client." It is the token a client actually sends with each API request, and the refresh token, which the enum already has, exists to get new ones.

So when a source reports the access token used for a request, or the issue of one, the producer has to set `type_id` to 99 (Other). The two values that look close don't fit:

- **Client Token (6)** is for "IdP-issued tokens used for service-to-service authentication", such as client secrets and machine to machine tokens.
- **API Token (7)** is for API keys "NOT issued by Identity Providers".

An access token that an authorization server issued to an app acting for a user is neither.

### Where the data comes from

| source | what it reports | fields |
|---|---|---|
| Microsoft Graph activity logs | every API request, with the access token it was made with | `TokenIssuedAt` ("The timestamp the token was issued at"), `UniqueTokenId` ("The unique token identifier of the API call used to make the audited change"), `Scopes` ("The scopes in token claims"), `Roles`, `SignInActivityId` |
| Okta System Log | token grant events, with the token type in the event type | `app.oauth2.token.grant.access_token`, `app.oauth2.as.token.grant.access_token`, `app.oauth2.authorize.implicit.access_token` and `app.oauth2.as.authorize.implicit.access_token` |

In both cases the source says the token is an access token, but OCSF has no value for it.

### Why it matters

Stolen access tokens are their own attack path. MITRE ATT&CK covers it as **T1528, Steal Application Access Token** and **T1550.001, Use Alternate Authentication Material: Application Access Token**. Detections need to look at access tokens specifically:

- **Token replay.** The same token identifier (`UniqueTokenId` in Graph activity logs) used from a new IP address or device after it was issued is a sign the token was stolen and replayed.
- **Scope abuse.** Access tokens carry the scopes granted to the client. Requests with broad mail or file scopes from an app that normally doesn't use them stand out.
- **Lifetime.** Access tokens are short lived and refresh tokens long lived. Telling them apart matters when deciding what to revoke after an incident.

With the new value, these filter on `api.token.type_id = 8` (or `authentication_token.type_id = 8`) instead of parsing `type` strings, for example:

```
class_uid = 6003 AND api.token.type_id = 8
  AND api.token.uid = "<token id>"
  AND src_endpoint.ip NOT IN (<IPs seen at sign-in>)
```

### Design

- **An enum value on `token`.** `authentication_token` extends `token` and inherits its enum. That is how it already has Client Token and API Token, so one change covers both API Activity (`api.token`) and Authentication (`authentication_token`).
- **The id is 8**, the next free value after API Token (7).
- **The description says when to use it and when not to.** Use it for OAuth 2.0 access tokens issued to a client, for example after an authorization code or refresh token grant on behalf of a user. Tokens for service-to-service authentication without a user stay Client Token, which keeps the existing values meaning what they mean today.
- **The reference** is RFC 6749 section 1.4, the same way other values point at their protocol.

If reviewers would rather call it "OAuth Access Token" to be explicit, or think machine to machine access tokens should also use this value, I can adjust the caption or the description.

### What changes

- `objects/token.json`: adds `8` Access Token to `type_id`, with a description and a reference to RFC 6749 section 1.4.
- `changelog.d/1834.md`: the changelog entries for this PR, as described in `changelog.d/README.md`. The `changelog.py check --pr 1834` run passes.

### Example

Microsoft Graph activity log entry, an app reading a user's mail with a delegated access token (trimmed):

```json
{
  "TimeGenerated": "2026-11-18T10:14:26.118Z",
  "RequestId": "a3f9c2d1-6e4b-4c7a-8b15-2d9e0f7a1c64",
  "ApiVersion": "v1.0",
  "RequestMethod": "GET",
  "RequestUri": "https://graph.microsoft.com/v1.0/me/messages?$top=50",
  "ResponseStatusCode": 200,
  "IPAddress": "203.0.113.48",
  "UserAgent": "python-requests/2.32.3",
  "AppId": "1fec8e78-bce4-4aaf-ab1b-5451cc387264",
  "UserId": "4b2e8f61-0c3d-4a97-b5e2-9f1a6d8c7e30",
  "SessionId": "008a1b2c-3d4e-5f60-7182-93a4b5c6d7e8",
  "TokenIssuedAt": "2026-11-18T10:03:32Z",
  "UniqueTokenId": "kD3mH8pQ2EuV7sX1tY9zAw",
  "Scopes": "Mail.Read User.Read offline_access",
  "SignInActivityId": "Zq0vB8xYk0yI3mT5nR2wAA",
  "AadTenantId": "7c1d3e2a-5b4f-4a8e-9d61-0f2b8c3a6e19",
  "Location": "West Europe"
}
```

Field mapping:

| Graph activity log field | OCSF |
|---|---|
| `TimeGenerated` | `time` |
| `RequestId` | `api.request.uid` |
| `RequestMethod`, `RequestUri`, `UserAgent` | `api.operation`, `http_request.http_method`, `http_request.url`, `http_request.user_agent` |
| `ApiVersion` | `api.version` |
| `ResponseStatusCode` | `api.response.code` |
| `IPAddress` | `src_endpoint.ip` |
| `UserId`, `AppId`, `SessionId` | `actor.user.uid`, `actor.application.uid`, `actor.session.uid` |
| `AadTenantId`, `Location` | `cloud.account.uid`, `cloud.region` |
| **(the token the request was made with)** | **`api.token.type_id` = 8 (Access Token)**, Other today |
| `UniqueTokenId`, `TokenIssuedAt` | `api.token.uid`, `api.token.created_time` |
| `Scopes`, `SignInActivityId` | `unmapped` |

Result, API Activity (6003), Read:

```json
{
  "activity_id": 2,
  "category_uid": 6,
  "class_uid": 6003,
  "type_uid": 600302,
  "severity_id": 1,
  "status_id": 1,
  "time": 1795090466118,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Microsoft Graph", "vendor_name": "Microsoft" },
    "log_name": "MicrosoftGraphActivityLogs"
  },
  "cloud": { "provider": "Azure", "region": "West Europe", "account": { "uid": "7c1d3e2a-5b4f-4a8e-9d61-0f2b8c3a6e19" } },
  "api": {
    "operation": "GET",
    "service": { "name": "Microsoft Graph" },
    "version": "v1.0",
    "request": { "uid": "a3f9c2d1-6e4b-4c7a-8b15-2d9e0f7a1c64" },
    "response": { "code": 200 },
    "token": {
      "type_id": 8,
      "type": "Access Token",
      "uid": "kD3mH8pQ2EuV7sX1tY9zAw",
      "created_time": 1795089812000
    }
  },
  "actor": {
    "user": { "uid": "4b2e8f61-0c3d-4a97-b5e2-9f1a6d8c7e30" },
    "application": { "uid": "1fec8e78-bce4-4aaf-ab1b-5451cc387264" },
    "session": { "uid": "008a1b2c-3d4e-5f60-7182-93a4b5c6d7e8" }
  },
  "src_endpoint": { "ip": "203.0.113.48" },
  "http_request": {
    "http_method": "GET",
    "user_agent": "python-requests/2.32.3",
    "url": { "path": "/v1.0/me/messages", "query_string": "$top=50" }
  },
  "unmapped": { "Scopes": "Mail.Read User.Read offline_access", "SignInActivityId": "Zq0vB8xYk0yI3mT5nR2wAA" }
}
```

### Testing

- The sample event validates against the API Activity class compiled from this branch. On current `main` the only error is `invalid enum api.token.type_id=8`.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled `token` and `authentication_token` objects both list Access Token (8).
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed file.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new description.
- Commits are signed off.

### References

- RFC 6749, The OAuth 2.0 Authorization Framework, section 1.4 Access Token: https://www.rfc-editor.org/rfc/rfc6749#section-1.4
- Microsoft Graph activity logs table reference: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs
- Okta, View OAuth and OIDC token grant events for a specific Okta application: https://support.okta.com/help/s/article/view-oauth-and-oidc-token-grant-events-for-a-specific-okta-application
- Okta, Event types: https://developer.okta.com/docs/reference/api/event-types/
- MITRE ATT&CK T1528 Steal Application Access Token: https://attack.mitre.org/techniques/T1528/
- MITRE ATT&CK T1550.001 Application Access Token: https://attack.mitre.org/techniques/T1550/001/
