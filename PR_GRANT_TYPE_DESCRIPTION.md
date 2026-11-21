This adds `grant_type` and `grant_type_id` to the Authentication class, for the OAuth 2.0 authorization grant that a sign-in or token request used (Authorization Code, Client Credentials, Device Code, Resource Owner Password Credentials and so on). The enum follows the grant types defined in the OAuth RFCs.

### The problem

`auth_protocol_id` can say a sign-in used OAUTH 2.0 or OpenID, but OAuth has several very different ways for a client to get tokens, and that difference matters for security. A user signing in through a browser with the Authorization Code grant is the normal case. A **Device Code** sign-in, where a code is entered on another device, is what device code phishing abuses. A **Resource Owner Password Credentials** (ROPC) sign-in sends the password straight to the token endpoint and skips interactive MFA prompts, which is why password spraying likes it. A **Client Credentials** request has no user at all.

Identity providers record which one was used, but OCSF has no attribute for it, so it ends up in `unmapped`.

### Where the data comes from

| source | field | values |
|---|---|---|
| Entra ID sign-in logs (`SigninLogs`) | `AuthenticationProtocol`: "Lists the protocol type or grant type used in the authentication. The possible values are: none, oAuth2, ropc, wsFederation, saml20, deviceCode." | `deviceCode`, `ropc` |
| Entra ID sign-in logs | `OriginalTransferMethod` | `deviceCodeFlow` |
| Okta System Log, `app.oauth2.as.token.grant` and related token grant events | `debugContext.debugData.grantType` | the OAuth `grant_type` of the request, for example `client_credentials` |
| OAuth token requests in general | the `grant_type` request parameter (RFC 6749 and its extensions) | `authorization_code`, `password`, `client_credentials`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code`, ... |

### Why it matters

- **Device code phishing.** Microsoft Threat Intelligence describes Storm-2372's campaign as "threat actors exploit the device code authentication flow to capture authentication tokens". Elastic's prebuilt rules for it key on the grant type: "Entra ID OAuth Device Code Grant by Unusual User" matches `azure.signinlogs.properties.authentication_protocol:deviceCode` or `original_transfer_method:deviceCodeFlow`, and is mapped to MITRE ATT&CK T1078.004 (Cloud Accounts) and T1566.002 (Spearphishing Link). Elastic also has "First Occurrence of Entra ID Auth via DeviceCode Protocol" and "Entra ID OAuth Device Code Phishing via AiTM".
- **Client credentials misuse.** Elastic's "Unauthorized Scope for Public App OAuth2 Token Grant with Client Credentials" matches Okta's `app.oauth2.as.token.grant` with `okta.debug_context.debug_data.flattened.grantType: "client_credentials"` (T1078.004).
- **ROPC and legacy flows.** Sign-ins with ROPC are a common target for password spraying (T1110.003), because the password is sent directly to the token endpoint. Finding the apps that still use it is a standard clean-up step.

With the attribute these become one query across identity providers, for example:

```
class_uid = 3002 AND grant_type_id = 6 AND status_id = 1
```

### Design

- **On Authentication, next to `auth_protocol_id`.** The grant type refines the protocol: `auth_protocol_id` stays OAUTH 2.0 (or OpenID, which uses the same grants), and `grant_type_id` says which grant. That keeps `auth_protocol_id` meaning what it means today. Entra's `AuthenticationProtocol` mixes the two (`saml20` and `wsFederation` are protocols, `deviceCode` and `ropc` are grants), so a producer maps it to both attributes.
- **An enum from the standards.** Authorization Code, Implicit, Resource Owner Password Credentials, Client Credentials and Refresh Token from RFC 6749, Device Code from RFC 8628, JWT Bearer from RFC 7523, SAML 2.0 Bearer from RFC 7522 and Token Exchange from RFC 8693. Each value has its `grant_type` parameter value as `source` (for Implicit, `response_type=token`, since it has no grant type parameter) and a reference to its RFC section, so producers can map the raw value directly.
- **Primary and recommended**, because detections key on it. It only applies to OAuth based sign-ins, and other sources leave it unset.
- **Not on `authentication_token`.** The grant is how the client authenticated for this request, not a property of the token, and the same sign-in can return several tokens.

If reviewers would rather call it `oauth_grant_type`, or put it on another object, I can change it.

### What changes

- `dictionary.json`: adds `grant_type` and `grant_type_id` with generic descriptions.
- `events/iam/authentication.json`: adds both attributes (primary, recommended), with the enum, a `source` on each value and RFC references.
- `changelog.d/<this PR>.md`: I'll add it once the PR has a number, as described in `changelog.d/README.md`.

### Example

Entra ID `SigninLogs` record for a device code sign-in (trimmed):

```json
{
  "TimeGenerated": "2026-11-21T09:23:18.412Z",
  "Id": "3f0c6a1e-8b2d-4c57-9e41-7a5d2b8c9f10",
  "UserPrincipalName": "j.doe@contoso.com",
  "UserId": "4b2e8f61-0c3d-4a97-b5e2-9f1a6d8c7e30",
  "AppDisplayName": "Microsoft Authentication Broker",
  "AppId": "29d9ed98-a469-4536-ade2-f981bc1d605e",
  "ResourceDisplayName": "Microsoft Graph",
  "ResourceIdentity": "00000003-0000-0000-c000-000000000000",
  "AuthenticationProtocol": "deviceCode",
  "OriginalTransferMethod": "deviceCodeFlow",
  "AuthenticationRequirement": "singleFactorAuthentication",
  "IPAddress": "198.51.100.23",
  "LocationDetails": { "city": "Amsterdam", "countryOrRegion": "NL" },
  "SessionId": "008a1b2c-3d4e-5f60-7182-93a4b5c6d7e8",
  "ResultType": "0"
}
```

Field mapping:

| Entra ID field | OCSF |
|---|---|
| `TimeGenerated`, `Id` | `time`, `metadata.uid` |
| `UserPrincipalName`, `UserId` | `user.name`, `user.email_addr`, `user.uid` |
| `AuthenticationProtocol` = `deviceCode` | `auth_protocol_id` = 6 (OAUTH 2.0) and **`grant_type_id` = 6 (Device Code)**, no place for the grant today |
| `AuthenticationRequirement` = `singleFactorAuthentication` | `is_mfa` = false |
| `ResourceDisplayName`, `ResourceIdentity` | `service.name`, `service.uid` |
| `IPAddress`, `LocationDetails` | `src_endpoint.ip`, `src_endpoint.location` |
| `SessionId` | `session.uid` |
| `ResultType` = `0` | `status_id` = 1, `status_code` = `0` |
| `AppDisplayName`, `AppId`, `OriginalTransferMethod` | `unmapped` |

Result, Authentication (3002), Logon:

```json
{
  "activity_id": 1,
  "category_uid": 3,
  "class_uid": 3002,
  "type_uid": 300201,
  "severity_id": 1,
  "status_id": 1,
  "status_code": "0",
  "time": 1795267398412,
  "metadata": {
    "version": "1.11.0",
    "uid": "3f0c6a1e-8b2d-4c57-9e41-7a5d2b8c9f10",
    "product": { "name": "Entra ID", "vendor_name": "Microsoft" },
    "log_name": "SigninLogs"
  },
  "user": {
    "name": "j.doe@contoso.com",
    "uid": "4b2e8f61-0c3d-4a97-b5e2-9f1a6d8c7e30",
    "email_addr": "j.doe@contoso.com"
  },
  "auth_protocol_id": 6,
  "auth_protocol": "OAUTH 2.0",
  "grant_type_id": 6,
  "grant_type": "Device Code",
  "is_mfa": false,
  "service": { "name": "Microsoft Graph", "uid": "00000003-0000-0000-c000-000000000000" },
  "src_endpoint": { "ip": "198.51.100.23", "location": { "country": "NL", "city": "Amsterdam" } },
  "session": { "uid": "008a1b2c-3d4e-5f60-7182-93a4b5c6d7e8" },
  "unmapped": {
    "AppDisplayName": "Microsoft Authentication Broker",
    "AppId": "29d9ed98-a469-4536-ade2-f981bc1d605e",
    "OriginalTransferMethod": "deviceCodeFlow"
  }
}
```

An Okta `app.oauth2.as.token.grant` event with `debugContext.debugData.grantType` = `client_credentials` maps the same way, to `grant_type_id` = 4 (Client Credentials).

### Testing

- The sample event validates against the Authentication class compiled from this branch. On current `main` the only errors are `grant_type_id` and `grant_type` being unknown attributes.
- `python .github/scripts/format_schema.py --check` reports no files that need formatting, and every changed file ends with a newline.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- RFC 6749, The OAuth 2.0 Authorization Framework (sections 4.1 to 4.4 and 6): https://www.rfc-editor.org/rfc/rfc6749
- RFC 8628, OAuth 2.0 Device Authorization Grant: https://www.rfc-editor.org/rfc/rfc8628
- RFC 7523, JWT Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://www.rfc-editor.org/rfc/rfc7523
- RFC 7522, SAML 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants: https://www.rfc-editor.org/rfc/rfc7522
- RFC 8693, OAuth 2.0 Token Exchange: https://www.rfc-editor.org/rfc/rfc8693
- Azure Monitor Logs reference, SigninLogs (`AuthenticationProtocol`): https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Microsoft Threat Intelligence, Storm-2372 conducts device code phishing campaign: https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/
- Elastic, Entra ID OAuth Device Code Grant by Unusual User: https://www.elastic.co/guide/en/security/current/entra-id-oauth-device-code-grant-by-unusual-user.html
- Elastic, Unauthorized Scope for Public App OAuth2 Token Grant with Client Credentials: https://github.com/elastic/detection-rules/blob/main/rules/integrations/okta/defense_evasion_first_occurence_public_app_client_credential_token_exchange.toml
- MITRE ATT&CK T1078.004 Cloud Accounts: https://attack.mitre.org/techniques/T1078/004/
- MITRE ATT&CK T1566.002 Spearphishing Link: https://attack.mitre.org/techniques/T1566/002/
- MITRE ATT&CK T1110.003 Password Spraying: https://attack.mitre.org/techniques/T1110/003/
