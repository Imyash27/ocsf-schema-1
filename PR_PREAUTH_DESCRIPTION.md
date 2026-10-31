This adds `preauth_type_id` and its sibling `preauth_type` to the `authentication_token` object, so the Kerberos pre-authentication type of a ticket request can be normalized instead of going to `unmapped`.

It is a follow up to #1787, which added RC4 to `encryption_details`. That PR made the encryption half of the AS-REP roasting detection mappable. This one adds the pre-authentication half.

### The problem

When a client asks a Kerberos KDC for a TGT, it normally proves it knows the account key first. This is pre-authentication, and the method used is carried in the PA-DATA of the request (`padata-type` in RFC 4120). Common methods are an encrypted timestamp for passwords, PKINIT for smart cards and certificates, and an encrypted challenge when Kerberos armoring (FAST) is used. Accounts flagged with "Do not require Kerberos preauthentication" skip it.

Windows domain controllers log this on every TGT request and every pre-authentication failure:

| event | when it fires | field |
|---|---|---|
| 4768 | a TGT was requested (success or failure) | `PreAuthType` |
| 4771 | Kerberos pre-authentication failed (wrong password `0x18`, smart card issue `0x10`) | `PreAuthType` |

The Authentication class already covers the rest of these events: the user, the `krbtgt` service, the client address, `kerberos_flags` for `TicketOptions`, and since #1787 the ticket encryption type in `encryption_details`. `PreAuthType` is the one field from these events with nowhere to go.

### Why it matters

**AS-REP roasting (MITRE ATT&CK T1558.004).** If an account does not require pre-authentication, anyone can request a TGT for it and crack the encrypted part of the reply offline. MITRE's detection strategy for this technique (DET0113) looks for "Event ID 4768 with Pre-Auth Type 0", and the Sigma rule "Potential AS-REP Roasting via Kerberos TGT Requests" matches 4768 with `PreAuthType` 0, `TicketEncryptionType` `0x17` and `ServiceName` `krbtgt`. After #1787 the RC4 part can be written on OCSF. Without this PR the `PreAuthType` 0 part still cannot.

**Microsoft's own monitoring guidance.** The 4768 documentation lists four things to watch in this field:

- value is 0: pre-authentication was not used, which Microsoft calls "a security risk"
- value is not 15 when the account must use a smart card
- value is not 2 when only standard password authentication is in use
- value is not 138 when Kerberos armoring is enabled for all Kerberos traffic

The 4771 documentation repeats the last three. Each of these is a policy check that a SOC would want to run across domain controllers, and each needs the pre-authentication type as a normalized field.

**Telling failures apart.** A 4771 with failure code `0x18` and type 2 is a wrong password, which is what a password spray looks like. A 4771 with `0x10` and type 15 is a smart card or certificate problem. Same event ID, very different meaning, and the type is what tells you which one it is.

### The enum

The raw Kerberos number cannot be used as the enum directly. Windows logs `0` for "no pre-authentication", which would collide with OCSF's `0` Unknown. Some of the values Windows can log (`PA-ETYPE-INFO`, `PA-ETYPE-INFO2`, `PA-SVR-REFERRAL-INFO`) are hints and referral data, not a method the client used to prove its key. So the enum normalizes to the categories that detections actually use:

| id | caption | Kerberos PA-DATA type |
|---|---|---|
| 0 | Unknown | |
| 1 | None | no pre-authentication |
| 2 | Encrypted Timestamp | `PA-ENC-TIMESTAMP` (2) |
| 3 | Public Key | PKINIT `PA-PK-AS-REQ` (16), `PA-PK-AS-REP` (17), and the older 14 and 15 |
| 4 | Encrypted Challenge | FAST `PA-ENCRYPTED-CHALLENGE` (138) |
| 99 | Other | anything else, with the source value in `preauth_type` |

Mapping from the Windows `PreAuthType` values in Microsoft's Table 5:

| 4768 / 4771 `PreAuthType` | Microsoft name | `preauth_type_id` |
|---|---|---|
| `0` | Logon without pre-authentication | 1 None |
| `2` | `PA-ENC-TIMESTAMP` | 2 Encrypted Timestamp |
| `15`, `16`, `17` | `PA-PK-AS-REP_OLD`, `PA-PK-AS-REQ`, `PA-PK-AS-REP` | 3 Public Key |
| `138` | `PA-ENCRYPTED-CHALLENGE` | 4 Encrypted Challenge |
| `11`, `19`, `20` | `PA-ETYPE-INFO`, `PA-ETYPE-INFO2`, `PA-SVR-REFERRAL-INFO` | 99 Other |
| `-` | shown in audit failure events | not set |

`preauth_type_id` has `"source": "padata-type"`, the field name from RFC 4120, so it is clear where the value comes from.

### Design

- **On `authentication_token`, not the event root.** All the Kerberos request fields from 4768 and 4771 already live there (`kerberos_flags`, `encryption_details`), so `preauth_type_id` sits next to them and the Authentication class root does not grow. If the group prefers the class root, I can move it.
- **The name `preauth_type`.** It matches the existing Authentication activity "Preauth" (6). I can rename it, for example to `pre_authentication_type`, if that reads better.
- **Generic description.** The dictionary text describes "the method the client used to pre-authenticate to the authentication service", with Kerberos as the example, so a non Kerberos source with a similar step could use it later.
- **Dictionary first.** Full descriptions, enum and references are in `dictionary.json`. The object only sets the requirement, following the review feedback on #1788.

### What changes

- `dictionary.json`: adds `preauth_type_id` (`integer_t` enum, `source` `padata-type`, references to RFC 4120, RFC 4556, RFC 6113 and the IANA Kerberos registry) and `preauth_type` (`string_t` sibling).
- `objects/authentication_token.json`: adds both as `optional`.
- `CHANGELOG.md`: entries under Dictionary Attributes and Objects, with the link to this PR.
- `.github/.project-words.txt`: adds `padata` and `PKINIT` for cspell.

### Example 1: AS-REP roasting (4768)

A TGT issued for an account that does not require pre-authentication, with RC4:

```xml
<Data Name="TargetUserName">svc_backup</Data>
<Data Name="TargetDomainName">CONTOSO.LOCAL</Data>
<Data Name="TargetSid">S-1-5-21-3114123713-1067509961-1646476345-1108</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="ServiceSid">S-1-5-21-3114123713-1067509961-1646476345-502</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="PreAuthType">0</Data>
<Data Name="IpAddress">::ffff:172.27.248.104</Data>
<Data Name="IpPort">54393</Data>
```

Field mapping:

| 4768 field | OCSF |
|---|---|
| `TargetUserName`, `TargetDomainName`, `TargetSid` | `user.name`, `user.domain`, `user.uid` |
| `ServiceName`, `ServiceSid` | `service.name`, `service.uid` |
| `TicketOptions` | `authentication_token.kerberos_flags` |
| `TicketEncryptionType` (`0x17`) | `authentication_token.encryption_details.algorithm_id` = 7 (RC4), from #1787 |
| **`PreAuthType` (`0`)** | **`authentication_token.preauth_type_id` = 1 (None)**, no place for it today |
| `Status` (`0x0`) | `status_id` = 1, `status_code` = `0x0` |
| `IpAddress`, `IpPort` | `src_endpoint.ip`, `src_endpoint.port` |

Result, Authentication (3002), Authentication Ticket (3):

```json
{
  "activity_id": 3,
  "class_uid": 3002,
  "category_uid": 3,
  "type_uid": 300203,
  "severity_id": 1,
  "status_id": 1,
  "status_code": "0x0",
  "time": 1793265262885,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Windows Security Auditing", "vendor_name": "Microsoft" },
    "event_code": "4768"
  },
  "auth_protocol_id": 2,
  "auth_protocol": "Kerberos",
  "user": { "name": "svc_backup", "domain": "CONTOSO.LOCAL", "uid": "S-1-5-21-3114123713-1067509961-1646476345-1108" },
  "service": { "name": "krbtgt", "uid": "S-1-5-21-3114123713-1067509961-1646476345-502" },
  "src_endpoint": { "ip": "172.27.248.104", "port": 54393 },
  "dst_endpoint": { "hostname": "DC01.contoso.local" },
  "authentication_token": {
    "type_id": 1,
    "type": "Ticket Granting Ticket",
    "kerberos_flags": "0x40810010",
    "encryption_details": { "algorithm_id": 7, "algorithm": "RC4" },
    "preauth_type_id": 1,
    "preauth_type": "None"
  }
}
```

The AS-REP roasting rule on this data then becomes `activity_id = 3 AND authentication_token.preauth_type_id = 1 AND authentication_token.encryption_details.algorithm_id = 7`.

### Example 2: smart card pre-authentication failure (4771)

This is the event from Microsoft's 4771 documentation: a smart card logon for `dadmin` that failed with `0x10` (KDC has no support for the PA-DATA type):

```xml
<Data Name="TargetUserName">dadmin</Data>
<Data Name="TargetSid">S-1-5-21-3457937927-2839227994-823803824-1104</Data>
<Data Name="ServiceName">krbtgt/CONTOSO.LOCAL</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x10</Data>
<Data Name="PreAuthType">15</Data>
<Data Name="IpAddress">::ffff:10.0.0.12</Data>
<Data Name="IpPort">49254</Data>
```

Result, Authentication (3002), Preauth (6):

```json
{
  "activity_id": 6,
  "class_uid": 3002,
  "category_uid": 3,
  "type_uid": 300206,
  "severity_id": 1,
  "status_id": 2,
  "status_code": "0x10",
  "status_detail": "KDC_ERR_PADATA_TYPE_NOSUPP",
  "time": 1438971021495,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Windows Security Auditing", "vendor_name": "Microsoft" },
    "event_code": "4771"
  },
  "auth_protocol_id": 2,
  "auth_protocol": "Kerberos",
  "user": { "name": "dadmin", "uid": "S-1-5-21-3457937927-2839227994-823803824-1104" },
  "service": { "name": "krbtgt/CONTOSO.LOCAL" },
  "src_endpoint": { "ip": "10.0.0.12", "port": 49254 },
  "dst_endpoint": { "hostname": "DC01.contoso.local" },
  "authentication_token": {
    "type_id": 1,
    "type": "Ticket Granting Ticket",
    "kerberos_flags": "0x40810010",
    "preauth_type_id": 3,
    "preauth_type": "Public Key"
  }
}
```

With `preauth_type_id` = 3 and `status_code` `0x10`, this is clearly a certificate problem and not a password guess, which would show `preauth_type_id` = 2 and `0x18`.

### Testing

- Both sample events validate against the Authentication class compiled from this branch. On current `main` the only errors are `preauth_type_id` and `preauth_type` being unknown attributes.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

Microsoft documentation
- 4768(S, F) A Kerberos authentication ticket (TGT) was requested, with Table 5 (pre-authentication types) and the monitoring recommendations: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
- 4771(F) Kerberos pre-authentication failed, with the failure codes and the same pre-authentication table: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771

Standards
- RFC 4120, The Kerberos Network Authentication Service (V5), Section 5.2.7 (PA-DATA) and Section 7.5.2 (pre-authentication data types): https://www.rfc-editor.org/rfc/rfc4120
- RFC 4556, PKINIT (`PA_PK_AS_REQ` 16, `PA_PK_AS_REP` 17): https://www.rfc-editor.org/rfc/rfc4556
- RFC 6113, A Generalized Framework for Kerberos Pre-Authentication (FAST, `PA-ENCRYPTED-CHALLENGE` 138): https://www.rfc-editor.org/rfc/rfc6113
- IANA Kerberos Parameters, pre-authentication and typed data registry: https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml

Detection content
- MITRE ATT&CK T1558.004, AS-REP Roasting: https://attack.mitre.org/techniques/T1558/004/
- MITRE detection strategy DET0113: https://attack.mitre.org/detectionstrategies/DET0113/
- Sigma, Potential AS-REP Roasting via Kerberos TGT Requests: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml

The four standards links are also in the attribute `references`.
