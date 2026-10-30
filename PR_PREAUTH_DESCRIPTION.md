#### Related Issue:
None. Follow-up to #1787 (RC4 in `encryption_details`); the problem, sample mapping and references are below.

#### Description of changes:

Adds two optional attributes to the `authentication_token` object so the Kerberos pre-authentication type of a ticket request can be normalized instead of going to `unmapped`.

| attribute | type | requirement |
|---|---|---|
| `preauth_type_id` | `integer_t` | optional |
| `preauth_type` | `string_t` | optional |

Both are defined in `dictionary.json` with full descriptions, and `authentication_token` only sets the requirement, next to `kerberos_flags` and `encryption_details`, which already carry the other fields of the same Windows events. `preauth_type_id` has `"source": "padata-type"`, the field name in RFC 4120.

| id | caption | Kerberos PA-DATA type |
|---|---|---|
| 0 | Unknown | |
| 1 | None | no pre-authentication |
| 2 | Encrypted Timestamp | `PA-ENC-TIMESTAMP` (2) |
| 3 | Public Key | PKINIT `PA-PK-AS-REQ` (16) / `PA-PK-AS-REP` (17), and the older 14 / 15 |
| 4 | Encrypted Challenge | FAST `PA-ENCRYPTED-CHALLENGE` (138) |
| 99 | Other | any other type, raw value in `preauth_type` |

#### Background

Windows domain controllers record the pre-authentication type in the "Pre-Authentication Type" field of security events 4768 (TGT requested) and 4771 (Kerberos pre-authentication failed). Microsoft documents these values:

| 4768 / 4771 value | name | proposed id |
|---|---|---|
| `0` | Logon without pre-authentication | 1 None |
| `2` | `PA-ENC-TIMESTAMP` (standard password) | 2 Encrypted Timestamp |
| `15`, `16`, `17` | `PA-PK-AS-REP_OLD`, `PA-PK-AS-REQ`, `PA-PK-AS-REP` (smart card) | 3 Public Key |
| `138` | `PA-ENCRYPTED-CHALLENGE` (Kerberos armoring, FAST) | 4 Encrypted Challenge |
| `11`, `19`, `20` | `PA-ETYPE-INFO`, `PA-ETYPE-INFO2`, `PA-SVR-REFERRAL-INFO` | 99 Other |
| `-` | shown in audit failure events | not set |

#### Why it matters

- AS-REP roasting (MITRE ATT&CK T1558.004): an attacker requests a TGT for an account that does not require pre-authentication and cracks the reply offline. MITRE's detection strategy DET0113 monitors "Event ID 4768 with Pre-Auth Type 0", and the Sigma rule "Potential AS-REP Roasting via Kerberos TGT Requests" matches 4768 with `PreAuthType` 0, `TicketEncryptionType` `0x17` and `ServiceName` `krbtgt`. #1787 made the RC4 half of that detection mappable; this PR adds the pre-authentication half.
- Microsoft's monitoring guidance for 4768 is built on this field: type 0 means pre-authentication was not used, which is a security risk; a type other than 15 when an account must use a smart card; other than 2 when only password authentication is in use; other than 138 when Kerberos armoring is enforced.

Today none of these can be expressed in OCSF, so a query on the normalized event cannot find a TGT issued without pre-authentication.

#### Why normalized values instead of the raw PA-DATA number

The raw Kerberos number cannot be used as the enum directly: Windows reports `0` for "no pre-authentication", which would collide with OCSF's `0` Unknown, and several values are informational hints rather than client pre-authentication methods (`PA-ETYPE-INFO`, `PA-ETYPE-INFO2`). The normalized enum keeps the categories detections actually use (none, password, certificate, armored), and `preauth_type` keeps the source value for anything mapped to Other.

#### Example

Security event 4768, TGT for an account without pre-authentication, issued with RC4 (field names from the Microsoft documentation example):

```xml
<Data Name="TargetUserName">svc_backup</Data>
<Data Name="TargetDomainName">CONTOSO.LOCAL</Data>
<Data Name="TargetSid">S-1-5-21-3114123713-1067509961-1646476345-1108</Data>
<Data Name="ServiceName">krbtgt</Data>
<Data Name="TicketOptions">0x40810010</Data>
<Data Name="Status">0x0</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="PreAuthType">0</Data>
<Data Name="IpAddress">::ffff:172.27.248.104</Data>
<Data Name="IpPort">54393</Data>
```

Maps to Authentication (3002), Authentication Ticket (3):

```json
{
  "activity_id": 3,
  "class_uid": 3002,
  "category_uid": 3,
  "type_uid": 300203,
  "severity_id": 1,
  "status_id": 1,
  "status_code": "0x0",
  "time": 1740528699885,
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

The sample validates against the Authentication class compiled with this change. Against current `main` the only errors are the two new attributes (the RC4 value already validates since #1787).

#### Design choices worth flagging

1. On `authentication_token` rather than the Authentication class root, so all Kerberos request fields from 4768 / 4771 sit together (`kerberos_flags`, `encryption_details`, `preauth_type_id`) and the event root does not grow. Happy to move it if the group prefers.
2. Named `preauth_type` to match the existing Authentication activity "Preauth" (#1018) and the `auth_*` naming already used in the schema. Happy to rename (for example to `pre_authentication_type`) if preferred.
3. Defined fully in the dictionary, with the object only setting the requirement, following the review feedback on #1788.

#### References

Microsoft documentation
- [4768(S, F) A Kerberos authentication ticket (TGT) was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768): "Pre-Authentication Type" field, Table 5 Kerberos Pre-Authentication types, and the monitoring recommendations for types 0, 2, 15 and 138.
- [4771(F) Kerberos pre-authentication failed](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771): the same field on pre-authentication failures.

Standards
- [RFC 4120, The Kerberos Network Authentication Service (V5)](https://www.rfc-editor.org/rfc/rfc4120): Section 5.2.7 PA-DATA (`padata-type`), Section 7.5.2 PreAuthentication Data Types (`PA-ENC-TIMESTAMP` = 2).
- [RFC 4556, Public Key Cryptography for Initial Authentication in Kerberos (PKINIT)](https://www.rfc-editor.org/rfc/rfc4556): `PA_PK_AS_REQ` = 16, `PA_PK_AS_REP` = 17.
- [RFC 6113, A Generalized Framework for Kerberos Pre-Authentication](https://www.rfc-editor.org/rfc/rfc6113): FAST, `PA-ENCRYPTED-CHALLENGE` = 138.
- [IANA Kerberos Parameters, Pre-authentication and Typed Data](https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml): registry of all padata-type values.

Detection content
- [MITRE ATT&CK T1558.004, AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) and its detection strategy [DET0113](https://attack.mitre.org/detectionstrategies/DET0113): 4768 with Pre-Auth Type 0, with RC4 as an additional signal.
- [Sigma rule, Potential AS-REP Roasting via Kerberos TGT Requests](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_kerberos_asrep_roasting.yml): 4768 with `PreAuthType` 0, `TicketEncryptionType` `0x17` and `ServiceName` `krbtgt`.

Files touched: `dictionary.json`, `objects/authentication_token.json`, `CHANGELOG.md`, `.github/.project-words.txt` (adds `padata` and `PKINIT`).

#### Confirmations

1. `Unreleased` entries added to `CHANGELOG.md` (Dictionary Attributes and Objects). PR link to be added once the number is known.
2. Contribution guidelines followed. Every commit carries a `Signed-off-by` trailer.
3. Validated locally:
   - `python -m ocsf_validator .` passes, with the same output as `main`
   - `ocsf-schema-compiler .` compiles with zero errors and zero warnings, in both default and browser mode
   - `python -m ocsf.validate.compatibility` against `main` passes all five checks
   - `cspell` with the repository config reports no unknown words in the changed lines
   - the sample event is valid against the compiled Authentication class
4. PR title matches the description.
5. Captions and descriptions follow the normative and neutral style: no URLs, trademark marks or company names in captions or descriptions, and citations are in `references`.
