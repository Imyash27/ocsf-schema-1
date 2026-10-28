#### Related Issue:
None. The problem, sample mapping and references are below.

#### Description of changes:

Adds one enum value to `algorithm_id` in the `encryption_details` object so that Kerberos tickets encrypted with RC4 can be normalized instead of falling into `Other`.

| object | attribute | new value |
|---|---|---|
| `encryption_details` | `algorithm_id` | `7` RC4 |

The enum currently has DES (1), TripleDES (2), AES (3), RSA (4), ECC (5) and SM2 (6). RC4 is the next free value. `algorithm` stays the sibling, so producers send `"algorithm_id": 7, "algorithm": "RC4"`.

#### Background

`encryption_details` is used by `file`, `databucket` and `authentication_token`. On `authentication_token` it describes how a Kerberos ticket is encrypted, which the Authentication class (3002) already carries for the "Authentication Ticket" (TGT) and "Service Ticket Request" activities.

Windows records this on every domain controller in the "Ticket Encryption Type" field of security events 4768 (TGT requested) and 4769 (service ticket requested). Microsoft documents these values:

| 4768 / 4769 value | name | OCSF mapping today | with this PR |
|---|---|---|---|
| `0x1` | DES-CBC-CRC | DES (1) | DES (1) |
| `0x3` | DES-CBC-MD5 | DES (1) | DES (1) |
| `0x11` | AES128-CTS-HMAC-SHA1-96 | AES (3), `key_length` 128 | AES (3), `key_length` 128 |
| `0x12` | AES256-CTS-HMAC-SHA1-96 | AES (3), `key_length` 256 | AES (3), `key_length` 256 |
| `0x17` | RC4-HMAC | Other (99) | **RC4 (7)** |
| `0x18` | RC4-HMAC-EXP | Other (99) | **RC4 (7)** |

RC4-HMAC is Kerberos encryption type 23, defined in RFC 4757 and deprecated by RFC 8429 (BCP 218).

#### Why it matters

RC4 is the one value in that table that detections are written against:

- Kerberoasting (MITRE ATT&CK T1558.003): an attacker requests service tickets with RC4 for accounts with an SPN and cracks them offline. MITRE's detection strategy for the technique, and the widely used Sigma rule "Suspicious Kerberos RC4 Ticket Encryption", both match 4769 with ticket encryption type `0x17`.
- AS-REP roasting (T1558.004) shows the same RC4 pattern on 4768.
- Microsoft's own monitoring guidance for 4769 is to alert on DES (`0x1`, `0x3`) and on any ticket encryption type other than `0x11` and `0x12`.
- Microsoft states that "the Kerberos RC4 default encryption type can be abused to carry out an attack method known as Kerberoasting", and plans to disable RC4 as the default assumed supported encryption type for Active Directory domain controllers by the end of the second quarter of 2026 (CVE-2026-20833). Its guidance for finding remaining RC4 usage before enforcement is to audit the ticket encryption type in 4768 and 4769, so an RC4 ticket in a modern domain is both a hardening gap and a stronger attack signal.

Today DES and AES map cleanly, but RC4 has to be sent as Other (99) with the string in `algorithm`, so a query on the normalized id cannot find it.

#### Example

Security event 4769, service ticket for an SPN account issued with RC4 (field names from the Microsoft documentation example):

```xml
<Data Name="TargetUserName">duser@CONTOSO.LOCAL</Data>
<Data Name="TargetDomainName">CONTOSO.LOCAL</Data>
<Data Name="ServiceName">svc_sql</Data>
<Data Name="ServiceSid">S-1-5-21-3114123713-1067509961-1646476345-1107</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="IpAddress">::ffff:172.27.248.104</Data>
<Data Name="IpPort">54394</Data>
<Data Name="Status">0x0</Data>
```

Maps to Authentication (3002), Service Ticket Request (4):

```json
{
  "activity_id": 4,
  "class_uid": 3002,
  "category_uid": 3,
  "type_uid": 300204,
  "severity_id": 1,
  "status_id": 1,
  "status_code": "0x0",
  "time": 1740528699887,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Windows Security Auditing", "vendor_name": "Microsoft" },
    "event_code": "4769"
  },
  "auth_protocol_id": 2,
  "auth_protocol": "Kerberos",
  "user": { "name": "duser", "domain": "CONTOSO.LOCAL" },
  "service": { "name": "svc_sql", "uid": "S-1-5-21-3114123713-1067509961-1646476345-1107" },
  "src_endpoint": { "ip": "172.27.248.104", "port": 54394 },
  "dst_endpoint": { "hostname": "DC01.contoso.local" },
  "authentication_token": {
    "type_id": 2,
    "type": "Service Ticket",
    "kerberos_flags": "0x40810000",
    "encryption_details": { "algorithm_id": 7, "algorithm": "RC4" }
  }
}
```

The sample validates against the Authentication class compiled with this change. Against current `main` the only error is `invalid enum authentication_token.encryption_details.algorithm_id=7`.

#### Design choices worth flagging

1. The value is the cipher, `RC4`, not the Kerberos suite name `RC4-HMAC`, consistent with `DES` and `AES` in the same enum, where the Kerberos suite variants (DES-CBC-CRC, AES256-CTS-HMAC-SHA1-96) also map to the cipher and key size goes in `key_length`. The enum value description mentions RC4-HMAC as the Kerberos example.
2. RC4-HMAC-EXP (`0x18`) also maps to RC4. The audit failure value `0xFFFFFFFF` maps to no algorithm.
3. Scope is limited to RC4 because there is a concrete, widely used mapping that needs it. Other ciphers (for example ChaCha20) can be added the same way when a source needs them.

#### References

Microsoft documentation
- [4768(S, F) A Kerberos authentication ticket (TGT) was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768): "Ticket Encryption Type" field and Table 4, Kerberos encryption types (`0x1`, `0x3`, `0x11`, `0x12`, `0x17`, `0x18`).
- [4769(S, F) A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769): same field for service tickets, and the monitoring recommendation to watch for DES and for values other than `0x11` and `0x12`.
- [Detect and Remediate RC4 Usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos): RC4 and Kerberoasting, the 2026 default change, and auditing RC4 through 4768 and 4769.

Standards
- [RFC 3962, Advanced Encryption Standard (AES) Encryption for Kerberos 5](https://www.rfc-editor.org/rfc/rfc3962): aes128-cts-hmac-sha1-96 (etype 17, `0x11`) and aes256-cts-hmac-sha1-96 (etype 18, `0x12`), which map to AES with `key_length`.
- [RFC 4757, The RC4-HMAC Kerberos Encryption Types Used by Microsoft Windows](https://www.rfc-editor.org/rfc/rfc4757): rc4-hmac (etype 23, `0x17`).
- [RFC 8429, Deprecate Triple-DES (3DES) and RC4 in Kerberos](https://www.rfc-editor.org/rfc/rfc8429): BCP 218, deprecates rc4-hmac.

Detection content
- [MITRE ATT&CK T1558.003, Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) and its detection strategy [DET0157](https://attack.mitre.org/detectionstrategies/DET0157/): RC4 (etype 23, `0x17`) service tickets in 4769.
- [MITRE ATT&CK T1558.004, AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/): 4768 with pre-authentication type 0 and RC4 (`0x17`).
- [Sigma rule, Suspicious Kerberos RC4 Ticket Encryption](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/security/win_security_susp_rc4_kerberos.yml): matches 4769 with `TicketEncryptionType` `0x17`.

Files touched: `objects/encryption_details.json`, `CHANGELOG.md`.

#### Confirmations

1. `Unreleased` entry added to `CHANGELOG.md` under Improved, Objects. with the PR link.
2. Contribution guidelines followed.
3. Validated locally:
   - `python -m ocsf_validator .` passes, with the same output as `main`
   - `ocsf-schema-compiler .` compiles with zero errors and zero warnings, in both default and browser mode
   - `python -m ocsf.validate.compatibility` against `main` passes all five checks
   - `cspell` with the repository config reports no unknown words in the changed lines
   - the sample event is valid against the compiled Authentication class
4. PR title matches the description.
5. Captions and descriptions follow the normative and neutral style: no URLs, trademark marks or company names in the caption or description.
