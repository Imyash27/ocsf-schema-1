This adds an optional `session_key_encryption_details` attribute to the `authentication_token` object, using the existing `encryption_details` object, so the encryption type of a Kerberos ticket session key can be normalized separately from the ticket encryption.

It is a follow-up to #1787 (RC4 in `encryption_details`) and #1791 (Kerberos pre-authentication type), which mapped the other fields of the same Windows events.

### The problem

A Kerberos ticket has two different encryption types, and they are not always the same:

- the **ticket encryption type**, the suite the ticket itself is encrypted with. This maps to `authentication_token.encryption_details` today.
- the **session key encryption type**, the suite of the session key handed to the client with the ticket.

Windows reports both. The 4768 and 4769 documentation describes the ticket field as "Ticket Encryption Type ... the cryptographic suite that was used for issued TGT" and the session field, added in the January 2025 cumulative update, as "Session Encryption Type ... the cryptographic suite that was used for session key in the issued TGT." The two are logged as separate fields (`TicketEncryptionType` and `SessionKeyEncryptionType`) with the same value table.

OCSF can carry only one of them today. The ticket type goes in `encryption_details`, and the session key type has nowhere to go, so it ends up in `unmapped`.

### Where the data comes from

| source | field | example |
|---|---|---|
| Windows 4768 (TGT requested) | `TicketEncryptionType`, `SessionKeyEncryptionType` | `0x12`, `0x12` |
| Windows 4769 (service ticket requested) | `TicketEncryptionType`, `SessionKeyEncryptionType` | `0x17`, `0x12` |

The Microsoft guidance "Detect and Remediate RC4 Usage in Kerberos" treats the session field as its own signal: "Session Encryption Type: Encryption type used for the Ticket Session Key", and says to "use the msDS-SupportedEncryptionTypes or the Advertized Etypes fields to determine if a client or target machine doesn't support AES-SHA1 or only supports RC4."

### Why it matters

The two types can disagree, and the disagreement is the interesting part. A service ticket can be encrypted with RC4 (because the target account only has an RC4 key) while the session key is AES, or the reverse. For Kerberoasting (MITRE ATT&CK T1558.003), the ticket encryption type is what an attacker cracks offline, but when hunting for RC4 exposure across a domain you want to see both: a modern client with an AES session key still requesting an RC4 service ticket points at a weak target account, which is exactly what Microsoft's RC4 audit guidance is about ahead of the RC4 default being disabled.

Keeping them in one field loses that. With `session_key_encryption_details`, a producer maps `TicketEncryptionType` to `encryption_details` and `SessionKeyEncryptionType` to `session_key_encryption_details`, and a query can compare them, for example find service tickets where `authentication_token.encryption_details.algorithm_id = 7` (RC4 ticket) but `authentication_token.session_key_encryption_details.algorithm_id = 3` (AES session key).

### Design

- **Reuse `encryption_details`.** The session key encryption is the same shape as the ticket encryption (algorithm, key length), so the new attribute is an `encryption_details` object, the same type `encryption_details` already is on `authentication_token`. Nothing new is needed to describe RC4, AES and so on, and #1787's RC4 value applies to both.
- **New attribute, not a sub-field.** The two encryption types are peers on the ticket, so `session_key_encryption_details` sits next to `encryption_details` rather than inside it.
- **Generic dictionary entry.** The dictionary description is generic ("the encryption details of the session key, when these are reported separately from the content or ticket encryption"), and the `authentication_token` object carries the Kerberos specific description with the Windows field name. That leaves it reusable for other protocols that split content and session key encryption.
- **Optional.** Only some sources report the session key type separately, and the field itself only appeared in Windows in 2025.

### What changes

- `dictionary.json`: adds `session_key_encryption_details` (`encryption_details` object) with a generic description.
- `objects/authentication_token.json`: adds `session_key_encryption_details` as `optional`, with the Kerberos specific description.
- `CHANGELOG.md`: entries under Dictionary Attributes and Objects.

### Example

Security event 4769, a service ticket for an SPN account issued with an RC4 ticket but an AES256 session key (field names from the Microsoft example):

```xml
<Data Name="TargetUserName">duser@CONTOSO.LOCAL</Data>
<Data Name="ServiceName">svc_sql</Data>
<Data Name="ServiceSid">S-1-5-21-3114123713-1067509961-1646476345-1107</Data>
<Data Name="TicketOptions">0x40810000</Data>
<Data Name="TicketEncryptionType">0x17</Data>
<Data Name="SessionKeyEncryptionType">0x12</Data>
<Data Name="Status">0x0</Data>
<Data Name="IpAddress">::ffff:172.27.248.104</Data>
<Data Name="IpPort">54394</Data>
```

Field mapping:

| 4769 field | OCSF |
|---|---|
| `TargetUserName` | `user.name`, `user.domain` |
| `ServiceName`, `ServiceSid` | `service.name`, `service.uid` |
| `TicketOptions` | `authentication_token.kerberos_flags` |
| `TicketEncryptionType` (`0x17`) | `authentication_token.encryption_details.algorithm_id` = 7 (RC4) |
| **`SessionKeyEncryptionType` (`0x12`)** | **`authentication_token.session_key_encryption_details.algorithm_id` = 3 (AES), `key_length` 256**, no place for it today |
| `Status` (`0x0`) | `status_id` = 1, `status_code` = `0x0` |
| `IpAddress`, `IpPort` | `src_endpoint.ip`, `src_endpoint.port` |

Result, Authentication (3002), Service Ticket Request (4):

```json
{
  "activity_id": 4,
  "class_uid": 3002,
  "category_uid": 3,
  "type_uid": 300204,
  "severity_id": 1,
  "status_id": 1,
  "status_code": "0x0",
  "time": 1794219664900,
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
    "encryption_details": { "algorithm_id": 7, "algorithm": "RC4" },
    "session_key_encryption_details": { "algorithm_id": 3, "algorithm": "AES", "key_length": 256 }
  }
}
```

This event is the hunt target: an RC4 service ticket (crackable) issued to a client that otherwise uses AES, which the single `encryption_details` field could not express before.

### Testing

- The sample event validates against the Authentication class compiled from this branch. On current `main` the only error is `authentication_token.session_key_encryption_details` being an unknown attribute.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- 4768(S, F) A Kerberos authentication ticket (TGT) was requested, with the "Ticket Encryption Type" and "Session Encryption Type" fields: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768
- 4769(S, F) A Kerberos service ticket was requested: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
- Detect and Remediate RC4 Usage in Kerberos, "Session Encryption Type": https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos
- MITRE ATT&CK T1558.003, Kerberoasting: https://attack.mitre.org/techniques/T1558/003/
