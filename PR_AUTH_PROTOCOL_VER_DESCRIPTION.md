This adds `auth_protocol_ver` to the Authentication class, for the version or variant of the authentication protocol (for NTLM: `LM`, `NTLM V1` or `NTLM V2`), and reuses `key_length` for the length of the session key negotiated for the logon. Both come from Windows logon events and have no place in OCSF today.

### The problem

`auth_protocol_id` tells you a logon used NTLM, but not which NTLM. That difference is what matters for security. LM and NTLMv1 responses can be brute forced, Microsoft deprecated NTLMv1 in June 2024, and finding the systems that still use it is a standard step before turning it off.

Windows records both pieces of information in the logon events:

- **Package Name (NTLM only)** (`LmPackageName`): "The name of the LAN Manager subpackage (NTLM-family protocol name) that was used during logon. Possible values are: "NTLM V1", "NTLM V2", "LM". Only populated if "Authentication Package" = "NTLM"."
- **Key Length** (`KeyLength`): "the length of NTLM Session Security key. Typically it has 128-bit or 56-bit length. This parameter is always 0 if "Authentication Package" = "Kerberos"".

A producer mapping 4624 to OCSF today puts `AuthenticationPackageName` in `auth_protocol` and has to send these two to `unmapped`.

### Where the data comes from

| source | field | example |
|---|---|---|
| Windows 4624 (successful logon) and 4625 (failed logon) | `LmPackageName` (Package Name (NTLM only)) | `NTLM V1`, `NTLM V2`, `LM`, `-` |
| Windows 4624 and 4625 | `KeyLength` | `128`, `56`, `0` |

### Why it matters

Microsoft's own guidance is built on these two fields:

- **"Audit use of NTLMv1 on a domain controller"** (KB 4090105): "To find applications that use NTLMv1, enable Logon Success Auditing on the DC. Then, review the event log on the DC for Success auditing Event ID 4624. This log entry contains information about the version of NTLM." It also says to ignore the result for `ANONYMOUS LOGON`, because NTLM auditing reports NTLMv1 for every session without NTLMv2 key material.
- **The 4624 monitoring recommendations**: "If a particular version of NTLM is always used in your organization. In this case, you can use this event to monitor Package Name (NTLM only), for example, to find events where Package Name (NTLM only) doesn't equal NTLM V2." And: "If the Authentication Package is NTLM. In this case, monitor for Key Length not equal to 128, because all Windows operating systems starting with Windows 2000 support 128-bit Key Length."

Detection content uses the same signal. The Sigma rule "NTLMv1 Logon Between Client and Server" (tagged `attack.t1550.002`, Pass the Hash) alerts on NTLMv1 use from the LsaSrv events, because NTLMv1 is "insecure as the underlying encryption algorithms can be brute-forced by modern hardware". A downgrade to NTLMv1 is also how some attacks get a response that can be cracked back to the NT hash.

With the attributes, the Microsoft audit is one normalized query:

```
class_uid = 3002 AND auth_protocol_id = 1
  AND auth_protocol_ver IN ("LM", "NTLM V1")
  AND user.name != "ANONYMOUS LOGON"
```

The key length check is `auth_protocol_id = 1 AND key_length != 128`.

### Design

- **`auth_protocol_ver` is a generic string**, not an NTLM specific enum. Several protocols in `auth_protocol_id` have versions or variants that sources report (NTLM V1 and V2, SAML 1.1 and 2.0, OAuth 2.0), and a single enum across all of them would not be useful. The class description gives the NTLM values as the main example. If reviewers would rather have an `ntlm_version_id` enum (LM, NTLMv1, NTLMv2), I can do that instead.
- **The name** follows `auth_protocol` / `auth_protocol_id` and the `_ver` suffix used by `protocol_ver`.
- **`key_length` is reused.** It already exists in the dictionary ("The length of the encryption key"), and `tls` and `encryption_details` use it. The class description says it is the session key negotiated for the logon, and that it is 0 when no session key applies, for example with Kerberos.
- **Both are context and optional**, since most logons are Kerberos.

### What changes

- `dictionary.json`: adds `auth_protocol_ver` (`string_t`) with a generic description.
- `events/iam/authentication.json`: adds `auth_protocol_ver` and `key_length` as optional context attributes, with Authentication specific descriptions.
- `changelog.d/1832.md`: the changelog entries for this PR, as described in `changelog.d/README.md`. The `changelog.py check --pr 1832` run passes.

### Example

Windows 4624, a network logon to a file server by a scanner service account using NTLMv1 (event data, trimmed):

```xml
<Data Name="TargetUserSid">S-1-5-21-3623811015-3361044348-30300820-2187</Data>
<Data Name="TargetUserName">svc-scan</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetLogonId">0x3f1a2c4</Data>
<Data Name="LogonType">3</Data>
<Data Name="LogonProcessName">NtLmSsp</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">SCANNER01</Data>
<Data Name="LmPackageName">NTLM V1</Data>
<Data Name="KeyLength">128</Data>
<Data Name="IpAddress">10.30.4.88</Data>
<Data Name="IpPort">50712</Data>
```

Field mapping:

| 4624 field | OCSF |
|---|---|
| `TargetUserName`, `TargetDomainName`, `TargetUserSid` | `user.name`, `user.domain`, `user.uid` |
| `TargetLogonId` | `session.uid` |
| `LogonType` = 3 | `logon_type_id` = 3 (Network) |
| `LogonProcessName` | `logon_process.name` |
| `AuthenticationPackageName` = `NTLM` | `auth_protocol_id` = 1 (NTLM) |
| **`LmPackageName`** | **`auth_protocol_ver`**, no place for it today |
| **`KeyLength`** | **`key_length`**, no place for it today |
| `WorkstationName`, `IpAddress`, `IpPort` | `src_endpoint.hostname`, `src_endpoint.ip`, `src_endpoint.port` |

Result, Authentication (3002), Logon:

```json
{
  "activity_id": 1,
  "category_uid": 3,
  "class_uid": 3002,
  "type_uid": 300201,
  "severity_id": 1,
  "status_id": 1,
  "time": 1795088102611,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Microsoft Windows", "vendor_name": "Microsoft" },
    "log_name": "Security",
    "event_code": "4624"
  },
  "device": { "type_id": 1, "hostname": "FS-02.corp.example.com", "os": { "name": "Windows", "type_id": 100 } },
  "user": { "name": "svc-scan", "domain": "CORP", "uid": "S-1-5-21-3623811015-3361044348-30300820-2187" },
  "logon_type_id": 3,
  "logon_type": "Network",
  "logon_process": { "name": "NtLmSsp" },
  "auth_protocol_id": 1,
  "auth_protocol": "NTLM",
  "auth_protocol_ver": "NTLM V1",
  "key_length": 128,
  "is_remote": true,
  "session": { "uid": "0x3f1a2c4" },
  "src_endpoint": { "ip": "10.30.4.88", "port": 50712, "hostname": "SCANNER01" }
}
```

### Testing

- The sample event validates against the Authentication class compiled from this branch. On current `main` the only errors are `auth_protocol_ver` and `key_length` being unknown attributes.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- 4624(S) An account was successfully logged on (Package Name (NTLM only), Key Length, monitoring recommendations): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- Audit use of NTLMv1 on a domain controller (KB 4090105): https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/audit-domain-controller-ntlmv1
- Sigma, NTLMv1 Logon Between Client and Server: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/system/lsasrv/win_system_lsasrv_ntlmv1.yml
- MITRE ATT&CK T1550.002 Pass the Hash: https://attack.mitre.org/techniques/T1550/002/
