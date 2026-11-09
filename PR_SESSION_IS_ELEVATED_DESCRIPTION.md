This adds an optional `is_elevated` boolean to the `session` object, so a session that runs with elevated privileges can be flagged in normalized events.

### The problem

With User Account Control, a Windows administrator who logs on gets two linked logon sessions: a filtered one used for normal work, and an elevated one with the full administrator token. The second is the one that matters for a lot of detections, because an action performed in the elevated session runs with full admin rights.

Security event 4624 (an account was successfully logged on) records which one each session is in the "Elevated Token" field. The Microsoft documentation describes it as "a 'Yes' or 'No' flag. If 'Yes', then the session this event represents is elevated and has administrator privileges." The two sessions are tied together through the "Linked Logon ID" field.

The Authentication class (3002) already carries the 4624 logon in a `session` object, with `session.uid` for the logon id. But there is no attribute for whether the session is elevated, so that flag ends up in `unmapped`.

### Where the data comes from

| source | field | example |
|---|---|---|
| Windows 4624 (successful logon) | `ElevatedToken` (`%%1842` = Yes, `%%1843` = No), paired session in `TargetLinkedLogonId` | `%%1842` |
| Windows 4688 (new process), via the process token | the related token elevation type (`token_elevation_type_id`, added in #1788) | `%%1937` (Full) |

4624 is the session level view (is this logon elevated), and #1788's `token_elevation_type_id` is the process level view (which half of the split token a process got). This PR fills in the session level flag.

### Why it matters

An elevated logon session is a normal part of administrator activity, but where and how it appears is a detection signal:

- An elevated session for a normal user account, or on a workstation where that user should not be an admin, is worth flagging. Microsoft's 4624 guidance is built on correlating the account, the logon type and the elevated flag.
- Pairing the elevated session with its linked non-elevated session (through `session.uid` and `session.uid_alt`) is how analysts reconstruct a UAC elevation, and how token manipulation (MITRE ATT&CK T1134) shows up, where a process in the filtered session ends up acting through the elevated token.

With the flag normalized, a query can find elevated interactive logons directly, for example `class_uid = 3002 AND activity_id = 1 AND logon_type_id = 2 AND session.is_elevated = true`, filtered to accounts that should not be local administrators.

### Design

- **A boolean on `session`.** The 4624 field is a Yes/No flag about the session, so a boolean on the `session` object is the natural fit, next to the existing `is_mfa`, `is_remote` and `is_vpn` session flags.
- **Generic dictionary entry, specific usage on `session`.** Following the review feedback on #1792, the dictionary description is generic ("Indicates that the object has elevated privileges. See specific usage."), and the session specific description with the Windows field name is on the `session` object. That leaves `is_elevated` reusable for other objects that have an elevated or non-elevated form.
- **Session level, not process level.** This is deliberately the logon session flag. The process token elevation type is already covered by #1788's `token_elevation_type_id` on the Windows `process` object, and the two answer different questions.
- **Optional.** Only some sources report it, and on Windows the field exists only from the version 2 schema of 4624.

### What changes

- `dictionary.json`: adds `is_elevated` (`boolean_t`) with a generic description.
- `objects/session.json`: adds `is_elevated` as `optional`, with the Windows specific description.
- `CHANGELOG.md`: entries under Dictionary Attributes and Objects.

### Example

Security event 4624 from the Microsoft documentation example, an interactive logon of the built-in Administrator with an elevated token (`ElevatedToken` = `%%1842`):

```xml
<Data Name="TargetUserName">Administrator</Data>
<Data Name="TargetDomainName">WIN-GG82ULGC9GO</Data>
<Data Name="TargetUserSid">S-1-5-21-1377283216-344919071-3415362939-500</Data>
<Data Name="TargetLogonId">0x8dcdc</Data>
<Data Name="LogonType">2</Data>
<Data Name="IpAddress">127.0.0.1</Data>
<Data Name="TargetLinkedLogonId">0x0</Data>
<Data Name="ElevatedToken">%%1842</Data>
```

Field mapping:

| 4624 field | OCSF |
|---|---|
| `LogonType` (`2`) | `logon_type_id` = 2 (Interactive) |
| `TargetUserName`, `TargetDomainName`, `TargetUserSid` | `user.name`, `user.domain`, `user.uid` |
| `TargetLogonId` | `session.uid` |
| `TargetLinkedLogonId` | `session.uid_alt` |
| **`ElevatedToken` (`%%1842`)** | **`session.is_elevated` = `true`**, no place for it today |
| `IpAddress` | `src_endpoint.ip` |

Result, Authentication (3002), Logon (1):

```json
{
  "activity_id": 1,
  "activity_name": "Logon",
  "class_uid": 3002,
  "category_uid": 3,
  "type_uid": 300201,
  "severity_id": 1,
  "status_id": 1,
  "time": 1794219665000,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Windows Security Auditing", "vendor_name": "Microsoft" },
    "event_code": "4624"
  },
  "logon_type_id": 2,
  "logon_type": "Interactive",
  "user": { "name": "Administrator", "domain": "WIN-GG82ULGC9GO", "uid": "S-1-5-21-1377283216-344919071-3415362939-500" },
  "src_endpoint": { "ip": "127.0.0.1" },
  "dst_endpoint": { "hostname": "WIN-GG82ULGC9GO" },
  "session": {
    "uid": "0x8dcdc",
    "uid_alt": "0x0",
    "is_elevated": true
  }
}
```

### Testing

- The sample event validates against the Authentication class compiled from this branch. On current `main` the only error is `session.is_elevated` being an unknown attribute.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- 4624(S) An account was successfully logged on, with the "Elevated Token" and "Linked Logon ID" fields: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- How User Account Control works (split token): https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works
- MITRE ATT&CK T1134, Access Token Manipulation: https://attack.mitre.org/techniques/T1134/
