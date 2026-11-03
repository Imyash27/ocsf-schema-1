This adds `token_elevation_type_id` and its sibling `token_elevation_type` to the Windows extension, on the Windows `process` object, so the User Account Control (UAC) elevation type of a process token can be normalized instead of going to `unmapped`.

### The problem

With UAC turned on, an administrator who logs on gets a split token. One half is a limited token with the administrative privileges removed, used for normal work. The other half is a linked full token, used only when a program is started with Run as administrator. Accounts that do not get a split token (UAC turned off, the built-in Administrator, service accounts, local system) get a single token with no linked token.

Windows records which of these a new process received in two places:

| source | field | values |
|---|---|---|
| Security event 4688 (new process created) | `TokenElevationType` | `%%1936` (Type 1), `%%1937` (Type 2), `%%1938` (Type 3) |
| `GetTokenInformation` with `TokenElevationType`, used by endpoint sensors | `TOKEN_ELEVATION_TYPE` | `TokenElevationTypeDefault` (1), `TokenElevationTypeFull` (2), `TokenElevationTypeLimited` (3) |

When 4688 is converted to OCSF today, the new process, the parent, the user and the "Mandatory Label" (as `integrity_id`) all map, but the token elevation type has nowhere to go.

### Why it matters

Microsoft's monitoring guidance for 4688 is built on this field:

- Type 2 (`%%1937`, full token) on a standard workstation for a real user account means a user ran a program with administrative privileges.
- Type 1 (`%%1936`, no linked token) for a real user account usually means UAC is turned off for that account.

Both are common signals for privilege escalation and UAC bypass (MITRE ATT&CK T1548.002, Bypass User Account Control). A UAC bypass ends with a process running on the full token without the user consenting to elevation, and the elevation type is how you see that on the process event. Microsoft's first recommendation becomes a simple query, for example `class_uid = 1007 AND activity_id = 1 AND process.token_elevation_type_id = 2` on workstations, filtered to real user accounts.

### Why this is not `integrity_id`

`process.integrity_id` already covers the 4688 "Mandatory Label" field (S-1-16-8192 is Medium and so on). Integrity level and elevation type are related but they are different facts. The elevation type says which half of a split token the process got, or that it had no linked token at all. Detections usually need both: a Medium integrity process on a Limited token is normal, a High integrity process on a Full token is an elevated admin process, and a High integrity process with no linked token for an interactive user points at UAC being turned off.

### The enum

| id | caption | `TOKEN_ELEVATION_TYPE` | 4688 value |
|---|---|---|---|
| 0 | Unknown | | |
| 1 | None | `TokenElevationTypeDefault` | `%%1936` |
| 2 | Full | `TokenElevationTypeFull` | `%%1937` |
| 3 | Limited | `TokenElevationTypeLimited` | `%%1938` |
| 99 | Other | | |

The ids match the Windows enumeration, so 4688 and sensors that call `GetTokenInformation` map directly without a lookup table. The caption for 1 is None rather than Default (following review feedback), because it makes clear that the token has no linked token. Each enum description says which Windows constant it corresponds to.

### Design

- **Windows extension, not core `process`.** Split tokens and UAC only exist on Windows, and the Windows `process` object already holds Windows specific attributes such as `hosted_services`. If the group would rather have it in core, I can move it.
- **Dictionary first.** Following review feedback, the full descriptions, enum and references are in `extensions/windows/dictionary.json`, and `token_elevation_type_id` has `"source": "TOKEN_ELEVATION_TYPE"`. The Windows `process` object only sets the requirement.
- **Values start at 1** to match the Windows enumeration, while keeping 0 Unknown and 99 Other as the enum convention requires.
- **Out of scope.** Other token properties, for example restricted or virtualization enabled tokens, are not part of this PR. They could follow the same pattern if there is demand.

### What changes

- `extensions/windows/dictionary.json`: adds `token_elevation_type_id` (`integer_t` enum with `source` and references) and `token_elevation_type` (`string_t` sibling).
- `extensions/windows/objects/process.json`: adds both as `optional`.
- `CHANGELOG.md`: entry under Platform Extensions, with the link to this PR.

### Example

Security event 4688 from the Microsoft documentation example: `explorer.exe` starting `rundll32.exe` for `CONTOSO\dadmin` with a limited token:

```xml
<Data Name="SubjectUserSid">S-1-5-18</Data>
<Data Name="SubjectUserName">WIN-GG82ULGC9GO$</Data>
<Data Name="SubjectDomainName">CONTOSO</Data>
<Data Name="NewProcessId">0x2bc</Data>
<Data Name="NewProcessName">C:\Windows\System32\rundll32.exe</Data>
<Data Name="TokenElevationType">%%1938</Data>
<Data Name="ProcessId">0xe74</Data>
<Data Name="TargetUserSid">S-1-5-21-1377283216-344919071-3415362939-1104</Data>
<Data Name="TargetUserName">dadmin</Data>
<Data Name="TargetDomainName">CONTOSO</Data>
<Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
<Data Name="MandatoryLabel">S-1-16-8192</Data>
```

Field mapping:

| 4688 field | OCSF |
|---|---|
| `NewProcessId` (`0x2bc`) | `process.pid` = 700 |
| `NewProcessName` | `process.file.path`, `process.file.name` |
| `TargetUserName`, `TargetDomainName`, `TargetUserSid` | `process.user.name`, `process.user.domain`, `process.user.uid` |
| `MandatoryLabel` (`S-1-16-8192`) | `process.integrity_id` = 3 (Medium) |
| **`TokenElevationType` (`%%1938`)** | **`process.token_elevation_type_id` = 3 (Limited)**, no place for it today |
| `ProcessId` (`0xe74`) | `actor.process.pid` = 3700 |
| `ParentProcessName` | `actor.process.file.path` |
| `SubjectUserName`, `SubjectDomainName`, `SubjectUserSid` | `actor.user.name`, `actor.user.domain`, `actor.user.uid` |

Result, Process Activity (1007), Launch:

```json
{
  "activity_id": 1,
  "category_uid": 1,
  "class_uid": 1007,
  "type_uid": 100701,
  "severity_id": 1,
  "time": 1447295092377,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Windows Security Auditing", "vendor_name": "Microsoft" },
    "event_code": "4688",
    "extensions": [{ "name": "win", "uid": "2", "version": "1.10.0" }]
  },
  "device": {
    "type_id": 0,
    "hostname": "WIN-GG82ULGC9GO.contoso.local",
    "os": { "name": "Windows", "type_id": 100 }
  },
  "actor": {
    "process": {
      "pid": 3700,
      "file": { "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe", "type_id": 1 }
    },
    "user": { "name": "WIN-GG82ULGC9GO$", "domain": "CONTOSO", "uid": "S-1-5-18" }
  },
  "process": {
    "pid": 700,
    "file": { "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe", "type_id": 1 },
    "user": { "name": "dadmin", "domain": "CONTOSO", "uid": "S-1-5-21-1377283216-344919071-3415362939-1104" },
    "integrity_id": 3,
    "integrity": "Medium",
    "token_elevation_type_id": 3,
    "token_elevation_type": "Limited"
  }
}
```

### Testing

- The sample event validates against the Process Activity class compiled from this branch. On current `main` the only errors are the two new attributes being unknown.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- How User Account Control works: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works
- `TOKEN_ELEVATION_TYPE` enumeration: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type
- `GetTokenInformation` function: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation
- 4688(S) A new process has been created, with the "Token Elevation Type" field and the monitoring recommendations: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- MITRE ATT&CK T1548.002, Bypass User Account Control: https://attack.mitre.org/techniques/T1548/002/

The `TOKEN_ELEVATION_TYPE` and 4688 links are also in the attribute `references`.
