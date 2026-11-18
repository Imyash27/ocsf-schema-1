This adds an optional `is_restricted_admin` boolean to the `session` object, for whether a remote interactive logon used restricted admin mode. It comes from the same Windows logon event as `is_elevated` (#1809), and today it has no place in OCSF.

### The problem

Restricted admin mode is a way of logging on over RDP without sending reusable credentials to the remote host. The RDP spec describes it as "credential-less logon over CredSSP (also known as "restricted admin mode")", and the Sigma rule for it says "RestrictedAdmin mode prevents the transmission of reusable credentials to the remote system to which you connect using Remote Desktop".

It cuts both ways:

- **Defenders want it** for administrators connecting to servers that might be compromised, so their credentials cannot be harvested there.
- **Attackers turn it on**, because with restricted admin mode a client can log on with only an NTLM hash, which makes pass the hash over RDP possible.

Windows records it on every logon in event 4624 as **Restricted Admin Mode**: "Only populated for RemoteInteractive logon type sessions. This value is a Yes/No flag indicating if the credentials provided were passed using Restricted Admin mode." OCSF maps the rest of that event (logon type, session, `is_elevated` from the same event) but has nothing for this flag, so it goes to `unmapped`.

### Where the data comes from

| source | field | values |
|---|---|---|
| Windows 4624 (successful logon) | `RestrictedAdminMode` (Restricted Admin Mode) | `Yes`, `No`, and `-` for logons that are not RemoteInteractive |
| RDP protocol (MS-RDPBCGR 2.2.1.2.1) | `RESTRICTED_ADMIN_MODE_SUPPORTED` flag in the RDP Negotiation Response | the server supports restricted admin logons |

### Why it matters

- **Microsoft's monitoring recommendation for 4624**: "If "Restricted Admin" mode must be used for logons by certain accounts, use this event to monitor logons by "New Logon\Security ID" in relation to "Logon Type"=10 and "Restricted Admin Mode"="Yes". If "Restricted Admin Mode"="No" for these accounts, trigger an alert."
- **Pass the hash over RDP** (MITRE ATT&CK T1550.002). A restricted admin logon from an account or host that normally doesn't use it is worth a look, especially right after the setting was turned on.
- **The setting change is already detected.** Sigma's "RestrictedAdminMode Registry Value Tampering" (level high) alerts on changes to `HKLM\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin`. With `is_restricted_admin`, the logons that follow such a change can be found in normalized data too.

Microsoft's recommendation as a query:

```
class_uid = 3002 AND logon_type_id = 10
  AND user.name IN ("adm-jdoe", "adm-asmith")
  AND session.is_restricted_admin = false
```

### Design

- **On `session`, next to `is_elevated`.** Restricted admin mode is a property of the logon session that 4624 creates, the same as the elevated token flag that #1809 added to `session` as `is_elevated`. This keeps both flags from the same event together.
- **A boolean.** Windows reports Yes or No, and `-` for logons that are not RemoteInteractive, which a producer can leave unset.
- **Optional**, since it only applies to remote interactive logons.
- **Left out for now.** Remote Credential Guard is the related mode in which credentials are redirected back to the client (`REDIRECTED_AUTHENTICATION_MODE_SUPPORTED` in the same RDP flags). 4624 doesn't report it, so I didn't add it. If a source shows up that does, the boolean could become a `credential_mode_id` enum (Default, Restricted Admin, Remote Credential Guard), and I'm happy to do that now if reviewers prefer.

If people would rather keep Windows specific logon flags out of the core `session` object, I can move it, but I followed where `is_elevated` went.

### What changes

- `dictionary.json`: adds `is_restricted_admin` (`boolean_t`) with a generic description.
- `objects/session.json`: adds `is_restricted_admin` as `optional`, with the specific description and references to the 4624 documentation and to the RDP Negotiation Response flags.
- `changelog.d/<this PR>.md`: I'll add it once the PR has a number, as described in `changelog.d/README.md`.

### Example

Windows 4624, an administrator logging on to an application server over RDP with restricted admin mode, authenticated with NTLM (event data, trimmed):

```xml
<Data Name="TargetUserSid">S-1-5-21-3623811015-3361044348-30300820-1544</Data>
<Data Name="TargetUserName">adm-jdoe</Data>
<Data Name="TargetDomainName">CORP</Data>
<Data Name="TargetLogonId">0x5b7e91d</Data>
<Data Name="LogonType">10</Data>
<Data Name="LogonProcessName">User32</Data>
<Data Name="AuthenticationPackageName">NTLM</Data>
<Data Name="WorkstationName">WS-0417</Data>
<Data Name="IpAddress">10.30.6.21</Data>
<Data Name="IpPort">0</Data>
<Data Name="RestrictedAdminMode">Yes</Data>
<Data Name="ElevatedToken">%%1842</Data>
```

Field mapping:

| 4624 field | OCSF |
|---|---|
| `TargetUserName`, `TargetDomainName`, `TargetUserSid` | `user.name`, `user.domain`, `user.uid` |
| `TargetLogonId` | `session.uid` |
| `LogonType` = 10 | `logon_type_id` = 10 (RemoteInteractive) |
| `LogonProcessName` | `logon_process.name` |
| `AuthenticationPackageName` = `NTLM` | `auth_protocol_id` = 1 (NTLM) |
| **`RestrictedAdminMode` = `Yes`** | **`session.is_restricted_admin` = true**, no place for it today |
| `ElevatedToken` = `%%1842` (Yes) | `session.is_elevated` = true |
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
  "time": 1795089340925,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Microsoft Windows", "vendor_name": "Microsoft" },
    "log_name": "Security",
    "event_code": "4624"
  },
  "device": { "type_id": 2, "hostname": "SRV-APP07.corp.example.com", "os": { "name": "Windows", "type_id": 100 } },
  "user": { "name": "adm-jdoe", "domain": "CORP", "uid": "S-1-5-21-3623811015-3361044348-30300820-1544" },
  "logon_type_id": 10,
  "logon_type": "RemoteInteractive",
  "logon_process": { "name": "User32" },
  "auth_protocol_id": 1,
  "auth_protocol": "NTLM",
  "is_remote": true,
  "session": { "uid": "0x5b7e91d", "is_restricted_admin": true, "is_elevated": true },
  "src_endpoint": { "ip": "10.30.6.21", "port": 0, "hostname": "WS-0417" }
}
```

An NTLM authenticated restricted admin logon like this one is the pattern to review for pass the hash over RDP.

### Testing

- The sample event validates against the Authentication class compiled from this branch. On current `main` the only error is `session.is_restricted_admin` being an unknown attribute.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled `session` object has `is_restricted_admin` as an optional boolean.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- 4624(S) An account was successfully logged on (Restricted Admin Mode, monitoring recommendations): https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624
- MS-RDPBCGR 2.2.1.2.1, RDP Negotiation Response (`RESTRICTED_ADMIN_MODE_SUPPORTED`): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
- Sigma, RestrictedAdminMode Registry Value Tampering: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_lsa_disablerestrictedadmin.yml
- MITRE ATT&CK T1550.002 Pass the Hash: https://attack.mitre.org/techniques/T1550/002/
- Related: #1809 (`is_elevated` on `session`, from the same event)
