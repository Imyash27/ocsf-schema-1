#### Related Issue:
None. The problem, sample mapping and references are below.

#### Description of changes:

Adds two optional attributes to the Windows extension so the User Account Control (UAC) elevation type of a process token can be normalized instead of going to `unmapped`.

| attribute | type | requirement |
|---|---|---|
| `token_elevation_type_id` | `integer_t` | optional |
| `token_elevation_type` | `string_t` | optional |

Both are added to `extensions/windows/dictionary.json` and to the Windows `process` object (`extensions/windows/objects/process.json`), next to `hosted_services`. `token_elevation_type_id` carries Unknown (0), Default (1), Full (2), Limited (3) and Other (99), with `token_elevation_type` as its sibling. Both Microsoft pages are cited in `references`.

#### Background

With UAC enabled, an administrator who logs on receives a split token: a limited token with administrative privileges removed, used for normal work, and a linked full token, used only when a program is started with Run as administrator. Accounts that do not get a split token (UAC disabled, the built-in Administrator, service accounts, local system) receive a single default token.

Security event 4688 records which of these a new process received, in the "Token Elevation Type" field:

| 4688 value | meaning | proposed id |
|---|---|---|
| `%%1936` (Type 1) | Default: no linked token | 1 |
| `%%1937` (Type 2) | Full: the process runs elevated | 2 |
| `%%1938` (Type 3) | Limited: administrative privileges removed | 3 |

The enum values deliberately match the Windows `TOKEN_ELEVATION_TYPE` enumeration (`TokenElevationTypeDefault` = 1, `TokenElevationTypeFull` = 2, `TokenElevationTypeLimited` = 3), so 4688 and sensors that call `GetTokenInformation` map directly without a lookup table.

#### Why it matters

Microsoft's monitoring guidance for 4688 is built on this field:

- Full (`%%1937`) on a standard workstation for a real user account means a user ran a program with administrative privileges.
- Default (`%%1936`) for a real user account usually means UAC is disabled for that account.

Both are common detection signals for privilege escalation and UAC bypass. Today a producer converting 4688 to OCSF has no attribute for them.

#### Why this is not `integrity_id`

`process.integrity_id` already covers the 4688 "Mandatory Label" field (S-1-16-8192 = Medium and so on). Integrity level and elevation type are related but separate: the elevation type says which half of a split token the process received, or that it had no linked token. Detections typically need both, for example a Medium integrity process with a Limited token versus a High integrity process with a Full token.

#### Example

Microsoft's documented 4688 example (`explorer.exe` starting `rundll32.exe` for `CONTOSO\dadmin`, `TokenElevationType` = `%%1938`, `MandatoryLabel` = `S-1-16-8192`) maps to Process Activity (1007), Launch, as:

```json
"process": {
  "pid": 700,
  "file": { "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe", "type_id": 1 },
  "user": { "name": "dadmin", "domain": "CONTOSO", "uid": "S-1-5-21-1377283216-344919071-3415362939-1104" },
  "integrity_id": 3,
  "integrity": "Medium",
  "token_elevation_type_id": 3,
  "token_elevation_type": "Limited"
}
```

The sample validates against Process Activity compiled with this change, and against current `main` it fails only on the two new attributes.

#### Design choices worth flagging

1. Windows extension rather than core `process`. Split tokens and UAC exist only on Windows, and the Windows `process` object already holds Windows specific attributes such as `hosted_services`. Happy to move it to core if the group prefers.
2. Values start at 1 to match `TOKEN_ELEVATION_TYPE` and 4688 exactly, while keeping 0 Unknown and 99 Other as the enum convention requires.
3. Other token properties (for example restricted or virtualization enabled tokens) are left out of scope. They can follow the same pattern if there is demand.

#### References

Microsoft documentation
- [How User Account Control works](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works): "When an administrator logs on, two separate access tokens are created for the user: a standard user access token and an administrator access token."
- [TOKEN_ELEVATION_TYPE enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type): `TokenElevationTypeDefault` = 1 ("The token does not have a linked token"), `TokenElevationTypeFull`, `TokenElevationTypeLimited`. Cited in the attribute `references`.
- [GetTokenInformation function](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation): the API endpoint sensors use to read the elevation type of a process token.
- [4688(S) A new process has been created](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688): "Token Elevation Type" field (`%%1936`, `%%1937`, `%%1938`), "Mandatory Label" field, and the monitoring recommendations for `%%1936` and `%%1937`. Cited in the attribute `references`.

Related technique
- [MITRE ATT&CK T1548.002, Abuse Elevation Control Mechanism: Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002/): the technique whose outcome is a process running with the full administrator token without the user consenting to elevation.

Files touched: `extensions/windows/dictionary.json`, `extensions/windows/objects/process.json`, `CHANGELOG.md`.

#### Confirmations

1. `Unreleased` entry added to `CHANGELOG.md` under Platform Extensions. with the PR link.
2. Contribution guidelines followed.
3. Validated locally:
   - `python -m ocsf_validator .` passes, with the same output as `main`
   - `ocsf-schema-compiler .` compiles with zero errors and zero warnings, in both default and browser mode
   - `python -m ocsf.validate.compatibility` against `main` passes all five checks
   - `cspell` with the repository config reports no unknown words in the changed lines
   - the sample event is valid against the compiled Process Activity class
4. PR title matches the description.
5. Captions and descriptions follow the normative and neutral style. Windows terms are used only inside the Windows extension, and citations are in `references`.
