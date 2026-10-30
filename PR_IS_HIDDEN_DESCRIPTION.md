#### Related Issue:
No separate issue, details are below.

#### Description of changes:

This adds an optional `is_hidden` boolean to the `file` object, next to `is_system` and `is_readonly`.

| attribute | type | requirement |
|---|---|---|
| `is_hidden` | `boolean_t` | optional |

The description and references live in `dictionary.json`. The `file` object only sets the requirement.

#### Problem

We normalize endpoint file data from Windows, macOS and Linux, and there is no clean way to say a file is hidden. The only option today is `file.attributes`, which is a raw bitmask. That works for Windows if you pass the value through, but the consumer still has to know it came from Windows to check bit `0x2`. It does not cover macOS at all, and it does not cover dot files on Linux.

Each platform does it differently:

| platform | how a file gets hidden | what the sensor reports |
|---|---|---|
| Windows | `FILE_ATTRIBUTE_HIDDEN` (`0x2`), e.g. `attrib +h` | attributes, e.g. osquery `attributes` = `H` |
| macOS | `UF_HIDDEN` flag, e.g. `chflags hidden` | BSD flags, e.g. osquery `bsd_flags` = `HIDDEN` |
| Linux / Unix | file name starts with a period | just the file name |

`is_system` and `is_readonly` already exist for the same reason (they also have bits in the Windows bitmask), so `is_hidden` fits the same pattern.

#### Why it is useful

Hiding a dropped file is a common evasion step. MITRE ATT&CK T1564.001 (Hidden Files and Directories) lists all three methods above, and Sigma has a rule for `attrib.exe` with ` +h `. The Sigma rule only catches the command line though. With `is_hidden` on the file itself, a hunt like "hidden scripts or executables under `C:\Users\Public`" can run on file events and inventory data no matter which tool hid the file, and the same query works on macOS and Linux.

#### Sample mapping

osquery `file` table result from a Windows host. `HA` means hidden and archive.

```json
{
  "name": "pack_hunting_hidden_files",
  "hostIdentifier": "WS-0142",
  "calendarTime": "Thu Oct 29 09:14:22 2026 UTC",
  "unixTime": 1793265262,
  "action": "added",
  "columns": {
    "path": "C:\\Users\\Public\\Libraries\\update.ps1",
    "directory": "C:\\Users\\Public\\Libraries",
    "filename": "update.ps1",
    "size": "4182",
    "mtime": "1793264980",
    "btime": "1793264978",
    "attributes": "HA"
  }
}
```

Mapped to File Query (5007):

```json
{
  "activity_id": 1,
  "activity_name": "Query",
  "category_uid": 5,
  "class_uid": 5007,
  "type_uid": 500701,
  "severity_id": 1,
  "query_result_id": 1,
  "query_result": "Exists",
  "time": 1793265262000,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "osquery", "vendor_name": "osquery" },
    "event_code": "pack_hunting_hidden_files"
  },
  "device": { "type_id": 2, "hostname": "WS-0142", "os": { "name": "Windows", "type_id": 100 } },
  "file": {
    "name": "update.ps1",
    "path": "C:\\Users\\Public\\Libraries\\update.ps1",
    "parent_folder": "C:\\Users\\Public\\Libraries",
    "type_id": 1,
    "size": 4182,
    "modified_time": 1793264980000,
    "created_time": 1793264978000,
    "attributes": 34,
    "is_hidden": true
  }
}
```

`attributes` still carries the raw Windows value (`0x22`) and `is_hidden` is the normalized flag. A macOS row with `bsd_flags` = `HIDDEN` maps to the same `is_hidden: true`.

I checked the sample against the File Query class compiled from this branch and it passes. On current `main` the only error is `file.is_hidden` being unknown.

#### Notes

- I kept it as a plain boolean like the other `is_*` flags on `file`, and did not try to break `attributes` into named bits.
- The dictionary description is written generically so it could be reused later (hidden registry keys, hidden accounts and so on), but this PR only adds it to `file`. Open to changing the scope if needed.

#### References

- [File Attribute Constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants): `FILE_ATTRIBUTE_HIDDEN` (`0x2`), "The file or directory is hidden. It is not included in an ordinary directory listing."
- [chflags(2) man page](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/chflags.2.html): `UF_HIDDEN`, file "is not intended to be displayed to the user".
- [osquery `file` table spec](https://github.com/osquery/osquery/blob/master/specs/utility/file.table): `attributes` on Windows and `bsd_flags` on macOS.
- [MITRE ATT&CK T1564.001, Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/)
- [Sigma, Hiding Files with Attrib.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml)

The first two are also in the attribute `references`.

Files changed: `dictionary.json`, `objects/file.json`, `CHANGELOG.md`.

#### Confirmations

1. Added `Unreleased` entries in `CHANGELOG.md` (Dictionary Attributes and Objects). Will add the PR link once I have the number.
2. Followed the contribution guidelines, commits are signed off.
3. Tested locally:
   - `python -m ocsf_validator .` passes, same output as `main`
   - `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings
   - `python -m ocsf.validate.compatibility` against `main` passes all five checks
   - `cspell` with the repo config is clean on the changed lines
   - the sample event validates against the compiled File Query class
4. PR title matches the description.
5. Caption and description have no URLs, trademark marks or company names; links are in `references`.
