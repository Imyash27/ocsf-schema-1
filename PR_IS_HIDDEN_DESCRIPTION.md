#### Related Issue:
None. The problem, sample mapping and references are below.

#### Description of changes:

Adds one optional attribute to the `file` object so a hidden file or directory can be flagged directly, next to the existing `is_system` and `is_readonly` flags.

| attribute | type | requirement |
|---|---|---|
| `is_hidden` | `boolean_t` | optional |

`is_hidden` is defined in `dictionary.json` with its full description and `references`. The `file` object only sets the requirement.

#### Background

Every major platform has a notion of a hidden file, but each records it differently:

| platform | how a file is hidden | how a sensor sees it |
|---|---|---|
| Windows | `FILE_ATTRIBUTE_HIDDEN` (`0x2`), set with `attrib +h` | file attributes bitmask, for example osquery `attributes` = `H` |
| macOS | `UF_HIDDEN` file flag, set with `chflags hidden` | BSD file flags, for example osquery `bsd_flags` = `HIDDEN` |
| Linux and other Unix-like systems | name begins with a period | the file name |

Microsoft describes `FILE_ATTRIBUTE_HIDDEN` as "The file or directory is hidden. It is not included in an ordinary directory listing." The `chflags(2)` manual page describes `UF_HIDDEN` as a hint that the file "is not intended to be displayed to the user".

Today the only place for this in OCSF is `file.attributes`, an `integer_t` bitmask with no defined bit meanings. That works for Windows producers that pass the raw value through, but it does not work for macOS flags or for dot files, and a consumer has to know which platform's bit layout was used before it can test for "hidden". `is_system` and `is_readonly` already solve the same problem for the system and read only bits, so `is_hidden` follows the same pattern.

#### Why it matters

Hiding files is a common defense evasion step, so "is this file hidden" is a field detections are written against:

- MITRE ATT&CK [T1564.001, Hide Artifacts: Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/) covers all three mechanisms above: `attrib.exe +h` on Windows, `chflags hidden` (`UF_HIDDEN`) on macOS, and a leading period on Linux and macOS.
- The Sigma rule "Hiding Files with Attrib.exe" matches `attrib.exe` launched with ` +h `. That rule sees the command, and `is_hidden` lets the resulting file state be queried in file events and inventory data, whichever tool did the hiding.
- Hunting queries often look for executables or scripts that are hidden in user writable locations, for example a hidden `.ps1` under `C:\Users\Public`. With `is_hidden` this becomes one normalized predicate instead of one per platform.

#### Example

osquery scheduled query result from the `file` table on Windows (`attributes` is the attrib string, `HA` = hidden and archive):

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

Maps to File Query (5007), Query:

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

`attributes` keeps the raw Windows value (`0x22`, hidden and archive) and `is_hidden` carries the normalized flag. The same row from macOS, with `bsd_flags` = `HIDDEN`, maps to `is_hidden: true` without any Windows bit layout.

The sample validates against the File Query class compiled with this change. Against current `main` the only error is `unknown attribute file.is_hidden`.

#### Design choices worth flagging

1. A boolean on `file`, not a new enum or a breakdown of `attributes`. This matches `is_system`, `is_readonly`, `is_encrypted` and `is_deleted`, and keeps `attributes` as the raw value.
2. Defined generically in the dictionary ("the object is hidden from ordinary directory listings and default user interfaces") so it can be reused later, for example for hidden registry keys or hidden accounts, with the file specific meaning given as the example.
3. Only the `file` object is changed. Happy to add it elsewhere if the group prefers.

#### References

Platform documentation
- [File Attribute Constants](https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants): `FILE_ATTRIBUTE_HIDDEN` (`0x2`), "The file or directory is hidden. It is not included in an ordinary directory listing." Cited in the attribute `references`.
- [chflags(2) manual page](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/chflags.2.html): `UF_HIDDEN`, "not intended to be displayed to the user". Cited in the attribute `references`.
- [osquery `file` table spec](https://github.com/osquery/osquery/blob/master/specs/utility/file.table): `attributes` (Windows attrib string) and `bsd_flags` (macOS, includes `HIDDEN`).

Detection content
- [MITRE ATT&CK T1564.001, Hide Artifacts: Hidden Files and Directories](https://attack.mitre.org/techniques/T1564/001/): `attrib.exe +h`, `UF_HIDDEN` and dot files.
- [Sigma rule, Hiding Files with Attrib.exe](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml): `attrib.exe` with ` +h `.

Files touched: `dictionary.json`, `objects/file.json`, `CHANGELOG.md`.

#### Confirmations

1. `Unreleased` entries added to `CHANGELOG.md` (Dictionary Attributes and Objects). PR link to be added once the number is known.
2. Contribution guidelines followed. Every commit carries a `Signed-off-by` trailer.
3. Validated locally:
   - `python -m ocsf_validator .` passes, with the same output as `main`
   - `ocsf-schema-compiler .` compiles with zero errors and zero warnings, in both default and browser mode
   - `python -m ocsf.validate.compatibility` against `main` passes all five checks
   - `cspell` with the repository config reports no unknown words in the changed lines
   - the sample event is valid against the compiled File Query class
4. PR title matches the description.
5. Captions and descriptions follow the normative and neutral style: no URLs, trademark marks or company names in the caption or description, and citations are in `references`.
