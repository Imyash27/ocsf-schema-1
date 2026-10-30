This adds an optional `is_hidden` boolean to the `file` object, next to `is_system` and `is_readonly`.

Right now there is no good way to say a file is hidden in OCSF. The only place is `file.attributes`, which is just the raw bitmask. That kind of works for Windows if the producer passes the value through, but the consumer still has to know it came from Windows and check bit `0x2`. It doesn't help at all for macOS, where hidden is the `UF_HIDDEN` flag (`chflags hidden`), or for Linux, where hidden just means the name starts with a period.

We run into this when normalizing endpoint data from all three platforms. Hiding a dropped file is a pretty common evasion step (MITRE ATT&CK T1564.001 covers `attrib +h`, `chflags hidden` and dot files), and there is a Sigma rule for `attrib.exe` with ` +h `. That rule only sees the command line though. With `is_hidden` on the file itself you can hunt for things like hidden scripts under `C:\Users\Public` in file events or inventory data, whatever tool hid the file, and the same query works on macOS and Linux.

`is_system` and `is_readonly` already exist for the same reason, so this just follows that pattern. The description and references are in `dictionary.json` and the `file` object only sets the requirement. I kept the dictionary description generic so it could be reused later (hidden registry keys, hidden accounts), but this PR only adds it to `file`.

Example, an osquery `file` table result from a Windows host (`HA` = hidden + archive):

```json
{
  "name": "pack_hunting_hidden_files",
  "hostIdentifier": "WS-0142",
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

mapped to File Query (5007):

```json
{
  "activity_id": 1,
  "category_uid": 5,
  "class_uid": 5007,
  "type_uid": 500701,
  "severity_id": 1,
  "query_result_id": 1,
  "time": 1793265262000,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "osquery", "vendor_name": "osquery" }
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

`attributes` keeps the raw Windows value and `is_hidden` is the normalized flag. A macOS row with `bsd_flags` = `HIDDEN` would map to the same `is_hidden: true`.

I validated the sample against the compiled schema from this branch, and ran the validator, compiler, compatibility check and cspell locally. All pass.

References:
- https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants (`FILE_ATTRIBUTE_HIDDEN`)
- https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/chflags.2.html (`UF_HIDDEN`)
- https://github.com/osquery/osquery/blob/master/specs/utility/file.table
- https://attack.mitre.org/techniques/T1564/001/
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_attrib_hiding_files.yml
