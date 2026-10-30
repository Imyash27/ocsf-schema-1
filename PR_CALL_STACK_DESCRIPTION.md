This adds a `call_stack` attribute to Process Activity (1007), for the call stack of the thread that opened or injected into the target process.

### The problem

Sysmon event 10 (ProcessAccess) is one of the most used Windows events for credential theft detection. It fires when one process opens another, and it includes a `CallTrace` field with the stack of the thread that made the `OpenProcess` call. It is one string, frames separated by `|`, each frame a module path plus an offset:

```
C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|C:\Windows\System32\comsvcs.dll+3b8ef|...
```

Process Activity already covers everything else in that event:

| Sysmon event 10 | OCSF today |
|---|---|
| `SourceProcessId`, `SourceThreadId`, `SourceImage` | `actor.process.pid`, `actor.process.tid`, `actor.process.file.path` |
| `SourceUser` | `actor.user` |
| `TargetProcessId`, `TargetImage` | `process.pid`, `process.file.path` |
| `GrantedAccess` | `actual_permissions` |
| `CallTrace` | nothing, goes to `unmapped` |

So the field that most of the detections key on is the one that gets lost. EDR products report the same kind of data too. Elastic Defend, for example, puts call stacks in `process.thread.Ext.call_stack` and a short form in `call_stack_summary` (like `ntdll.dll|kernelbase.dll|Unbacked`) on its process, file, library and registry events.

### Why it matters

The call stack tells you how the access happened, not just who opened what. That matters a lot for LSASS (MITRE ATT&CK T1003.001), because plenty of legitimate software opens lsass, and the call stack is often what separates a real dump from a normal access. Sigma alone has 17 rules under `rules/windows/process_access` that match on `CallTrace`. A few examples:

- **Lsass Memory Dump via Comsvcs DLL**: `TargetImage` ends with `\lsass.exe`, `SourceImage` ends with `\rundll32.exe`, `CallTrace` contains `comsvcs.dll`. This is the `rundll32 comsvcs.dll, MiniDump` trick.
- **Potential Credential Dumping Activity Via LSASS**: lsass access where `CallTrace` contains `dbgcore.dll` or `dbghelp.dll`, the DLLs behind `MiniDumpWriteDump`.
- **Potential Direct Syscall of NtOpenProcess**: `CallTrace` starts with `UNKNOWN`, meaning the call came from memory that is not backed by any module on disk. This is a common sign of shellcode or tools that skip the normal API to avoid hooks.

Elastic's prebuilt rule "Suspicious Process Access via Direct System Call" uses the same idea: alert when the call trace does not start with ntdll or another known system module.

None of these can be written against normalized OCSF data today. With `call_stack`, the comsvcs rule becomes something like `activity_id = 3 AND process.file.name = "lsass.exe" AND call_stack contains "comsvcs.dll"`, and it works the same for Sysmon and for any EDR that maps its stack into the same attribute.

### Design

The value is an array of strings, one per frame, most recent call first, each frame kept as the source reports it. For Sysmon, that just means splitting `CallTrace` on `|`.

I thought about making each frame an object (module, offset, symbol, is backed), but decided against it for now:

- Sources format frames differently: `module+offset` in Sysmon, `module!function+offset` or `module!function` in EDR stacks, and `UNKNOWN(address)` or `Unbacked` for frames with no module behind them. Splitting these into fields would mean guessing for some sources.
- The detections above only do "contains" or "starts with" on the frame text. An array of strings supports that directly.
- Keeping frames as text means nothing gets lost in mapping.

If people would rather have a structured frame object, I am happy to rework it. A string array could still be kept next to it as the raw form.

It is `optional` in the `context` group, since most sources do not send a call stack and it is only present on some activities (Open and Inject mainly).

### What changes

- `dictionary.json`: new `call_stack` attribute, an array of `string_t`, with the full description.
- `events/system/process_activity.json`: adds `call_stack` to the class. The class only sets the group and requirement.
- `CHANGELOG.md`: entries under Dictionary Attributes and Event Classes.
- `.github/.project-words.txt`: adds `ntdll`, which cspell flags in the description example.

I only added it to Process Activity. The dictionary description is written generically ("the call stack of the thread that performed the activity"), so it can be added later to classes like Module Activity, Memory Activity or File System Activity, where some EDRs also send stacks. I kept this PR small on purpose.

### Example

Sysmon event 10, rundll32 opening lsass through comsvcs.dll:

```xml
<Data Name="UtcTime">2026-10-29 09:14:22.448</Data>
<Data Name="SourceProcessId">6412</Data>
<Data Name="SourceThreadId">5520</Data>
<Data Name="SourceImage">C:\Windows\System32\rundll32.exe</Data>
<Data Name="TargetProcessId">724</Data>
<Data Name="TargetImage">C:\Windows\System32\lsass.exe</Data>
<Data Name="GrantedAccess">0x1FFFFF</Data>
<Data Name="CallTrace">C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|C:\Windows\System32\comsvcs.dll+3b8ef|C:\Windows\System32\rundll32.exe+3bd4|C:\Windows\System32\KERNEL32.DLL+17034|C:\Windows\SYSTEM32\ntdll.dll+52651</Data>
<Data Name="SourceUser">CONTOSO\jdoe</Data>
```

mapped to Process Activity, Open:

```json
{
  "activity_id": 3,
  "category_uid": 1,
  "class_uid": 1007,
  "type_uid": 100703,
  "severity_id": 1,
  "time": 1793265262448,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Sysmon", "vendor_name": "Microsoft" },
    "event_code": "10"
  },
  "device": { "type_id": 2, "hostname": "WS-0142.contoso.local", "os": { "name": "Windows", "type_id": 100 } },
  "actor": {
    "process": {
      "pid": 6412,
      "tid": 5520,
      "file": { "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe", "type_id": 1 }
    },
    "user": { "name": "jdoe", "domain": "CONTOSO" }
  },
  "process": {
    "pid": 724,
    "file": { "name": "lsass.exe", "path": "C:\\Windows\\System32\\lsass.exe", "type_id": 1 }
  },
  "actual_permissions": 2097151,
  "call_stack": [
    "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4",
    "C:\\Windows\\System32\\KERNELBASE.dll+2c13e",
    "C:\\Windows\\System32\\comsvcs.dll+3b8ef",
    "C:\\Windows\\System32\\rundll32.exe+3bd4",
    "C:\\Windows\\System32\\KERNEL32.DLL+17034",
    "C:\\Windows\\SYSTEM32\\ntdll.dll+52651"
  ]
}
```

The third frame is `comsvcs.dll`, which is exactly what the Sigma comsvcs rule looks for. For a direct syscall case the first frame would be something like `UNKNOWN(00000216A4C10F2B)` instead of ntdll.

### Testing

- The sample event validates against the Process Activity class compiled from this branch. On current `main` the only error is `call_stack` being an unknown attribute.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- Sysmon, Event ID 10 ProcessAccess: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sigma, Lsass Memory Dump via Comsvcs DLL: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml
- Sigma, Potential Credential Dumping Activity Via LSASS: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml
- Sigma, Potential Direct Syscall of NtOpenProcess: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_susp_direct_ntopenprocess_call.yml
- Elastic, Suspicious Process Access via Direct System Call: https://www.elastic.co/guide/en/security/current/suspicious-process-access-via-direct-system-call.html
- Elastic Security Labs, Peeling back the curtain with call stacks: https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks
- MITRE ATT&CK T1003.001, LSASS Memory: https://attack.mitre.org/techniques/T1003/001/
