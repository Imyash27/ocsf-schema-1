This adds a `call_stack` attribute to Process Activity (1007), for the call stack of the thread that opened or injected into the target process.

Sysmon event 10 (ProcessAccess) has a `CallTrace` field with the stack of the thread that called `OpenProcess`, for example `C:\Windows\SYSTEM32\ntdll.dll+9d4c4|C:\Windows\System32\KERNELBASE.dll+2c13e|...`. Process Activity already covers the rest of that event (`actor.process`, `process`, `actual_permissions` for `GrantedAccess`), but there is nowhere to put the call trace, so it goes to `unmapped`. Elastic Defend has the same kind of data in `call_stack` / `call_stack_summary` on its process events.

This is one of the more useful fields in that event. Sigma alone has 17 rules in `rules/windows/process_access` that match on `CallTrace`, for example:

- "Lsass Memory Dump via Comsvcs DLL": `TargetImage` lsass.exe, `SourceImage` rundll32.exe, `CallTrace` contains `comsvcs.dll`
- "Potential Credential Dumping Activity Via LSASS": `CallTrace` contains `dbgcore.dll` or `dbghelp.dll`
- "Potential Direct Syscall of NtOpenProcess": `CallTrace` starts with `UNKNOWN`, meaning the call came from memory that is not backed by a module

Elastic's "Suspicious Process Access via Direct System Call" rule uses the same idea. None of these can be written on normalized OCSF data today.

The value is an array of strings, one per frame, most recent call first, kept as the source reports it. For Sysmon that means splitting `CallTrace` on `|`. I did not try to turn each frame into an object with module and offset fields. Sources format frames differently (`module+offset`, `module!symbol+offset`, `UNKNOWN(address)`), and the detections above only do contains / starts with on the frame text, so plain strings are enough and easy to map. If people would rather have a structured frame object, I can change it.

The description is in `dictionary.json` and the class only sets the requirement. It is `optional` in the `context` group, since most sources do not send it. I also added `ntdll` to the project words for cspell.

Example, a Sysmon event 10 for rundll32 opening lsass through comsvcs.dll:

```xml
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

I validated the sample against the compiled schema from this branch (on current `main` the only error is `call_stack` being unknown), and ran the validator, compiler, compatibility check and cspell locally. All pass.

The dictionary description is generic enough to reuse later on other classes like Memory Activity or Module Activity, but this PR only adds it to Process Activity.

References:
- https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon (Event ID 10, ProcessAccess)
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll.yml
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_lsass_memdump.yml
- https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_susp_direct_ntopenprocess_call.yml
- https://www.elastic.co/guide/en/security/current/suspicious-process-access-via-direct-system-call.html
- https://www.elastic.co/security-labs/peeling-back-the-curtain-with-call-stacks
- https://attack.mitre.org/techniques/T1003/001/
