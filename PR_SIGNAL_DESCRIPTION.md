This adds a `signal` attribute to Process Activity (1007), so a Terminate event can say which signal ended the target process, or which signal the actor sent to it.

### The problem

Right now the only thing Process Activity has for how a process ended is `exit_code`. That is fine on Windows, but on Linux and macOS it is only half the story. A process either exits on its own and returns a code, or it gets a signal (`SIGKILL`, `SIGTERM`, `SIGSEGV` and so on). When it is killed by a signal, the exit code does not really tell you anything, and the signal is the part you care about.

Endpoint sources already report this separately:

| source | where the signal is | what it looks like |
|---|---|---|
| auditd, `kill` / `tkill` / `tgkill` syscall | `a1` argument of the `SYSCALL` record, target in `OBJ_PID` | `a1=9` |
| auditd, `ANOM_ABEND` (process crashed) | `sig` field | `sig=11` |
| Tetragon `process_exit` | `signal` field, next to `status` | `"signal": "SIGKILL"` |
| macOS Endpoint Security `ES_EVENT_TYPE_NOTIFY_SIGNAL` | `sig` field of `es_event_signal_t`, with `target` and `instigator` | `sig = 9` |

When we normalize these into OCSF today, the actor and target processes map fine, but the signal has nowhere to go and ends up in `unmapped`. Every detection that needs it then has to know the raw field name for each source.

### Why it matters

Killing security tooling is a very common step once someone has root on a Linux box. MITRE ATT&CK T1562.001 (Disable or Modify Tools) mentions "killing security software processes or services", and T1562.012 (Disable or Modify Linux Audit System) calls out killing the `auditd` processes directly. Ransomware also stops services and processes before it encrypts data (T1489, Service Stop).

The signal is what separates the bad case from the normal one:

- `SIGKILL` sent to `falco`, `auditd` or an EDR agent by an interactive root shell is worth an alert.
- `SIGTERM` sent to the same agent by `systemd` during a package upgrade is normal.

Without `signal`, both of these are just Terminate events with the same actor and target shape. With it, the rule is simple, for example `activity_id = 2 AND process.name IN ("auditd", "falco") AND signal = "SIGKILL"`.

It also helps on the crash side. A burst of `SIGSEGV` or `SIGABRT` exits from a network facing service (from `ANOM_ABEND` or Tetragon) is a common sign of memory corruption exploit attempts, and right now that cannot be queried on normalized data at all.

### Why the name and not the number

The value is the signal name, like `SIGKILL`, not the number. Signal numbers are not the same on every architecture. The signal(7) man page shows `SIGUSR1` as 10 on x86 and ARM, 30 on Alpha and SPARC, and 16 on MIPS, and `SIGBUS` as 7 on x86 and ARM but 10 on the others. A raw number is not safe to compare across a mixed fleet. The names come from POSIX `signal.h` and are the same everywhere.

For producers this is a small lookup. auditd and Endpoint Security give the number, and auditd also gives the `arch`, so the producer converts the number to the name for that architecture. Tetragon already gives the name.

I did not add a `signal_id` enum. The list of signals is long, it includes real time signals (`SIGRTMIN+n`), and the numbers would not match any single platform anyway. A string with the POSIX name keeps it simple. If the group would like an enum for the common ones, I can add it.

### What changes

- `dictionary.json`: new `signal` attribute (`string_t`), with the description and references to signal(7) and POSIX `signal.h`.
- `events/system/process_activity.json`: adds `signal` to the class. The class only sets the group and requirement, the description comes from the dictionary.
- `CHANGELOG.md`: entries under Dictionary Attributes and Event Classes.

It is `recommended` in the `primary` group, the same as `exit_code`. I first tried `optional`, but the metaschema does not allow `optional` for `primary` attributes. If `context` / `optional` fits better, I can move it.

I kept it on Process Activity only. The dictionary description is generic ("the signal delivered to a process"), so it could be reused later, for example on a Kernel Activity event, but that is not part of this PR.

### Example

auditd records for `kill -9 7978` run as root against the Falco agent on x86_64. `a1=9` is the signal and `a0=1f2a` is the target pid (7978):

```
type=SYSCALL msg=audit(1793265262.123:4521): arch=c000003e syscall=62 success=yes exit=0 a0=1f2a a1=9 a2=0 a3=0 items=0 ppid=2201 pid=2245 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="kill" exe="/usr/bin/kill" key="sig_kill"
type=OBJ_PID msg=audit(1793265262.123:4521): opid=7978 oauid=-1 ouid=0 oses=-1 ocomm="falco"
```

Field mapping:

| auditd | OCSF |
|---|---|
| `syscall=62` (`kill` on x86_64) | `activity_id` = 2 (Terminate) |
| `pid`, `ppid`, `comm`, `exe` | `actor.process.pid`, `actor.process.parent_process.pid`, `actor.process.name`, `actor.process.file.path` |
| `uid`, `auid` | `actor.process.user.uid`, `actor.process.auid` |
| `opid`, `ocomm`, `ouid` | `process.pid`, `process.name`, `process.user.uid` |
| `a1=9` with `arch=c000003e` | **`signal` = `SIGKILL`** (no place for it today) |
| `success=yes` | `status_id` = 1 |

Result, Process Activity, Terminate:

```json
{
  "activity_id": 2,
  "category_uid": 1,
  "class_uid": 1007,
  "type_uid": 100702,
  "severity_id": 1,
  "status_id": 1,
  "time": 1793265262123,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "auditd", "vendor_name": "Linux Audit" },
    "event_code": "SYSCALL",
    "uid": "4521"
  },
  "device": { "type_id": 1, "hostname": "web-01", "os": { "name": "Linux", "type_id": 200 } },
  "actor": {
    "process": {
      "pid": 2245,
      "name": "kill",
      "file": { "name": "kill", "path": "/usr/bin/kill", "type_id": 1 },
      "parent_process": { "pid": 2201 },
      "user": { "uid": "0" },
      "auid": 1000
    }
  },
  "process": {
    "pid": 7978,
    "name": "falco",
    "user": { "uid": "0" }
  },
  "signal": "SIGKILL"
}
```

The same thing from other sources:

- Tetragon `process_exit` for the Falco process with `"signal": "SIGKILL"` maps to `signal` = `SIGKILL`, with `status` going to `exit_code`.
- macOS Endpoint Security `NOTIFY_SIGNAL` with `sig = 9` maps to `signal` = `SIGKILL`, with `instigator` as the actor and `target` as `process`.

### Testing

- The sample event validates against the Process Activity class compiled from this branch. On current `main` the only error is `signal` being an unknown attribute.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- signal(7) man page, signal names and the per architecture numbers: https://man7.org/linux/man-pages/man7/signal.7.html
- POSIX `signal.h`, the standard signal names: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/signal.h.html
- Tetragon API, `ProcessExit` (`signal` and `status`): https://tetragon.io/docs/reference/grpc-api/
- Linux audit field dictionary (`sig`): https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv
- Apple Endpoint Security, `es_event_signal_t`: https://developer.apple.com/documentation/endpointsecurity/es_event_signal_t
- MITRE ATT&CK T1562.001, Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1562.012, Disable or Modify Linux Audit System: https://attack.mitre.org/techniques/T1562/012/
- MITRE ATT&CK T1489, Service Stop: https://attack.mitre.org/techniques/T1489/

The first two are also in the attribute `references`.
