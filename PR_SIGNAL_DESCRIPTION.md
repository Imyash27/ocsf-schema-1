This adds `terminating_signal_id` and its sibling `terminating_signal` to Process Activity (1007), so a Terminate event can say which signal ended the target process, or which signal the actor sent to terminate it.

### The problem

Right now the only thing Process Activity has for how a process ended is `exit_code`. That is fine on Windows, but on Linux, macOS and other Unix-like systems it is only half the story. A process either exits on its own and returns a code, or it is terminated by a signal (`SIGKILL`, `SIGTERM`, `SIGSEGV` and so on). When it is killed by a signal, the exit code does not really tell you anything, and the signal is the part you care about.

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

Without the signal, both of these are just Terminate events with the same actor and target shape. With it, the rule is simple, for example `activity_id = 2 AND process.name IN ("auditd", "falco") AND terminating_signal_id = 9`.

It also helps on the crash side. A burst of `SIGSEGV` or `SIGABRT` exits from a network facing service (from `ANOM_ABEND` or Tetragon) is a common sign of memory corruption exploit attempts, and right now that cannot be queried on normalized data at all.

### Scope

- **Only termination.** The attribute is about the signal that terminated the process, or that the actor sent to terminate it, so it only makes sense on the Terminate activity. A signal that does not end the process (for example `SIGSTOP`, or `SIGHUP` caught by a daemon to reload its config) does not produce a Terminate event.
- **POSIX and Unix-like systems.** Signals are a POSIX mechanism. Windows does not terminate processes with signals (it uses `TerminateProcess` and an exit code), so on Windows `terminating_signal_id` is simply not set and `exit_code` carries the result.

### The enum

The enum lists the POSIX signals whose default action is to terminate the process (POSIX `signal.h` actions T and A). The ids follow the Linux signal numbers on x86 and ARM, which covers most Linux producers, so those can map the number directly:

| id | caption | POSIX description |
|---|---|---|
| 0 | Unknown | |
| 1 | SIGHUP | Hangup |
| 2 | SIGINT | Terminal interrupt signal |
| 3 | SIGQUIT | Terminal quit signal |
| 4 | SIGILL | Illegal instruction |
| 5 | SIGTRAP | Trace or breakpoint trap |
| 6 | SIGABRT | Process abort signal |
| 7 | SIGBUS | Access to an undefined portion of a memory object |
| 8 | SIGFPE | Erroneous arithmetic operation |
| 9 | SIGKILL | Kill (cannot be caught or ignored) |
| 10 | SIGUSR1 | User-defined signal 1 |
| 11 | SIGSEGV | Invalid memory reference |
| 12 | SIGUSR2 | User-defined signal 2 |
| 13 | SIGPIPE | Write on a pipe with no one to read it |
| 14 | SIGALRM | Alarm clock |
| 15 | SIGTERM | Termination signal |
| 24 | SIGXCPU | CPU time limit exceeded |
| 25 | SIGXFSZ | File size limit exceeded |
| 26 | SIGVTALRM | Virtual timer expired |
| 31 | SIGSYS | Bad system call |
| 99 | Other | any other signal, with the source value in `terminating_signal` |

Signal numbers are not the same everywhere. The signal(7) man page shows `SIGUSR1` as 10 on x86 and ARM, 30 on Alpha and SPARC, and 16 on MIPS, and `SIGBUS` as 7 on x86 and ARM but 10 on the others, and macOS uses the BSD numbering. So the ids are OCSF normalized values, not raw numbers. Producers on other architectures or operating systems map by signal name, which POSIX defines the same everywhere. auditd gives the number along with the `arch`, Endpoint Security gives the macOS number, and Tetragon already gives the name.

The gaps in the ids (16 to 23, 27 to 30) are the signals that do not terminate by default (`SIGCHLD`, `SIGCONT`, `SIGSTOP` and so on) or are not in POSIX (`SIGSTKFLT`, `SIGPROF`, `SIGWINCH`, `SIGIO`, `SIGPWR`). Real-time signals and anything else go to Other.

### Design

- **Name.** Following review feedback, the attribute is `terminating_signal` rather than plain `signal`, which means many things in a security schema (detection signals, weak signals in hunting).
- **Enum with sibling.** Also following review feedback, it is an `integer_t` enum with a `string_t` sibling, which models the mechanism better than a free string and keeps the well known names as captions.
- **Class attribute.** It sits on Process Activity next to `exit_code`. It is `recommended` in the `primary` group, the same as `exit_code` (the metaschema does not allow `optional` for `primary` attributes). If `context` / `optional` fits better, I can move it.
- **Dictionary first.** Full descriptions, the enum and the references are in `dictionary.json`. The class only sets the group and requirement.

### What changes

- `dictionary.json`: adds `terminating_signal_id` (`integer_t` enum with references to signal(7) and POSIX `signal.h`) and `terminating_signal` (`string_t` sibling).
- `events/system/process_activity.json`: adds both to the class.
- `CHANGELOG.md`: entries under Dictionary Attributes and Event Classes, with the link to this PR.

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
| `a1=9` with `arch=c000003e` | **`terminating_signal_id` = 9, `terminating_signal` = `SIGKILL`** (no place for it today) |
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
  "terminating_signal_id": 9,
  "terminating_signal": "SIGKILL"
}
```

The same thing from other sources:

- Tetragon `process_exit` for the Falco process with `"signal": "SIGKILL"` maps to `terminating_signal_id` = 9 by name, with `status` going to `exit_code`.
- macOS Endpoint Security `NOTIFY_SIGNAL` with `sig = 9` maps to `terminating_signal_id` = 9, with `instigator` as the actor and `target` as `process`. For signals where the macOS number differs from Linux (for example `SIGBUS` is 10 on macOS), the producer maps by name.

### Testing

- The sample event validates against the Process Activity class compiled from this branch. On current `main` the only errors are the two new attributes being unknown.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- signal(7) man page, signal names and the per architecture numbers: https://man7.org/linux/man-pages/man7/signal.7.html
- POSIX `signal.h`, the standard signals and their default actions: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/signal.h.html
- Tetragon API, `ProcessExit` (`signal` and `status`): https://tetragon.io/docs/reference/grpc-api/
- Linux audit field dictionary (`sig`): https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv
- Apple Endpoint Security, `es_event_signal_t`: https://developer.apple.com/documentation/endpointsecurity/es_event_signal_t
- MITRE ATT&CK T1562.001, Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1562.012, Disable or Modify Linux Audit System: https://attack.mitre.org/techniques/T1562/012/
- MITRE ATT&CK T1489, Service Stop: https://attack.mitre.org/techniques/T1489/

The first two are also in the attribute `references`.
