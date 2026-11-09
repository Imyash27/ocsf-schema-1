This adds two values to the `injection_type_id` enum, `Ptrace (4)` and `Proc Memory (5)`, so code injection on Linux can be normalized instead of falling into `Other`.

### The problem

Process Activity has an Inject activity and an `injection_type_id` enum for the method used. Today the enum has three values, all from the Windows world:

| id | caption |
|---|---|
| 1 | Remote Thread |
| 2 | Load Library |
| 3 | Queue APC |
| 99 | Other |

The two common ways to inject code into another process on Linux have no value:

- **Ptrace.** The process trace system call lets one process attach to another (`PTRACE_ATTACH`, `PTRACE_SEIZE`) and then write to its memory (`PTRACE_POKETEXT`, `PTRACE_POKEDATA`) or registers (`PTRACE_SETREGS`). This is how debuggers work, and also how injection tools work.
- **Proc memory.** A process with enough rights can open `/proc/[pid]/mem` and write straight into the target's memory, without ptrace at all, for example with `dd`.

A producer that sees either of these today has to use `injection_type_id = 99` with a free text `injection_type`, so a query on the normalized id cannot find them.

### Where the data comes from

| source | what it reports | example |
|---|---|---|
| auditd, `ptrace` syscall rule | `SYSCALL` record with `syscall=101` (x86_64), the request in `a0`, the target pid in `a1`, and an `OBJ_PID` record for the target | `a0=10` (`PTRACE_ATTACH`), `a1=1e61` |
| Falco, default rule "PTRACE attached to process" | `evt.type=ptrace` with `evt.arg.request` one of `PTRACE_POKETEXT`, `PTRACE_POKEDATA`, `PTRACE_ATTACH`, `PTRACE_SEIZE`, `PTRACE_SETREGS` | rule fires with `Detected ptrace PTRACE_ATTACH attempt` |
| Sigma, "Potential Linux Process Code Injection Via DD Utility" | process creation of `dd` with `of=` pointing at `/proc/.../mem` | `dd if=payload of=/proc/7777/mem bs=1 seek=...` |

The widely used Neo23x0 auditd ruleset logs every ptrace call (`-a always,exit -F arch=b64 -S ptrace -k tracing`) and notes that the request value tells injection apart from debugging (`0x4=PTRACE_POKETEXT, 0x5=PTRACE_POKEDATA, 0x6=PTRACE_POKEUSR`).

### Why it matters

Both are named MITRE ATT&CK techniques:

- **T1055.008, Ptrace System Calls**: "Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges." MITRE calls out `PTRACE_POKETEXT`/`PTRACE_POKEDATA` specifically.
- **T1055.009, Proc Memory**: "Proc memory injection involves enumerating the memory of a process via the /proc filesystem (`/proc/[pid]`)", after which the memory "can be overwritten using dd."

Falco's rule for the first is tagged `T1055.008`, and the Sigma rule for the second is tagged `attack.t1055.009`. With the new values, one normalized query covers both sources, for example `class_uid = 1007 AND activity_id = 4 AND injection_type_id IN (4, 5) AND process.name IN ("sshd", "nginx", "systemd")`.

### Design

- **Two new enum values, not a new attribute.** The Inject activity and `injection_type_id` already model exactly this. The new values just fill in the Linux methods, the same way #1787 added RC4 to an existing algorithm enum.
- **Names follow MITRE.** `Ptrace` and `Proc Memory` match the ATT&CK sub-technique names, so mapping from ATT&CK tagged detections is direct.
- **Descriptions.** The existing values have captions only. The two new ones also have a description, so it is clear that Proc Memory means writing through `/proc/[pid]/mem` without ptrace, and Ptrace means the system call. I added references to the ptrace(2) and proc_pid_mem(5) man pages on `injection_type_id`.
- **Out of scope.** Other sub-techniques (for example Thread Execution Hijacking, Process Hollowing, VDSO Hijacking) could be added the same way when a source needs them. I kept this PR to the two Linux methods that have clear telemetry today.

### What changes

- `dictionary.json`: adds `4` Ptrace and `5` Proc Memory to `injection_type_id`, with descriptions, plus references to ptrace(2) and proc_pid_mem(5).
- `CHANGELOG.md`: entry under Improved, Dictionary Attributes.
- `.github/.project-words.txt`: adds `POKEDATA`, `POKETEXT` and `SETREGS` (ptrace request names in the description) for cspell.

### Example

auditd records for a root `python3` process attaching to the `nginx` worker (pid 7777, `www-data`) with ptrace on x86_64. `syscall=101` is `ptrace`, `a0=10` is `PTRACE_ATTACH` (16), `a1=1e61` is the target pid:

```
type=SYSCALL msg=audit(1794219664.211:9031): arch=c000003e syscall=101 success=yes exit=0 a0=10 a1=1e61 a2=0 a3=0 items=0 ppid=48211 pid=48390 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4 comm="python3" exe="/usr/bin/python3.10" key="tracing"
type=OBJ_PID msg=audit(1794219664.211:9031): opid=7777 oauid=-1 ouid=33 oses=-1 ocomm="nginx"
```

Field mapping:

| auditd | OCSF |
|---|---|
| `syscall=101` (`ptrace`) with `a0=10` (`PTRACE_ATTACH`) | `activity_id` = 4 (Inject), **`injection_type_id` = 4 (Ptrace)**, no place for it today |
| `pid`, `ppid`, `comm`, `exe` | `actor.process.pid`, `actor.process.parent_process.pid`, `actor.process.name`, `actor.process.file.path` |
| `uid`, `auid` | `actor.process.user.uid`, `actor.process.auid` |
| `opid`, `ocomm`, `ouid` | `process.pid`, `process.name`, `process.user.uid` |
| `success=yes` | `status_id` = 1 |

Result, Process Activity (1007), Inject:

```json
{
  "activity_id": 4,
  "category_uid": 1,
  "class_uid": 1007,
  "type_uid": 100704,
  "severity_id": 1,
  "status_id": 1,
  "time": 1794219664211,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "auditd", "vendor_name": "Linux Audit" },
    "event_code": "SYSCALL",
    "uid": "9031"
  },
  "device": { "type_id": 1, "hostname": "web-02", "os": { "name": "Linux", "type_id": 200 } },
  "actor": {
    "process": {
      "pid": 48390,
      "name": "python3",
      "file": { "name": "python3.10", "path": "/usr/bin/python3.10", "type_id": 1 },
      "parent_process": { "pid": 48211 },
      "user": { "uid": "0" },
      "auid": 1000
    }
  },
  "process": {
    "pid": 7777,
    "name": "nginx",
    "user": { "uid": "33" }
  },
  "injection_type_id": 4,
  "injection_type": "Ptrace"
}
```

A write to `/proc/7777/mem` by another process (for example the `dd` case from the Sigma rule, seen by an EDR as a file write to the target's mem file) maps the same way with `injection_type_id` = 5 (Proc Memory).

### Testing

- The sample event validates against the Process Activity class compiled from this branch. On current `main` the only error is `invalid enum injection_type_id=4`.
- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- ptrace(2) man page: https://man7.org/linux/man-pages/man2/ptrace.2.html
- proc_pid_mem(5) man page: https://man7.org/linux/man-pages/man5/proc_pid_mem.5.html
- MITRE ATT&CK T1055.008, Ptrace System Calls: https://attack.mitre.org/techniques/T1055/008/
- MITRE ATT&CK T1055.009, Proc Memory: https://attack.mitre.org/techniques/T1055/009/
- Falco default rules, "PTRACE attached to process": https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
- Sigma, Potential Linux Process Code Injection Via DD Utility: https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_dd_process_injection.yml
- Neo23x0 auditd rules, ptrace section: https://github.com/Neo23x0/auditd/blob/master/audit.rules

The two man pages are also in the attribute `references`.
