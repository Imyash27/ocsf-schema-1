This adds a `signal` attribute to Process Activity (1007), so a Terminate event can say which signal ended the target process, or which signal the actor sent to it.

Right now Process Activity has `exit_code` and nothing else for how a process ended. On Linux and macOS that is only half the story. A process either exits on its own with a code, or it is killed by a signal (`SIGKILL`, `SIGTERM`, `SIGSEGV` and so on), and in the second case the exit code is not really meaningful. Sources report this separately: Tetragon's `process_exit` event has a `signal` field next to `status`, auditd records the signal in the `kill` syscall arguments, and `ANOM_ABEND` records have a `sig` field when a process crashes. Today all of that ends up in `unmapped`.

The reason we care is detection. Killing security tooling is a pretty standard first step on Linux hosts. MITRE ATT&CK T1562.001 mentions "killing security software processes or services", and T1562.012 calls out killing the `auditd` processes directly. A `SIGKILL` sent to an EDR agent or to `auditd` is exactly what you want to alert on, and a `SIGTERM` from systemd during a normal restart is not. Without the signal, those two Terminate events look the same. On the crash side, a burst of `SIGSEGV` or `SIGABRT` in a network service is a common sign of exploitation attempts.

The value is the signal name, not the number. Signal numbers depend on the CPU architecture (the signal(7) man page shows `SIGUSR1` is 10 on x86 and ARM, 30 on Alpha and SPARC, 16 on MIPS), so a raw number is not safe to compare across a fleet. The names come from POSIX `signal.h` and are the same everywhere. auditd gives the number along with the `arch` field, so the producer converts it, and Tetragon already gives the name.

The description and references are in `dictionary.json`, and the class only sets the group and requirement. It is `recommended` in the `primary` group, the same as `exit_code` (the metaschema does not allow `optional` for `primary` attributes). Happy to move it to `context` / `optional` if that fits better.

Example, auditd records for `kill -9 7978` run as root against the Falco agent on x86_64 (`a1=9` is the signal, `a0=1f2a` is the target pid):

```
type=SYSCALL msg=audit(1793265262.123:4521): arch=c000003e syscall=62 success=yes exit=0 a0=1f2a a1=9 a2=0 a3=0 items=0 ppid=2201 pid=2245 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="kill" exe="/usr/bin/kill" key="sig_kill"
type=OBJ_PID msg=audit(1793265262.123:4521): opid=7978 oauid=-1 ouid=0 oses=-1 ocomm="falco"
```

mapped to Process Activity, Terminate:

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

A Tetragon `process_exit` with `"signal": "SIGKILL"` maps to the same `signal` value.

I validated the sample against the compiled schema from this branch (on current `main` the only error is `signal` being unknown), and ran the validator, compiler, compatibility check and cspell locally. All pass.

References:
- https://man7.org/linux/man-pages/man7/signal.7.html (signal names and the per-architecture numbers)
- https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/signal.h.html (POSIX `signal.h`)
- https://tetragon.io/docs/reference/grpc-api/ (`ProcessExit.signal`)
- https://github.com/linux-audit/audit-documentation/blob/main/specs/fields/field-dictionary.csv (`sig` field)
- https://attack.mitre.org/techniques/T1562/001/
- https://attack.mitre.org/techniques/T1562/012/
