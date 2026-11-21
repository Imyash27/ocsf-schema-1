This adds `security_protocol` and `security_protocol_id` to RDP Activity, for the security protocol that the server selected for the connection (Standard RDP Security, TLS, CredSSP and so on). It reuses the existing generic dictionary attributes and adds an RDP specific enum to the class.

### The problem

When an RDP connection starts, the client lists the security protocols it supports and the server picks one in the RDP Negotiation Response (`selectedProtocol`). That choice decides how the connection is protected and, more importantly, whether the user is authenticated before the remote session is set up:

- With **CredSSP**, which is what Network Level Authentication (NLA) uses, the user is authenticated first.
- With **TLS** or **Standard RDP Security**, the server sets up a session and shows the remote logon screen before anyone has authenticated, and the password is typed into that remote session.

RDP Activity has `protocol_ver`, `certificate_chain`, `capabilities`, `identifier_cookie` and the rest, but nothing for the security protocol, so a producer that has it can only put it in `unmapped`.

### Where the data comes from

| source | field | values |
|---|---|---|
| RDP protocol (MS-RDPBCGR 2.2.1.2.1) | `selectedProtocol` in the RDP Negotiation Response | `PROTOCOL_RDP` (0x0), `PROTOCOL_SSL` (0x1), `PROTOCOL_HYBRID` (0x2), `PROTOCOL_RDSTLS` (0x4), `PROTOCOL_HYBRID_EX` (0x8), `PROTOCOL_RDSAAD` (0x10) |
| Zeek `rdp.log` | `security_protocol` | `RDP`, `SSL`, `HYBRID`, `HYBRID_EX` (from `RDP::security_protocols` in `consts.zeek`) |

The protocol spec describes the values as "Standard RDP Security", "TLS 1.0, 1.1 or 1.2", "CredSSP", "RDSTLS protocol", "Credential Security Support Provider protocol (CredSSP) coupled with the Early User Authorization Result PDU" and "RDS-AAD-Auth Security".

### Why it matters

- **Finding servers that accept RDP without NLA.** Requiring NLA is a standard hardening control for RDP (MITRE ATT&CK T1021.001, Remote Desktop Protocol, is the technique these servers are exposed to). Connections that negotiated TLS or Standard RDP Security show where it is not enforced, and with network data this can be checked across the whole estate, not host by host.
- **Credential exposure.** Without CredSSP, the user types the password into the remote session. A connection to a server that should require NLA but negotiated TLS or Standard RDP Security can mean a misconfiguration or a downgrade by something in the path (T1557, Adversary-in-the-Middle).
- **Policy audits.** Older clients that only offer Standard RDP Security stand out.

With the attribute, the NLA check is one query across network sources:

```
class_uid = 4005 AND activity_id = 2 AND security_protocol_id IN (1, 2)
```

### Design

- **Reuse the dictionary attributes.** `security_protocol` and `security_protocol_id` already exist in the dictionary as generic "See specific usage" attributes, and the `wifi` object uses them with its own enum. RDP Activity does the same, so no new dictionary entries are needed.
- **Enum from the protocol spec.** One value per `selectedProtocol` value, each with `source` set to the constant name (`PROTOCOL_RDP`, `PROTOCOL_SSL` and so on), so producers can map either the number or the name. 0 stays Unknown and 99 Other, as usual.
- **Descriptions say what each value means for authentication**, since that is what people query on: Standard RDP Security and TLS authenticate the user after the session is set up, CredSSP and CredSSP with Early User Authorization before it.
- **Primary and recommended**, since it is one of the main facts about an RDP connection.
- **Left out for now.** Zeek also reports `encryption_level` and `encryption_method`, which only apply to Standard RDP Security. I'm happy to add them here or in a follow-up if people want them.

If reviewers prefer different captions, for example "Hybrid" instead of "CredSSP" to follow the constant names, I can change them.

### What changes

- `events/network/rdp_activity.json`: adds `security_protocol` and `security_protocol_id` (primary, recommended), with the enum, a `source` on each value, and a reference to the RDP Negotiation Response section of MS-RDPBCGR.
- `.github/.project-words.txt`: adds `RDPBCGR`, `RDSAAD` and `RDSTLS` for cspell.
- `changelog.d/1830.md`: the changelog entries for this PR, as described in `changelog.d/README.md`. The `changelog.py check --pr 1830` run passes.

### Example

Zeek `rdp.log` record for a connection where the server selected TLS, so no NLA. Once TLS is negotiated the rest of the connection setup is encrypted, so Zeek only logs what it saw before that:

```json
{
  "ts": 1795084215.337,
  "uid": "CRd3pW1kQx8mYt0fa",
  "id.orig_h": "10.30.2.15",
  "id.orig_p": 53122,
  "id.resp_h": "10.30.9.40",
  "id.resp_p": 3389,
  "cookie": "jdoe",
  "security_protocol": "SSL"
}
```

Field mapping:

| Zeek field | OCSF |
|---|---|
| `ts` | `time` |
| `uid` | `connection_info.uid` |
| `id.orig_h`, `id.orig_p` | `src_endpoint.ip`, `src_endpoint.port` |
| `id.resp_h`, `id.resp_p` | `dst_endpoint.ip`, `dst_endpoint.port` |
| `cookie` | `identifier_cookie` |
| **`security_protocol` = `SSL`** | **`security_protocol_id` = 2 (TLS)**, no place for it today |

Result, RDP Activity (4005), Initial Response:

```json
{
  "activity_id": 2,
  "category_uid": 4,
  "class_uid": 4005,
  "type_uid": 400502,
  "severity_id": 1,
  "time": 1795084215337,
  "metadata": {
    "version": "1.10.0",
    "product": {
      "name": "Zeek",
      "vendor_name": "Zeek"
    },
    "log_name": "rdp"
  },
  "src_endpoint": {
    "ip": "10.30.2.15",
    "port": 53122
  },
  "dst_endpoint": {
    "ip": "10.30.9.40",
    "port": 3389,
    "hostname": "FS-02"
  },
  "connection_info": {
    "uid": "CRd3pW1kQx8mYt0fa",
    "protocol_name": "tcp",
    "direction_id": 0
  },
  "identifier_cookie": "jdoe",
  "security_protocol_id": 2,
  "security_protocol": "TLS"
}
```

### Testing

- The sample event validates against the RDP Activity class compiled from this branch. On current `main` the only errors are `security_protocol_id` and `security_protocol` being unknown attributes.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled class shows the enum with its `source` values.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- MS-RDPBCGR 2.2.1.2.1, RDP Negotiation Response (RDP_NEG_RSP): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/b2975bdc-6d56-49ee-9c57-f2ff3a0b6817
- Zeek RDP analyzer (`rdp.log`): https://github.com/zeek/zeek/blob/master/scripts/base/protocols/rdp/main.zeek
- Zeek RDP constants (`security_protocols`): https://github.com/zeek/zeek/blob/master/scripts/base/protocols/rdp/consts.zeek
- MITRE ATT&CK T1021.001 Remote Desktop Protocol: https://attack.mitre.org/techniques/T1021/001/
- MITRE ATT&CK T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
