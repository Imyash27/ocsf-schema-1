This adds an `LDAP Activity` event class (4016) to the Network category, for Lightweight Directory Access Protocol operations such as Bind, Search, Modify, Add and Delete. It gives the search filter, base DN, search scope, requested attributes and bind method a normalized place, so they no longer end up in `unmapped`.

### The problem

LDAP is how almost everything talks to Active Directory and other directories, and it is also how attackers map a domain. BloodHound/SharpHound, PowerView, ADFind and similar tools collect users, groups, computers, trusts and SPNs with LDAP searches, and what gives them away is the search itself: the filter, where it starts, and which attributes it asks for.

OCSF has no class for this. The closest options today are:

- `Network Activity`, which keeps the connection but has no place for the filter, base DN, scope or attributes.
- `Authentication` with `auth_protocol_id` = LDAP (12), which works for a Bind that logs a user on, but not for a Search, Modify or Delete.

So a producer that reads Zeek or Suricata LDAP logs, or the LDAP search events from an endpoint sensor, has to put the interesting fields in `unmapped`, and a detection cannot be written once for all of them.

### Where the data comes from

| source | what it reports | fields |
|---|---|---|
| Zeek `ldap.log` | one record per LDAP message ID | `message_id`, `version`, `opcode` (`bind simple`, `bind SASL`, `sicily_negotiate`, `search`, `modify`, `add`, `delete`, `compare`, `abandon`, `extended`, ...), `object`, `argument`, `result`, `diagnostic_message` |
| Zeek `ldap_search.log` | one record per search | `message_id`, `base_object`, `scope` (`base`, `single`, `tree`), `deref_aliases`, `filter`, `attributes`, `result_count`, `result`, `diagnostic_message` |
| Suricata `ldap` EVE events | each request and its responses | `ldap.request.operation` (`bind_request`, `search_request`, `modify_request`, `del_request`, ...), `ldap.request.bind_request.name`, `ldap.request.bind_request.sasl.mechanism`, `ldap.request.search_request.base_object`, `ldap.request.search_request.attributes[]`, `ldap.responses[].operation`, and the result code that the `ldap.responses.result_code` keyword matches |
| Microsoft Defender for Endpoint | `DeviceEvents` with `ActionType` `LdapSearch` | `AdditionalFields`: `SearchFilter`, `DistinguishedName`, `ScopeOfSearch`, `AttributeList` |
| Windows LDAP client tracing | Microsoft-Windows-LDAP-Client/Debug event 30 | `SearchFilter`, `DistinguishedName` |
| Microsoft Defender for Identity | `IdentityQueryEvents` | `Query`, `QueryType`, `QueryTarget`, `Protocol` |

Zeek writes the SASL mechanism to `argument` for a SASL bind (for example `GSS-SPNEGO`) and `REDACTED` for a simple bind, unless password capture is turned on. The `attributes` column of `ldap_search.log` is the attribute list from the search request, and it is only logged when `LDAP::default_log_search_attributes` is set.

### Why it matters

LDAP searches are the main signal for Active Directory discovery:

- **MITRE ATT&CK:** T1087.002 Domain Account, T1069.002 Domain Groups, T1482 Domain Trust Discovery, and BloodHound (S0521), which collects this data over LDAP.
- **Sigma:** "Potential Active Directory Reconnaissance/Enumeration Via LDAP" matches `EventID: 30` from the LDAP client trace on `SearchFilter|contains` and `DistinguishedName|contains`. It is tagged `attack.t1069.002`, `attack.t1087.002` and `attack.t1482`.
- **Microsoft's LDAP hunting guidance** works on the same fields. It looks for `(&(samAccountType=805306368)(servicePrincipalName=*))`, the PowerView filter for user accounts with an SPN (Kerberoasting candidates), for SharpHound's computer collection filters, and for searches that ask for `admincount` in `AttributeList`.

Bind details matter too. A simple bind on a connection without TLS sends the password in clear text, and a Sicily bind is NTLM authentication to the directory, which matters when looking for NTLM relayed to LDAP. Zeek already reports both, but they have nowhere to go.

With the class, the Kerberoasting recon search becomes one query across Zeek, Suricata and endpoint sources:

```
class_uid = 4016 AND activity_id = 3
  AND search_filter CONTAINS "servicePrincipalName=*"
  AND search_filter CONTAINS "805306368"
```

Cleartext binds become `class_uid = 4016 AND activity_id = 1 AND bind_type_id = 1 AND is_cleartext = true`.

### Design

- **A protocol class, like DNS, SMB, RDP and SSH.** These protocols each have their own class in the Network category because their requests carry protocol specific fields. LDAP is the same. The class extends `network`, so endpoints, `connection_info`, `traffic` and `tls` come from the base. Because the `host` profile applies, an endpoint sensor can also set `actor.process` for the process that ran the search.
- **One event per operation.** Zeek and Suricata both log a request together with its result, keyed by message ID, so each event is one operation and its outcome, with the message ID in `transaction_id`. I did not split requests and responses into separate activities.
- **Activities follow RFC 4511.** Bind, Unbind, Search, Modify, Add, Delete, Modify DN, Compare, Abandon and Extended. Responses belong to their operation, and an intermediate response belongs to Extended.
- **Result code.** The result goes in the base `status_id` (Success or Failure), the RFC 4511 `resultCode` as the source gives it (number or name) in `status_code`, and the `diagnosticMessage` in `status_detail`. I thought about a normalized result code enum like `rcode_id` in DNS, but RFC 4511 already fixes the numbers and names, so the source value is enough. I can add a `result_code_id` enum if reviewers prefer.
- **Reuse.** `ldap_dn` holds the entry the operation applies to (the bind name, the search base, or the entry being modified, added, deleted, renamed or compared). `transaction_id`, `num_records` (entries returned by a search) and `is_cleartext` are reused as well.
- **New dictionary attributes** are `bind_type` / `bind_type_id`, `sasl_mechanism`, `search_filter`, `search_scope` / `search_scope_id` and `requested_attributes`. The dictionary entries are generic ("See specific usage"), and the class carries the LDAP specific descriptions and enums.
- **`bind_type_id`** is Simple, SASL or Sicily. Sicily is the Microsoft bind method for NTLM described in MS-ADTS 5.1.1.1, and Zeek reports it as `sicily_negotiate` / `sicily_response`.
- **`search_scope_id`** values are 1 greater than the RFC 4511 `scope` values, so that 0 stays Unknown. This follows `download_info.type_id`, which does the same with Mark of the Web zone ids.
- **Uid 16** is the next free uid in the Network category, after DNS Zone Transfer Activity (15).
- **Left out for now.** The list of changes in a Modify (Zeek writes it to `argument`, for example `replace(attribute=value)`), dereferencing of aliases, size and time limits, and the OID of an Extended request. Each can be added later without changing anything here, and I'm happy to add any of them in this PR if people want them now.

If reviewers would rather group the search fields into an `ldap_search` object, or name things differently, I can rework it.

### What changes

- `events/network/ldap_activity.json`: new `LDAP Activity` class (uid 16, so `class_uid` 4016), extending `network`, with the activities above and the class specific descriptions.
- `dictionary.json`: adds `bind_type`, `bind_type_id`, `requested_attributes`, `sasl_mechanism` (with the IANA SASL mechanisms registry as a reference), `search_filter`, `search_scope` and `search_scope_id`.
- `.github/.project-words.txt`: adds `SASL` and `SPNEGO` for cspell.
- `changelog.d/1827.md`: the changelog entries for this PR, as described in `changelog.d/README.md`. The `changelog.py check --pr 1827` run passes.

### Example

Zeek `ldap_search.log` record for a search for user accounts that have an SPN:

```json
{
  "ts": 1795002061.482,
  "uid": "CmES5u32sYpV7JYN1",
  "id.orig_h": "10.20.4.57",
  "id.orig_p": 50122,
  "id.resp_h": "10.20.1.10",
  "id.resp_p": 389,
  "message_id": 7,
  "scope": "tree",
  "deref_aliases": "never",
  "base_object": "DC=corp,DC=example,DC=com",
  "result_count": 14,
  "result": "success",
  "filter": "(&(samAccountType=805306368)(servicePrincipalName=*))",
  "attributes": ["sAMAccountName", "servicePrincipalName", "memberOf"]
}
```

Field mapping:

| Zeek field | OCSF |
|---|---|
| `ts` | `time` |
| `uid` | `connection_info.uid` |
| `id.orig_h`, `id.orig_p` | `src_endpoint.ip`, `src_endpoint.port` |
| `id.resp_h`, `id.resp_p` | `dst_endpoint.ip`, `dst_endpoint.port` |
| (log is `ldap_search`) | `activity_id` = 3 (Search) |
| `message_id` | `transaction_id` |
| `base_object` | **`ldap_dn`** |
| `scope` = `tree` | **`search_scope_id`** = 3 (Whole Subtree) |
| `filter` | **`search_filter`** |
| `attributes` | **`requested_attributes`** |
| `result_count` | `num_records` |
| `result` | `status_code`, and `status_id` = 1 |
| `deref_aliases` | `unmapped` |

Result, LDAP Activity (4016), Search:

```json
{
  "activity_id": 3,
  "category_uid": 4,
  "class_uid": 4016,
  "type_uid": 401603,
  "severity_id": 1,
  "status_id": 1,
  "status": "Success",
  "status_code": "success",
  "time": 1795002061482,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Zeek", "vendor_name": "Zeek" },
    "log_name": "ldap_search"
  },
  "app_protocol_name": "ldap",
  "src_endpoint": { "ip": "10.20.4.57", "port": 50122 },
  "dst_endpoint": { "ip": "10.20.1.10", "port": 389 },
  "connection_info": { "uid": "CmES5u32sYpV7JYN1", "protocol_name": "tcp", "direction_id": 0 },
  "transaction_id": 7,
  "ldap_dn": "DC=corp,DC=example,DC=com",
  "search_scope_id": 3,
  "search_scope": "Whole Subtree",
  "search_filter": "(&(samAccountType=805306368)(servicePrincipalName=*))",
  "requested_attributes": ["sAMAccountName", "servicePrincipalName", "memberOf"],
  "num_records": 14,
  "unmapped": { "deref_aliases": "never" }
}
```

A failed simple bind from Zeek `ldap.log` (`opcode` = `bind simple`, `result` = `invalid credentials`) maps to `activity_id` = 1 (Bind), `bind_type_id` = 1 (Simple), `is_cleartext` = true, `ldap_dn` from `object`, `status_id` = 2, `status_code` from `result` and `status_detail` from `diagnostic_message`. I validated that one too.

### Testing

- Both samples (the search above and the failed simple bind) validate against the LDAP Activity class compiled from this branch. On current `main` there is no class 4016.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings. The compiled class has `uid` 4016 in the `network` category, and includes `actor` and `device` from the `host` profile.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new captions and descriptions (no URLs, marks or vendor names).
- Commits are signed off.

### References

- RFC 4511, LDAP: The Protocol (operations, `scope`, `resultCode`, `MessageID`): https://www.rfc-editor.org/rfc/rfc4511
- RFC 4513, LDAP: Authentication Methods and Security Mechanisms: https://www.rfc-editor.org/rfc/rfc4513
- RFC 4515, LDAP: String Representation of Search Filters: https://www.rfc-editor.org/rfc/rfc4515
- MS-ADTS 5.1.1.1, Supported Authentication Methods (Sicily): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e7d814a5-4cb5-4b0d-b408-09d79988b550
- IANA SASL Mechanisms registry: https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml
- Zeek LDAP logs (`ldap.log`, `ldap_search.log`): https://docs.zeek.org/en/master/scripts/base/protocols/ldap/main.zeek.html
- Suricata LDAP keywords and EVE fields: https://docs.suricata.io/en/latest/rules/ldap-keywords.html
- Microsoft, Hunting for reconnaissance activities using LDAP search filters: https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/hunting-for-reconnaissance-activities-using-ldap-search-filters/ba-p/824726
- Microsoft Defender XDR, IdentityQueryEvents table: https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-identityqueryevents-table
- Sigma, Potential Active Directory Reconnaissance/Enumeration Via LDAP: https://github.com/SigmaHQ/sigma/blob/master/rules/windows/builtin/ldap/win_ldap_recon.yml
- MITRE ATT&CK T1087.002 Domain Account: https://attack.mitre.org/techniques/T1087/002/
- MITRE ATT&CK T1069.002 Domain Groups: https://attack.mitre.org/techniques/T1069/002/
- MITRE ATT&CK T1482 Domain Trust Discovery: https://attack.mitre.org/techniques/T1482/
- MITRE ATT&CK S0521 BloodHound: https://attack.mitre.org/software/S0521/
