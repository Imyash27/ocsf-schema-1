This adds the algorithms negotiated for an SSH connection (`kex_algorithm`, `host_key_algorithm`, `cipher_algorithm`, `mac_algorithm`, `compression_algorithm`) and the server host key fingerprint (`host_key_fingerprint`) to SSH Activity, so they no longer end up in `unmapped`.

### The problem

At the start of every SSH connection, client and server agree on a key exchange method, a host key algorithm, a cipher, a MAC and a compression method (RFC 4253 section 7.1), and the server proves its identity with its host key. Those choices decide how strong the connection is, and the host key is what tells a client it is talking to the right server.

SSH Activity has `client_hassh` and `server_hassh`, but HASSH is a hash of the algorithm lists each side *offers*. It identifies the client or server software. It does not say which algorithms were actually used, and it says nothing about the host key. So for a given connection OCSF can't answer "was this negotiated with a weak cipher" or "is this the same host key as yesterday".

### Where the data comes from

| source | fields |
|---|---|
| Zeek `ssh.log` | `kex_alg` ("The key exchange algorithm in use"), `host_key_alg` ("The server host key's algorithm"), `cipher_alg` ("The encryption algorithm in use"), `mac_alg` ("The signing (MAC) algorithm in use"), `compression_alg` ("The compression algorithm in use"), `host_key_fingerprint` ("For example, a sha256 fingerprint will look like `SHA256:<fingerprint>`") |
| OpenSSH client with `-v` | `kex: algorithm: ...`, `kex: host key algorithm: ...`, `kex: client->server cipher: ... MAC: ... compression: ...`, and the `Server host key: ssh-ed25519 SHA256:...` line |

Zeek computes the negotiated value from both sides' lists, and writes `To server: ..., to client: ...` when the two directions differ.

### Why it matters

- **Terrapin (CVE-2023-48795).** The attack works on connections that use the `chacha20-poly1305@openssh.com` cipher, or a `-cbc` cipher together with an `-etm@openssh.com` MAC. Spotting such connections needs the negotiated cipher and MAC.
- **Weak or legacy algorithms.** Policies forbid things like `diffie-hellman-group1-sha1` key exchange, `ssh-dss` host keys, `3des-cbc` or `arcfour` ciphers and `hmac-md5` MACs. With these attributes, finding connections that still use them is a query instead of a packet capture.
- **Host key changes.** A host key that changes for the same server can be a rebuilt server, or someone in the middle of the connection (MITRE ATT&CK T1557, Adversary-in-the-Middle). Tracking `host_key_fingerprint` per `dst_endpoint` catches both, and lets the expected ones be confirmed.

For example, the Terrapin check becomes:

```
class_uid = 4007
  AND (cipher_algorithm = "chacha20-poly1305@openssh.com"
       OR (cipher_algorithm LIKE "%-cbc" AND mac_algorithm LIKE "%-etm@openssh.com"))
```

### Design

- **Flat attributes on the class**, next to `client_hassh` and `server_hassh`, the same way the class already models SSH details.
- **Names.** `kex_algorithm`, `host_key_algorithm`, `cipher_algorithm`, `mac_algorithm` and `compression_algorithm` follow the RFC 4253 categories. I didn't reuse `cipher`, because its dictionary caption is "Cipher Suite" and it describes the TLS cipher suite, which is a different thing from an SSH encryption algorithm.
- **Strings, not enums.** SSH algorithm names are an open set (the IANA SSH parameters registry plus `name@domain` names such as `chacha20-poly1305@openssh.com`), so the value is the name as negotiated.
- **`host_key_fingerprint` is a `fingerprint` object**, so the hash algorithm is explicit (`algorithm_id` 3, SHA-256, for the OpenSSH `SHA256:` format) and it lines up with how other fingerprints are stored.
- **Requirements.** `host_key_fingerprint` is primary and recommended, since it identifies the server. The algorithms are context and optional.
- **Dictionary entries are generic** ("See specific usage"), with the SSH specific descriptions and examples on the class.

If reviewers would rather group these into an `ssh_algorithms` object, or reuse `cipher` after all, I can change it.

### What changes

- `dictionary.json`: adds `cipher_algorithm`, `compression_algorithm`, `host_key_algorithm`, `host_key_fingerprint` (type `fingerprint`), `kex_algorithm` and `mac_algorithm`.
- `events/network/ssh_activity.json`: adds the six attributes with SSH specific descriptions.
- `.github/.project-words.txt`: adds `nistp` (from `ecdsa-sha2-nistp256` in a description) for cspell.
- `changelog.d/<this PR>.md`: I'll add it once the PR has a number, as described in `changelog.d/README.md`.

### Example

Zeek `ssh.log` record (trimmed):

```json
{
  "ts": 1795086011.204,
  "uid": "CmS8f02YtQk3vDwa7",
  "id.orig_h": "10.30.2.15",
  "id.orig_p": 51844,
  "id.resp_h": "10.30.9.12",
  "id.resp_p": 22,
  "version": 2,
  "auth_success": true,
  "auth_attempts": 1,
  "direction": "OUTBOUND",
  "client": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
  "server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
  "cipher_alg": "chacha20-poly1305@openssh.com",
  "mac_alg": "umac-64-etm@openssh.com",
  "compression_alg": "none",
  "kex_alg": "curve25519-sha256",
  "host_key_alg": "ssh-ed25519",
  "host_key_fingerprint": "SHA256:u4lB0nB6rW8o9Q2bS1xTz3pVq7mJkYh5fGd2cXe8aL0"
}
```

Field mapping:

| Zeek field | OCSF |
|---|---|
| `ts` | `time` |
| `uid` | `connection_info.uid` |
| `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p` | `src_endpoint`, `dst_endpoint` |
| `direction` | `connection_info.direction_id` = 2 (Outbound) |
| `version` | `protocol_ver` |
| `auth_success` | `status_id` = 1 |
| **`kex_alg`** | **`kex_algorithm`** |
| **`host_key_alg`** | **`host_key_algorithm`** |
| **`host_key_fingerprint`** | **`host_key_fingerprint`**, `algorithm_id` = 3 (SHA-256) and the Base64 value |
| **`cipher_alg`**, **`mac_alg`**, **`compression_alg`** | **`cipher_algorithm`**, **`mac_algorithm`**, **`compression_algorithm`** |
| `client`, `server`, `auth_attempts` | `unmapped` |

Result, SSH Activity (4007), Open:

```json
{
  "activity_id": 1,
  "category_uid": 4,
  "class_uid": 4007,
  "type_uid": 400701,
  "severity_id": 1,
  "status_id": 1,
  "time": 1795086011204,
  "metadata": {
    "version": "1.10.0",
    "product": { "name": "Zeek", "vendor_name": "Zeek" },
    "log_name": "ssh"
  },
  "src_endpoint": { "ip": "10.30.2.15", "port": 51844 },
  "dst_endpoint": { "ip": "10.30.9.12", "port": 22 },
  "connection_info": { "uid": "CmS8f02YtQk3vDwa7", "protocol_name": "tcp", "direction_id": 2 },
  "protocol_ver": "2",
  "kex_algorithm": "curve25519-sha256",
  "host_key_algorithm": "ssh-ed25519",
  "host_key_fingerprint": { "algorithm_id": 3, "algorithm": "SHA-256", "value": "u4lB0nB6rW8o9Q2bS1xTz3pVq7mJkYh5fGd2cXe8aL0" },
  "cipher_algorithm": "chacha20-poly1305@openssh.com",
  "mac_algorithm": "umac-64-etm@openssh.com",
  "compression_algorithm": "none",
  "unmapped": {
    "client": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
    "server": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    "auth_attempts": 1
  }
}
```

This connection negotiated `chacha20-poly1305@openssh.com`, so the Terrapin query above matches it. Whether it is actually exposed also depends on strict key exchange support, which Zeek does not log.

### Testing

- The sample event validates against the SSH Activity class compiled from this branch. On current `main` the only errors are the six new attributes being unknown.
- `python -m ocsf_validator .` passes with no failures.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- `cspell` with the repo config is clean on the changed files.
- The normative precheck from `.github/scripts/review_descriptions.py` finds nothing in the new descriptions.
- Commits are signed off.

### References

- RFC 4253, The Secure Shell (SSH) Transport Layer Protocol (section 7.1, algorithm negotiation): https://www.rfc-editor.org/rfc/rfc4253
- IANA Secure Shell (SSH) Protocol Parameters: https://www.iana.org/assignments/ssh-parameters
- Zeek SSH analyzer (`ssh.log`): https://github.com/zeek/zeek/blob/master/scripts/base/protocols/ssh/main.zeek
- Terrapin attack (CVE-2023-48795): https://terrapin-attack.com/
- MITRE ATT&CK T1557 Adversary-in-the-Middle: https://attack.mitre.org/techniques/T1557/
