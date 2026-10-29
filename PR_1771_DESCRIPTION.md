#### Related Issue:
None. Related follow-on discussion: #1777.

#### Description of changes:

Adds one optional attribute to the `file` object so that a measured content entropy can be normalized instead of going to `unmapped`.

| attribute | type | requirement |
|---|---|---|
| `shannon_entropy` | `float_t` | optional |

- `dictionary.json`: generic `shannon_entropy` entry, using the description proposed in review: for file content (alphabet size 256) the measure is bits per byte from `0.0` to `8.0`, and for domain names (alphabet size 37) the maximum is 5.2, so the same attribute can be reused outside `file`.
- `objects/file.json`: the specific description, Shannon entropy of the full file content in bits per byte, range `0.0` to `8.0`.
- `references`: Shannon (1948) as the formal definition, and Lyda and Hamrock (2007) for the practical bits per byte calculation over file content.

Entropy is a common signal for compressed, encrypted or packed content, reported by endpoint, sandbox and file-scanning tools, but OCSF currently has no attribute for it. Measured on real files:

| content | entropy (bits/byte) |
|---|---|
| Plain text document | 4.8423 |
| Same document, AES-256 encrypted | 7.9943 |
| Same document, gzip compressed | 7.9786 |
| Native executable | 5.9347 |

Compressed and encrypted data score almost the same, so the description presents a high value as "compressed, encrypted, or packed" and not as proof of encryption. Detections combine it with `ext`, `mime_type` and the acting process.

Sample mapping, File System Activity (1001), a process writing `report.md.locked`:

```json
"file": {
  "name": "report.md.locked",
  "path": "C:\\Users\\a.mehta\\Documents\\Finance\\report.md.locked",
  "ext": "locked",
  "size": 31344,
  "type_id": 1,
  "shannon_entropy": 7.9943
}
```

For an in-place Update (`activity_id` 3), the before value maps to `file.shannon_entropy` and the after value to `file_result.shannon_entropy`, so no extra attribute is needed for before/after.

Naming: as agreed in review, the attribute is named `shannon_entropy` so the name states the algorithm, rather than an `entropy` object with an algorithm id (renamed in 08b122a7, proposed description applied in 427de02a). Per-section entropy for executables (for example PE sections) can be added later as an object that reuses `shannon_entropy` (see #1777).

Files touched: `dictionary.json`, `objects/file.json`, `CHANGELOG.md`, `.github/.project-words.txt`.

#### Confirmations

1. `Unreleased` entries added to `CHANGELOG.md` (Dictionary Attributes and Objects), with the PR link.
2. Contribution guidelines followed.
3. Validated locally:
   - `python -m ocsf_validator .` passes, with the same output as `main`
   - `ocsf-schema-compiler .` compiles with zero errors and zero warnings, in both default and browser mode
   - `python -m ocsf.validate.compatibility` against `main` passes all five checks
   - `cspell` with the repository config reports no unknown words in the changed lines
   - the sample event is valid against the compiled File System Activity class
4. PR title matches the description.
5. Captions and descriptions follow the normative and neutral style: no URLs, trademark marks or vendor names in captions or descriptions, and citations are in `references`.
