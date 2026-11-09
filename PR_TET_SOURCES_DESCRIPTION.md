This is the follow-up to #1788 that was agreed in its review. It changes the caption of `token_elevation_type_id` value 1 back to `Default` and adds `source` to each value, so the enum lines up with the Windows `TOKEN_ELEVATION_TYPE` names.

### Why

On #1788 the caption for value 1 was changed from `Default` to `None` during review, to make it clear that the token has no linked token. In the approving reviews @pagbabian-splunk and @mikeradka both asked to go back to `Default`, since that matches the Windows names that the enum descriptions already reference, and to explain the "default means no linked token" point in the description instead. @pagbabian-splunk also asked for a `source` tag on each value. To avoid dismissing the approvals on #1788, I said I would do both in a separate PR once it merged.

### Where the names come from

| id | caption | `TOKEN_ELEVATION_TYPE` constant | 4688 value |
|---|---|---|---|
| 1 | Default | `TokenElevationTypeDefault` | `%%1936` |
| 2 | Full | `TokenElevationTypeFull` | `%%1937` |
| 3 | Limited | `TokenElevationTypeLimited` | `%%1938` |

The ids are unchanged, so nothing changes for producers. A 4688 event with `%%1936`, or a sensor reading `TokenElevationTypeDefault` from `GetTokenInformation`, still maps to `token_elevation_type_id` = 1. Only the caption, which producers put in `token_elevation_type`, goes from `None` to `Default`.

### What changes

- `extensions/windows/dictionary.json`:
  - value 1 caption `None` to `Default`. Its description now starts with "The default elevation type, meaning that the token does not have a linked token, so there is no split between a limited and a full token."
  - `"source"` added to values 1, 2 and 3 with the matching Windows constant. The enum schema already supports `source` on enum values ("for example an OS-specific enumeration value").
- `CHANGELOG.md`: entry under Improved, Platform Extensions.

There is no change to types, ids or requirements. Since #1788 has not been released yet (it is in the 1.10 Unreleased section), the caption change does not affect any released version.

### Example

The 4688 sample from #1788 is unchanged and still validates. For a process with no linked token:

```json
"process": {
  "pid": 4128,
  "file": { "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "type_id": 1 },
  "token_elevation_type_id": 1,
  "token_elevation_type": "Default"
}
```

### Testing

- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled Windows `process` object shows captions Unknown, Default, Full, Limited, Other with the three sources.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- The #1788 sample event still validates against the compiled Process Activity class.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

The `source` tag for `is_hidden` that was asked for on #1792 will follow once that PR merges, since the attribute is not on `main` yet.

### References

- `TOKEN_ELEVATION_TYPE` enumeration: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_elevation_type
- 4688(S) A new process has been created, "Token Elevation Type" field: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688
- Review comments on #1788: https://github.com/ocsf/ocsf-schema/pull/1788#pullrequestreview-5774722491 and https://github.com/ocsf/ocsf-schema/pull/1788#pullrequestreview-5774724368
