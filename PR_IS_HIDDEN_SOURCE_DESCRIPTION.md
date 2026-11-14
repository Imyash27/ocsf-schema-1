This is the follow-up to #1792 that was agreed in its review. It adds a `source` tag to `is_hidden` on the `file` object, so the attribute is tied to the platform flags it maps from.

### Why

On #1792, @pagbabian-splunk approved with the note: "We should follow up on adding the `source` tag for `is_hidden` in the file.json to tie to the MS and Apple names (FILE_ATTRIBUTE_HIDDEN) and (UF_HIDDEN)." I said I would do it once #1792 merged, together with the source tags asked for on #1788 (those went in #1804).

### Where the names come from

| platform | flag | meaning |
|---|---|---|
| Windows | `FILE_ATTRIBUTE_HIDDEN` (`0x2`) | "The file or directory is hidden. It is not included in an ordinary directory listing." |
| macOS and BSD | `UF_HIDDEN` (set with `chflags hidden`) | the file "is not intended to be displayed to the user" |

Both pages are already in the attribute `references` from #1792. The third case in the description, a dot file on Unix-like systems, is a naming convention rather than a flag, so it has no constant to put in `source`.

### What changes

- `objects/file.json`: adds `"source": "FILE_ATTRIBUTE_HIDDEN; UF_HIDDEN"` to `is_hidden`. The two names are separated with a semicolon, the same way the existing `impact_id` source lists two names (`"impact value; impact level"`).
- `CHANGELOG.md`: entry under Improved, Objects.

There is no change to the type, requirement or description, and since `is_hidden` is still in the 1.10 Unreleased section, nothing changes for a released version.

### Testing

- `python -m ocsf_validator .` passes.
- `ocsf-schema-compiler .` and `ocsf-schema-compiler -b .` compile with no errors or warnings, and the compiled `file` object shows `is_hidden` with the new `source`.
- `python -m ocsf.validate.compatibility` against `main` passes all five checks.
- The #1792 sample event (osquery `file` table row mapped to File Query) still validates.
- `cspell` with the repo config is clean on the changed lines.
- Commits are signed off.

### References

- File Attribute Constants, `FILE_ATTRIBUTE_HIDDEN`: https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants
- chflags(2), `UF_HIDDEN`: https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/chflags.2.html
- Review comment on #1792: https://github.com/ocsf/ocsf-schema/pull/1792#pullrequestreview-5774607006
