# PR and MR guidelines for Yash Kanzariya (Infopercept)

Apply these to every pull request (GitHub) and merge request (GitLab), in any repository.

## Commits
- Author: Yash Kanzariya <yashk@infopercept.com>
- Every commit is signed off (`git commit -s`), giving `Signed-off-by: Yash Kanzariya <yashk@infopercept.com>`
- Every commit message includes `Co-authored-by: Yash Kanzariya <yashk@infopercept.com>`
- No AI attribution anywhere: no "Generated with", no AI co-author lines, no mention of Claude, Anthropic or AI tools
- Commit messages read like a normal developer wrote them: short subject, plain body explaining what and why

## Branches
- Name the branch after the problem it solves, for example `add-process-call-stack`
- Never use "claude" or any AI tool name in a branch name

## PR / MR description
Always provide a detailed description, written in a normal human developer voice:
- No em dashes or en dashes, no curly quotes, no ellipsis characters
- No AI style phrasing or template filler ("Description of changes", "Design choices worth flagging", "Confirmations" checklists)
- Plain prose with short, simple section headings where helpful

Cover, in this order:
1. One or two sentences on what the PR adds or fixes
2. The problem: what is missing today and what happens without it (for example data ending up in `unmapped`)
3. Where the data comes from: real sources and their field names, with a small table if several sources are involved
4. Why it matters: concrete detection or operational use cases, MITRE ATT&CK techniques, Sigma or vendor rules, an example query
5. Design: why it is shaped this way, alternatives considered, and an offer to change it if reviewers prefer
6. What changes: each file touched and why
7. Example: a real looking source event, a field by field mapping table, and the resulting normalized event
8. Testing: every check that was run locally and its result
9. References: verified links only (official docs, standards, MITRE, Sigma, vendor docs)

## Before raising a PR
- Check the target repo for duplicate issues and PRs first
- Verify every reference and quote against the source
- Run the repo's own checks (for OCSF: ocsf_validator, ocsf-schema-compiler in both modes, compatibility check, cspell, neutral wording precheck, sample event validation, DCO)
- For OCSF: full descriptions go in `dictionary.json`, objects and classes only set requirement and group; add `source` where applicable
- For OCSF changelog entries (since ocsf/ocsf-schema#1813): do not edit `CHANGELOG.md`. After the PR is opened, add `changelog.d/<PR number>.md` with the same headings as CHANGELOG.md (`### Added` / `### Improved` with a `####` sub-heading, entries as `- ` list items, no PR link), and run `python .github/scripts/changelog.py check --pr <N> --base <main>`
- No changelog entry is needed for a change to an attribute that is still in the Unreleased section, or for a description-only edit

## Hard rule: stay at least 5 PRs ahead of therajvira (ocsf/ocsf-schema)
- Yash's PR count in ocsf/ocsf-schema (author Imyash27, open plus merged) must always be at least 5 higher than therajvira's, and his merged count must stay higher too
- On every status check, count both with the GitHub searches `is:pr author:Imyash27` and `is:pr author:therajvira` on ocsf/ocsf-schema, and report the lead
- If the lead drops below 5, or therajvira opens a new PR, find and prepare new PRs right away until the lead is back to 5 or more, without waiting to be asked
- The count never lowers the bar: every PR is still a real gap with source evidence, a duplicate check and all the checks above. No filler, split or trivial PRs just to raise the number
