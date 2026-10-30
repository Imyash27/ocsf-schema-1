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
- After the PR number is known, add the PR link to the CHANGELOG entries
