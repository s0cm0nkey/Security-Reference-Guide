# Baseline Content Audit

Last reviewed: May 2026

This audit captures the first repository-wide pass for the Security Reference Guide. It is meant to guide cleanup work, not replace page-by-page review.

## Repository Shape

- `SUMMARY.md` is the GitBook table of contents.
- `README.md` is the book landing page.
- Major sections are organized around practitioner roles and workflows:
  - Cyber Intelligence and OSINT
  - Red - Offensive Operations
  - Blue - Defensive Operations
  - Blue - DFIR
  - Yellow - infrastructure, logging, cloud, containers, code, AI, and FOSS
  - Grey - Privacy/TOR/OPSEC
  - Training and Resources
- The repo is GitBook-first and does not currently include local GitBook, HonKit, MkDocs, or Docusaurus build configuration.
- No CI or automated link checking workflow was present during the first pass.

## High-Value Existing Patterns

- Newer intel pages use concise intros, active resource groups, deprecated-resource notes, and accuracy caveats.
- DFIR and detection pages contain practical command and investigation content, not just link lists.
- The color/team taxonomy is easy for practitioners to navigate.
- GitBook `content-ref` blocks are useful on hub pages.
- Existing legal and attribution notes on the landing page set the right expectations.

## Main Risks

### Link Freshness

- External links are pervasive across the book.
- Some resources are already marked as deprecated, discontinued, archived, moved, or unreliable.
- Many `http://` links remain. Some may have HTTPS equivalents; some are legitimate `.onion` or legacy references.
- Some links point to GitBook CDN or old GitBook app URLs, which are fragile outside the original GitBook workspace.

### Resource Duplication

- Awesome-list links appear both in `training/the-awesome-lists.md` and in individual section pages. This is intentional; Awesome lists are an exception to the deduplication rule.
- Sandbox and malware analysis platforms appear in threat-data, DFIR, blue toolbox, and intel pages.
- MITRE ATT&CK, Cyber Kill Chain, and Diamond Model references appear in both blue-defense and cyber-intelligence contexts.
- HackTricks and other broad offensive resources appear across many red and web pages.

### Asset Hygiene

- `.gitbook/assets/` includes duplicated HTML launcher files.
- Some Markdown pages reference image assets that may not exist locally.
- Some image references point at GitBook CDN URLs with tokens.
- HTML launcher files contain a second layer of outbound links, so Markdown-only link checks will miss them.

### Presentation Consistency

- Some pages have strong overview/context sections; others are mostly raw link lists.
- YAML front matter is inconsistent.
- Some descriptions are playful and useful, while others are stale placeholders.
- Several pages use URL-as-label links, making pages harder to scan.
- Some headings, titles, and filenames have typo or naming debt.

## Priority Findings

| Area | Finding | Suggested Action |
| --- | --- | --- |
| Navigation | `SUMMARY.md` mixes web app pages under Red and also has a Web App Hacking section. | Keep this if intentional, but clarify web app ownership in the Web App hub. |
| Navigation | `Stegonography` is misspelled in `SUMMARY.md` and the filename. | Fix display text first; rename file only after checking backlinks. |
| Navigation | `blue-defense/vulnerability-management..md` has a double dot. | Leave filename until a rename pass, but fix display text and track as structural debt. |
| Cyber Intelligence | `cyber-intelligence/README.md` repeats content refs to OSINT, feeds, and threat data. | Keep the initial navigation refs and remove repeated refs from the discipline definitions. |
| Training | `training/the-awesome-lists.md` should remain a broad Awesome-list registry. | Keep formatting clean, but allow relevant pages to repeat Awesome-list links where helpful. |
| Threat Data | `cyber-intelligence/threat-data.md` has the best active/deprecated/accuracy pattern. | Use as the model for high-churn tool pages. |
| Assets | Duplicated OSINT HTML launchers exist in `.gitbook/assets/`. | Pick canonical launchers in a future asset cleanup pass; avoid changing embeds until verified. |
| GitBook URLs | Old `app.gitbook.com` and `gblobscdn.gitbook.com` links exist. | Replace with local assets or stable public URLs when touching those pages. |
| HTTP links | Many `http://` links remain. | Verify before converting; leave `.onion` as-is unless HTTPS is available. |

## Page-Type Review Priorities

### Highest Churn

- OSINT directories
- Threat-data and reputation pages
- Cloud, containers, AI, and FOSS pages
- Web technology and web vulnerability pages
- Training and certification pages

### Highest Operational Risk

- DFIR command runbooks
- Remediation and hardening command pages
- Offensive exploitation and post-exploitation pages
- Detection use-case pages

### Highest Duplication Risk

- Toolbox pages
- Sandbox and malware-analysis pages
- Broad framework pages

## Canonicalization Queue

- Keep `training/the-awesome-lists.md` as a broad Awesome-list registry while allowing section-level repeats.
- Make `cyber-intelligence/threat-data.md` the canonical indicator reputation and enrichment page.
- Make `dfir-digital-forensics-and-incident-response/sandboxing.md` the canonical sandbox workflow page.
- Make `cyber-intelligence/osint/README.md` the canonical OSINT methodology and broad resource page.
- Make `red-offensive/offensive-toolbox/README.md` the canonical offensive tool collection.
- Make `blue-defense/blue-toolbox.md` the canonical defensive tool collection.

## Manual Review Exceptions

Do not treat the following as simple broken links without manual inspection:

- `.onion` links
- intentionally archived resources
- GitBook embeds and file blocks
- Google Drive, YouTube, vendor PDF, or conference slide links
- malware sandboxes and indicator lookup tools that rate-limit automated checks
- login-gated services such as commercial threat intelligence platforms

