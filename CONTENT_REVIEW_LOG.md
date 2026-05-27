# Content Review Log

This log records notable content-maintenance decisions so future updates do not need to rediscover the same context.

## May 2026 Initial Cleanup

### Added

- Added `BASELINE_AUDIT.md` to capture repository structure, link hygiene risks, asset risks, duplication patterns, and cleanup priorities.
- Added `CONTENT_MAINTENANCE.md` to define page review rubrics, page-type templates, link hygiene rules, review workflow, and manual link-check exceptions.

### Presentation Improvements

- Tightened the landing page and added a short "How to use this guide" section.
- Updated visible navigation labels in `SUMMARY.md` without renaming files.
- Added "How to use this section/page" guidance to major hubs and high-churn singleton pages.
- Clarified safety context on offensive, web, DFIR, container, privacy, and AI pages.

### Deduplication Decisions

- Awesome lists are an exception to the deduplication rule. They may remain on topic pages when useful locally, even when also listed in `training/the-awesome-lists.md`.
- `cyber-intelligence/threat-data.md` is the primary page for indicator reputation, enrichment, URL scanning, public sandboxing links, and threat-data lookups.
- `dfir-digital-forensics-and-incident-response/sandboxing.md` is the primary page for sandbox workflow and OPSEC guidance.
- `blue-defense/blue-toolbox.md` now points to Threat Data and DFIR Sandboxing for malware-analysis and sandbox references instead of duplicating the same tool list.
- `cyber-intelligence/osint/domain.md` now points to Threat Data for reputation pivots while keeping domain-specific OSINT tools local.
- `cyber-intelligence/intel-feeds-and-sources.md` now points to Threat Data for reputation and sandbox tools while keeping feed/source material local.

### Deferred

- File renames such as `blue-defense/vulnerability-management..md` and `blue-defense/stegonography.md` are intentionally deferred until backlinks and GitBook navigation can be checked together.
- `.gitbook/assets/` cleanup is deferred until the duplicated HTML launchers and missing image references can be audited as a dedicated asset pass.
- Full automated link checking is deferred until manual exceptions are defined for `.onion`, archived, login-gated, rate-limited, GitBook embed, and vendor PDF links.

