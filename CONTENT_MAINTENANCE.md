# Content Maintenance Guide

This guide keeps the Security Reference Guide useful as a teaching resource without turning it into an unmaintainable link dump. Use it before adding, removing, or reorganizing pages.

## Baseline Inventory

Last reviewed: May 2026

- Primary navigation lives in `SUMMARY.md`.
- The book has about 153 Markdown pages.
- The main publishing target is GitBook; GitBook-specific blocks such as `{% hint %}`, `{% tabs %}`, `{% embed %}`, `{% file %}`, and `{% content-ref %}` are expected.
- External links appear in most pages, with the highest link density in threat intelligence, OSINT, DFIR, cloud, training, and offensive methodology pages.
- `.gitbook/assets/` contains bundled HTML launchers and downloadable assets. Some duplicated HTML launcher variants appear to be export artifacts.
- Known hygiene risks include stale external links, `http://` links, GitBook CDN image URLs, old `app.gitbook.com` links, missing local image assets, and repeated sandbox/reputation tooling. Awesome-list links are allowed to repeat when they help the local page.

## Page Review Rubric

Every page should be reviewed with the same compact checklist:

- **Purpose**: State what the page helps a practitioner do.
- **Audience**: Make it clear whether the page is for analysts, hunters, responders, pentesters, engineers, or learners.
- **Presentation**: Prefer short intros, descriptive headings, and skimmable resource groups.
- **Freshness**: Check product names, command syntax, project status, and official documentation links.
- **Deprecation**: Move dead, archived, or superseded resources into a legacy section instead of mixing them with active recommendations.
- **Deduplication**: Link to the canonical owner page when another page already owns a resource category. Awesome-list links are an exception and may be repeated on relevant pages.
- **Safety**: Keep legal, ethical, operational, and false-positive context close to high-risk guidance.
- **Rendering**: Verify GitBook blocks, internal refs, file embeds, and image references after editing.

## Page Type Templates

### Hub Page

Use for section landing pages such as `cyber-intelligence/README.md` or `blue-defense/README.md`.

Recommended shape:

1. One short paragraph explaining the section.
2. A "Start here" or "How to use this section" note.
3. GitBook content refs to child pages.
4. Short learning context or methodology.
5. Links to canonical resource pages instead of repeated tool dumps.

### OSINT Directory

Use for OSINT topic pages such as domain, IP, username, email, files, media, or social media.

Recommended shape:

1. Scope and ethical reminder.
2. Investigation questions this page helps answer.
3. Active tools grouped by task.
4. Notes about access limits, paid tiers, login requirements, or API limits.
5. Deprecated or unreliable tools.
6. Accuracy notes.

### Command Runbook

Use for DFIR, hardening, remediation, and shell command pages.

Recommended shape:

1. When to use the commands.
2. Required permissions and operating system assumptions.
3. Commands grouped by investigative goal.
4. Expected output or interpretation notes.
5. Legacy commands separated from modern alternatives.
6. Caution notes for commands that change system state.

### Detection or Use-Case Page

Use for SIEM, hunting, and event detection pages.

Recommended shape:

1. Detection goal.
2. Required data sources.
3. Example signals, queries, or fields.
4. False positives and tuning notes.
5. Related MITRE ATT&CK techniques when relevant.
6. References and maintained rule repositories.

### Tool Catalog

Use for toolbox pages.

Recommended shape:

1. What belongs on this page and what belongs elsewhere.
2. Active tools grouped by workflow.
3. Clear notes for commercial, API-limited, or unmaintained tools.
4. Legacy tools at the end.
5. Links to canonical resource pages for adjacent categories.

### Web Vulnerability Page

Use for web app attacks and methodology pages.

Recommended shape:

1. What the vulnerability is.
2. Why it matters.
3. How to test safely in authorized environments.
4. Common payloads or methodology.
5. Defensive notes.
6. PortSwigger, OWASP, and other maintained references.

### Training Index

Use for training, books, labs, certifications, and Awesome lists.

Recommended shape:

1. Who the resource is for.
2. Free and paid resources separated where useful.
3. Current certification or course names.
4. Archived or outdated resources clearly labeled.
5. Links back to topic sections where useful, while allowing repeated Awesome-list links when they help local context.

### Long-Form Guide

Use for large explanatory guides.

Recommended shape:

1. A table of contents or "How to use this page" paragraph.
2. Section headings that match reader tasks.
3. Collapsible blocks only when they reduce scanning burden.
4. References close to the claim or technique they support.
5. A concise "keep current" note for fast-changing tools.

## Canonical Resource Ownership

Use "link once, reference many" unless a repeated link is needed for workflow continuity. Awesome-list links are an explicit exception.

- `training/the-awesome-lists.md` tracks Awesome-list collections, but section pages may repeat specific Awesome-list links when they are useful in context.
- `cyber-intelligence/threat-data.md` owns indicator reputation, enrichment, threat maps, sandbox overlap, and threat-data sources.
- `dfir-digital-forensics-and-incident-response/sandboxing.md` owns sandbox workflow and malware detonation guidance.
- `red-offensive/offensive-toolbox/README.md` owns red-team tool collections and offensive distros.
- `blue-defense/blue-toolbox.md` owns defensive tooling, but should point to threat-data and DFIR pages when those pages are more specific.
- `cyber-intelligence/osint/README.md` owns OSINT methodology, training, blogs, and broad OSINT collections.

## Link Hygiene Rules

- Prefer descriptive link labels: `[VirusTotal](https://www.virustotal.com/)`, not `[https://www.virustotal.com/](https://www.virustotal.com/)`.
- Prefer official documentation, maintained GitHub repositories, and vendor-neutral explainers.
- Upgrade `http://` links to `https://` only after verifying the destination supports HTTPS.
- Keep `.onion` links as `http://` unless the onion service publishes an HTTPS endpoint.
- Mark abandoned, archived, discontinued, or unreliable resources in a legacy/deprecated section.
- Do not remove historically useful resources just because they are old; label them honestly.
- For resources requiring login, paid plans, APIs, academic access, or region-specific access, say so near the link.

## Section Review Workflow

Review section by section, and page by page inside each section.

1. Read the section hub first.
2. Review child pages in `SUMMARY.md` order.
3. Check whether the page owns its resources or should point to a canonical owner page.
4. Tighten intro copy and headings before changing links.
5. Move stale resources into a legacy section.
6. Add only current resources that directly improve the page.
7. Verify internal links, GitBook blocks, and asset references.
8. Record notable removals, replacements, and deduplication decisions in the change summary.

## Link Check Exceptions

Some links need manual review instead of automated pass/fail handling:

- `.onion` services
- archived pages
- rate-limited services
- login-gated platforms
- malware analysis sandboxes
- GitBook embeds
- PDFs and slide decks hosted on conference or vendor sites
- intentionally preserved legacy references

## Priority Order

1. Cyber Intelligence and OSINT
2. Threat Data
3. Blue Defense
4. DFIR
5. Red Offensive
6. Web App Hacking
7. Yellow sections: logging, cloud, containers, code, AI, FOSS
8. Grey privacy and OPSEC
9. Training and resources

