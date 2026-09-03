# Confluence Secret Scanner

A small, read-only AppSec scanner for finding accidentally exposed credentials
in Confluence pages, page history, and text attachments.

> **Status:** functional MVP, suitable for local evaluation and controlled
> scans. Review [Known limitations](#known-limitations) before using it against
> a production Confluence instance.

The scanner reports metadata and stable fingerprints. It intentionally omits
the matched secret and surrounding source text from text, JSON, SARIF, and
baseline output.

## Features

- paginated discovery of spaces and current pages through Confluence REST API
  v1;
- explicit space inclusion/exclusion and conservative defaults for personal and
  archived spaces;
- optional historical page-version scanning;
- optional scanning of supported text attachments with a hard size limit;
- 27 built-in rules covering common tokens, keys, connection strings, private
  keys, and labelled credentials;
- rule-specific context, entropy thresholds, allowlists, and stopwords;
- deduplication of the same finding across page versions;
- retry/backoff for rate limits and transient server failures;
- text, JSON, and SARIF 2.1.0 reports;
- versioned baselines for suppressing reviewed findings;
- CI-friendly exit codes.

## Known limitations

- Authentication is currently **Bearer only**. Confluence setups that require
  Basic auth with an email/API-token pair are not supported yet.
- The client targets the REST API v1 response shape. It has not yet been
  compatibility-tested against every Confluence Cloud and Data Center release.
- Only Confluence `body.storage` page content is extracted.
- Attachments are limited to UTF-8 and BOM-marked UTF-16 text. PDF, Office,
  archives, images, and other binary formats are skipped.
- Historical scanning performs a request for each candidate version and can be
  expensive on large spaces.
- Scans are full-scope within the selected spaces; there is no modified-since or
  CQL-based incremental mode yet.
- Regex and entropy detection can produce false positives and false negatives.
  This is a secret scanner, not a general-purpose DLP system.
- Findings are reported but not revoked, deleted, or sent to an issue tracker.

## Requirements

- Python 3.9 or newer;
- network access from the scanner to the Confluence REST API;
- a token accepted as `Authorization: Bearer ...`;
- read access to every space, page, historical version, or attachment included
  in the scan.

Use a dedicated least-privilege account where possible.

## Installation

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

The project currently runs directly from the checkout; it is not packaged as a
wheel or console script yet.

## Quick start

Set the Confluence base URL and token:

```bash
export CONFLUENCE_URL='https://confluence.example.com'
export CONFLUENCE_TOKEN='<bearer-token>'
```

For installations under a context path, include it in the URL, for example
`https://confluence.example.com/confluence`. The configured base must expose
the scanner endpoints below `<base>/rest/api/...`.

Start with a small, current-page-only scan:

```bash
python -m scanner --space ENG --max-pages 100
```

`--max-pages` intentionally truncates the result and marks it as truncated. It
is useful for evaluation, but a truncated result cannot be written as a
baseline.

After reviewing the initial behavior, expand the scope deliberately:

```bash
python -m scanner \
  --space ENG \
  --space OPS \
  --attachments \
  --history-limit 5 \
  --request-delay 0.1 \
  --format json
```

## Scan scope

### Spaces

By default the scanner discovers all spaces but scans only current global
spaces. Personal and archived spaces are skipped.

```bash
# Scan only selected spaces. The option can be repeated.
python -m scanner --space ENG --space OPS

# Scan all default spaces except selected ones.
python -m scanner --exclude-space PUBLIC

# Expand the default selection.
python -m scanner --include-personal-spaces --include-archived-spaces
```

An explicitly selected `--space` is scanned even if it is personal or archived.
The same key cannot be both included and excluded.

### Page history

History is opt-in:

```bash
# All available previous versions.
python -m scanner --history

# At most five previous versions per current page.
python -m scanner --history-limit 5
```

Passing `--history-limit` automatically enables history. Missing historical
versions that return `404` are skipped. Identical findings across versions are
collapsed and retain the list of matching version numbers.

### Attachments

Attachment scanning is also opt-in:

```bash
# Supported text attachments up to 5 MiB each.
python -m scanner --attachments

# Override the per-attachment limit.
python -m scanner --attachments --max-attachment-size-mb 1
```

Supported extensions are `.cfg`, `.conf`, `.csv`, `.env`, `.ini`, `.js`,
`.json`, `.log`, `.md`, `.properties`, `.py`, `.sh`, `.sql`, `.ts`, `.txt`,
`.xml`, `.yaml`, and `.yml`. Known text MIME types are also accepted.

An explicit binary MIME type takes precedence over a text-looking filename.
Declared and actually downloaded bytes are both checked against the limit.
Cross-origin attachment links are rejected before a request is made.

## Reports and exit codes

Human-readable output is the default:

```bash
python -m scanner --format text
```

Scanner-native JSON:

```bash
python -m scanner --format json > confluence-results.json
```

SARIF 2.1.0:

```bash
python -m scanner --format sarif > confluence-results.sarif
```

SARIF output contains rule descriptors, severity, confidence, page or
attachment locations, and stable partial fingerprints. It validates against
the [OASIS SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json).
Because findings point to Confluence URLs rather than repository files,
repository-centric SARIF consumers may display the result without annotating a
source file in the repository.

Use `--fail-on` to make findings affect CI:

```bash
python -m scanner --format sarif --fail-on high > confluence-results.sarif
```

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed and no unsuppressed finding reached `--fail-on`. |
| `1` | Configuration, baseline, or Confluence error; also returned for a partial `--continue-on-error` result. |
| `2` | At least one unsuppressed finding reached the configured severity threshold. |

Critical findings satisfy every threshold. Severity order is `low`, `medium`,
`high`, `critical`.

## Baselines

A baseline suppresses reviewed findings so CI can focus on newly introduced
ones.

Create it only after reviewing a complete scan of the intended scope:

```bash
python -m scanner \
  --space ENG \
  --attachments \
  --write-baseline confluence-baseline.json
```

Use the same scope on subsequent runs:

```bash
python -m scanner \
  --space ENG \
  --attachments \
  --baseline confluence-baseline.json \
  --format sarif \
  --fail-on high > confluence-results.sarif
```

Baseline entries contain an opaque finding ID, rule ID, page ID, and optional
attachment ID. They do not contain matched values, source snippets, titles, or
raw secret fingerprints.

Identity is stable across page renames, new page versions, and line movement.
The same match on another page or attachment is treated as new. Baselines are
written atomically with owner-only permissions (`0600`). Writing is refused if
the result contains errors or was truncated by `--max-pages`.

Keep the selected scope consistent. A successful but intentionally narrow scan
is complete for that scope and can therefore replace a broader baseline if the
same output path is used.

## Detection rules

The default rules live in
[`scanner/default_rules.yaml`](scanner/default_rules.yaml). Supply a different
file with `--rules`:

```bash
python -m scanner --rules ./organization-rules.yaml
```

Minimal rule:

```yaml
rules:
  - id: internal-service-token
    name: Internal service token
    severity: high
    confidence: 0.9
    regex: '\b(?P<secret>svc_[A-Za-z0-9]{32})\b'
```

Supported fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable unique rule identifier. |
| `severity` | yes | `low`, `medium`, `high`, or `critical`. |
| `regex` | yes | Python regular expression. |
| `name` | no | Display name; defaults to `id`. |
| `confidence` | no | Number from `0` to `1`; default `0.8`. |
| `keywords` | no | Lower-cased context hints. |
| `require_context` | no | Require at least one keyword near the match. |
| `context_radius` | no | Characters inspected on each side; default `120`. |
| `min_entropy` | no | Reject values below this Shannon entropy. |
| `allowlist.regexes` | no | Case-insensitive patterns applied to the matched value. |
| `allowlist.stopwords` | no | Case-insensitive substrings that suppress a match. |

Prefer a named `secret` capture group so only the credential value is
fingerprinted. Alternatives may use groups named `secret_*`. Without either,
the entire regex match is treated as the secret.

Example false-positive controls:

```yaml
min_entropy: 3.2
keywords:
  - api_key
  - token
require_context: true
allowlist:
  regexes:
    - '^(?:x+|0+|\*+|<.+>)$'
  stopwords:
    - example
    - placeholder
    - redacted
```

Changing a rule ID changes finding fingerprints and baseline identities. Treat
rule IDs as persistent API identifiers once a baseline is in use.

## Reliability controls

The client retries `429`, `500`, `502`, `503`, and `504` responses with
exponential backoff and honors `Retry-After`.

```bash
python -m scanner \
  --retries 5 \
  --backoff 1 \
  --request-delay 0.2 \
  --timeout 30
```

`--continue-on-error` records recoverable request failures and continues with
other spaces or pages. The report remains partial and the process exits with
code `1`.

## Command reference

Run `python -m scanner --help` for the authoritative CLI help.

```text
--url URL                    override CONFLUENCE_URL
--rules PATH                 load a YAML rules file
--format {text,json,sarif}   output format (default: text)
--page-size N                pagination size (default: 50; capped at 200)
--timeout SECONDS            request timeout (default: 20)

--space KEY                  include only KEY; repeatable
--exclude-space KEY          exclude KEY; repeatable
--include-personal-spaces    include personal spaces by default
--include-archived-spaces    include archived spaces by default
--max-pages N                stop after N current pages

--history                    scan all previous page versions
--history-limit N            scan at most N previous versions per page
--attachments                scan supported text attachments
--max-attachment-size-mb MB  attachment limit (default: 5 MiB)

--continue-on-error          emit a partial result and continue
--retries N                  transient request retries (default: 3)
--backoff SECONDS            retry backoff factor (default: 0.5)
--request-delay SECONDS      minimum delay between request starts

--baseline PATH              suppress known findings
--write-baseline PATH        atomically write a baseline
--fail-on SEVERITY           return exit code 2 at this threshold
```

## Architecture

```text
Confluence REST API
        │
        ▼
ConfluenceClient ── pagination / retry / throttling / download limits
        │
        ▼
SecretScanner ──── scope / current pages / history / attachments
        │
        ├── HTML and text extraction
        ▼
Detector ───────── regex / context / entropy / allowlists
        │
        ▼
deduplicated Findings
        │
        ├── optional baseline suppression
        ▼
text / JSON / SARIF ── exit threshold
```

The detector operates on a small document model and does not make Confluence
requests. This keeps data access, extraction, detection, and reporting separate
enough to refactor independently.

## Security notes

- The token is read only from `CONFLUENCE_TOKEN`; do not put it in command-line
  arguments or commit it to the repository.
- HTTP response bodies are not included in request exceptions.
- Matched values and source snippets are not written to reports or baselines.
- Attachment downloads reject direct cross-origin URLs to avoid forwarding the
  Confluence authorization header to an unrelated host.
- Reports still contain page titles, URLs, attachment names, rule IDs, and
  fingerprints. Treat them as internal security data.
- Fingerprints are hashes, not encryption. Low-entropy credentials may be
  guessable offline, so reports still need appropriate retention and access
  controls.
- A real finding should trigger credential revocation or rotation; removing it
  from Confluence alone is not sufficient.

## Testing

Run the complete test suite:

```bash
python -m unittest discover -s tests -v
```

Optional syntax compilation check:

```bash
python -m compileall -q scanner tests
```

The tests cover extraction, rules, context and entropy filtering, report
redaction, history deduplication, attachment classification and limits, retry
configuration, SARIF structure, baseline stability, and partial-error behavior.

## Repository layout

```text
scanner/
  main.py             CLI and exit-code policy
  confluence.py       REST client, pagination, retries, downloads
  service.py          scan orchestration and scope
  extractor.py        Confluence storage HTML to text
  attachments.py      attachment classification and decoding
  detector.py         rule matching and fingerprints
  rules.py            YAML rule loader and validation
  default_rules.yaml  built-in rule pack
  models.py           domain and report models
  baseline.py         baseline identity, loading, and atomic writing
  report.py           text and scanner-native JSON output
  sarif.py            SARIF 2.1.0 output
tests/                 unit and integration-oriented tests
```

## Suggested refactoring checklist

The MVP behavior is covered by tests, so the following work can be done in
small steps:

1. Add `pyproject.toml`, package metadata, a console entry point, and one
   centralized version constant.
2. Introduce typed protocols for the Confluence client and document scanner to
   make test doubles explicit.
3. Split `SecretScanner` page, history, and attachment orchestration into
   focused components.
4. Replace string locations such as `line:2:column:10` with a typed source
   region in the domain model.
5. Add CLI-level tests for argument validation and combinations of baseline,
   history, attachments, and exit thresholds.
6. Add sanitized fixtures captured from the exact target Confluence editions
   and versions.
7. Add an authentication strategy abstraction before supporting Basic auth or
   OAuth flows.
8. Evaluate incremental scanning, bounded concurrency, and structured metrics
   only after establishing rate-limit behavior on the target instance.

## Roadmap

- compatibility testing against the target Confluence Cloud/Data Center
  versions;
- optional PDF and Office extraction without adding heavy dependencies to the
  base installation;
- modified-since or CQL-based incremental scans;
- issue-tracker integration;
- packaging, release versioning, and CI configuration;
- further performance and operational hardening before unattended corporate
  runs.
