# Confluleaks

A small, read-only AppSec scanner for finding accidentally exposed credentials
in Confluence pages, page history, comments, and text attachments.

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
- optional scanning of current footer, inline, and resolved comments;
- optional scanning of supported text attachments with a hard size limit;
- Bearer token and HTTP Basic authentication;
- 27 built-in rules covering common tokens, keys, connection strings, private
  keys, and labelled credentials;
- rule-specific context, entropy thresholds, allowlists, and stopwords;
- deduplication of the same finding across page versions;
- retry/backoff for rate limits and transient server failures;
- bounded REST responses, document sizes, regex execution, finding counts, and
  total runtime for safer operation on large installations;
- text, JSON, and SARIF 2.1.0 reports;
- versioned baselines for suppressing reviewed findings;
- CI-friendly exit codes.

## Known limitations

- Browser/SSO sessions, OAuth, Kerberos, client certificates, and manually
  supplied cookies are not supported.
- The client targets the REST API v1 response shape. It has not yet been
  compatibility-tested against every Confluence Cloud and Data Center release.
- Only Confluence `body.storage` page content is extracted.
- Comment history is not scanned; only comments currently returned for each page
  are inspected.
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
- either a Bearer token or credentials accepted through HTTP Basic auth;
- read access to every space, page, historical version, comment, or attachment
  included in the scan.

Use a dedicated least-privilege account where possible.

## Installation

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

This installs the `confluleaks` command in the active environment. For editable
development with a current pip version, use `python -m pip install -e .`.
Running `python -m confluleaks` directly from the checkout is also supported.

## Authentication

Authentication secrets are read only from environment variables. Bearer is the
default and is appropriate for Confluence Data Center personal access tokens:

```bash
export CONFLUENCE_URL='https://confluence.example.com'
export CONFLUENCE_TOKEN='<personal-access-token>'
confluleaks --space ENG
```

Basic authentication uses `CONFLUENCE_USERNAME` as the user ID and
`CONFLUENCE_TOKEN` as the password or API token. For Confluence Cloud, use the
account email as the username and an API token as the secret:

```bash
export CONFLUENCE_URL='https://example.atlassian.net/wiki'
export CONFLUENCE_AUTH='basic'
export CONFLUENCE_USERNAME='scanner@example.com'
export CONFLUENCE_TOKEN='<api-token-or-password>'
confluleaks --space ENG
```

`--auth bearer` or `--auth basic` overrides `CONFLUENCE_AUTH`. Bearer remains
the default for backward compatibility. Prefer a dedicated least-privilege
account and tokens over reusable account passwords.

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
confluleaks --space ENG --max-pages 100
```

If `--max-pages` prevents the scanner from processing another discovered page,
the result is marked as incomplete and the process exits with code `1`. This is
useful for evaluation, but an incomplete result cannot be written as a
baseline.

After reviewing the initial behavior, expand the scope deliberately:

```bash
confluleaks \
  --space ENG \
  --space OPS \
  --comments \
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
confluleaks --space ENG --space OPS

# Scan all default spaces except selected ones.
confluleaks --exclude-space PUBLIC

# Expand the default selection.
confluleaks --include-personal-spaces --include-archived-spaces
```

An explicitly selected `--space` is scanned even if it is personal or archived.
The same key cannot be both included and excluded.

### Page history

History is opt-in:

```bash
# All available previous versions.
confluleaks --history

# At most five previous versions per current page.
confluleaks --history-limit 5
```

Passing `--history-limit` automatically enables history. Missing historical
versions that return `404` are skipped. Identical findings across versions are
collapsed and retain the list of matching version numbers.

### Comments

Comment scanning is opt-in and covers the current comments returned by the
Confluence REST API, including footer, inline, and resolved locations:

```bash
confluleaks --comments
```

Comments are fetched page by page. Findings identify the parent page and
comment ID, but never include the comment body, author, matched value, or a
surrounding snippet. Comment edit history is not scanned.

### Attachments

Attachment scanning is also opt-in:

```bash
# Supported text attachments up to 5 MiB each.
confluleaks --attachments

# Override the per-attachment limit.
confluleaks --attachments --max-attachment-size-mb 1
```

Supported extensions are `.cfg`, `.conf`, `.csv`, `.env`, `.ini`, `.js`,
`.json`, `.log`, `.md`, `.properties`, `.py`, `.sh`, `.sql`, `.ts`, `.txt`,
`.xml`, `.yaml`, and `.yml`. Known text MIME types are also accepted.

An explicit binary MIME type takes precedence over a text-looking filename.
Declared and actually downloaded bytes are both checked against the limit.
Cross-origin attachment links are rejected before a request is made.
Skipping an oversized supported attachment marks the scan as incomplete.

## Reports and exit codes

Human-readable output is the default:

```bash
confluleaks --format text
```

Scanner-native JSON:

```bash
confluleaks --format json > confluence-results.json
```

SARIF 2.1.0:

```bash
confluleaks --format sarif > confluence-results.sarif
```

SARIF output contains rule descriptors, severity, confidence, page, comment,
or attachment locations, and stable partial fingerprints. It validates against
the [OASIS SARIF 2.1.0 schema](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json).
Because findings point to Confluence URLs rather than repository files,
repository-centric SARIF consumers may display the result without annotating a
source file in the repository.

Use `--fail-on` to make findings affect CI:

```bash
confluleaks --format sarif --fail-on high > confluence-results.sarif
```

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed and no unsuppressed finding reached `--fail-on`. |
| `1` | Configuration, baseline, or Confluence error; also returned for any incomplete result caused by an operational guardrail or `--continue-on-error`. |
| `2` | At least one unsuppressed finding reached the configured severity threshold. |

Critical findings satisfy every threshold. Severity order is `low`, `medium`,
`high`, `critical`.

## Baselines

A baseline suppresses reviewed findings so CI can focus on newly introduced
ones.

Create it only after reviewing a complete scan of the intended scope:

```bash
confluleaks \
  --space ENG \
  --comments \
  --attachments \
  --write-baseline confluence-baseline.json
```

Use the same scope on subsequent runs:

```bash
confluleaks \
  --space ENG \
  --comments \
  --attachments \
  --baseline confluence-baseline.json \
  --format sarif \
  --fail-on high > confluence-results.sarif
```

Baseline entries contain an opaque finding ID, rule ID, page ID, and optional
comment or attachment ID. They do not contain matched values, source snippets,
titles, or raw secret fingerprints.

Identity is stable across page renames, new page versions, and line movement.
The same match on another page or attachment is treated as new. Baselines are
written atomically with owner-only permissions (`0600`). Writing is refused if
the result contains errors or was made incomplete by any operational
guardrail.

Keep the selected scope consistent. A successful but intentionally narrow scan
is complete for that scope and can therefore replace a broader baseline if the
same output path is used.

## Detection rules

The default rules live in
[`scanner/default_rules.yaml`](scanner/default_rules.yaml). Supply a different
file with `--rules`:

```bash
confluleaks --rules ./organization-rules.yaml
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
confluleaks \
  --retries 5 \
  --backoff 1 \
  --request-delay 0.2 \
  --timeout 30
```

`--continue-on-error` records recoverable request failures and continues with
other spaces or pages. The report remains partial and the process exits with
code `1`.

### Large-installation guardrails

The scanner applies conservative limits by default so an unexpectedly large
page, response, pathological rule, or finding storm cannot consume memory and
CPU without a bound.

| Option | Default | Behavior when reached |
| --- | ---: | --- |
| `--max-response-size-mb` | 16 MiB | Abort that streamed REST response before retaining more bytes. |
| `--max-document-size-mb` | 5 MiB | Skip that page, version, comment, or decoded attachment. |
| `--regex-timeout` | 0.25 s | Bound each regex operation; on timeout, stop the rule and skip the rest of that document. |
| `--max-findings-per-document` | 1,000 | Retain the first matches and omit the rest from that document. |
| `--max-findings` | 10,000 | Stop the entire scan once additional matches are observed. |
| `--max-runtime` | 3,600 s | Stop between scan units after the soft wall-clock budget expires. |

The attachment download limit is controlled separately by
`--max-attachment-size-mb` and has the same incomplete-result semantics. The
runtime limit is soft: a single HTTP request can run until `--timeout`, and a
single regex operation can run until `--regex-timeout` before the
total-runtime check runs again.

Every triggered guardrail sets `truncated: true`, records a stable identifier
in `truncation_reasons` in JSON and SARIF, and returns exit code `1`. Text output
prints the reasons as `Result incomplete`. This prevents a bounded scan from
being mistaken for a clean complete scan or used to write a baseline.

## Command reference

Run `confluleaks --help` for the authoritative CLI help.

```text
confluleaks [OPTIONS]

--url URL                    override CONFLUENCE_URL
--auth {bearer,basic}        authentication method (default: bearer)
--version                    print the installed version
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
--comments                   scan current page comments
--attachments                scan supported text attachments
--max-attachment-size-mb MB  attachment limit (default: 5 MiB)
--max-response-size-mb MB    REST response limit (default: 16 MiB)
--max-document-size-mb MB    content body limit (default: 5 MiB)
--regex-timeout SECONDS      per-operation regex timeout (default: 0.25)
--max-findings N             global finding limit (default: 10000)
--max-findings-per-document N
                             per-document finding limit (default: 1000)
--max-runtime SECONDS        soft scan runtime limit (default: 3600)

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
ConfluenceClient ── pagination / retry / throttling / response limits
        │
        ▼
SecretScanner ──── scope / current pages / history / comments / attachments
        │
        ├── HTML and text extraction
        ▼
Detector ───────── bounded regex / context / entropy / allowlists
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

- Authentication secrets are read only from `CONFLUENCE_TOKEN`; Basic auth also
  reads `CONFLUENCE_USERNAME`. Do not put secrets in command-line arguments or
  commit them to the repository.
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
python -m compileall -q confluleaks scanner tests
```

The tests cover extraction, rules, context and entropy filtering, report
redaction, history deduplication, comment scanning, attachment classification
and limits, response/document/finding/runtime guardrails, regex timeouts, retry
configuration, SARIF structure, baseline stability, and partial-error behavior.

## Repository layout

```text
scanner/
  auth.py             Bearer and Basic authentication strategies
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
confluleaks/
  __main__.py         branded `python -m confluleaks` entry point
tests/                 unit and integration-oriented tests
pyproject.toml         Python build backend configuration
setup.cfg              metadata, dependencies, package data, and console script
```

## Suggested refactoring checklist

The MVP behavior is covered by tests, so the following work can be done in
small steps:

1. Complete package metadata with project URLs, license selection, build checks,
   and a release workflow.
2. Introduce typed protocols for the Confluence client and document scanner to
   make test doubles explicit.
3. Split `SecretScanner` page, history, comment, and attachment orchestration
   into focused components.
4. Replace string locations such as `line:2:column:10` with a typed source
   region in the domain model.
5. Add CLI-level tests for argument validation and combinations of baseline,
   history, comments, attachments, and exit thresholds.
6. Add sanitized fixtures captured from the exact target Confluence editions
   and versions.
7. Evaluate whether OAuth or enterprise authentication adapters belong in the
   base package or optional integrations.
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
- bounded concurrency and structured operational metrics.
