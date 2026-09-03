# Confluence Secret Scanner

A tool for detecting accidentally exposed secrets in Confluence.

It looks for API keys, tokens, passwords, private keys, and other potentially sensitive data in page content, with support for page history and attachments planned.

The project is intended as a small internal AppSec tool rather than a general-purpose DLP solution.

## What it does

Current focus:

* scans Confluence pages;
* detects secrets using configurable rules;
* takes surrounding context into account;
* reduces false positives;
* does not print discovered secrets in full;
* produces results that can be consumed by other tools.

Planned:

* page version history;
* attachments;
* entropy analysis;
* allowlists;
* finding deduplication;
* JSON/SARIF output;
* integration with issue trackers.

## Example

A Confluence page contains:

```yaml
database:
  host: prod-db
  username: admin
  password: "SuperSecret123!"
```

The scanner should report something like:

```text
[HIGH] Generic password

Page: Production deployment
Location: database.password
Version: 17
Confidence: 0.94
```

The actual secret is never included in the output.

## How it works

```text
             Confluence
                  │
                  ▼
             Page fetch
                  │
                  ▼
              Extractor
                  │
                  ▼
              Detector
             /    |    \
          rules entropy context
             \    |    /
                  ▼
              Findings
                  │
                  ▼
             JSON / CLI
```

The scanner is separated from the data source. The detection engine works with extracted content and does not need to know where it came from.

This makes it possible to add other data sources later without rewriting the detection logic.

## Installation

```bash
git clone <repository>
cd confluence-secret-scanner

python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Usage

```bash
python -m scanner
```

Example output:

```text
Confluence Secret Scanner

Scanned:
  Spaces: 12
  Pages: 4281

Findings:
  Critical: 3
  High:     17
  Medium:   42
```

## Rules

Detection rules are kept separately from the scanner code.

Example:

```yaml
id: github-token
severity: high
regex: 'gh[pousr]_[A-Za-z0-9_]{20,}'
```

This makes it possible to add or modify detection rules without changing the scanner itself.

## Security

The scanner itself processes sensitive data, so discovered secrets should never end up in:

* stdout;
* logs;
* telemetry;
* exception messages;
* stored scan results.

Fingerprints can be used to identify duplicate findings without storing the original secret.

## Why not Gitleaks?

Gitleaks is a good fit for finding secrets in files and Git repositories.

This project targets a different use case: scanning corporate Confluence while taking its specific features into account, such as pages, version history, attachments, and document context.

Gitleaks can therefore be used as a reference point for detection quality rather than something this project is trying to replace.

## Status

Work in progress.

The goal for `1.0` is a stable scanner that can be run regularly against a corporate Confluence instance and produce reproducible security findings without requiring someone to manually review thousands of pages.
