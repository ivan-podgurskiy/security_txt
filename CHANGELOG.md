# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-18

### Added

- `SecurityTxt.parse/1` for RFC 9116 parsing and validation with structured diagnostics separated into errors, recommendations, and notifications.
- `SecurityTxt.serialize/1` for canonical unsigned document generation from a validated keyword list.
- Parsing and validation for Contact, Expires, Acknowledgments, Canonical, CSAF, Encryption, Hiring, Policy, and Preferred-Languages with source-order field preservation and convenience accessors.
- OpenPGP cleartext envelope detection and dash-unescaped body extraction without a cryptography dependency.
- Stable diagnostic codes with messages and one-based source line numbers.
- Physical-line scanning with UTF-8 BOM rejection, LF and CRLF support, and bounded resource limits for file size, line count, and field length.
- URI scheme validation for registered fields, RFC 3339 expiry classification, and RFC 5646 language-tag checks.
- Shared language-neutral conformance fixtures, property-based tests, and timestamped real-world snapshots from Google, GitHub, Microsoft, and Dropbox.
- Hex package metadata, ExDoc documentation, and CI across Elixir 1.14–1.20 on Ubuntu, macOS, and Windows.

[1.0.0]: https://github.com/ivan-podgurskiy/security_txt/releases/tag/v1.0.0
