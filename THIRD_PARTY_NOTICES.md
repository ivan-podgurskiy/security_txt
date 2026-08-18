# Third-Party Notices

## RFC 9116 examples and errata

The shared conformance fixture includes adapted examples and behavioral cases
from [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) and its
[errata](https://www.rfc-editor.org/errata_search.php?rfc=9116). The examples
remove document indentation and replace the illustrative signature payload
with a non-verifying placeholder. RFC text is published under the IETF Trust
Legal Provisions.

## Re-expressed upstream test ideas

Test scenarios were independently re-expressed from the MIT-licensed
[DigitalTrustCenter/sectxt](https://github.com/DigitalTrustCenter/sectxt) Python
project and the [eikendev/sectxt](https://github.com/eikendev/sectxt) Rust
project. No upstream source code was copied.

## Real-world security.txt snapshots

The following response bodies were captured on 2026-08-16 and are stored as
timestamped fixtures so tests and CI never fetch live network content:

- Google: <https://www.google.com/.well-known/security.txt>
- GitHub: <https://github.com/.well-known/security.txt>
- Microsoft: <https://www.microsoft.com/.well-known/security.txt>
- Dropbox: <https://www.dropbox.com/.well-known/security.txt>

The snapshots are used only as interoperability test data. Their contents
remain attributable to their respective publishers.

## Elixir port

The shared conformance fixture and real-world snapshots are mirrored byte-for-byte
from the npm `security-txt-parser` package for cross-ecosystem behavioral parity.
