# Documentation assets

`assets/mcp-demo-redacted.png` is an edited illustration based on an operator-supplied screenshot. The original is not stored in this repository. It was produced with the built-in image-editing tool and visually reviewed before publication. Device identity, IP address, client count, calendar/timezone details and connection/message timestamps are covered. Its approved SHA-256 is pinned in the privacy checker; replacing it requires another review.

Editing prompt:

> Use case: precise-object-edit. Edit target: the supplied chat screenshot. Produce a privacy-redacted copy for a private GitHub README. Preserve the exact screenshot layout, dimensions, dark background, all non-sensitive text and the UniFi integration icon. Do not restyle, paraphrase, invent text or add claims. The ONLY changes: use solid opaque dark rectangular redaction bars over (1) the small clock timestamp at top right, (2) the numeric client count in the sentence beginning 'I found ... clients online', (3) the timezone and calendar date in the table column heading, (4) the device name in the first table data row, (5) its connection time, and (6) its entire IP address. Do not blur; fully remove sensitive pixel information. Keep the natural-language user question and the explanation that the API lacks first-seen history fully readable. Keep table column labels 'Device', 'Connected since', and 'IP' readable. Do not expose the covered values elsewhere or add replacements.

The generated output was rescaled by the editing tool and is labeled as edited; it is not an unaltered forensic screenshot. It demonstrates the interaction and explicit API limitations. The UniFi icon is covered separately by THIRD-PARTY-NOTICES.md.

Before publication, ancillary PNG metadata was removed without modifying the generated pixels. The committed image contains only IHDR, IDAT and IEND chunks; no hidden source attachments or textual metadata are retained. The edited/AI-assisted provenance remains explicitly disclosed here and in the README caption.
