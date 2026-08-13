# Presidio and document redaction notes

Use Presidio to detect and redact sensitive text entities before writing the output file.

## Entity scope

Redact:
- PERSON / names
- EMAIL_ADDRESS
- PHONE_NUMBER
- LOCATION / addresses when present
- ID-like values
- organization or company names
- project names

Add custom recognizers when organization-specific names or project codenames are not detected reliably by Presidio defaults.

## Redaction approach

Use a full redaction operator, not a reversible anonymizer. The result should not retain the original sensitive text in visible content.

## Per-file expectations

### PDF
- Extract text per page.
- Run Presidio on each page's text.
- Redact matching text at the page level.
- Recheck the final PDF by extracting text again.

### Word
- Process paragraphs, tables, headers, footers, and other accessible text containers.
- Replace sensitive runs while preserving layout.

### PowerPoint
- Process text frames on slides and in notes.
- Preserve the deck structure while removing sensitive text.

## Safety check

Do not return a file unless the visible text has been rechecked for the targeted sensitive entities.
