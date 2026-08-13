# Custom recognizers for company and project names

Presidio default recognizers are strong for generic PII, but company and project names usually need a document-specific hint.

## Use these signals

Create extra recognizers or deny lists from:
- names explicitly mentioned by the user
- project codename lists from the document header, title, or repeated labels
- organization glossary terms that recur across the file
- obvious company names in signatures, footers, cover pages, or slide masters

## Practical rule

Treat a repeated, distinctive proper noun phrase as a candidate company or project name when it is clearly not a person name and is central to the document context.

## Avoid

Do not over-redact generic business words such as "project", "team", "solution", or "platform" unless they are part of the exact named term to remove.
