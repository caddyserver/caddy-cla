# Migrating signatures

The bundled `agreement.md` is the exact text from the pinned Gist revision above.
Although the old UI calls it “Caddy CLA”, the text is the Linux Foundation's
Developer Certificate of Origin 1.1. We retain the content verbatim; this is the
same web acceptance flow, not a new requirement for commit sign-off trailers.

With the service stopped (recommended for the initial cutover):

```sh
go run ./cmd/caddy-cla -config config.json -import /private/path/caddy-cla-signatures.json
```

Accepts the raw API record array or the `{repository, gistVersion, signatures}`
wrapper produced by the export command in our migration discussion. It does not
accept the old dashboard's transformed JSON or username-only CSV: those may lose
numeric identity or evidence. Import is transactional and idempotent. Invalid IDs/dates, wrong agreement versions, Gist mismatches and repository mismatches
reject the import. Records missing an ID are preserved in a separate legacy table
and require explicit administrator identity verification before granting approval.
The configured `repository_id` allows historical names for the same GitHub repository. Original records (including custom fields) remain in SQLite;
original timestamps and revocation/expiry fields are retained.

Historical exports can contain names from repository transfers and signatures without
numeric GitHub IDs. Set `repository_id` to accept aliases of that same repository.
Records without IDs remain in the legacy table until an administrator verifies and
links the current account. Imports and databases must remain outside version control.

Agreement versions are immutable. Configure the selected repository's Gist or
agreement text through the admin interface; changing the text creates a revision
and requires new acceptance. Existing versions and signatures remain in history.

The same JSON and CSV uploads are supported at **Administration → Signatures →
Import signatures**. Select the repository and the existing agreement revision
that the records represent. An invalid upload commits no records. CSV records
without numeric GitHub IDs require identity review rather than granting approval.
