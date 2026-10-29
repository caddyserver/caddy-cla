# Behavior

## Repository configuration

Administrators need GitHub write access to the repository they manage. Agreement
text, public Gist selection and exemptions are editable in the admin interface.
The GitHub App must be installed before adding another repository.

Publishing changed agreement text creates an immutable revision and queues that
repository's open PRs. Older text and signatures remain available. Gists can be
pinned to a revision or refreshed manually with **Refresh from Gist**. There is no
automatic Gist polling.
Configuration files provide initial defaults; restarting does not overwrite live edits.

Signatures are scoped to repository, agreement revision and numeric GitHub ID.
Accepting an agreement for one repository does not approve another repository,
even when both use identical text. Contributors can view their own history and
revoke their own scoped acceptances; changes queue PR checks automatically.

## Pull requests

The installed GitHub App receives `pull_request`, `issue_comment` and `merge_group` webhooks.
It posts or updates one app-owned comment and publishes the `license/cla` commit
status. **No GitHub Actions workflow is required.** Configure repository rules to
require `license/cla` from this GitHub App to block merges when approval is missing.

Automation is disabled unless `automation_enabled` is explicitly set to `true`.
Credentials alone never enable webhook processing or queued GitHub writes.
When enabled, checks run after new PR webhook activity and after signing or
agreement/exemption changes for already tracked PRs. Startup and maintenance
never discover or backfill existing PRs. A manual scan of all open PRs requires
an administrator to explicitly confirm that it can post comments on every PR.
An already-satisfied PR receives only the status check, with no new comment.
When action is needed, the bot creates one reminder and updates that same comment
as contributors sign or the check changes. Resolving a reminder never creates a
new success comment. Repeated checks with unchanged wording do not edit it.

Merge queues receive `license/cla` on their synthetic head commit. Merge checks
retry API failures and are requeued after signature or agreement changes. Pending
merge checks and retry errors appear in the repository’s admin page.

Unresolved reminders include **Recheck this PR**. Clicking it synchronously
checks that tracked PR and redirects back to GitHub, without login or a
confirmation page. Requests share a 30-second cooldown per PR; repeated clicks
return to the PR without another API call. A browser recheck never creates a new
reminder, and resolved comments omit the link. The PR author or a writer can also
comment `recheck` or `@cla-bot check`.

The PR opener and linked commit authors must have signed or be exempt. When GitHub
cannot associate an author email with an account, the comment identifies the
commits and links to GitHub email settings with instructions for fixing attribution.
The service does not request or compare private account email lists.

## Imports and history

The admin interface accepts raw CLA Assistant JSON, native JSON exports and CSV
exports up to 6 MiB. Import is atomic, preserves original evidence and recognizes
historical repository names by stable repository ID. Records lacking numeric user
IDs remain unresolved until an administrator verifies and links the identity.
Exports, admin history and legacy resolution are restricted to the selected repository.
A contributor's personal history includes only that authenticated GitHub ID.

## Current limits

- Real OAuth and GitHub App behavior still need live-repository validation.
  Browser tests use isolated sessions and mocked GitHub; they do not prove live OAuth.
- Co-authors resolve through identified author emails or GitHub noreply addresses;
  unresolved identities fail closed.
- PRs exceeding GitHub's 250-commit REST limit fail closed.
- Merge-group public comparison reads share GitHub’s unauthenticated API rate limit.
  Throttled checks remain pending and retry. Stored group jobs expire after seven days.
- No custom signer-form builder, private Gist access, small-diff thresholds,
  source-organization exemptions or corporate-signature administration.
- Gist network failures retain the last valid agreement snapshot and are logged.

Upstream reference: https://github.com/cla-assistant/cla-assistant
