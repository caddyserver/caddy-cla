# GitHub integration

The example URLs below use `/cla`. For root hosting, omit that prefix in the
GitHub application URLs.

Create **two separate applications** owned by whichever organization will operate
this service. Contributors authorize identity lookup only, not the repository bot.

## Ownership

The source repository, OAuth App, and GitHub App have independent ownership.
Prefer organization ownership for both app registrations. An organization owner
can grant a maintainer the GitHub App manager role without granting organization
ownership. Installation access is separate and may still need owner approval.

A personally owned GitHub App can be transferred to the organization later.
While personally owned, it must be public to install on a different account;
a private GitHub App installs only on its owner's account. Once owned by the
organization, it can be private if only that organization will install it.
The separate OAuth App supports public contributor login and can also be transferred.

Transferring the source repo into an organization requires permission to create
repositories there; creating it personally does not bypass that restriction.
Coordinate the transfer with an organization owner.

References: [GitHub App ownership](https://docs.github.com/en/apps/maintaining-github-apps/transferring-ownership-of-a-github-app),
[App managers](https://docs.github.com/en/apps/maintaining-github-apps/about-github-app-managers),
[app visibility](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/making-a-github-app-public-or-private),
[OAuth App ownership](https://docs.github.com/en/apps/oauth-apps/maintaining-oauth-apps/transferring-ownership-of-an-oauth-app),
and [repository transfers](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository).

For the Caddy deployment, an organization owner can use this
[pre-filled GitHub App registration form](https://github.com/organizations/caddyserver/settings/apps/new?name=Caddy+CLA&description=Contributor+agreement+checks+for+Caddy+repositories&url=https%3A%2F%2Fcaddyserver.com%2Fcla%2F&webhook_active=true&webhook_url=https%3A%2F%2Fcaddyserver.com%2Fcla%2Fwebhooks%2Fgithub&request_oauth_on_install=false&public=false&metadata=read&pull_requests=write&statuses=write&merge_queues=read&events%5B%5D=pull_request&events%5B%5D=issue_comment&events%5B%5D=merge_group).
Review permissions before submitting, keep user authorization disabled, and add
the webhook secret manually from `/etc/caddy-cla/secrets.env` on the server.
The secret is deliberately omitted from the registration URL. Install initially
on `caddyserver/caddy` only. Keep the required branch status unchanged until live
signing, webhook delivery and PR rechecks have been verified.

### OAuth App: contributor identity

* Homepage: `https://caddyserver.com/cla/`
* Callback: `https://caddyserver.com/cla/auth/github/callback`
* Set `GITHUB_OAUTH_CLIENT_ID` and `GITHUB_OAUTH_CLIENT_SECRET`.

The authorization URL deliberately has **no scope parameter**. Authentication uses
OAuth state bound to an HttpOnly cookie, a single-use expiring database state, and
PKCE S256. The token is used to call `/user` and is not stored. Sessions store
GitHub's numeric identity, login and a CSRF token; session identifiers are hashed.
Sessions expire after 12 hours. Signing requires a separate explicit POST and
acceptance checkbox; login alone never records agreement acceptance.

### GitHub App: PR automation

Use the service homepage as the App homepage. Do not enable user authorization,
user-token expiration/refresh, a setup URL, or device flow for this bot. Contributor
login uses the separate OAuth App above. Keep the webhook active. Generate an RSA
private key and install it as the PEM file named by `GITHUB_APP_PRIVATE_KEY_FILE`.
The webhook secret must match the server's environment file.

Install only on the configured repositories. Request:

| Repository permission | Level | Use |
| --- | --- | --- |
| Metadata | Read | Repository installation and collaborator permission checks |
| Pull requests | Write | Read PRs/commits and create/update the bot's PR comment |
| Commit statuses | Write | Update `license/cla` on PR and merge-group heads |
| Merge queues | Read | Receive `merge_group` check requests |

No account or organization permissions, repository contents, Actions, administration
or email permissions are requested. GitHub groups commenting with wider PR write
access; there is no comment-only permission in this setup.

Subscribe to `pull_request`, `issue_comment` and `merge_group` webhooks. Use:
`https://caddyserver.com/cla/webhooks/github`. Set a high-entropy webhook secret.
Set `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY_FILE` (an RSA PEM file), and
`GITHUB_WEBHOOK_SECRET`. The service mints short-lived installation tokens.

The app must be installed on every configured repository. Admin access is checked live against GitHub: the signed-in user must have
push/write (including maintain or admin) access on the repository being managed.
Settings, imports and exports are scoped to that repository. Plain organization membership does not
grant access. An optional `admin_ids` deployment allowlist can grant explicit
operator access; leave empty for GitHub-only authorization. No `read:org` scope is
needed. GitHub API errors deny admin access.

## Merge protection and rechecks

Require the `license/cla` status in each repository's branch protection or ruleset,
selecting this GitHub App as the expected source where supported. The App publishes
commit statuses directly; no Actions workflow is involved. An unsigned or unlinked
author produces a failing status and a PR comment with signing and recheck links.
Keep the status optional while testing the installation in a sandbox repository.

Public Gists are read without requesting the `gist` OAuth scope. Commit email
attribution comes from GitHub's linked author response, not private email access.

Merge-group requests are verified and queued durably. The bot evaluates the exact
base/head comparison, including commit co-authors and associated PR openers, and
reports `license/cla` on the synthetic merge-group head. Public commit comparisons
use unauthenticated reads; Contents permission is not requested.
