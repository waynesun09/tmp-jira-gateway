# Jira gateway (reference, direct OIDC route)

A small Go service that lets a CI run reach Jira Cloud with no Jira secret in the repository.
The run sends its CI OIDC token as `Authorization: Bearer <jwt>`. The gateway verifies the token,
looks up the caller's grant, checks the call against a fixed allowlist, and forwards it to
`https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3/...` with an OAuth `client_credentials`
token that only the gateway holds. The caller's token never goes upstream.

fullsend points its Jira API URL at the gateway and keeps the same path layout as Atlassian's
API gateway, so the client needs no other change.

## Quick start

Prerequisites: Go 1.26. Python 3 for the deploy renderer tests.

1. Run the tests:

   ```console
   $ go test -race ./...
   ok  	github.com/nonflux/tmp-jira-gateway/internal/auth	2.328s
   ok  	github.com/nonflux/tmp-jira-gateway/internal/config	1.450s
   ok  	github.com/nonflux/tmp-jira-gateway/internal/jql	1.698s
   ok  	github.com/nonflux/tmp-jira-gateway/internal/policy	2.161s
   ok  	github.com/nonflux/tmp-jira-gateway/internal/server	3.510s
   ok  	github.com/nonflux/tmp-jira-gateway/internal/strictjson	2.578s
   ok  	github.com/nonflux/tmp-jira-gateway/internal/upstream	2.412s
   $ python3 -m unittest discover -s deploy
   Ran 5 tests in 0.008s
   OK
   ```

2. Run a fuzz target (each one for at least 60 s before a release):

   ```console
   $ go test -run='^$' -fuzz='^FuzzValidate$' -fuzztime=75s ./internal/jql/
   $ go test -run='^$' -fuzz='^FuzzParse$' -fuzztime=75s ./internal/strictjson/
   $ go test -run='^$' -fuzz='^FuzzParseRequestURI$' -fuzztime=75s ./internal/policy/
   ```

3. Run it locally. Write a config (see [Configuration](#configuration)) whose client files hold
   any text, then start the gateway and probe it:

   ```console
   $ go build -o /tmp/jgw-local/jira-gateway ./cmd/jira-gateway
   $ /tmp/jgw-local/jira-gateway -config /tmp/jgw-local/config.json
   {"severity":"INFO","message":"started","time":"2026-11-16T16:28:46.870516Z","instance":"a60f03cdbb6e6427","detail":"listening on 127.0.0.1:8080, 1 grant(s)"}

   $ curl -s http://127.0.0.1:8080/healthz
   {"status":"ok"}
   $ curl -s -H 'Authorization: Bearer not-a-jwt' http://127.0.0.1:8080/ex/jira/x/rest/api/3/myself
   {"error":"unauthorized"}
   ```

   With the default issuer the gateway fetches GitHub's OIDC discovery document at startup, so
   it needs network access. A real call needs a GitHub Actions OIDC token for the configured
   audience, from a job with `id-token: write`.

## Configuration

One JSON file holds the settings and the grant table. Unknown fields, duplicate keys and
trailing data are refused. `jira-gateway -check -config FILE` validates it without reading any
secret or touching the network.

```json
{
  "listen": "127.0.0.1:8080",
  "audience": "fullsend-jira-gateway-dev",
  "read_client_id_file": "/tmp/jgw-local/read-id",
  "read_client_secret_file": "/tmp/jgw-local/read-secret",
  "grants": [
    {"repository": "example-org/example-repo", "repository_id": "100000001", "repository_owner_id": "200000002",
     "cloudId": "00000000-0000-0000-0000-000000000000", "level": "read", "projects": ["ABC"]}
  ]
}
```

| Field | Default | Meaning |
|---|---|---|
| `listen` | `:$PORT`, else `:8080` | Listen address |
| `issuer` | `https://token.actions.githubusercontent.com` | The token's `iss` must equal it exactly; keys come from its discovery document |
| `audience` | required | The token's `aud` must contain it |
| `clock_skew_seconds` | 30 (max 120) | Allowed skew on `exp` and `nbf` |
| `upstream_base_url` | `https://api.atlassian.com` | Where allowed calls go |
| `token_url` | `https://auth.atlassian.com/oauth/token` | OAuth `client_credentials` endpoint |
| `read_client_id_file`, `read_client_secret_file` | required with a read grant | Files holding the read OAuth client |
| `write_client_id_file`, `write_client_secret_file` | required with a write grant | Files holding the write OAuth client |
| `max_request_bytes` | 1 MiB | Larger request bodies get 413 |
| `max_response_bytes` | 10 MiB | Larger upstream bodies get 502 |
| `grants` | required | See below |

The client id and secret come only from files (Secret Manager mounts), never from flags, the
environment or the config. They are read on every token fetch, so a rotated mount is picked up,
and are never logged.

### Grants

| Field | Rule |
|---|---|
| `repository` | `owner/name`; must equal the token's `repository` |
| `repository_id`, `repository_owner_id` | Digit strings; must equal the token's claims |
| `cloudId` | The Jira site's cloud id; must equal the `{cloudId}` in the request path |
| `level` | `read` or `write`. A write grant may make every allowed call; a read grant only the read ones. The level also picks the OAuth client (read or write) |
| `projects` | Project keys (`^[A-Z][A-Z0-9_]+$`), compared case-sensitively |

## What the gateway allows

Paths are relative to `/ex/jira/{cloudId}/rest/api/3`. Everything else gets 403.

| Call | Level | Check | Query parameters |
|---|---|---|---|
| `GET /myself` | read | none | none |
| `GET /status/{id or name}` | read | none | none |
| `GET /project/{key}/role`, `GET /project/{key}/role/{id}` | read | key in grant | none |
| `GET /issue/{key}` | read | key prefix in grant | none |
| `GET /issue/{key}/comment` | read | key prefix in grant | `orderBy=created`, `maxResults`, `startAt`, `expand=properties` |
| `GET /issue/{key}/changelog` | read | key prefix in grant | `maxResults`, `startAt` |
| `GET /issue/{key}/transitions` | read | key prefix in grant | `expand=transitions.fields` |
| `GET /issue/{key}/properties/{k}` | read | key prefix in grant | none |
| `POST /search/jql` | read | [JQL grammar](#jql-grammar); body keys `jql`, `maxResults`, `fields`, `nextPageToken` only | none |
| `POST /issue/{key}/comment` | write | key prefix in grant; body keys `body`, `properties` only | none |
| `PUT /issue/{key}/comment/{id}` | write | key prefix in grant, numeric id; body keys `body` and/or `properties` only | none |
| `DELETE /issue/{key}/comment/{id}` | write | key prefix in grant, numeric id | none |
| `POST /issue/{key}/transitions` | write | key prefix in grant; body keys `transition` (`{"id": "<digits>"}`), `fields` (not `project`, `parent`, `issuelinks`), `update` (`comment` only) | none |
| `PUT`/`DELETE /issue/{key}/properties/{k}` | write | key prefix in grant; the PUT body may be any JSON value up to 32 KiB | none |
| `PUT /issue/{key}` | write | key prefix in grant; body exactly `{"update":{"labels":[{"add":"x"} or {"remove":"x"}, ...]}}` | none |
| `POST /issue` | write | `fields.project.key` and `fields.parent.key` (if present) in grant; `fields` keys `project`, `issuetype`, `summary`, `parent`, `description` only | none |
| `POST /issueLink` | write | both issue keys in grant; body exactly `type`, `inwardIssue`, `outwardIssue` | none |
| `/comment/{id}/properties/{k}`, any method | denied | always refused | |

Rules on every call:

- **Issue keys** must match `^[A-Z][A-Z0-9_]+-[0-9]+$`. Numeric issue ids and lowercase keys
  are refused.
- **Paths** must already be clean: an empty segment (`//`, a trailing slash), a dot segment in
  any encoding (`..`, `%2e%2e`), an encoded slash or backslash (`%2F`, `%2f`, `%5C`), a control
  character or a bad escape gets 403. `/rest/api/2` and `/rest/agile` paths are refused.
- **Query strings** may hold only the listed parameters, each once, with values in
  `[A-Za-z0-9_.-]`. A `jql` parameter is never allowed.
- **Bodies** are strict JSON: valid UTF-8, no duplicate keys at any depth (keys that differ only
  in ASCII case count as duplicates), no trailing data, an object at the top level (except the
  issue property PUT). `Content-Type` must be `application/json`. GET and DELETE take no body.

## JQL grammar

`POST /search/jql` is forwarded only if its `jql` matches this grammar and every project it
names is in the grant. The query is forwarded unchanged; the gateway never rewrites it.

```text
query   := conj [ORDER BY sort {"," sort}]
conj    := term {AND term}
term    := clause | "(" conj ")"                 at most 3 levels of parentheses
clause  := project = KEY
         | project IN (KEY {, KEY})
         | FIELD OP VALUE
         | FIELD [NOT] IN (VALUE {, VALUE})
         | FIELD IS [NOT] EMPTY|NULL
sort    := updated | created | key | priority | status   [ASC|DESC]
```

- **At least one project clause** is required, and every key in every project clause must be in
  the grant, written exactly as in the grant (`ABC`, not `abc`). Numeric project ids and project
  names are refused.
- **AND only.** Because every clause narrows the result, one project clause confines the query.
- Keywords and field names are case-insensitive (`and`, `Order By`, `Status`).
- `KEY` and `VALUE` are a quoted string (`"..."` or `'...'`, escapes `\"`, `\'`, `\\` only) or
  an unquoted word of `[A-Za-z0-9_-]` that is not a keyword.

| Field | Operators |
|---|---|
| `project` | `=`, `IN` |
| `status`, `statusCategory`, `issuetype`, `labels`, `assignee` | `=`, `!=`, `IN`, `NOT IN`, `IS [NOT] EMPTY`, `= EMPTY`, `!= EMPTY` |
| `updated` | `=`, `!=`, `>`, `>=`, `<`, `<=`, `IS [NOT] EMPTY` |

Accepted, with grant `ABC`, `DEF`:

```text
project = "ABC" AND statusCategory != Done ORDER BY updated DESC
project = "ABC" AND (statusCategory != Done) ORDER BY updated DESC
project IN (ABC, DEF) AND status IN (Open, "To Do") AND labels NOT IN (wontfix)
project = ABC AND assignee IS EMPTY AND updated >= -7d ORDER BY priority DESC, key
```

The first two are what fullsend sends with no custom poll query.

Refused (403):

| Query | Why |
|---|---|
| `statusCategory != Done` | no project clause |
| `project = OTHER` | project not granted |
| `project IN (ABC, OTHER)`, `project = ABC AND project = OTHER` | one key not granted |
| `project = ABC OR project = OTHER`, `... \|\| ...` | OR |
| `project = ABC AND status = Open) OR (project = OTHER` | unbalanced, and OR |
| `project != ABC`, `project NOT IN (X)`, `NOT status = Open`, `!(...)` | negation of scope |
| `project = abc`, `project = 10000`, `project = "My Project"` | not a granted key as written |
| `project = ABC AND summary ~ "x"`, `text ~ "x"`, `issue = X-1`, `key = X-1`, `parent = X-1`, `filter = 1`, `reporter = x`, `cf[1] = x` | field outside the grammar |
| `project = ABC AND assignee = currentUser()`, `issue in linkedIssues(X-1)` | function |
| `project = ABC AND status WAS Open`, `status CHANGED` | history operator |
| `project = ABC ORDER BY summary` | sort field outside the list |
| `"project" = ABC` | quoted field name |
| any non-ASCII character outside quotes, control characters, Unicode quotes or format characters in strings, `&`, `\|`, `;`, `#`, `[`, unbalanced quotes | not in the grammar |

A refused query always gets exactly this body, with no echo of the query:

```json
{"error":"jql outside the accepted grammar"}
```

A deployment whose custom poll query (`tracker.jira.poll.query`) is wider than this grammar must
simplify it, or keep static Jira credentials instead of the gateway.

## Responses

| Status | Body | When |
|---|---|---|
| 401 | `{"error":"unauthorized"}` | No `Authorization: Bearer` header, or the token fails signature (RS256 against the issuer's JWKS), issuer, audience, `exp` or `nbf` |
| 403 | `{"error":"no grant for caller"}` | No grant for `repository`, or `repository_id` / `repository_owner_id` differ |
| 403 | `{"error":"<reason>"}` | Allowlist refusal; reasons: `path not allowed`, `cloud id not in grant`, `endpoint not allowed`, `project not in grant`, `write grant required`, `query not allowed`, `request body not allowed`, `jql outside the accepted grammar`, `comment property calls are not allowed` |
| 413 | `{"error":"request too large"}` | Body over `max_request_bytes` |
| 502 | `{"error":"upstream token unavailable"}` | The OAuth token request failed |
| 502 | `{"error":"upstream authentication failed"}` | Jira answered 401 twice (once with a fresh token) |
| 403 | `{"error":"upstream refused the call"}` | Jira answered 403 |
| 5xx | `{"error":"upstream error"}` | Jira answered 5xx (same status) |
| 2xx, 400, 404, 409, 429 | Jira's body | Jira's answer to an allowed call, passed back with `Content-Type` and `Retry-After` |

Every gateway denial is JSON `{"error": "..."}` with a fixed reason and no upstream text. Jira's
own 2xx and 4xx answers to allowed calls pass back, because fullsend reads their error messages;
Jira's 401, 403, 3xx and 5xx bodies are replaced. A Jira 401 never reaches the caller as 401, so
fullsend cannot mistake it for a refusal of its own token.

`GET /healthz` answers `200 {"status":"ok"}` without authentication and without calling Jira or
Atlassian.

## Logs

One JSON line per event on stdout (Cloud Logging reads `severity`). Each process has a random
`instance` id.

```json
{"severity":"INFO","message":"request","time":"...","instance":"a60f03cdbb6e6427","repository":"example-org/example-repo","run_id":"1234567890","method":"POST","path":"/ex/jira/{cloudId}/rest/api/3/search/jql","decision":"allow","upstream_status":200,"status":200,"latency_ms":143,"jql_sha256":"..."}
{"severity":"INFO","message":"token_fetch","time":"...","instance":"a60f03cdbb6e6427","client":"read","outcome":"ok","token_endpoint_status":200}
```

`path` is the route template, never the raw path. The log types have no field for tokens,
client values, bodies or JQL text; a search logs only the SHA-256 of its JQL.

## Deploy (Cloud Run, dev)

`deploy/deploy.sh` follows a render, check, apply, post-check pattern. **It is a dry run by
default**: it prints every `gcloud`, `podman` and `curl` command and runs none. Add `--execute`
to run them.

Prerequisites:

- The four OAuth client values in Secret Manager as `fullsend-jira-gateway-dev-read-client-id`,
  `-read-client-secret`, `-write-client-id` and `-write-client-secret` (created by whoever owns
  the service account; the script never reads them).
- `deploy/grants.json`, the real grant table (git-ignored). Start from
  `deploy/grants.example.json`; `python3 deploy/render.py --verify-ids` checks the ids against
  GitHub.
- `gcloud`, `podman`, `curl`, `jq`, `python3`, `go`.

Steps, in order (names and project are in `deploy/gateway.env`):

| Step | What it does |
|---|---|
| `check` | Renders `deploy/out/config.json` and runs `jira-gateway -check` on it (local, always runs) |
| `inventory` | Read-only: describes the service, service account, secrets and image repository |
| `image` | Builds the Containerfile for linux/amd64, pushes it, records the digest |
| `sa` | Creates the runtime service account |
| `secrets` | Adds the rendered config as a new `fullsend-jira-gateway-dev-grants` version if it changed; grants the service account accessor on it and on the four client secrets |
| `deploy` | Refuses unless all five secrets have an ENABLED version; deploys the image digest with each secret mounted as a file at a pinned version, `--no-invoker-iam-check` (the gateway does its own auth) |
| `post` | Checks `/healthz`, a no-token call and a non-JWT bearer (both 401 JSON), and that the newest revision is ready with 100% of traffic |

Dry run of the `deploy` step:

```console
$ deploy/deploy.sh --grants deploy/grants.example.json deploy
# dry run: commands are printed, not run (add --execute to run them)
+ cat .../deploy/out/image-digest
+ gcloud secrets versions list fullsend-jira-gateway-dev-grants --project example-dev-project --filter=state=ENABLED --sort-by=~createTime --limit 1 --format=value\(name.basename\(\)\)
...
+ gcloud run deploy fullsend-jira-gateway-dev --project example-dev-project --region us-central1 --image us-central1-docker.pkg.dev/example-dev-project/fullsend-jira-gateway-dev/jira-gateway@sha256:\<digest-from-image-step\> --service-account fullsend-jira-gateway-dev@example-dev-project.iam.gserviceaccount.com --no-invoker-iam-check --ingress all --port 8080 --max-instances 1 --min-instances 0 --concurrency 80 --cpu 1 --memory 256Mi --cpu-throttling --set-secrets /etc/jira-gateway/config/config.json=fullsend-jira-gateway-dev-grants:\<...-version\>,/etc/jira-gateway/read-client-id/value=...
+ gcloud run services update-traffic fullsend-jira-gateway-dev --project example-dev-project --region us-central1 --to-latest
```

Not run with `--execute`: no GCP resource has been created by this repository.

## Decisions and limits

- **Narrow JQL, no rewriting.** The gateway does not add a project clause; it refuses a query
  without one. Wrapping a query as `project in (...) AND (...)` by concatenation is unsafe
  (`status = Open) OR (project = OTHER` escapes it), and rewriting would change what the user
  wrote.
- **Comment-property calls are refused.** `/comment/{id}/properties/{k}` names no issue, so the
  gateway cannot check its project. fullsend writes the property through
  `PUT /issue/{key}/comment/{id}` (`properties` field) instead.
- **Second boundary in Jira.** Give the service account access only to granted projects, with
  separate read and write OAuth clients, so a gateway bug cannot reach beyond them. A project
  clause value is compared as a key; if another project's *name* equals a granted key, Jira's
  resolution decides, and the service account's project access is the backstop.
- **Narrow write bodies.** `PUT /issue/{key}` accepts only label adds and removes, and
  `POST /issue` only the fields fullsend sends; other edits get 403.
- **Not in the allowlist:** `GET /user/groups`, which fullsend's poller uses for actor role
  resolution. Calls to it get 403.
- **Token cache.** The upstream token is replaced at half its lifetime or 5 minutes before
  expiry, whichever is sooner. A Jira 401 triggers one refresh and one retry.
- **Path forms** are refused rather than cleaned. A front end (for example Cloud Run's) may
  clean some forms before the gateway sees them; the gateway checks and forwards the path it
  receives.
- **One shared rate limit.** Every granted repository shares the service account's Jira limit.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `{"error":"unauthorized"}` on every call | Wrong audience, an expired token, or the token in another header | Fetch the OIDC token with the gateway's audience, send it as `Authorization: Bearer`, refresh from its `exp` |
| `{"error":"no grant for caller"}` | The repository or one of its ids is not in the grant table | Check `repository`, `repository_id`, `repository_owner_id` (`render.py --verify-ids`) |
| `{"error":"cloud id not in grant"}` | The Jira site's cloud id differs from the grant | Fix `cloudId` in the grant |
| `{"error":"jql outside the accepted grammar"}` | The poll query is wider than the grammar | Simplify `tracker.jira.poll.query` to the forms above |
| `{"error":"upstream token unavailable"}` | The OAuth client files are wrong or the token endpoint refused them | Check the `token_fetch` log line's `outcome` and `token_endpoint_status` |
| `deploy: secret ... has no ENABLED version` | A client secret was not created | Create it in Secret Manager, then rerun `deploy` |
