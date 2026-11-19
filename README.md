# Jira gateway (reference, direct OIDC route)

> **Status: prototype.** The tests run against a fake Atlassian. The gateway has not yet been run
> against a live Jira site, so do not put it in front of production credentials.

A small Go service that lets a CI run reach Jira Cloud with no Jira secret in the repository.
The run sends its CI OIDC token as `Authorization: Bearer <jwt>`. The gateway verifies the token,
looks up the caller's grant, checks the call against a fixed allowlist, confirms upstream that
every issue key still names an issue inside the grant, and forwards the call to
`https://api.atlassian.com/ex/jira/{cloudId}/rest/api/3/...` with an OAuth `client_credentials`
token that only the gateway holds. The caller's token never goes upstream.

fullsend points its Jira API URL at the gateway and keeps the same path layout as Atlassian's
API gateway, so the client needs no other change.

## Quick start

Prerequisites: Go 1.26. Python 3 for the deploy renderer tests.

1. Run the tests:

   ```console
   $ go test -race ./...
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/auth	2.886s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/config	3.198s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/jql	1.856s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/policy	2.095s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/preflight	1.668s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/respfilter	2.910s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/server	4.960s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/strictjson	2.298s
   ok  	github.com/waynesun09/tmp-jira-gateway/internal/upstream	2.789s
   $ python3 -m unittest discover -s deploy
   Ran 14 tests in 1.938s
   OK
   ```

2. Run a fuzz target (each one for at least 60 s before a release):

   ```console
   $ go test -run='^$' -fuzz='^FuzzValidate$' -fuzztime=65s ./internal/jql/
   $ go test -run='^$' -fuzz='^FuzzParse$' -fuzztime=65s ./internal/strictjson/
   $ go test -run='^$' -fuzz='^FuzzParseRequestURI$' -fuzztime=65s ./internal/policy/
   $ go test -run='^$' -fuzz='^FuzzSearchFilter$' -fuzztime=65s ./internal/respfilter/
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
   {"code":"unauthenticated","error":"unauthorized"}
   ```

   With the default issuer the gateway fetches GitHub's OIDC discovery document and keys at
   startup, so it needs network access. A real call needs a GitHub Actions OIDC token for the
   configured audience, from a job with `id-token: write`.

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
| `token_url` | `https://auth.atlassian.com/oauth/token` | OAuth `client_credentials` endpoint (JSON request body) |
| `read_client_id_file`, `read_client_secret_file` | required with a read grant | Files holding the read OAuth client |
| `write_client_id_file`, `write_client_secret_file` | required with a write grant | Files holding the write OAuth client |
| `max_request_bytes` | 1 MiB | Larger request bodies get 413 |
| `max_response_bytes` | 3 MiB | Larger upstream bodies get 502; see [Memory](#memory) |
| `preflight_cache_seconds` | 60 (0 disables, max 300) | How long a confirmed issue lookup is reused by read routes; see [Pre-flight](#pre-flight-cache-and-strip) |
| `filter_slots` | 2 (max 16) | How many responses are filtered at once; a caller waits up to 5 s for a slot, then gets 503 |
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
| `level` | `read` or `write`. A write grant may make every allowed call; a read grant only the read ones. The level also picks the OAuth client (read or write) for every upstream call, pre-flights included |
| `projects` | Project keys (`^[A-Z][A-Z0-9_]+$`), compared case-sensitively |

The fullsend poller needs a write grant (it writes its lock and checkpoint issue properties), and
every project in the repository's allowed targets must be in its grant.

## What the gateway allows

Paths are relative to `/ex/jira/{cloudId}/rest/api/3`. Everything else gets 403. "Pre-flight"
means the issue key is confirmed upstream first ([below](#pre-flight-cache-and-strip)).

| Call | Level | Checks | Query parameters accepted |
|---|---|---|---|
| `GET /myself` | read | none | none |
| `GET /status/{id or name}` | read | none (a global read; names are accepted as well as ids) | none |
| `GET /project/{key}/role`, `GET /project/{key}/role/{id}` | read | key in grant | none |
| `GET /user/groups` | read | none | `accountId`, exactly once, required |
| `GET /issue/{key}` | read | key prefix in grant, pre-flight; response stripped, and its `key` must equal the requested key | none |
| `GET /issue/{key}/comment` | read | key prefix in grant, pre-flight | `orderBy=created`, `maxResults`, `startAt`, `expand=properties` |
| `GET /issue/{key}/changelog` | read | key prefix in grant, pre-flight; response filtered to labels and status items | `maxResults`, `startAt` |
| `GET /issue/{key}/transitions` | read | key prefix in grant, pre-flight | `expand=transitions.fields` |
| `GET /issue/{key}/properties/{k}` | read | pre-flight; `{k}` is one of the caller's [two poller keys](#issue-property-keys) | none |
| `POST /search/jql` | read | [JQL grammar](#jql-grammar); body keys `jql`, `maxResults`, `fields`, `nextPageToken` only; response stripped | none |
| `POST /issue/{key}/comment` | write | pre-flight; body keys `body`, `properties` only | none |
| `PUT /issue/{key}/comment/{id}` | write | pre-flight, numeric id, comment belongs to the issue; body keys `body` and/or `properties` only | none |
| `DELETE /issue/{key}/comment/{id}` | write | pre-flight, numeric id, comment belongs to the issue | none |
| `POST /issue/{key}/transitions` | write | pre-flight; body: `transition` (`{"id":"<digits>"}`), optional `fields` holding only `resolution` (`{"name"}` or `{"id"}`), optional `update` holding only `comment` | none |
| `PUT /issue/{key}/properties/{k}` | write | pre-flight; `{k}` is a poller key; body any strict-JSON value up to 32 KiB | none |
| `DELETE /issue/{key}/properties/{k}` | write | pre-flight; `{k}` is the poller's `.lock` key | none |
| `PUT /issue/{key}` | write | pre-flight; body exactly `{"update":{"labels":[{"add":"x"} or {"remove":"x"}, ...]}}` | none |
| `POST /issue` | write | `fields.project.key` in grant; `fields.parent.key` (if present) in grant and pre-flighted; `fields` keys `project`, `issuetype`, `summary`, `parent`, `description` only | none |
| `POST /issueLink` | write | both issue keys in grant and pre-flighted; body exactly `type`, `inwardIssue`, `outwardIssue` | none |
| `/comment/{id}/properties/{k}`, any method | denied | always refused | |

**Query parameters are coupled to core.** The table lists every parameter the gateway accepts.
A new query parameter in fullsend's Jira client gets 403 `query_not_allowed` until the gateway
allows it. Values are limited to `[A-Za-z0-9_.-]` and each route's own pattern; `accountId` is
`<digits>:<uuid>` (with `:` sent as `%3A`, decoded once; `%253A` is refused) or 24 lowercase hex
digits.

Rules on every call:

- **Issue keys** must match `^[A-Z][A-Z0-9_]+-[1-9][0-9]*$`: numeric issue ids, lowercase keys
  and zero-padded numbers (`ABC-01`) are refused.
- **Paths** must already be clean: an empty segment (`//`, a trailing slash), a dot segment in
  any encoding (`..`, `%2e%2e`), an encoded slash or backslash (`%2F`, `%2f`, `%5C`), a control
  character or a bad escape gets 403. `/rest/api/2` and `/rest/agile` paths are refused. On
  Cloud Run, Google's front end may normalise `..` and `//` before the gateway sees the path; the
  answer is then the decision on the cleaned path.
- **Bodies** are strict JSON: valid UTF-8, no duplicate keys at any depth (keys that differ only
  in ASCII case count as duplicates), no trailing data, an object at the top level (except the
  issue property PUT). `Content-Type` must be `application/json`. GET and DELETE take no body.

### Issue property keys

A caller may touch only its own poller keys, built the way fullsend's poller builds them
(`internal/jirapoll/lock.go`):

| Key | Methods |
|---|---|
| `fullsend.poll.<esc(owner)>.<esc(repo)>.lock` | GET, PUT, DELETE |
| `fullsend.poll.<esc(owner)>.<esc(repo)>.lastCheck` | GET, PUT |

- `owner` and `repo` come from the verified token's `repository` claim, split on the last `/`.
- `esc` replaces each `.` with the literal three characters `%2E`. On the wire fullsend
  path-escapes the whole key, so `my.repo` arrives as `my%252Erepo`. The gateway decodes the
  segment exactly once (giving `my%2Erepo`) and compares; it never decodes twice.
- Owner and repo compare case-insensitively; everything else, `%2E` included, exactly.
- Any other key, another repository's key, an unescaped dot, a single-encoded `%2E` on the wire,
  a triple-encoded form and GitLab-form keys get 403 `not_granted` (or `endpoint_not_allowed` for
  a malformed segment).

Example: repository `Acme-Org/my.repo-x` may use
`/issue/PROJ-1/properties/fullsend.poll.Acme-Org.my%252Erepo-x.lock`.

## JQL grammar

`POST /search/jql` is forwarded only if its `jql` matches this grammar and every project it
names is in the grant. The query is forwarded unchanged; the gateway never adds or rewrites a
clause.

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
  names are outside the grammar.
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

Refused:

| Query | Code |
|---|---|
| `project = OTHER`, `project IN (ABC, OTHER)`, `project = ABC AND project = OTHER` | `not_granted` (inside the grammar, project outside the grant) |
| `statusCategory != Done` (no project clause) | `jql_grammar` |
| `project = ABC OR project = OTHER`, `... \|\| ...` | `jql_grammar` |
| `project = ABC AND status = Open) OR (project = OTHER` | `jql_grammar` |
| `project != ABC`, `project NOT IN (X)`, `NOT status = Open`, `!(...)` | `jql_grammar` |
| `project = abc`, `project = 10000`, `project = "My Project"` | `jql_grammar` |
| `summary ~ "x"`, `text ~ "x"`, `issue = X-1`, `key = X-1`, `parent = X-1`, `filter = 1`, `reporter = x`, `cf[1] = x` | `jql_grammar` |
| `assignee = currentUser()`, `issue in linkedIssues(X-1)` | `jql_grammar` |
| `status WAS Open`, `status CHANGED`, `ORDER BY summary`, `"project" = ABC` | `jql_grammar` |
| non-ASCII outside quotes, control characters, Unicode quotes or format characters in strings, `&`, `\|`, `;`, `#`, `[`, unbalanced quotes | `jql_grammar` |

A grammar refusal is exactly `{"code":"jql_grammar","error":"jql outside the accepted grammar"}`,
with no echo of the query. A deployment whose custom poll query (`tracker.jira.poll.query`) is
wider than this grammar must simplify it, or keep static Jira credentials.

## Pre-flight, cache and strip

**Pre-flight.** Jira resolves an issue key case-insensitively and follows moves: after `ABC-5`
moves to project `OTHER`, `GET /issue/ABC-5` returns the moved issue under its new key, with no
redirect. So before forwarding any call on an issue key (every `/issue/{key}...` route, both
`issueLink` keys and `POST /issue`'s `parent.key`), the gateway calls
`GET /issue/{key}?fields=project` with the grant level's own OAuth client and requires:

- status 200, and the returned `key` equal to the requested key exactly;
- `fields.project.key` in the grant.

The call is then forwarded with the requested key. For `PUT` and `DELETE` on
`/issue/{key}/comment/{id}`, the gateway also reads `GET /issue/{key}/comment/{id}` and requires
the issue id in the comment's `self` URL to equal the pre-flighted issue's id. On
`GET /issue/{key}`, the `key` in Jira's answer must also equal the requested key (checked for
free while the answer is filtered), which catches an issue that moved after a cached pre-flight.

**Outcomes.** Nothing is forwarded unless the pre-flight succeeds.

| Pre-flight answer | Caller gets |
|---|---|
| 200 with the requested key in a granted project | the call is forwarded |
| 200 with another key or a project outside the grant, 404, 403, 400 | `403 not_granted`, the same as any grant refusal, so a moved issue cannot be told from one never granted |
| 429 (Jira's `Retry-After` is passed back), 5xx, a redirect, a transport error, a timeout (10 s) | `502 upstream_error`; retry later |
| 401 after a token refresh, or the token endpoint refusing the client | `502 upstream_auth` |

**Cache.** Each instance keeps a positive cache of "on cloud C, `KEY-n` is issue N in project P",
for `preflight_cache_seconds` (default 60, at most 300; 0 disables), used by read routes only:
every write route always asks Jira. The cache holds only that fact, not grant decisions: every
hit is checked again against the caller's grant. Refusals, errors and timeouts are never cached,
nor is the comment check.

**Strip.** On every 2xx answer the gateway filters three responses, whatever `fields` the
request asked for, and sets `Content-Length`:

| Response | Filter |
|---|---|
| `GET /issue/{key}` | removes `fields.parent`, `fields.subtasks`, `fields.issuelinks` (and the same under `renderedFields`) |
| `POST /search/jql` | the same on every element of `issues[]`, every page |
| `GET /issue/{key}/changelog` | in every `values[]` entry, keeps only `items[]` whose `field` is exactly `labels` or `status` (the only ones fullsend reads). Entries are kept even when emptied, and `startAt`, `maxResults`, `total` and `isLast` are untouched, because fullsend pages with `startAt += len(values)` |

The filter copies kept values byte for byte; it never re-encodes them. It refuses invalid JSON or
UTF-8, trailing data, EXACT duplicate keys (keys that differ only in case are allowed in
responses: Jira field ids may) and nesting deeper than 256, with `502 upstream_error`. fullsend
does not read the removed data.

**Cost.** One extra upstream call per issue key per call on a cache miss or a write (an
`issueLink` has two keys), plus one per comment edit or delete. A poll cycle that reads N issues'
comments and changelog makes about N pre-flight calls per 60 s. Each request log line has a
`preflight_calls` count.

## Memory

Each instance runs with `GOMEMLIMIT` at 80% of its memory (set by the deploy script), so the Go
garbage collector works harder before the container limit is reached.

The budget is 12 copies of a maximum-size response for every request in flight:
`12 x CONCURRENCY x MAX_RESPONSE_BYTES + 32 MiB <= GOMEMLIMIT`, checked by `deploy/render.py`.
With the defaults: 12 x 10 x 3 MiB + 32 MiB = 392 MiB within 409 MiB (80% of 512 MiB).

Where 12 comes from: reading a body can hold up to 2 copies while the buffer grows, and the
filter allocates about 3 more. `TestStripMemoryBudget` pushes a 3 MiB search page of
issues with long descriptions through the filter with the garbage collector off and asserts it
allocates at most 12 times the body; it measures 2.6 times:

```console
$ go test -count=1 -v -run TestStripMemoryBudget ./internal/respfilter/ | grep allocated
    respfilter_test.go:214: body 3138501 bytes, allocated 8266352 bytes while filtering (2.6x)
```

`filter_slots` (default 2) also bounds how many responses are filtered at once; a request that
finds no free slot within 5 s gets `503 {"code":"upstream_error","error":"gateway busy"}`.

## Responses

Every gateway error body is `{"error":"<fixed text>","code":"<stable code>"}`. Branch on `code`.
None carries request or upstream text.

| Denial | Status | Code |
|---|---|---|
| Bad, missing or expired token; `alg: none`; a quoted or fractional `exp`/`nbf`; a token in another header than `Authorization` | 401 | `unauthenticated` |
| No grant for the repository, or its ids differ | 403 | `not_granted` |
| Path `{cloudId}` differs from the grant | 403 | `not_granted` |
| Issue or project key outside the grant | 403 | `not_granted` |
| In-grammar JQL naming a project outside the grant | 403 | `not_granted` |
| A write method on a read grant | 403 | `not_granted` |
| Moved issue (pre-flight found another key or project), pre-flight 404 or 403 | 403 | `not_granted` |
| `GET /issue/{key}` answered with a different `key` | 403 | `not_granted` |
| Comment id used through another issue's path | 403 | `not_granted` |
| Another repository's property key, or a non-poller property key | 403 | `not_granted` |
| `/comment/{id}/properties/{k}`, any method | 403 | `endpoint_not_allowed` |
| Numeric issue id, lowercase issue key, `../`, `%2F`/`%2f`, `//`, `/rest/api/2`, agile paths, any unlisted endpoint | 403 | `endpoint_not_allowed` |
| Unsent or unknown query parameter, a repeated or missing one | 403 | `query_not_allowed` |
| JQL outside the grammar | 403 | `jql_grammar` |
| Duplicate or unknown body key, a non-JSON body, a wrong `Content-Type` | 403 | `body_not_allowed` |
| Body over `max_request_bytes` | 413 | `body_not_allowed` |
| Atlassian refused the gateway's own credential: the token endpoint answered 400/401/403, or Jira answered 401 twice (once with a fresh token) | 502 | `upstream_auth` |
| Pre-flight 429 (with Jira's `Retry-After`), 5xx, redirect, transport error or timeout | 502 | `upstream_error` |
| Jira redirect (`upstream redirect`), Jira 403 (`upstream refused the call`), any other Jira status outside the pass-through list such as 405, 410, 413, 422 or 5xx (`upstream error`), transport failure, oversized or undecodable response | 502 | `upstream_error` |
| No response-filter slot within 5 s (`gateway busy`) | 503 | `upstream_error` |

Jira's own 2xx, 400, 404, 409 and 429 answers to allowed calls pass back with their body,
`Content-Type` and `Retry-After`, because fullsend reads their error messages. Every other
status gets a fixed body as above; a Jira 401 never reaches the caller as 401, so
fullsend cannot mistake it for a refusal of its own token. Do not retry `upstream_auth`.

`GET /healthz` answers `200 {"status":"ok"}` without authentication and without calling Jira or
Atlassian.

## Logs

One JSON line per event on stdout (Cloud Logging reads `severity`). Each process has a random
`instance` id.

```json
{"severity":"INFO","message":"request","time":"...","instance":"a60f03cdbb6e6427","repository":"example-org/example-repo","run_id":"1234567890","method":"GET","path":"/ex/jira/{cloudId}/rest/api/3/issue/{key}","decision":"allow","preflight_calls":1,"upstream_status":200,"status":200,"latency_ms":143}
{"severity":"WARNING","message":"request","time":"...","instance":"a60f03cdbb6e6427","repository":"example-org/example-repo","run_id":"1234567890","method":"POST","path":"/ex/jira/{cloudId}/rest/api/3/search/jql","decision":"deny","reason":"jql outside the accepted grammar","code":"jql_grammar","preflight_calls":0,"status":403,"latency_ms":0,"jql_sha256":"..."}
{"severity":"INFO","message":"token_fetch","time":"...","instance":"a60f03cdbb6e6427","client":"read","outcome":"ok","token_endpoint_status":200}
```

`path` is the route template, never the raw path. `reason` is an internal fixed reason (finer
than `code`). The log types have no field for tokens, client values, bodies or JQL text; a search
logs only the SHA-256 of its JQL.

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

Settings are in `deploy/gateway.env`. `render.py` refuses any project other than
`example-dev-project`, `MIN_INSTANCES` above `MAX_INSTANCES`, and a memory size that
does not fit the [memory budget](#memory). The deploy step sets `GOMEMLIMIT` (80% of `MEMORY`,
409MiB by default).

| Step | What it does |
|---|---|
| `check` | Renders `deploy/out/config.json` and runs `jira-gateway -check` on it (local, always runs) |
| `inventory` | Read-only: describes the service, service account, secrets and image repository |
| `image` | Creates the Artifact Registry repo (label `purpose=fullsend-jira-gateway-dev`), builds the Containerfile for linux/amd64, pushes it, records the digest |
| `sa` | Creates the runtime service account (description `purpose=fullsend-jira-gateway-dev`; service accounts have no labels) |
| `secrets` | Adds the rendered config as a new `fullsend-jira-gateway-dev-grants` version if it changed; grants the service account accessor on it and on the four client secrets |
| `deploy` | Refuses unless all five secrets have an ENABLED version; deploys the image digest with each secret mounted as a file at a pinned version, `--no-invoker-iam-check` (the gateway does its own auth), `MIN_INSTANCES`/`MAX_INSTANCES`, label `purpose=fullsend-jira-gateway-dev` |
| `post` | Checks `/healthz` (`.status == "ok"`), a no-token call and a non-JWT bearer (401 with `.code == "unauthenticated"`, read with jq rather than comparing whole bodies), and that the newest revision is ready with 100% of traffic |

Dry run of the `deploy` step:

```console
$ deploy/deploy.sh --grants deploy/grants.example.json deploy
# dry run: commands are printed, not run (add --execute to run them)
...
+ gcloud run deploy fullsend-jira-gateway-dev --project example-dev-project --region us-central1 --image us-central1-docker.pkg.dev/example-dev-project/fullsend-jira-gateway-dev/jira-gateway@sha256:\<digest-from-image-step\> --service-account fullsend-jira-gateway-dev@example-dev-project.iam.gserviceaccount.com --no-invoker-iam-check --ingress all --port 8080 --max-instances 1 --min-instances 0 --concurrency 10 --cpu 1 --memory 512Mi --cpu-throttling --labels purpose=fullsend-jira-gateway-dev --set-env-vars GOMEMLIMIT=409MiB --set-secrets /etc/jira-gateway/config/config.json=fullsend-jira-gateway-dev-grants:\<...-version\>,...
+ gcloud run services update-traffic fullsend-jira-gateway-dev --project example-dev-project --region us-central1 --to-latest
```

Not run with `--execute`: no GCP resource has been created by this repository.

## Known limits

- **Free text and custom fields pass through.** Comment bodies, descriptions, summaries, label
  values and custom field values in allowed calls and responses are not inspected. They can name
  or quote issues in other projects. What limits that is the service account's own Jira project
  access, and one service account covers the union of all grants. Give it access only to granted
  projects, with separate read and write OAuth clients.
- **Query parameters are coupled to core** (see the allowlist table): a new parameter gets 403
  until the gateway allows it.
- **Project-key aliases.** A project clause value and `/project/{key}/role` compare the key as
  written. If Jira also resolves an old (renamed) project key or a project name equal to a
  granted key, Jira's resolution decides; the service account's project access is the backstop.
  Issue keys are pre-flighted; project keys are not.
- **GitLab poll property keys** (containing `/` or `:`) and `GET /status/{name}` with `'` or `/`
  in the name are refused. GitLab-hosted runs are out of scope for now.
- **Narrow write bodies.** `PUT /issue/{key}` accepts only label adds and removes, `POST /issue`
  only the fields fullsend sends, transitions only `resolution`. Other edits get 403.
- **Path forms** are refused rather than cleaned, but a front end may clean them first.
- **Changelog items** other than `labels` and `status` are dropped, custom fields included;
  entries stay so paging does not shift.
- **One shared rate limit.** Every granted repository shares the service account's Jira limit;
  pre-flights add to it.

## Decisions

- **Narrow JQL, no rewriting.** Wrapping a query as `project in (...) AND (...)` by
  concatenation is unsafe (`status = Open) OR (project = OTHER` escapes it), and rewriting would
  change what the user wrote.
- **Comment-property calls are refused.** `/comment/{id}/properties/{k}` names no issue. fullsend
  writes the property through `PUT /issue/{key}/comment/{id}` (`properties` field) instead.
- **Forward with the requested key** after the pre-flight, not the resolved id, so Jira's answer
  matches what the client asked for.
- **Token cache.** The upstream token is replaced at half its lifetime or 5 minutes before
  expiry, whichever is sooner. A Jira 401 triggers one refresh and one retry.
- **JWKS refetch** for an unknown key id happens at most once per 30 s, with concurrent misses
  sharing one fetch and no lock held during it. A token with an unknown key id inside that window
  waits for the next allowed fetch, up to 5 s and never past its own `exp`, so a real key rotation
  is not refused because forged key ids forced a fetch moments earlier. Beyond 5 s it is refused.
  The fetch is detached from the request that started it, and the window starts when an attempt
  completes, so a caller that disconnects cannot spend the window without a real fetch.

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `"code":"unauthenticated"` on every call | Wrong audience, an expired token, or the token in another header | Fetch the OIDC token with the gateway's audience, send it as `Authorization: Bearer`, refresh from its `exp` |
| `"code":"not_granted"` on every call | The repository or one of its ids is not in the grant table, or the cloud id differs | Check `repository`, `repository_id`, `repository_owner_id` (`render.py --verify-ids`) and `cloudId` |
| `"code":"not_granted"` on one issue | The issue moved out of a granted project, or the pre-flight failed | Check the issue's current key; the log line's `reason` says `pre-flight` |
| `"code":"jql_grammar"` | The poll query is wider than the grammar | Simplify `tracker.jira.poll.query` to the forms above |
| `"code":"query_not_allowed"` | fullsend sent a parameter the gateway does not list | Add it to the route in `internal/policy` |
| `"code":"upstream_auth"` | The OAuth client files are wrong or the token endpoint refused them | Check the `token_fetch` log line's `outcome` and `token_endpoint_status` |
| `deploy: secret ... has no ENABLED version` | A client secret was not created | Create it in Secret Manager, then rerun `deploy` |
| `render.py`: `... exceeds GOMEMLIMIT` | `CONCURRENCY` or `MAX_RESPONSE_BYTES` too high for `MEMORY` | Lower one of them, or raise `MEMORY` |
| `"code":"upstream_error"` with `Retry-After` on an issue call | Jira rate-limited the pre-flight | Retry after the given seconds |
| `503` `"error":"gateway busy"` | All filter slots busy for 5 s | Retry; raise `FILTER_SLOTS` only within the memory budget |
