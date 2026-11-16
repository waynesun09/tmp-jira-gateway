#!/bin/bash
# Deploy the dev Jira gateway to Cloud Run. DRY RUN BY DEFAULT: every gcloud, podman and curl
# command is printed, not run. Add --execute to run them.
#
# usage: deploy/deploy.sh [--execute] [--grants FILE] <step>
#   check      render deploy/out/config.json from gateway.env + grants (default deploy/grants.json)
#              and validate it with `jira-gateway -check` (local; always runs, even in dry run)
#   inventory  read-only: list the service, service account, secrets and image repository
#   image      build the Containerfile with podman (linux/amd64), push it to Artifact Registry,
#              and record its digest in deploy/out/image-digest
#   sa         create the runtime service account $N@$P.iam.gserviceaccount.com if it is missing
#   secrets    add deploy/out/config.json as a new $CONFIG_SECRET version if it changed, and give
#              the service account secretAccessor on that secret and the four client secrets
#   deploy     refuse unless all four client secrets have an ENABLED version; deploy the image
#              digest with each secret mounted as a file at a pinned version
#   post       fail unless /healthz answers 200 with .status "ok", a call with no token and a call
#              with a non-JWT bearer get 401 with .code "unauthenticated" (checked with jq, not by
#              comparing the whole body), and the newest revision is
#              ready and serves 100% of traffic
#
# Needs: bash, python3, go (check); gcloud, podman, curl, jq (the other steps). Never reads the
# client id or secret values.
set -euo pipefail
D=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$D/.." && pwd)
EXECUTE=0
GRANTS="$D/grants.json"
while [ $# -gt 0 ]; do
  case "$1" in
  --execute) EXECUTE=1 ;;
  --dry-run) EXECUTE=0 ;;
  --grants)
    GRANTS=$2
    shift
    ;;
  -*)
    echo "unknown flag $1" >&2
    exit 2
    ;;
  *) break ;;
  esac
  shift
done
STEP=${1:-}
case "$STEP" in
check | inventory | image | sa | secrets | deploy | post) ;;
*)
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit 2
  ;;
esac

# eval is safe only because render.py rejects any value outside [A-Za-z0-9._:/-].
envs=$(python3 "$D/render.py" --print-env)
eval "$envs"
# The Go runtime's soft memory limit: 80% of the instance memory, so the
# garbage collector works harder before the container limit is reached.
GOMEMLIMIT=$(python3 "$D/render.py" --print-gomemlimit)
SA="$N@$P.iam.gserviceaccount.com"
AR="$R-docker.pkg.dev/$P/$N/jira-gateway"
OUT="$D/out"
MNT=/etc/jira-gateway

# run prints a command; with --execute it also runs it.
run() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if [ "$EXECUTE" = 1 ]; then
    "$@"
  fi
}

# capture runs a read-only command and prints its output; in a dry run it prints the command
# and returns the placeholder given as the first argument.
capture() {
  local placeholder=$1
  shift
  if [ "$EXECUTE" = 1 ]; then
    "$@"
  else
    printf '+' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    echo "$placeholder"
  fi
}

check() {
  python3 "$D/render.py" --grants "$GRANTS"
  (cd "$ROOT" && go run ./cmd/jira-gateway -check -config "$OUT/config.json")
}

[ "$EXECUTE" = 1 ] || echo "# dry run: commands are printed, not run (add --execute to run them)" >&2

case "$STEP" in
check) check ;;
inventory)
  run gcloud run services describe "$N" --project "$P" --region "$R" --format='value(status.url,status.latestReadyRevisionName)' || true
  run gcloud iam service-accounts describe "$SA" --project "$P" --format='value(email)' || true
  run gcloud secrets list --project "$P" --filter="name ~ ^projects/.*/secrets/$N" --format='table(name.basename(),createTime)'
  run gcloud artifacts repositories describe "$N" --project "$P" --location "$R" --format='value(name)' || true
  ;;
image)
  [ -z "$(git -C "$ROOT" status --porcelain)" ] || {
    echo "image: working tree is not clean" >&2
    exit 1
  }
  tag=$(git -C "$ROOT" rev-parse --short=12 HEAD)
  if [ "$EXECUTE" = 1 ] && ! gcloud artifacts repositories describe "$N" --project "$P" --location "$R" >/dev/null 2>&1; then
    run gcloud artifacts repositories create "$N" --project "$P" --location "$R" --repository-format docker --labels "purpose=$N"
  elif [ "$EXECUTE" = 0 ]; then
    run gcloud artifacts repositories create "$N" --project "$P" --location "$R" --repository-format docker --labels "purpose=$N"
  fi
  run podman build --platform linux/amd64 -f "$ROOT/Containerfile" -t "$AR:$tag" "$ROOT"
  # gcloud signs the registry access through its credential helper; no token on the command line.
  A=$(mktemp)
  trap 'rm -f "$A"' EXIT
  printf '{"credHelpers":{"%s-docker.pkg.dev":"gcloud"}}' "$R" >"$A"
  mkdir -p "$OUT"
  run podman push --authfile "$A" --digestfile "$OUT/image-digest" "$AR:$tag"
  if [ "$EXECUTE" = 1 ]; then
    echo "image $AR@$(cat "$OUT/image-digest") ($tag)"
  fi
  ;;
sa)
  if [ "$EXECUTE" = 0 ] || ! gcloud iam service-accounts describe "$SA" --project "$P" >/dev/null 2>&1; then
    # Service accounts have no labels; the purpose goes in the description.
    run gcloud iam service-accounts create "$N" --project "$P" --display-name "Jira gateway (dev)" \
      --description "purpose=$N"
  else
    echo "service account $SA exists"
  fi
  ;;
secrets)
  check
  if [ "$EXECUTE" = 0 ] || ! gcloud secrets describe "$CONFIG_SECRET" --project "$P" >/dev/null 2>&1; then
    run gcloud secrets create "$CONFIG_SECRET" --project "$P" --replication-policy automatic --labels "purpose=$N"
  fi
  cur=$(capture "<newest-config-version>" gcloud secrets versions list "$CONFIG_SECRET" --project "$P" \
    --filter=state=ENABLED --sort-by=~createTime --limit 1 --format='value(name.basename())')
  T=$(mktemp)
  trap 'rm -f "$T"' EXIT
  if [ "$EXECUTE" = 1 ] && [ -n "$cur" ]; then
    gcloud secrets versions access "$cur" --secret "$CONFIG_SECRET" --project "$P" --out-file="$T"
  fi
  if [ "$EXECUTE" = 1 ] && [ -n "$cur" ] && cmp -s "$T" "$OUT/config.json"; then
    echo "config unchanged: version $cur"
  else
    run gcloud secrets versions add "$CONFIG_SECRET" --project "$P" --data-file="$OUT/config.json"
  fi
  for s in "$CONFIG_SECRET" "$READ_ID_SECRET" "$READ_SECRET_SECRET" "$WRITE_ID_SECRET" "$WRITE_SECRET_SECRET"; do
    run gcloud secrets add-iam-policy-binding "$s" --project "$P" \
      --member "serviceAccount:$SA" --role roles/secretmanager.secretAccessor --condition=None
  done
  ;;
deploy)
  digest=$(capture "sha256:<digest-from-image-step>" cat "$OUT/image-digest")
  # Each secret is mounted at its newest ENABLED version, pinned.
  mounts=""
  for pair in "config/config.json=$CONFIG_SECRET" "read-client-id/value=$READ_ID_SECRET" \
    "read-client-secret/value=$READ_SECRET_SECRET" "write-client-id/value=$WRITE_ID_SECRET" \
    "write-client-secret/value=$WRITE_SECRET_SECRET"; do
    s=${pair#*=}
    v=$(capture "<$s-version>" gcloud secrets versions list "$s" --project "$P" --filter=state=ENABLED \
      --sort-by=~createTime --limit 1 --format='value(name.basename())')
    [ -n "$v" ] || {
      echo "deploy: secret $s has no ENABLED version; create it first (see README)" >&2
      exit 1
    }
    mounts+="${mounts:+,}$MNT/${pair%%=*}=$s:$v"
  done
  # The gateway does its own authentication, so Cloud Run's invoker IAM check is off.
  run gcloud run deploy "$N" --project "$P" --region "$R" --image "$AR@$digest" \
    --service-account "$SA" --no-invoker-iam-check --ingress all \
    --port 8080 --max-instances "$MAX_INSTANCES" --min-instances "$MIN_INSTANCES" --concurrency "$CONCURRENCY" \
    --cpu "$CPU" --memory "$MEMORY" --cpu-throttling --labels "purpose=$N" \
    --set-env-vars "GOMEMLIMIT=$GOMEMLIMIT" \
    --set-secrets "$mounts"
  run gcloud run services update-traffic "$N" --project "$P" --region "$R" --to-latest
  ;;
post)
  url=$(capture "https://<service-url>" gcloud run services describe "$N" --project "$P" --region "$R" --format='value(status.url)')
  fail=0
  # expect checks a status code and one field of the JSON body (with jq),
  # not the whole body, so a new field in the answer does not break it.
  expect() { # name, status, jq filter that must print true, curl args...
    local name=$1 want=$2 test=$3
    shift 3
    if [ "$EXECUTE" = 0 ]; then
      run curl "$@"
      return
    fi
    local body code ok
    body=$(mktemp)
    code=$(curl -s --connect-timeout 10 --max-time 30 -o "$body" -w '%{http_code}' "$@")
    ok=$(jq -r "$test" <"$body" 2>/dev/null || echo false)
    if [ "$code" = "$want" ] && [ "$ok" = true ]; then echo "ok   $name: $code $(tr -d '\n' <"$body")"; else
      echo "FAIL $name: got $code $(tr -d '\n' <"$body" | head -c 200), want $want with $test" >&2
      fail=1
    fi
    rm -f "$body"
  }
  expect health 200 '.status == "ok"' "$url/healthz"
  expect "no token" 401 '.code == "unauthenticated"' "$url/ex/jira/x/rest/api/3/myself"
  expect "non-JWT bearer" 401 '.code == "unauthenticated"' -H 'authorization: Bearer not-a-jwt' "$url/ex/jira/x/rest/api/3/myself"
  st=$(capture '{}' gcloud run services describe "$N" --project "$P" --region "$R" --format=json)
  if [ "$EXECUTE" = 1 ]; then
    created=$(jq -r '.status.latestCreatedRevisionName // ""' <<<"$st")
    ready=$(jq -r '.status.latestReadyRevisionName // ""' <<<"$st")
    serving=$(jq -r --arg r "$created" '[.status.traffic[] | select(.revisionName == $r) | .percent] | add // 0' <<<"$st")
    if [ -n "$created" ] && [ "$created" = "$ready" ] && [ "$serving" = 100 ]; then
      echo "ok   revision $created ready, 100% traffic"
    else
      echo "FAIL revision created '$created' ready '$ready' serving $serving%" >&2
      fail=1
    fi
  fi
  exit $fail
  ;;
esac
