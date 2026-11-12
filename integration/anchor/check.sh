#!/usr/bin/env bash
# Check a real anchor bucket's WORM behaviour (docs/anchor.md), then read it with mpc-admin.
#
#   integration/anchor/check.sh s3://bucket/prefix [cluster-id]
#   integration/anchor/check.sh gs://bucket/prefix [cluster-id]
#
# Needs the provider's CLI (aws or gcloud) and python3, with credentials of a node's role (put,
# get, list): it writes one probe object under <prefix>/check/ (retained like any record), then
# checks that the object cannot be overwritten, that a create-only write over it is refused, and
# that it cannot be deleted. With a cluster id it also runs `mpc-admin anchor check`. It never
# deletes anything that the bucket allows to be deleted: a delete that succeeds is the failure it
# reports.
#
# It also reads the bucket's lifecycle rules: a policy that denies new rules leaves a rule set
# before it running. A rule that expires records (S3: delete markers over them; GCS: deleted once
# retention ends) or moves them to a class read only after a restore (S3 Glacier, Deep Archive)
# fails. A setting these credentials cannot read is reported UNCHECKED: check it as the bucket's
# owner.
set -euo pipefail

location="${1:?usage: check.sh s3://bucket/prefix|gs://bucket/prefix [cluster-id]}"
cluster="${2:-}"
scheme="${location%%://*}"
rest="${location#*://}"
bucket="${rest%%/*}"
prefix="${rest#"$bucket"}"
prefix="${prefix#/}"
probe="${prefix:+$prefix/}check/probe-$(date -u +%Y%m%dT%H%M%SZ)-$$"
body="$(mktemp)"
errors="$(mktemp)"
trap 'rm -f "$body" "$errors"' EXIT
echo "anchor probe $(date -u +%FT%TZ)" >"$body"

failures=0
unchecked=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }
unchecked() { echo "UNCHECKED $*"; unchecked=$((unchecked + 1)); }

# lifecycle PROVIDER: the lifecycle configuration (JSON) on stdin; one line per rule that hides,
# deletes or archives records, nothing if none does.
lifecycle() {
	python3 -I -c '
import json, sys
provider, config = sys.argv[1], json.load(sys.stdin)
archived = {"GLACIER", "DEEP_ARCHIVE"}  # read only after a restore
if provider == "s3":
    for rule in config.get("Rules", []):
        if rule.get("Status") != "Enabled":
            continue
        name = rule.get("ID", "(no ID)")
        if "Expiration" in rule and set(rule["Expiration"]) - {"ExpiredObjectDeleteMarker"}:
            print(f"rule {name}: expires records (delete markers hide them)")
        for transition in rule.get("Transitions", []):
            if transition.get("StorageClass") in archived:
                print(f"rule {name}: moves records to {transition["StorageClass"]} (read only after a restore)")
else:
    lifecycle = config.get("lifecycle_config") or config.get("lifecycle") or {}
    for rule in lifecycle.get("rule", []):
        if rule.get("action", {}).get("type") == "Delete":
            print(f"rule {json.dumps(rule.get("condition", {}))}: deletes records once retention ends")
' "$1"
}

# rules_found PROVIDER CONFIG CLEAN: a FAIL per rule of CONFIG (JSON) that hides, deletes or
# archives records, else PASS CLEAN; UNCHECKED if CONFIG does not parse.
rules_found() {
	local found line
	if ! found="$(printf '%s' "$2" | lifecycle "$1" 2>"$errors")"; then
		unchecked "lifecycle rules: an answer that does not parse ($(head -c 200 "$errors"))"
	elif [ -n "$found" ]; then
		while IFS= read -r line; do fail "$line"; done <<<"$found"
	else
		pass "$3"
	fi
}

case "$scheme" in
s3)
	echo "== bucket configuration"
	aws s3api get-object-lock-configuration --bucket "$bucket" || fail "no Object Lock configuration"
	if policy="$(aws s3api get-bucket-policy --bucket "$bucket" --query Policy --output text)"; then
		echo "$policy"
		if printf '%s' "$policy" | python3 -I -c '
import json, sys
statements = json.load(sys.stdin).get("Statement", [])
statements = statements if isinstance(statements, list) else [statements]
def listed(value):
    return value if isinstance(value, list) else [value]
denied = any(s.get("Effect") == "Deny" and s.get("Principal") in ("*", {"AWS": "*"})
             and any(a in ("s3:PutLifecycleConfiguration", "s3:*") for a in listed(s.get("Action", [])))
             for s in statements)
sys.exit(0 if denied else 1)'; then
			pass "the policy denies new lifecycle rules to everyone"
		else
			fail "the policy does not deny s3:PutLifecycleConfiguration to everyone (docs/anchor.md)"
		fi
	else
		fail "no bucket policy (deletes and lifecycle rules must be denied)"
	fi
	echo "== lifecycle"
	if rules="$(aws s3api get-bucket-lifecycle-configuration --bucket "$bucket" --output json 2>"$errors")"; then
		rules_found s3 "$rules" "no lifecycle rule hides, deletes or archives records"
	elif grep -q NoSuchLifecycleConfiguration "$errors"; then
		pass "no lifecycle rules"
	else
		unchecked "lifecycle rules (s3:GetLifecycleConfiguration): $(tr '\n' ' ' <"$errors")"
	fi
	echo "== create-only write"
	aws s3api put-object --bucket "$bucket" --key "$probe" --body "$body" \
		--if-none-match '*' --checksum-algorithm SHA256 >/dev/null && pass "first write" || fail "first write"
	if aws s3api put-object --bucket "$bucket" --key "$probe" --body "$body" \
		--if-none-match '*' --checksum-algorithm SHA256 >/dev/null 2>&1; then
		fail "a second create-only write at the same key succeeded"
	else
		pass "a second create-only write is refused"
	fi
	aws s3api head-object --bucket "$bucket" --key "$probe" \
		--query '{mode: ObjectLockMode, until: ObjectLockRetainUntilDate}' || fail "head"
	echo "== deletes"
	if aws s3api delete-object --bucket "$bucket" --key "$probe" >/dev/null 2>&1; then
		fail "a delete (delete marker) succeeded: the bucket policy must deny s3:DeleteObject"
	else
		pass "a delete is refused"
	fi
	version="$(aws s3api list-object-versions --bucket "$bucket" --prefix "$probe" \
		--query 'Versions[0].VersionId' --output text)"
	if aws s3api delete-object --bucket "$bucket" --key "$probe" --version-id "$version" >/dev/null 2>&1; then
		fail "a version delete succeeded: retention is not in compliance mode"
	else
		pass "a version delete is refused"
	fi
	;;
gs)
	echo "== bucket configuration"
	gcloud storage buckets describe "gs://$bucket" --format='yaml(retention_policy,versioning_enabled)' ||
		fail "describe"
	echo "== lifecycle"
	if config="$(gcloud storage buckets describe "gs://$bucket" --format=json 2>"$errors")"; then
		rules_found gs "$config" "no lifecycle rule deletes records (another storage class is still read at once)"
	else
		unchecked "lifecycle rules (storage.buckets.get): $(tr '\n' ' ' <"$errors")"
	fi
	echo "== create-only write"
	gcloud storage cp --if-generation-match=0 "$body" "gs://$bucket/$probe" && pass "first write" || fail "first write"
	if gcloud storage cp --if-generation-match=0 "$body" "gs://$bucket/$probe" >/dev/null 2>&1; then
		fail "a second create-only write at the same key succeeded"
	else
		pass "a second create-only write is refused"
	fi
	if gcloud storage cp "$body" "gs://$bucket/$probe" >/dev/null 2>&1; then
		fail "an overwrite succeeded: no retention policy"
	else
		pass "an overwrite is refused"
	fi
	echo "== deletes"
	if gcloud storage rm "gs://$bucket/$probe" >/dev/null 2>&1; then
		fail "a delete succeeded: no retention policy"
	else
		pass "a delete is refused"
	fi
	;;
*)
	echo "s3:// or gs:// only" >&2
	exit 2
	;;
esac

if [ -n "$cluster" ]; then
	echo "== records"
	cargo run --quiet --bin mpc-admin -- anchor check --anchor "$location" --cluster "$cluster"
fi
echo "$failures failure(s), $unchecked unchecked"
[ "$failures" -eq 0 ]
