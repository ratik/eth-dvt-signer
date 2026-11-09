#!/usr/bin/env bash
# Check a real anchor bucket's WORM behaviour (docs/anchor.md), then read it with mpc-admin.
#
#   integration/anchor/check.sh s3://bucket/prefix [cluster-id]
#   integration/anchor/check.sh gs://bucket/prefix [cluster-id]
#
# Needs the provider's CLI (aws or gcloud) with credentials of a node's role (put, get, list): it
# writes one probe object under <prefix>/check/ (retained like any record), then checks that the
# object cannot be overwritten, that a create-only write over it is refused, and that it cannot be
# deleted. With a cluster id it also runs `mpc-admin anchor check`. It never deletes anything that
# the bucket allows to be deleted: a delete that succeeds is the failure it reports.
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
trap 'rm -f "$body"' EXIT
echo "anchor probe $(date -u +%FT%TZ)" >"$body"

failures=0
pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }

case "$scheme" in
s3)
	echo "== bucket configuration"
	aws s3api get-object-lock-configuration --bucket "$bucket" || fail "no Object Lock configuration"
	aws s3api get-bucket-policy --bucket "$bucket" --query Policy --output text || fail "no bucket policy (deletes must be denied)"
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
echo "$failures failure(s)"
[ "$failures" -eq 0 ]
