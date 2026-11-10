#!/usr/bin/env bash
# run.sh COMMAND ARGS...: `gcp.sh COMMAND ARGS...` on the test server, in the pinned gcloud CLI
# image, with IT_HOME at /it and the repository at /it/src (read-only).
#
# No GCP credential lives on this host: gcloud reads a one-hour access token of the test account
# (impersonated, narrow roles) from $IT_HOME/gcp/token, which the operator's machine writes and
# refreshes while a command runs:
#
#   gcloud auth print-access-token --configuration=<the test account's> |
#     ssh <user>@<test host> 'umask 077; cat > ~/eth-mpc-it/gcp/token.new && mv ~/eth-mpc-it/gcp/token.new ~/eth-mpc-it/gcp/token'
#
# The project's own values are in $IT_HOME/gcp/project.env, not in the repository (gcp.env).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
IT_HOME="${IT_HOME:-$HOME/eth-mpc-it}"
# shellcheck source=gcp.env
source "$here/gcp.env"
mkdir -p "$IT_HOME/gcp/config" "$IT_HOME/gcp/runs"
[ -s "$IT_HOME/gcp/token" ] || {
	echo "run.sh: no access token in $IT_HOME/gcp/token" >&2
	exit 2
}
exec docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp \
	-v "$IT_HOME:/it" -v "$repo:/it/src:ro" \
	-e CLOUDSDK_AUTH_ACCESS_TOKEN_FILE=/it/gcp/token \
	-e CLOUDSDK_CONFIG=/it/gcp/config \
	-e CLOUDSDK_CORE_PROJECT="$PROJECT" \
	-e CLOUDSDK_CORE_DISABLE_PROMPTS=1 \
	-w /it/src "$GCLOUD_IMAGE" bash /it/src/integration/tee/gcp/gcp.sh "$@"
