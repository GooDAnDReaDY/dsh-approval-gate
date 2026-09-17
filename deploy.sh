#!/usr/bin/env bash
set -euo pipefail

version=${1:?usage: ./deploy.sh <exact-version>}
dsh plugin --profile web remove @goodandready-private/dsh-approval-gate
dsh plugin --profile web add @goodandready/dsh-approval-gate@"$version"
sudo systemctl restart dsh-web.service
sudo systemctl is-active --quiet dsh-web.service
