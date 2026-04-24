#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
TMP_DIR=$(mktemp -d)

echo "Creating temporary worktree at ${TMP_DIR}..."
git worktree add -f "${TMP_DIR}" HEAD

# Ensure cleanup on exit
cleanup() {
  echo "Cleaning up worktree..."
  git worktree remove -f "${TMP_DIR}" || true
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

# Move to worktree root
cd "${TMP_DIR}"

echo "Running code generation..."
./hack/gen-proto.sh

echo "Checking for differences..."
if ! git diff --exit-code; then
  echo "ERROR: Generated code is not up to date."
  echo "Please run ./hack/gen-proto.sh locally and commit the changes."
  exit 1
fi

echo "Generated code is up to date."
