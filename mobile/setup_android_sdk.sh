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

set -euo pipefail

SDK_DIR="$HOME/Android/Sdk"
mkdir -p "$SDK_DIR"

echo "==> 1. Downloading Android SDK Command-line Tools..."
TEMP_ZIP=$(mktemp /tmp/cmdline-tools-XXXXXX.zip)
curl -sS -L -o "$TEMP_ZIP" "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"

echo "==> 2. Installing Command-line Tools..."
mkdir -p "$SDK_DIR/cmdline-tools"
unzip -q -o "$TEMP_ZIP" -d "$SDK_DIR/cmdline-tools"
rm -rf "$SDK_DIR/cmdline-tools/latest"
mv "$SDK_DIR/cmdline-tools/cmdline-tools" "$SDK_DIR/cmdline-tools/latest"
rm -f "$TEMP_ZIP"

echo "==> 3. Accepting Android Licenses..."
export PATH="$PATH:$SDK_DIR/cmdline-tools/latest/bin"
yes | sdkmanager --sdk_root="$SDK_DIR" --licenses >/dev/null

echo "==> 4. Installing Android NDK (26.1.10909125) and platform tools..."
sdkmanager --sdk_root="$SDK_DIR" "ndk;26.1.10909125" "platform-tools" "platforms;android-34"

echo "==> 5. Confirming Android Licenses via Flutter..."
yes | flutter doctor --android-licenses || true

echo "==> 6. Verifying installation status..."
flutter doctor

echo "=========================================================="
echo "Android SDK and NDK setup completed successfully!"
echo "Please restart your IDE or terminal to load the new paths."
echo "=========================================================="
