#!/usr/bin/env bash
# One-time setup of Play release signing for a GitHub repo. Run it yourself, on your own machine:
# the keystore and its passwords are generated here and go straight to GitHub, never through anyone else's session.
#
#   android/tools/setup-release.sh OWNER/REPO TAG_PATTERN [KEY_ALIAS]
#   e.g.  android/tools/setup-release.sh nodetide/nodetide 'android-v*'
#
# Creates an UPLOAD key (Play App Signing keeps the real app signing key; a lost or leaked upload key can be reset in the Play Console).
# - secrets in the "production" environment: UPLOAD_KEYSTORE_BASE64, UPLOAD_KEYSTORE_PASSWORD, UPLOAD_KEY_PASSWORD
# - variables (not secret): UPLOAD_KEY_ALIAS, UPLOAD_CERT_SHA256 (the release job refuses to publish if the key does not match it)
# - the "production" environment itself: you as required reviewer, deployable from tags matching TAG_PATTERN only
set -euo pipefail

repo=${1:?usage: setup-release.sh OWNER/REPO TAG_PATTERN [KEY_ALIAS]}
tags=${2:?usage: setup-release.sh OWNER/REPO TAG_PATTERN [KEY_ALIAS]}
alias=${3:-upload}
dir=${KEYSTORE_DIR:-$HOME/.android-upload-keys/${repo//\//_}}

command -v keytool >/dev/null || { echo "keytool (a JDK) is required" >&2; exit 1; }
command -v gh >/dev/null || { echo "the GitHub CLI (gh) is required, and must be logged in" >&2; exit 1; }
[ ! -e "$dir/upload.jks" ] || { echo "$dir/upload.jks already exists; refusing to overwrite a key. Move it away first." >&2; exit 1; }

mkdir -p "$dir"; chmod 700 "$dir"
store_pw=$(openssl rand -base64 24 | tr -d '/+=\n')
key_pw=$store_pw   # a PKCS12 keystore has one password for both

STORE_PW=$store_pw keytool -genkeypair -keystore "$dir/upload.jks" -storetype PKCS12 \
  -alias "$alias" -keyalg RSA -keysize 4096 -validity 10000 -dname "CN=$repo upload key" \
  -storepass:env STORE_PW
chmod 600 "$dir/upload.jks"

fingerprint=$(STORE_PW=$store_pw keytool -list -v -keystore "$dir/upload.jks" -alias "$alias" -storepass:env STORE_PW \
  | sed -n 's/^[[:space:]]*SHA256: *//p' | tr -d ':' | tr 'A-F' 'a-f')
STORE_PW=$store_pw keytool -exportcert -rfc -keystore "$dir/upload.jks" -alias "$alias" -storepass:env STORE_PW -file "$dir/upload-cert.pem"

[ ${#fingerprint} -eq 64 ] || { echo "could not read the certificate fingerprint" >&2; exit 1; }
umask 077
printf 'repo: %s\nalias: %s\npassword (keystore and key): %s\nSHA-256: %s\n' "$repo" "$alias" "$store_pw" "$fingerprint" > "$dir/passwords.txt"

# the environment: reviewer = you, tags only
uid=$(gh api user -q .id)
gh api -X PUT "repos/$repo/environments/production" --input - >/dev/null <<JSON
{"reviewers":[{"type":"User","id":$uid}],"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
gh api -X POST "repos/$repo/environments/production/deployment-branch-policies" -f name="$tags" -f type=tag >/dev/null \
  || echo "(tag rule for $tags exists already, or could not be added)"

base64 < "$dir/upload.jks" | tr -d '\n' | gh secret set UPLOAD_KEYSTORE_BASE64 -R "$repo" --env production
printf %s "$store_pw" | gh secret set UPLOAD_KEYSTORE_PASSWORD -R "$repo" --env production
printf %s "$key_pw" | gh secret set UPLOAD_KEY_PASSWORD -R "$repo" --env production
gh variable set UPLOAD_KEY_ALIAS -R "$repo" --env production --body "$alias"
gh variable set UPLOAD_CERT_SHA256 -R "$repo" --env production --body "$fingerprint"

cat <<MSG

Done. Upload key certificate SHA-256: $fingerprint
Keep $dir/upload.jks and $dir/passwords.txt in your password manager NOW; GitHub secrets cannot be read back,
so this is the only copy of the key that you control. Then delete or keep them off any synced/backed-up folder as you see fit.

Next, once (Google Play Console): create the app, enrol in Play App Signing, and upload the first release by hand
(the API cannot create an app or accept its very first bundle). For automatic uploads later:
  gh variable set PLAY_UPLOAD --body true -R $repo        # turns on the upload step
  gh secret set PLAY_SERVICE_ACCOUNT_JSON -R $repo --env production < service-account.json
  (the service account: Play Console > Users and permissions, release-manager rights for this app only)
MSG
