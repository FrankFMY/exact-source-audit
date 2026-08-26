#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

expected_tag="v$(node -p 'require("./package.json").version')"
current_tag=$(git describe --tags --exact-match HEAD 2>/dev/null || true)
[[ "$current_tag" == "$expected_tag" ]] || { echo "Bootstrap must run from exact tag $expected_tag" >&2; exit 1; }
[[ -z $(git status --porcelain) ]] || { echo "Bootstrap requires a clean tagged checkout" >&2; exit 1; }
[[ $(npm whoami --registry=https://registry.npmjs.org/) == frankfmy ]] || { echo "Expected npm user frankfmy" >&2; exit 1; }

package_name=$(node -p 'require("./package.json").name')
package_version=$(node -p 'require("./package.json").version')
encoded_name=${package_name/\//%2F}
http_code=$(curl -sS -o /dev/null -w '%{http_code}' "https://registry.npmjs.org/$encoded_name")
[[ "$http_code" == 404 ]] || { echo "$package_name registry preflight HTTP $http_code" >&2; exit 1; }

bun install --frozen-lockfile
bun run verify
package_file=$(npm pack --silent)
trap 'rm -f -- "$package_file"' EXIT
npm publish "$package_file" --access public --registry=https://registry.npmjs.org/
published=$(npm view "$package_name@$package_version" version --json --registry=https://registry.npmjs.org/)
published_version=$(node -e 'const value = JSON.parse(process.argv[1]); if (typeof value !== "string") process.exit(1); process.stdout.write(value);' "$published")
[[ "$published_version" == "$package_version" ]] || { echo "Registry readback failed" >&2; exit 1; }
printf '%s@%s bootstrap publication verified\n' "$package_name" "$package_version"
