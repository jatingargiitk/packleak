#!/usr/bin/env bash
# End to end with a real bundler and the real npm publish list.
set -euo pipefail
work=$(mktemp -d)
cp -r examples/leaky/src "$work/src"
cd "$work"
cat > package.json <<'JSON'
{ "name": "bundled-demo", "version": "1.0.0", "main": "dist/index.js", "files": ["dist"],
  "scripts": { "prepublishOnly": "packleak --npm ." } }
JSON

npx -y esbuild@0.24.0 src/index.ts --bundle --platform=node --sourcemap --outfile=dist/index.js
set +e; packleak --npm .; rc=$?; set -e
[ "$rc" = 1 ] || { echo "expected exit 1 with --sourcemap, got $rc"; exit 1; }

echo "--- npm publish --dry-run must be stopped by prepublishOnly"
if out=$(npm publish --dry-run 2>&1); then echo "$out"; echo "publish was not blocked"; exit 1; fi
echo "$out"
grep -q "SOURCEMAP_CONTENT" <<<"$out" || { echo "publish failed, but not because of packleak"; exit 1; }

rm -rf dist
npx -y esbuild@0.24.0 src/index.ts --bundle --platform=node --outfile=dist/index.js
packleak --npm .
echo "bundler e2e ok"
