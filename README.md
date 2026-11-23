# packleak

See what your npm package, wheel or build folder would leak **before** you publish or deploy it.

A `.map` file with `sourcesContent` hands out your original source to anyone who downloads the package. An `.env` that slipped past `.npmignore` ships your config. packleak looks at the exact set of files that would ship and lists what shouldn't be there, with the file, the line, and the fix. It exits 1 when it finds something.

- **`--npm DIR`** asks npm for the real publish list (`npm pack --dry-run --json --ignore-scripts`), so `files`, `.npmignore` and `.gitignore` rules are applied exactly as npm applies them.
- Also reads a build directory (a `dist/` you're about to deploy), an npm `.tgz`, a wheel or sdist, or any zip.
- Python 3.9+, no dependencies. Read-only: it never uploads, fetches or changes anything.

```console
$ packleak --npm examples/leaky
packleak: 6 files from npm pack file list of examples/leaky
HIGH  ENV_FILE           .env
      environment file .env
      fix: use a "files" allowlist in package.json instead of relying on .npmignore
HIGH  SOURCEMAP_CONTENT  dist/index.js.map
      embeds the original source of 1 file (3 lines): ../src/index.ts
      fix: add "!**/*.map" to "files" in package.json (or "*.map" to .npmignore)
2 high, 0 warn, 0 info -> exit 1
```

The same package with `"files": ["dist", "!**/*.map"]` in `package.json` (the `.env` is still sitting in the folder, it just isn't packed any more):

```console
$ packleak --npm examples/fixed
packleak: 3 files from npm pack file list of examples/fixed
0 high, 0 warn, 0 info -> exit 0
```

## Install

Not on PyPI. Install from GitHub:

```sh
pip install git+https://github.com/jatingargiitk/packleak
```

## What it checks

| Rule | Severity | What it means |
|---|---|---|
| `SOURCEMAP_CONTENT` | high (warn if only `node_modules` sources) | a `.map` file embeds original source in `sourcesContent` |
| `INLINE_SOURCEMAP` | high / warn | same, but the map is inlined in a `.js`/`.css` as a `data:` URL |
| `SOURCEMAP_FILE` | warn | a `.map` ships without embedded source (still exposes file names and structure) |
| `EXTERNAL_SOURCEMAP` | warn | a bundle's `sourceMappingURL` points at an http(s) URL |
| `DANGLING_SOURCEMAP` | info | a `sourceMappingURL` points at a map that isn't in the package |
| `LOCAL_PATH` | warn | source paths in a map reveal a home directory (`/Users/you/`, `/home/you/`, `C:\Users\you\`) |
| `SECRET` | high (Google API keys: warn) | AWS key ids, GitHub, Stripe live, OpenAI, Anthropic, Slack, npm and PyPI tokens, private key blocks; values are masked in the output |
| `ENV_FILE` | high | `.env`, `.env.production`, ... (`.env.example`, `.sample`, `.template` are fine) |
| `KEY_FILE` | high / warn | `id_rsa`/`id_ed25519`; `.pem`/`.key`/`.p12` (high when it holds a private key) |
| `REGISTRY_TOKEN` | high | `.npmrc`, `.yarnrc(.yml)` or `.pypirc` with an auth token or password |
| `VCS_DIR` | high | anything inside `.git/`, `.hg/` or `.svn/` |

Secrets are also searched inside each map's embedded sources and reported against the original file, because code the bundler tree-shook away still ships in `sourcesContent`.

## A build folder you're about to deploy

```console
$ packleak examples/site
packleak: 2 files from directory examples/site
HIGH  SOURCEMAP_CONTENT  app.js.map
      embeds the original source of 1 file (2 lines): /Users/dev/work/site/src/app.ts
      fix: don't ship this map: build with source maps off or 'hidden' and upload maps to your error tracker instead; or exclude *.map from the package
WARN  LOCAL_PATH         app.js.map
      source paths reveal a local home directory: /Users/dev/
      fix: build with relative source paths (e.g. sourceRoot/--sourcemap-root, or run the build in CI) so your username and home layout don't ship
1 high, 1 warn, 0 info -> exit 1
```

When scanning a directory, `node_modules/` is skipped. Use `--npm` to scan exactly what npm would publish.

## Shipping something on purpose

`--allow [RULE:]GLOB` ignores findings for matching files (repeatable). The same lines can go in a `.packleakignore` file in the scanned directory, or in any file passed with `--allow-file`.

```console
$ packleak examples/site --allow SOURCEMAP_CONTENT:*.map
packleak: 2 files from directory examples/site
WARN  LOCAL_PATH         app.js.map
      source paths reveal a local home directory: /Users/dev/
      fix: build with relative source paths (e.g. sourceRoot/--sourcemap-root, or run the build in CI) so your username and home layout don't ship
0 high, 1 warn, 0 info, 1 allowed -> exit 0
```

`--fail-on warn` (or `info`) makes lower severities fail too, and `--fail-on never` only reports. `-q` prints only the findings that fail the run.

## JSON

```console
$ packleak --npm examples/leaky --json
{
  "target": "examples/leaky",
  "source": "npm pack file list of examples/leaky",
  "files_scanned": 6,
  "counts": {
    "high": 2,
    "warn": 0,
    "info": 0
  },
  "ignored": 0,
  "findings": [
    {
      "severity": "high",
      "rule": "ENV_FILE",
      "path": ".env",
      "origin": null,
      "line": null,
      "detail": "environment file .env",
      "fix": "use a \"files\" allowlist in package.json instead of relying on .npmignore"
    },
    {
      "severity": "high",
      "rule": "SOURCEMAP_CONTENT",
      "path": "dist/index.js.map",
      "origin": null,
      "line": null,
      "detail": "embeds the original source of 1 file (3 lines): ../src/index.ts",
      "fix": "add \"!**/*.map\" to \"files\" in package.json (or \"*.map\" to .npmignore)"
    }
  ]
}
```

Each finding has `severity`, `rule`, `path`, `origin` (the original source file, for findings inside a map), `line`, `detail` and `fix`.

## Blocking a bad publish

Run it from `prepublishOnly`, so `npm publish` stops when packleak exits 1:

```json
{
  "scripts": {
    "prepublishOnly": "packleak --npm ."
  }
}
```

Or as a CI step before the publish step: `packleak --npm .` for npm, `packleak dist/*.whl` for a Python wheel.

Exit codes: `0` nothing at or above `--fail-on`, `1` something is, `2` bad input (missing path, not an archive, `npm pack` failed).

## Limits

- The secret patterns are a short list of high-confidence token formats. They aren't a replacement for a full scanner like gitleaks or trufflehog, and generic passwords in config won't be found.
- It doesn't fetch external source maps or anything else over the network.
- It reads files up to 20 MB and skips binary files and common image, font and media types.

## License

MIT
