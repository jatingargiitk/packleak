"""The checks. Each finding names the file, the rule, what leaks, and how to stop it."""
import base64
import json
import re

HIGH, WARN, INFO = "high", "warn", "info"
SEVERITY_ORDER = {INFO: 0, WARN: 1, HIGH: 2}

TEXT_EXT_SKIP = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf",
                 ".otf", ".eot", ".mp4", ".webm", ".mp3", ".wasm", ".so", ".dylib", ".dll",
                 ".node", ".pyc", ".gz", ".zip", ".br")

SECRET_PATTERNS = [
    ("AWS access key id", HIGH, re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", HIGH, re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained token", HIGH, re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b")),
    ("Stripe live secret key", HIGH, re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b")),
    ("Anthropic API key", HIGH, re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}")),
    ("OpenAI API key", HIGH, re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}")),
    ("OpenAI API key", HIGH, re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("Slack token", HIGH, re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("npm access token", HIGH, re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("PyPI upload token", HIGH, re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    ("private key block", HIGH, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("Google API key", WARN, re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
]

LOCAL_PATH = re.compile(r"(/Users/[^/\s\"']+/|/home/[^/\s\"']+/|[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s\"']+[\\/])")
MAPPING_URL = re.compile(r"[#@]\s*sourceMappingURL=([^\s*'\"]+)")
ENV_OK_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".schema")
KEY_FILES = ("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")
KEY_EXTS = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
VCS_DIRS = (".git", ".hg", ".svn")

FIX = {
    "SOURCEMAP_CONTENT": "don't ship this map: build with source maps off or 'hidden' and upload maps to your error tracker instead; or exclude *.map from the package",
    "INLINE_SOURCEMAP": "the map is inlined as a data: URL; switch the bundler from inline source maps to off/'hidden' for release builds",
    "SOURCEMAP_FILE": "the map has no embedded source but still exposes file names and points at your source; exclude *.map unless you publish maps on purpose",
    "EXTERNAL_SOURCEMAP": "the bundle tells browsers/devtools to fetch its map from this URL; make sure that URL isn't public, or strip the comment",
    "DANGLING_SOURCEMAP": "the referenced map isn't in the package; harmless, but strip the comment if the map is hosted somewhere public",
    "LOCAL_PATH": "build with relative source paths (e.g. sourceRoot/--sourcemap-root, or run the build in CI) so your username and home layout don't ship",
    "SECRET": "rotate this credential now (assume it is already copied), then remove it from the source and the build",
    "ENV_FILE": "env files hold real config; exclude it from the package and rotate anything in it that is secret",
    "KEY_FILE": "private key material; exclude it and rotate the key if it was ever published",
    "REGISTRY_TOKEN": "this config file holds a registry auth token; exclude it and revoke the token",
    "VCS_DIR": "a version-control directory ships your full history (including deleted secrets); exclude it",
}


class Finding(object):
    def __init__(self, severity, rule, path, detail, line=None, origin=None):
        self.severity = severity
        self.rule = rule
        self.path = path
        self.detail = detail
        self.line = line
        self.origin = origin  # for findings inside a source map's embedded source

    def where(self):
        loc = self.path
        if self.origin:
            loc += " -> " + self.origin
        if self.line:
            loc += ":%d" % self.line
        return loc

    def to_dict(self):
        return {
            "severity": self.severity,
            "rule": self.rule,
            "path": self.path,
            "origin": self.origin,
            "line": self.line,
            "detail": self.detail,
            "fix": FIX[self.rule],
        }


def mask(value):
    if len(value) <= 10:
        return value[:2] + "..."
    return "%s...%s (%d chars)" % (value[:6], value[-2:], len(value))


def _decode(data):
    if b"\x00" in data[:8192]:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")


def find_secrets(text, path, origin=None):
    out = []
    seen = set()
    for label, severity, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(0)
            if "EXAMPLE" in value or (m.start(), label) in seen:
                continue
            seen.add((m.start(), label))
            line = text.count("\n", 0, m.start()) + 1
            detail = "%s %s" % (label, mask(value) if "PRIVATE KEY" not in value else "")
            if label == "Google API key":
                detail += "; browser keys are often public by design, check it is restricted by referrer/API"
            out.append(Finding(severity, "SECRET", path, detail.strip(), line=line, origin=origin))
    return out


def _clean_source_name(name, source_root=""):
    name = (source_root or "") + (name or "")
    for prefix in ("webpack:///", "webpack://", "file://"):
        if name.startswith(prefix):
            name = name[len(prefix):]
    return name


def _is_third_party(name):
    return "node_modules/" in name or name.startswith(("webpack/", "(webpack)"))


def analyze_map(raw_text, path, inline_in=None):
    """Findings for one source map (a .map file, or an inline data: map inside `inline_in`)."""
    out = []
    try:
        sm = json.loads(raw_text)
    except ValueError:
        return out
    if not isinstance(sm, dict):
        return out
    if "sections" in sm and isinstance(sm["sections"], list):
        for sec in sm["sections"]:
            if isinstance(sec, dict) and isinstance(sec.get("map"), dict):
                out.extend(analyze_map(json.dumps(sec["map"]), path, inline_in))
        return out
    sources = sm.get("sources") or []
    contents = sm.get("sourcesContent") or []
    root = sm.get("sourceRoot") or ""
    if not isinstance(sources, list):
        return out
    names = [_clean_source_name(s if isinstance(s, str) else "", root) for s in sources]

    first, third = [], []
    for i, name in enumerate(names):
        body = contents[i] if i < len(contents) else None
        if not isinstance(body, str):
            continue
        (third if _is_third_party(name) else first).append((name, body))

    rule = "INLINE_SOURCEMAP" if inline_in else "SOURCEMAP_CONTENT"
    if first:
        lines = sum(b.count("\n") + 1 for _, b in first)
        shown = ", ".join(n for n, _ in first[:3]) + (", ..." if len(first) > 3 else "")
        detail = "embeds the original source of %d file%s (%d lines): %s" % (
            len(first), "" if len(first) == 1 else "s", lines, shown)
        if third:
            detail += " (+%d third-party)" % len(third)
        out.append(Finding(HIGH, rule, path, detail))
    elif third:
        out.append(Finding(WARN, rule, path, "embeds the source of %d third-party file%s only (node_modules)"
                           % (len(third), "" if len(third) == 1 else "s")))
    elif not inline_in and sources:
        out.append(Finding(WARN, "SOURCEMAP_FILE", path, "lists %d original source file%s (no embedded source)"
                           % (len(sources), "" if len(sources) == 1 else "s")))

    for name, body in first + third:
        out.extend(find_secrets(body, path, origin=name))

    local = set()
    for name in names + [root]:
        m = LOCAL_PATH.search(name or "")
        if m:
            local.add(m.group(1))
    if local:
        out.append(Finding(WARN, "LOCAL_PATH", path, "source paths reveal a local home directory: %s"
                           % ", ".join(sorted(local))))
    return out


def _check_mapping_url(text, path, present):
    out = []
    for m in MAPPING_URL.finditer(text):
        url = m.group(1)
        line = text.count("\n", 0, m.start()) + 1
        if url.startswith("data:"):
            head, _, payload = url.partition(",")
            try:
                raw = base64.b64decode(payload + "===") if ";base64" in head else payload.encode()
                found = analyze_map(raw.decode("utf-8", "replace"), path, inline_in=path)
            except (ValueError, TypeError):
                found = []
            for f in found:
                if f.line is None and f.origin is None:
                    f.line = line
            out.extend(found)
        elif url.startswith(("http://", "https://", "//")):
            out.append(Finding(WARN, "EXTERNAL_SOURCEMAP", path, "sourceMappingURL points at %s" % url, line=line))
        else:
            base = path.rsplit("/", 1)[0] + "/" if "/" in path else ""
            target = _normalize(base + url.split("?")[0].split("#")[0])
            if target not in present:
                out.append(Finding(INFO, "DANGLING_SOURCEMAP", path,
                                   "references %s, which is not in the package" % url, line=line))
    return out


def _normalize(path):
    parts = []
    for p in path.split("/"):
        if p in ("", "."):
            continue
        if p == "..":
            if parts:
                parts.pop()
            continue
        parts.append(p)
    return "/".join(parts)


def check_name(path):
    """Findings that follow from the file name alone."""
    parts = path.split("/")
    name = parts[-1]
    lower = name.lower()
    for d in parts[:-1]:
        if d in VCS_DIRS:
            return [Finding(HIGH, "VCS_DIR", path, "file inside a %s/ directory" % d)]
    if (lower == ".env" or lower.startswith(".env.")) and not lower.endswith(ENV_OK_SUFFIXES):
        return [Finding(HIGH, "ENV_FILE", path, "environment file %s" % name)]
    if lower in KEY_FILES:
        return [Finding(HIGH, "KEY_FILE", path, "SSH private key file %s" % name)]
    if lower.endswith(KEY_EXTS):
        return [Finding(WARN, "KEY_FILE", path, "key/certificate container %s (check it holds no private key)" % name)]
    return []


def _parses_as_map(text):
    try:
        sm = json.loads(text)
    except ValueError:
        return False
    return isinstance(sm, dict) and ("sources" in sm or "sections" in sm)


def scan(entries):
    findings = []
    present = set(e.path for e in entries)
    for e in entries:
        named = check_name(e.path)
        findings.extend(named)
        lower = e.path.lower()
        if lower.endswith(TEXT_EXT_SKIP):
            continue
        data = e.read()
        if data is None:
            continue
        text = _decode(data)
        if text is None:
            continue
        base = lower.rsplit("/", 1)[-1]
        if base in (".npmrc", ".yarnrc", ".yarnrc.yml", ".pypirc"):
            if re.search(r"(_authToken|_auth|npmAuthToken|password)\s*[=:]\s*\S", text):
                findings.append(Finding(HIGH, "REGISTRY_TOKEN", e.path, "%s contains a registry credential" % base))
        is_map = lower.endswith(".map") and _parses_as_map(text)
        # a parsed map's embedded sources are scanned per source file (with origin) below
        secrets = [] if is_map else find_secrets(text, e.path)
        if any(f.rule == "KEY_FILE" for f in named):
            for f in named:
                if f.rule == "KEY_FILE" and any("private key" in s.detail for s in secrets):
                    f.severity = HIGH
                    f.detail = "%s holds a private key" % e.path.rsplit("/", 1)[-1]
            secrets = [s for s in secrets if "private key" not in s.detail]
        findings.extend(secrets)
        if is_map:
            findings.extend(analyze_map(text, e.path))
        elif lower.endswith((".js", ".mjs", ".cjs", ".css", ".jsx", ".ts")):
            findings.extend(_check_mapping_url(text, e.path, present))
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.path, f.origin or "", f.line or 0))
    return findings
