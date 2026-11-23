import base64
import io
import json
import os
import tarfile
import zipfile

import pytest

from packleak.cli import main
from packleak.scan import analyze_map, check_name, find_secrets, mask, scan
from packleak.sources import Entry, load, strip_common_root

from fakes import AWS, AWS_DOC, GITHUB, GOOGLE, OPENAI, PEM, STRIPE


def entries(files):
    return [Entry(p, len(b), (lambda b=b: b)) for p, b in
            ((p, c.encode() if isinstance(c, str) else c) for p, c in files.items())]


def rules(findings):
    return sorted((f.severity, f.rule, f.path) for f in findings)


def smap(sources, contents=None, root=None):
    d = {"version": 3, "sources": sources, "mappings": "AAAA"}
    if contents is not None:
        d["sourcesContent"] = contents
    if root is not None:
        d["sourceRoot"] = root
    return json.dumps(d)


def write_tree(root, files):
    for p, c in files.items():
        full = os.path.join(str(root), p)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(c.encode() if isinstance(c, str) else c)


# ---- source maps -----------------------------------------------------------

def test_map_with_first_party_source_is_high():
    f = analyze_map(smap(["../src/a.ts", "../src/b.ts"], ["x\ny\n", "z"]), "dist/a.js.map")
    assert [(x.severity, x.rule) for x in f] == [("high", "SOURCEMAP_CONTENT")]
    assert "2 files (3 lines)" in f[0].detail
    assert "../src/a.ts, ../src/b.ts" in f[0].detail


def test_map_with_only_node_modules_source_is_warn():
    f = analyze_map(smap(["../node_modules/lodash/index.js"], ["module.exports=1"]), "a.map")
    assert [(x.severity, x.rule) for x in f] == [("warn", "SOURCEMAP_CONTENT")]


def test_map_counts_third_party_separately():
    f = analyze_map(smap(["webpack:///./src/app.js", "webpack:///./node_modules/x/y.js"], ["a", "b"]), "m.map")
    assert "1 file (1 lines): ./src/app.js (+1 third-party)" in f[0].detail


def test_map_without_content_is_sourcemap_file():
    f = analyze_map(smap(["../src/a.ts"]), "a.js.map")
    assert [(x.severity, x.rule) for x in f] == [("warn", "SOURCEMAP_FILE")]


def test_map_null_contents_are_not_counted():
    f = analyze_map(smap(["../src/a.ts", "../src/b.ts"], [None, None]), "a.js.map")
    assert [x.rule for x in f] == ["SOURCEMAP_FILE"]


def test_secret_inside_embedded_source_has_origin_and_line():
    src = "const a = 1;\nconst key = '%s';\n" % STRIPE
    f = analyze_map(smap(["../src/pay.ts"], [src]), "dist/pay.js.map")
    sec = [x for x in f if x.rule == "SECRET"]
    assert len(sec) == 1
    assert sec[0].where() == "dist/pay.js.map -> ../src/pay.ts:2"
    assert STRIPE not in sec[0].detail


def test_local_home_paths_in_sources():
    f = analyze_map(smap(["/Users/alice/code/app/src/a.ts", "C:\\Users\\bob\\x\\b.ts"]), "a.map")
    lp = [x for x in f if x.rule == "LOCAL_PATH"]
    assert lp and "/Users/alice/" in lp[0].detail and "C:\\Users\\bob\\" in lp[0].detail


def test_local_path_in_source_root():
    f = analyze_map(smap(["a.ts"], root="/home/carol/proj/"), "a.map")
    assert any(x.rule == "LOCAL_PATH" and "/home/carol/" in x.detail for x in f)


def test_indexed_map_sections():
    inner = json.loads(smap(["../src/a.ts"], ["code"]))
    d = {"version": 3, "sections": [{"offset": {"line": 0, "column": 0}, "map": inner}]}
    f = analyze_map(json.dumps(d), "a.map")
    assert [x.rule for x in f] == ["SOURCEMAP_CONTENT"]


def test_invalid_map_json_is_ignored():
    assert analyze_map("not json", "a.map") == []


def test_inline_data_url_map_is_detected():
    m = smap(["../src/a.ts"], ["secret logic"])
    js = "console.log(1);\n//# sourceMappingURL=data:application/json;base64,%s\n" % base64.b64encode(m.encode()).decode()
    f = scan(entries({"dist/a.js": js}))
    assert [(x.severity, x.rule, x.line) for x in f] == [("high", "INLINE_SOURCEMAP", 2)]


def test_external_sourcemap_url_is_warn():
    f = scan(entries({"a.js": "x\n//# sourceMappingURL=https://cdn.example.com/a.js.map\n"}))
    assert [(x.severity, x.rule) for x in f] == [("warn", "EXTERNAL_SOURCEMAP")]


def test_dangling_relative_mapping_url_is_info():
    f = scan(entries({"dist/a.js": "x\n//# sourceMappingURL=a.js.map"}))
    assert [(x.severity, x.rule) for x in f] == [("info", "DANGLING_SOURCEMAP")]


def test_present_relative_mapping_url_is_not_dangling():
    f = scan(entries({"dist/a.js": "x\n//# sourceMappingURL=../maps/a.js.map",
                      "maps/a.js.map": smap(["a.ts"])}))
    assert [x.rule for x in f] == ["SOURCEMAP_FILE"]


def test_css_mapping_url_comment():
    f = scan(entries({"s.css": "a{}\n/*# sourceMappingURL=https://x.test/s.css.map */"}))
    assert [x.rule for x in f] == ["EXTERNAL_SOURCEMAP"]
    assert f[0].detail.endswith("https://x.test/s.css.map")


def test_secret_in_map_not_double_reported():
    m = smap(["../src/a.ts"], ["k='%s'" % STRIPE])
    f = scan(entries({"a.js.map": m}))
    assert [x.rule for x in f].count("SECRET") == 1


# ---- secrets ---------------------------------------------------------------

@pytest.mark.parametrize("value,label", [
    (STRIPE, "Stripe live secret key"),
    (GITHUB, "GitHub token"),
    (AWS, "AWS access key id"),
    (OPENAI, "OpenAI API key"),
])
def test_secret_patterns(value, label):
    f = find_secrets("x = '%s'" % value, "a.js")
    assert len(f) == 1 and f[0].detail.startswith(label) and f[0].severity == "high"


def test_aws_documentation_example_key_is_skipped():
    assert find_secrets(AWS_DOC, "a.js") == []


def test_google_key_is_warn_with_note():
    f = find_secrets(GOOGLE, "a.js")
    assert f[0].severity == "warn" and "restricted" in f[0].detail


def test_private_key_block_detected_without_echoing_it():
    f = find_secrets("x\n" + PEM, "config.js")
    assert f[0].detail == "private key block" and f[0].line == 2


def test_mask():
    assert mask("abcdefghijklmnop") == "abcdef...op (16 chars)"
    assert mask("short") == "sh..."


def test_binary_files_are_skipped():
    f = scan(entries({"img.bin": b"\x00\x01" + STRIPE.encode()}))
    assert f == []


# ---- file names ------------------------------------------------------------

@pytest.mark.parametrize("path,rule,sev", [
    (".env", "ENV_FILE", "high"),
    ("config/.env.production", "ENV_FILE", "high"),
    (".git/config", "VCS_DIR", "high"),
    ("pkg/.svn/entries", "VCS_DIR", "high"),
    ("keys/id_ed25519", "KEY_FILE", "high"),
    ("certs/server.pem", "KEY_FILE", "warn"),
])
def test_name_rules(path, rule, sev):
    f = check_name(path)
    assert [(x.rule, x.severity) for x in f] == [(rule, sev)]


@pytest.mark.parametrize("path", [".env.example", ".env.sample", "env.ts", "id_ed25519.pub", "src/git.js"])
def test_name_rules_negative(path):
    assert check_name(path) == []


def test_pem_with_private_key_is_upgraded_and_not_doubled():
    f = scan(entries({"server.pem": PEM}))
    assert [(x.severity, x.rule) for x in f] == [("high", "KEY_FILE")]
    assert "holds a private key" in f[0].detail


def test_npmrc_with_token():
    f = scan(entries({".npmrc": "//registry.npmjs.org/:_authToken=abc123\n"}))
    assert [(x.severity, x.rule) for x in f] == [("high", "REGISTRY_TOKEN")]


def test_npmrc_without_token_is_fine():
    assert scan(entries({".npmrc": "save-exact=true\n"})) == []


def test_clean_package_has_no_findings():
    assert scan(entries({"index.js": "module.exports = 1;\n", "README.md": "# hi", "package.json": "{}"})) == []


# ---- sources ---------------------------------------------------------------

def test_load_directory_skips_node_modules(tmp_path):
    write_tree(tmp_path, {"a.js": "1", "node_modules/x/.env": "A=1", "sub/b.js": "2"})
    ents, desc = load(str(tmp_path))
    assert sorted(e.path for e in ents) == ["a.js", "sub/b.js"]
    assert desc.startswith("directory ")


def test_load_npm_tarball_strips_package_prefix(tmp_path):
    p = tmp_path / "pkg-1.0.0.tgz"
    with tarfile.open(str(p), "w:gz") as tf:
        for name, data in (("package/package.json", b"{}"), ("package/.env", b"A=1")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    ents, _ = load(str(p))
    assert sorted(e.path for e in ents) == [".env", "package.json"]
    assert [f.rule for f in scan(ents)] == ["ENV_FILE"]


def test_load_wheel_keeps_paths(tmp_path):
    p = tmp_path / "demo-0.1-py3-none-any.whl"
    with zipfile.ZipFile(str(p), "w") as zf:
        zf.writestr("demo/__init__.py", "")
        zf.writestr("demo/.env", "TOKEN=1")
        zf.writestr("demo-0.1.dist-info/METADATA", "Name: demo")
    ents, desc = load(str(p))
    assert sorted(e.path for e in ents) == ["demo-0.1.dist-info/METADATA", "demo/.env", "demo/__init__.py"]
    assert desc.startswith("zip archive")


def test_strip_common_root_only_when_shared():
    ents = entries({"a/x": "", "b/y": ""})
    assert strip_common_root(ents) is None


def test_load_missing_path_errors(capsys):
    assert main(["/nonexistent/thing"]) == 2
    assert "no such file" in capsys.readouterr().err


def test_load_non_archive_errors(tmp_path, capsys):
    p = tmp_path / "notes.txt"
    p.write_text("hi")
    assert main([str(p)]) == 2


# ---- CLI -------------------------------------------------------------------

def test_cli_exit_codes_and_fail_on(tmp_path, capsys):
    write_tree(tmp_path, {"a.js": "x\n//# sourceMappingURL=https://cdn.test/a.js.map\n"})
    assert main([str(tmp_path)]) == 0
    assert main([str(tmp_path), "--fail-on", "warn"]) == 1
    out = capsys.readouterr().out
    assert "0 high, 1 warn, 0 info -> exit 1" in out


def test_cli_allow_rule_glob_and_ignore_file(tmp_path, capsys):
    write_tree(tmp_path, {".env": "A=1", "dist/a.js.map": smap(["../src/a.ts"], ["x"])})
    assert main([str(tmp_path)]) == 1
    assert main([str(tmp_path), "--allow", "ENV_FILE:.env", "--allow", "*.map"]) == 0
    (tmp_path / ".packleakignore").write_text("# shipped on purpose\nENV_FILE:.env\nSOURCEMAP_CONTENT:dist/*.map\n")
    assert main([str(tmp_path)]) == 0
    assert "2 allowed" in capsys.readouterr().out


def test_cli_allow_rule_does_not_cover_other_rules(tmp_path):
    write_tree(tmp_path, {".env": "A=1"})
    assert main([str(tmp_path), "--allow", "SECRET:.env"]) == 1


def test_cli_json(tmp_path, capsys):
    write_tree(tmp_path, {"a.js": "k='%s'\n" % GITHUB})
    assert main([str(tmp_path), "--json"]) == 1
    data = json.loads(capsys.readouterr().out)
    assert data["counts"] == {"high": 1, "warn": 0, "info": 0}
    f = data["findings"][0]
    assert (f["rule"], f["path"], f["line"]) == ("SECRET", "a.js", 1)
    assert GITHUB not in json.dumps(data)


def test_cli_quiet_hides_below_threshold(tmp_path, capsys):
    write_tree(tmp_path, {"a.js": "x\n//# sourceMappingURL=a.js.map", ".env": "A=1"})
    main([str(tmp_path), "-q"])
    out = capsys.readouterr().out
    assert "ENV_FILE" in out and "DANGLING" not in out


def test_cli_fail_on_never(tmp_path):
    write_tree(tmp_path, {".env": "A=1"})
    assert main([str(tmp_path), "--fail-on", "never"]) == 0


def test_cli_npm_requires_directory(tmp_path, capsys):
    p = tmp_path / "x.tgz"
    p.write_bytes(b"")
    assert main([str(p), "--npm"]) == 2
