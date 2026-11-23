"""Runs the real `npm pack --dry-run`; skipped when npm isn't installed."""
import json
import shutil

import pytest

from packleak.cli import main
from packleak.sources import npm_pack_files

pytestmark = pytest.mark.skipif(shutil.which("npm") is None, reason="npm not installed")


def make_pkg(tmp_path, files_field=None):
    pkg = {"name": "leaky-demo", "version": "1.0.0", "main": "dist/index.js",
           "scripts": {"prepack": "exit 1"}}
    if files_field is not None:
        pkg["files"] = files_field
    (tmp_path / "package.json").write_text(json.dumps(pkg))
    (tmp_path / "dist").mkdir()
    (tmp_path / "dist" / "index.js").write_text("module.exports=1;\n//# sourceMappingURL=index.js.map\n")
    (tmp_path / "dist" / "index.js.map").write_text(json.dumps(
        {"version": 3, "sources": ["../src/index.ts"], "sourcesContent": ["export = 1\n"], "mappings": "AAAA"}))
    (tmp_path / ".env").write_text("DB_PASSWORD=hunter2\n")
    return tmp_path


def test_npm_file_list_without_files_field_includes_env(tmp_path):
    paths = npm_pack_files(str(make_pkg(tmp_path)))
    assert ".env" in paths and "dist/index.js.map" in paths


def test_npm_files_allowlist_excludes_env_but_not_map(tmp_path, capsys):
    pkg = make_pkg(tmp_path, ["dist"])
    assert main([str(pkg), "--npm"]) == 1
    out = capsys.readouterr().out
    assert "SOURCEMAP_CONTENT" in out and "ENV_FILE" not in out
    assert '"!**/*.map"' in out


def test_npm_files_allowlist_with_map_negation_is_clean(tmp_path, capsys):
    pkg = make_pkg(tmp_path, ["dist", "!**/*.map"])
    assert main([str(pkg), "--npm"]) == 0
    assert "DANGLING_SOURCEMAP" in capsys.readouterr().out
