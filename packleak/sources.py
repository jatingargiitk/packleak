"""Where the file list comes from: a directory, an archive, or `npm pack --dry-run`."""
import fnmatch
import json
import os
import subprocess
import tarfile
import zipfile

MAX_READ = 20 * 1024 * 1024  # files bigger than this are listed but not read


class Entry(object):
    """One file that would ship. `read()` returns its bytes (or None if too big)."""

    def __init__(self, path, size, reader):
        self.path = path
        self.size = size
        self._reader = reader

    def read(self):
        if self.size is not None and self.size > MAX_READ:
            return None
        return self._reader()


class SourceError(Exception):
    pass


def _dir_entries(root, skip_dirs=("node_modules",)):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            out.append(_file_entry(rel, full))
    return out


def _file_entry(rel, full):
    def reader():
        with open(full, "rb") as fh:
            return fh.read()

    return Entry(rel, os.path.getsize(full), reader)


def _tar_entries(path):
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, OSError) as exc:
        raise SourceError("cannot open %s as a tar archive: %s" % (path, exc))
    out = []
    for member in tf.getmembers():
        if not member.isfile():
            continue
        name = member.name
        if name.startswith("./"):
            name = name[2:]

        def reader(m=member):
            fh = tf.extractfile(m)
            return fh.read() if fh else b""

        out.append(Entry(name, member.size, reader))
    return out


def _zip_entries(path):
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise SourceError("cannot open %s as a zip archive: %s" % (path, exc))
    out = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        out.append(Entry(info.filename, info.file_size, lambda i=info: zf.read(i)))
    return out


def npm_pack_files(pkgdir, npm="npm"):
    """Ask npm for the exact file list `npm publish` would upload. Scripts are not run."""
    cmd = [npm, "pack", "--dry-run", "--json", "--ignore-scripts"]
    try:
        proc = subprocess.run(cmd, cwd=pkgdir, capture_output=True, text=True)
    except OSError as exc:
        raise SourceError("could not run npm: %s" % exc)
    if proc.returncode != 0:
        raise SourceError("npm pack --dry-run failed:\n%s" % (proc.stderr.strip() or proc.stdout.strip()))
    text = proc.stdout
    start = text.find("[")
    try:
        data = json.loads(text[start:])
        files = data[0]["files"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise SourceError("could not parse `npm pack --dry-run --json` output")
    return sorted(f["path"] for f in files)


def strip_common_root(entries):
    """npm tarballs put everything under package/; strip one shared top-level dir."""
    tops = set(e.path.split("/", 1)[0] for e in entries)
    if len(tops) == 1 and all("/" in e.path for e in entries):
        top = tops.pop() + "/"
        for e in entries:
            e.path = e.path[len(top):]
        return top.rstrip("/")
    return None


def load(target, npm=False):
    """Return (entries, description)."""
    if npm:
        if not os.path.isdir(target):
            raise SourceError("--npm needs a package directory, got %s" % target)
        paths = npm_pack_files(target)
        entries = [_file_entry(p, os.path.join(target, p)) for p in paths]
        return entries, "npm pack file list of %s" % target
    if os.path.isdir(target):
        return _dir_entries(target), "directory %s" % target
    if not os.path.exists(target):
        raise SourceError("no such file or directory: %s" % target)
    lower = target.lower()
    if lower.endswith((".whl", ".zip", ".jar", ".vsix", ".xpi", ".crx")) or zipfile.is_zipfile(target):
        entries = _zip_entries(target)
        kind = "zip archive"
    elif lower.endswith((".tgz", ".tar.gz", ".tar", ".tar.bz2", ".tar.xz")) or tarfile.is_tarfile(target):
        entries = _tar_entries(target)
        kind = "tar archive"
    else:
        raise SourceError("%s is not a directory, tar or zip archive" % target)
    strip_common_root(entries)
    desc = "%s %s" % (kind, target)
    return entries, desc


def is_allowed(rule, path, allows):
    for a_rule, glob in allows:
        if a_rule not in ("*", rule):
            continue
        if fnmatch.fnmatchcase(path, glob) or fnmatch.fnmatchcase(path.rsplit("/", 1)[-1], glob):
            return True
    return False
