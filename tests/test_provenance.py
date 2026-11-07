import subprocess

from aegis.provenance import PACKAGE_DIR, git_state, source_hash


def write_package(root):
    package = root / PACKAGE_DIR.name
    package.mkdir(parents=True)
    (package / "a.py").write_text("x = 1\n", encoding="utf-8")
    return package


def test_source_hash_follows_python_source_only(tmp_path):
    package = write_package(tmp_path)
    original = source_hash(tmp_path)
    (package / "notes.txt").write_text("not code", encoding="utf-8")
    assert source_hash(tmp_path) == original
    (package / "a.py").write_text("x = 2\n", encoding="utf-8")
    assert source_hash(tmp_path) != original


def test_git_state_counts_untracked_files_as_dirty(tmp_path):
    package = write_package(tmp_path)
    assert git_state(package) == "unknown"

    def git(*args):
        subprocess.run(
            ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-C", str(tmp_path), *args],
            check=True,
            capture_output=True,
        )

    git("init")
    git("add", ".")
    git("commit", "-m", "start")
    clean = git_state(package)
    assert clean != "unknown" and not clean.endswith("-dirty")

    # A change outside the package does not describe the package's code.
    (tmp_path / "notes.md").write_text("notes", encoding="utf-8")
    assert git_state(package) == clean

    (package / "b.py").write_text("y = 1\n", encoding="utf-8")
    assert git_state(package) == f"{clean}-dirty"
