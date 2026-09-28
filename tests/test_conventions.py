"""Guards on the repo's own conventions.

These do not test behaviour; they stop a change from quietly breaking a
promise the project makes about itself - that no credentials are committed.

It is the kind of rule that a reviewer enforces once and then forgets, so
it is pinned here instead.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Directories that are not part of the shipped source.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "tests"}
TEXT_SUFFIXES = {".py", ".md", ".json", ".js", ".html", ".txt", ".example", ".yml", ".yaml"}


def source_files():
    """Files that are actually committed.

    This deliberately asks git rather than walking the filesystem: the guard
    is about what the repo publishes, not what happens to sit in a working
    directory. Untracked local files - scratch notes, private drafts, a
    downloaded sample - are none of its business, and scanning them would
    make the result depend on whose machine it runs on.
    """
    for relative in _tracked_files():
        path = REPO_ROOT / relative
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in relative.split("/")):
            continue
        yield path


def _tracked_files():
    import subprocess
    try:
        out = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT,
                             capture_output=True, text=True, check=True)
    except (OSError, subprocess.SubprocessError):
        raise unittest.SkipTest("git unavailable - cannot determine tracked files")
    return [line for line in out.stdout.splitlines() if line.strip()]

class TestSecretsHygiene(unittest.TestCase):

    CREDENTIAL_PATTERNS = [
        re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ]

    def test_no_credentials_committed(self):
        offenders = []
        for path in source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for pattern in self.CREDENTIAL_PATTERNS:
                if pattern.search(text):
                    offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [], f"possible credentials: {offenders}")

    def test_env_file_is_not_tracked(self):
        """.env holds real credentials on a developer machine. It is
        gitignored; this catches the day someone force-adds it."""
        self.assertFalse((REPO_ROOT / ".env").exists() and _is_tracked(".env"),
                         ".env must never be committed")


def _is_tracked(relative_path):
    import subprocess
    try:
        out = subprocess.run(["git", "ls-files", "--error-unmatch", relative_path],
                             cwd=REPO_ROOT, capture_output=True, text=True)
        return out.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


if __name__ == "__main__":
    unittest.main()
