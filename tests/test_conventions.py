"""Guards on the repo's own conventions.

These do not test behaviour; they stop a change from quietly breaking a
promise the project makes about itself - that mock data is always labelled,
and that the repo names integrations by category, never by vendor.

Both are the kind of rule that a reviewer enforces once and then forgets, so
they are pinned here instead.
"""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Directories that are not part of the shipped source.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "tests"}
TEXT_SUFFIXES = {".py", ".md", ".json", ".js", ".html", ".txt", ".example", ".yml", ".yaml"}

# The blocked vendor names and fingerprints live in a local-only file, never
# in the repo: a published list of what was removed would disclose the very
# tooling the sanitisation hides. One term per line, '#' for comments.
BLOCKLIST_RELATIVE = "tests/blocklist.local.txt"
BLOCKLIST = REPO_ROOT / BLOCKLIST_RELATIVE


def load_blocklist():
    if not BLOCKLIST.is_file():
        raise unittest.SkipTest(f"{BLOCKLIST_RELATIVE} not present - "
                                "vendor guard runs only on the maintainer's machine")
    lines = BLOCKLIST.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines
            if line.strip() and not line.strip().startswith("#")]


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


class TestVendorSanitisation(unittest.TestCase):
    """The repo refers to every integration by category, never by vendor, so
    that publishing it discloses no team's tooling choices. GitHub remains
    named: it is a personal account and it is where this repo lives.

    The terms come from a local-only blocklist; without it this guard skips."""

    def test_no_blocklisted_terms_in_source(self):
        blocklist = load_blocklist()
        offenders = []
        for path in source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore").lower()
            except OSError:
                continue
            for term in blocklist:
                if term.lower() in text:
                    offenders.append(f"{path.relative_to(REPO_ROOT)}: {term}")
        self.assertEqual(offenders, [], "blocklisted vendor terms reintroduced:\n"
                                        + "\n".join(offenders))

    def test_blocklist_is_never_tracked(self):
        """Committing the blocklist would publish the list it exists to hide."""
        self.assertFalse(_is_tracked(BLOCKLIST_RELATIVE),
                         f"{BLOCKLIST_RELATIVE} must never be committed")


class TestProjectNaming(unittest.TestCase):
    """The project is Lyntinel. It carried a different name earlier, and a
    half-applied rename left the dashboard saying one thing while every other
    file said another - a poor look in a repo whose whole argument is that it
    is trustworthy about what it is.

    The old name is never written literally here: this file would otherwise
    trip its own guard, and a blanket rename would silently corrupt it."""

    # Split so this guard does not trip over its own source, and so a
    # find-and-replace across the repo cannot rewrite the thing being detected.
    OLD_NAME = "Sent" + "inel"

    # The one permitted use: the README title uses the word as a plain noun,
    # which is where the project name comes from. Scoped to that one file and
    # that exact phrase, so any other appearance still fails.
    ALLOWED = {"README.md": "an AI security " + "sent" + "inel"}

    def test_old_project_name_is_gone(self):
        offenders = []
        for path in source_files():
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            allowed = self.ALLOWED.get(path.relative_to(REPO_ROOT).as_posix())
            if allowed:
                text = text.replace(allowed, "")
            if self.OLD_NAME.lower() in text.lower():
                offenders.append(str(path.relative_to(REPO_ROOT)))
        self.assertEqual(offenders, [],
                         f"old project name still present in: {offenders}")


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
