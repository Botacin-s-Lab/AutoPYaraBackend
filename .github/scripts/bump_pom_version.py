#!/usr/bin/env python3
"""
Bumps the project <version> in pom.xml, in place, and prints the new version
to stdout (the release workflow captures this via $GITHUB_OUTPUT).

Usage: python .github/scripts/bump_pom_version.py <patch|minor>
  patch: 1.0.0 -> 1.0.1   (triggered by "NewSubversion" in the commit subject)
  minor: 1.0.5 -> 1.1.0   (triggered by "NewVersion"; resets patch, per semver)

Only the *project's own* <version> is touched -- the first <version> element
that follows the project <artifactId>. Dependency versions are left alone.
"""
import os
import re
import sys

POM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pom.xml")

# Anchored on the project artifactId so we never rewrite a dependency's version.
PROJECT_VERSION_RE = re.compile(
    r"(<artifactId>AutoYara</artifactId>.*?<version>)(\d+)\.(\d+)\.(\d+)(</version>)",
    re.DOTALL,
)


def bump(kind):
    with open(POM) as f:
        content = f.read()

    match = PROJECT_VERSION_RE.search(content)
    if not match:
        print(
            "ERROR: could not find the project <version>X.Y.Z</version> in pom.xml",
            file=sys.stderr,
        )
        sys.exit(1)

    prefix, major, minor, patch, suffix = match.groups()
    major, minor, patch = int(major), int(minor), int(patch)

    if kind == "patch":
        patch += 1
    elif kind == "minor":
        minor += 1
        patch = 0
    else:
        print(f'ERROR: unknown bump kind {kind!r}, expected "patch" or "minor"', file=sys.stderr)
        sys.exit(1)

    new_version = f"{major}.{minor}.{patch}"
    content = content[: match.start()] + f"{prefix}{new_version}{suffix}" + content[match.end():]

    with open(POM, "w") as f:
        f.write(content)

    print(new_version)


def current():
    with open(POM) as f:
        match = PROJECT_VERSION_RE.search(f.read())
    if not match:
        print("ERROR: could not find the project <version> in pom.xml", file=sys.stderr)
        sys.exit(1)
    print(f"{match.group(2)}.{match.group(3)}.{match.group(4)}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--current":
        current()
    elif len(sys.argv) == 2 and sys.argv[1] in ("patch", "minor"):
        bump(sys.argv[1])
    else:
        print("Usage: bump_pom_version.py <patch|minor|--current>", file=sys.stderr)
        sys.exit(1)
