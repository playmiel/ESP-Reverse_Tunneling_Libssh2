#!/usr/bin/env python3

import json
import pathlib
import re
import sys


def update_library_json(repo_root: pathlib.Path, new_version: str) -> None:
    json_path = repo_root / "library.json"
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"Missing {json_path}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Unable to parse {json_path}: {exc}")

    data["version"] = new_version
    json_content = json.dumps(data, indent=2, ensure_ascii=True)
    json_path.write_text(json_content + "\n", encoding="utf-8")


def update_library_properties(repo_root: pathlib.Path, new_version: str) -> None:
    props_path = repo_root / "library.properties"
    try:
        lines = props_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        raise SystemExit(f"Missing {props_path}")

    version_pattern = re.compile(r"^version\s*=")
    replaced = False
    for idx, line in enumerate(lines):
        if version_pattern.match(line):
            lines[idx] = f"version={new_version}"
            replaced = True
            break

    if not replaced:
        raise SystemExit(f"Could not find version= line in {props_path}")

    props_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: bump_version.py <new-version>")

    new_version = sys.argv[1].strip()
    if not new_version:
        raise SystemExit("Version cannot be empty")

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    update_library_json(repo_root, new_version)
    update_library_properties(repo_root, new_version)
    print(f"Bumped version to {new_version}")


if __name__ == "__main__":
    main()
