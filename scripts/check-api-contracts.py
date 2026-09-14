#!/usr/bin/env python3
"""Check that every exported PKCS#11 entry point has exactly one contract."""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STANDARD_HEADER = ROOT / "include" / "pkcs11f.h"
EXTENSION_HEADER = ROOT / "include" / "pkcs11_canokey.h"
CONTRACTS = ROOT / "docs" / "api-contracts.md"


def exported_names() -> set[str]:
    standard = re.findall(
        r"CK_PKCS11_FUNCTION_INFO\((C_[A-Za-z0-9_]+)\)",
        STANDARD_HEADER.read_text(encoding="utf-8"),
    )
    extensions = re.findall(
        r"CK_DEFINE_FUNCTION\(CK_RV,\s*(C_[A-Za-z0-9_]+)\)",
        EXTENSION_HEADER.read_text(encoding="utf-8"),
    )
    return set(standard + extensions)


def documented_rows() -> list[tuple[str, str, str, str]]:
    return re.findall(
        r"^\|\s*`(C_[A-Za-z0-9_]+)`\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|$",
        CONTRACTS.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )


def main() -> int:
    exported = exported_names()
    rows = documented_rows()
    documented = [row[0] for row in rows]
    counts = Counter(documented)
    duplicates = sorted(name for name, count in counts.items() if count != 1)
    missing = sorted(exported - counts.keys())
    extra = sorted(counts.keys() - exported)

    incomplete = sorted(
        name
        for name, profile, lifetime, guarantee in rows
        if not profile.strip() or not lifetime.strip() or not guarantee.strip()
        or "TODO" in (profile + lifetime + guarantee)
    )

    if duplicates or missing or extra or incomplete:
        if missing:
            print("Missing API contracts: " + ", ".join(missing), file=sys.stderr)
        if extra:
            print("Unknown API contracts: " + ", ".join(extra), file=sys.stderr)
        if duplicates:
            print("Duplicate API contracts: " + ", ".join(duplicates), file=sys.stderr)
        if incomplete:
            print("Incomplete API contracts: " + ", ".join(incomplete), file=sys.stderr)
        return 1

    print(f"API contract coverage: {len(exported)}/{len(exported)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
