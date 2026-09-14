"""Download the two public reference documents the system reasons over.

    python scripts/fetch_reference_data.py

Both are committed to the repository as snapshots so the app boots with no
network access, and so a reviewer sees exactly the data the deployed system
used. Re-run this to refresh them, then rebuild the index if NIST changed:

    python scripts/build_index.py

Sources:
  CISA Known Exploited Vulnerabilities  https://github.com/cisagov/kev-data
  NIST SP 800-53 Rev. 5 control catalogue
      https://csrc.nist.gov/projects/risk-management/sp800-53-controls/downloads
"""
from __future__ import annotations

import csv
import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

from app import settings  # noqa: E402

TIMEOUT = 120


def _download(url: str, target: Path, label: str) -> bool:
    print(f"\n{label}\n  {url}")
    try:
        response = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "cyber-risk-assistant"})
        response.raise_for_status()
    except Exception as exc:  # noqa: BLE001 - reported, not raised
        print(f"  FAILED: {exc}", file=sys.stderr)
        return False

    body = response.content
    if len(body) < 10_000:
        print(f"  FAILED: response was only {len(body)} bytes, which is not the catalogue.",
              file=sys.stderr)
        return False

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(body)
    print(f"  wrote {target.name} ({len(body) / 1e6:.2f} MB)")
    return True


def _verify_kev(path: Path) -> bool:
    with io.open(path, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {"cveID", "knownRansomwareCampaignUse", "dateAdded", "requiredAction"}
    missing = required - set(rows[0].keys() if rows else ())
    if missing:
        print(f"  FAILED: KEV csv is missing columns {sorted(missing)}", file=sys.stderr)
        return False
    ransomware = sum(1 for r in rows if (r.get("knownRansomwareCampaignUse") or "").lower() == "known")
    print(f"  verified: {len(rows)} CVEs, {ransomware} with known ransomware use")
    return True


def _verify_nist(path: Path) -> bool:
    with io.open(path, encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    required = {"identifier", "name", "control_text", "discussion"}
    missing = required - set(rows[0].keys() if rows else ())
    if missing:
        print(f"  FAILED: NIST csv is missing columns {sorted(missing)}", file=sys.stderr)
        return False
    identifiers = {(r.get("identifier") or "").strip() for r in rows}
    # The controls the assignment brief calls out by name.
    expected = {"SI-2", "RA-5", "IR-4", "AC-2", "SA-22"}
    absent = expected - identifiers
    if absent:
        print(f"  FAILED: catalogue is missing {sorted(absent)}", file=sys.stderr)
        return False
    base = sum(1 for i in identifiers if i and "(" not in i)
    print(f"  verified: {len(rows)} controls ({base} base, {len(rows) - base} enhancements)")
    return True


def main() -> int:
    ok = True

    if _download(settings.KEV_URL, settings.KEV_CSV, "CISA Known Exploited Vulnerabilities"):
        ok &= _verify_kev(settings.KEV_CSV)
    else:
        ok = False

    if _download(settings.NIST_URL, settings.NIST_CSV, "NIST SP 800-53 Rev. 5 control catalogue"):
        ok &= _verify_nist(settings.NIST_CSV)
    else:
        ok = False

    if ok:
        print(
            "\nBoth reference documents are current.\n"
            "If the NIST catalogue changed, rebuild the search index:\n"
            "  python scripts/build_index.py"
        )
        return 0

    print(
        "\nOne or more downloads failed. The committed snapshots in "
        f"{settings.REFERENCE_DIR} are unchanged and still usable.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
