"""CISA Known Exploited Vulnerabilities catalogue.

This is a structured lookup, not a retrieval problem: the join key is an exact
CVE id. Embedding it would replace a certain answer with a probable one.

The snapshot in data/reference is committed so the app boots with no network.
scripts/fetch_reference_data.py refreshes it.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path

from .. import settings


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    known_ransomware: bool
    notes: str

    @property
    def added_on(self) -> date | None:
        try:
            return datetime.strptime(self.date_added, "%Y-%m-%d").date()
        except (ValueError, TypeError):
            return None


@dataclass
class KevCatalogue:
    entries: dict[str, KevEntry]
    source_path: str
    loaded: bool

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, cve: str) -> KevEntry | None:
        return self.entries.get((cve or "").strip().upper())

    def newest_entry_date(self) -> date | None:
        dates = [e.added_on for e in self.entries.values() if e.added_on]
        return max(dates) if dates else None

    def age_days(self) -> int | None:
        """How stale this snapshot is, by its most recent entry.

        Surfaced in the UI: a KEV snapshot that has not been refreshed will
        silently fail to flag a CVE added since it was taken.
        """
        newest = self.newest_entry_date()
        return (date.today() - newest).days if newest else None


_TRUE = {"known", "yes", "true"}


@lru_cache(maxsize=1)
def load(path: str | None = None) -> KevCatalogue:
    target = Path(path) if path else settings.KEV_CSV
    if not target.exists():
        return KevCatalogue(entries={}, source_path=str(target), loaded=False)

    entries: dict[str, KevEntry] = {}
    with io.open(target, encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            cve = (row.get("cveID") or "").strip().upper()
            if not cve:
                continue
            entries[cve] = KevEntry(
                cve_id=cve,
                vendor_project=(row.get("vendorProject") or "").strip(),
                product=(row.get("product") or "").strip(),
                vulnerability_name=(row.get("vulnerabilityName") or "").strip(),
                date_added=(row.get("dateAdded") or "").strip(),
                short_description=(row.get("shortDescription") or "").strip(),
                required_action=(row.get("requiredAction") or "").strip(),
                due_date=(row.get("dueDate") or "").strip(),
                known_ransomware=(row.get("knownRansomwareCampaignUse") or "").strip().lower()
                in _TRUE,
                notes=(row.get("notes") or "").strip(),
            )
    return KevCatalogue(entries=entries, source_path=str(target), loaded=True)
