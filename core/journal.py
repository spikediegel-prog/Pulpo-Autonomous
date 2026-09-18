from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class JournalRecord:
    sequence: int
    event: str
    payload: dict[str, Any]
    previous_hash: str
    record_hash: str


class DurableJournal:
    """Append-only evidence journal; it is not an authority ledger."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, event: str, payload: dict[str, Any]) -> JournalRecord:
        records = self.read(verify=True)
        previous_hash = records[-1].record_hash if records else ""
        body = {
            "sequence": len(records) + 1,
            "event": event,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        record_hash = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        record = {**body, "record_hash": record_hash}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        return JournalRecord(**record)

    def read(self, *, verify: bool = True) -> list[JournalRecord]:
        if not self.path.exists():
            return []
        records: list[JournalRecord] = []
        previous_hash = ""
        with self.path.open("r", encoding="utf-8") as stream:
            for expected_sequence, line in enumerate(stream, start=1):
                raw = json.loads(line)
                body = {key: raw[key] for key in ("sequence", "event", "payload", "previous_hash")}
                calculated = hashlib.sha256(
                    json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
                ).hexdigest()
                if verify and (
                    raw["sequence"] != expected_sequence
                    or raw["previous_hash"] != previous_hash
                    or raw["record_hash"] != calculated
                ):
                    raise ValueError("journal_integrity_failure")
                record = JournalRecord(**raw)
                records.append(record)
                previous_hash = record.record_hash
        return records
