"""
AgentGuard Audit Logger

Writes audit records to:
  1. The SQLite database (AuditRecord table)
  2. A JSONL flat file (append-only, human-readable backup)

Every record is SHA-256 hash-chained to the previous record.

DISCLAIMER:
    This audit system provides integrity evidence, not security proof.
    See audit/integrity.py for full disclaimer.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.audit.integrity import compute_event_hash, genesis_hash, INTEGRITY_DISCLAIMER
from app.core.logging_setup import get_logger

logger = get_logger(__name__)


class AuditLogger:
    """
    Central audit logger for AgentGuard security decisions.
    
    Usage:
        audit = AuditLogger(log_path="./audit_logs/audit.jsonl")
        audit.log_decision(decision)
    """

    def __init__(self, log_path: str = "./audit_logs/audit.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: Optional[str] = None
        self._record_count: int = 0
        self._load_last_hash()
        logger.info(f"AuditLogger initialized — log_path={self.log_path}")

    def _load_last_hash(self) -> None:
        """Load the hash of the last record from an existing log file."""
        if not self.log_path.exists():
            self._last_hash = None
            return
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            if lines:
                last_record = json.loads(lines[-1])
                self._last_hash = last_record.get("event_hash")
                self._record_count = len(lines)
                logger.info(
                    f"Loaded existing audit log — {self._record_count} records, "
                    f"last_hash={self._last_hash[:8] if self._last_hash else None}..."
                )
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Could not load existing audit log: {e}")
            self._last_hash = None

    def log_raw(
        self,
        event_id: str,
        agent_id: str,
        action: str,
        target: str,
        decision: str,
        risk_score: Optional[int],
        reasons: list[str],
        timestamp: Optional[datetime] = None,
    ) -> dict:
        """
        Write a raw audit record to the JSONL file.
        
        Returns:
            The complete audit record dict including hashes.
        """
        ts = timestamp or datetime.now(timezone.utc)

        # Build the event data that gets hashed
        event_data = {
            "event_id": event_id,
            "agent_id": agent_id,
            "action": action,
            "target": target,
            "decision": decision,
            "risk_score": risk_score,
            "reasons": reasons,
            "timestamp": ts.isoformat(),
        }

        # Compute chained hash
        event_hash = compute_event_hash(event_data, self._last_hash)

        record = {
            "record_id": str(uuid.uuid4()),
            "data": event_data,
            "event_hash": event_hash,
            "previous_event_hash": self._last_hash,
            "integrity_note": INTEGRITY_DISCLAIMER,
        }

        # Append to JSONL file
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, default=str) + "\n")
            self._last_hash = event_hash
            self._record_count += 1
        except OSError as e:
            logger.error(f"Failed to write audit record: {e}")
            raise

        return record

    @property
    def record_count(self) -> int:
        return self._record_count

    @property
    def last_hash(self) -> Optional[str]:
        return self._last_hash
