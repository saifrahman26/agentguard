"""
AgentGuard Audit Integrity System

Implements SHA-256 hash chaining for tamper-evident audit records.

DISCLAIMER:
    SHA-256 hash chaining provides INTEGRITY evidence for audit records.
    It allows detection of post-hoc tampering with log entries.
    It does NOT prove that an agent action was safe, authorized, or correct.
    Security decisions are made by the Policy Engine, not by hashing.

Hash Chain Design:
    event_hash         = SHA-256(canonical_json(event_data))
    chained_event_hash = SHA-256(canonical_json({event, previous_hash}))

    Each record includes the previous record's hash, so modifying
    any record invalidates all subsequent hashes in the chain.
"""
import hashlib
import json
from datetime import datetime
from typing import Optional

# Integrity disclaimer — embed in generated reports
INTEGRITY_DISCLAIMER = (
    "SHA-256 hash chaining provides integrity evidence for audit records. "
    "It allows detection of post-hoc tampering with log entries. "
    "It does NOT prove that an agent action was safe or authorized."
)


def _canonical_json(data: dict) -> str:
    """
    Produce a deterministic, canonical JSON string from a dict.
    
    sort_keys=True ensures consistent ordering regardless of
    Python dict insertion order.
    default=str handles datetime and other non-serializable types.
    """
    return json.dumps(data, sort_keys=True, default=str, separators=(",", ":"))


def hash_event(event_data: dict) -> str:
    """
    Produce a deterministic SHA-256 hash of an event dict.
    
    Args:
        event_data: Dictionary of event fields to hash.
    
    Returns:
        64-character lowercase hex string (SHA-256 digest).
    
    Example:
        >>> hash_event({"agent_id": "a1", "action": "read_file"})
        'e3b0c44298fc1c149afb...'
    """
    canonical = _canonical_json(event_data)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def chain_hash(event_data: dict, previous_hash: str) -> str:
    """
    Produce a chained SHA-256 hash linking this event to the previous one.
    
    The hash covers both the event data AND the previous hash, so
    any modification to the chain is detectable.
    
    Args:
        event_data:     Dictionary of event fields.
        previous_hash:  SHA-256 hash of the previous audit record.
    
    Returns:
        64-character lowercase hex string.
    """
    chained = {
        "event": event_data,
        "previous_hash": previous_hash,
    }
    canonical = _canonical_json(chained)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_event_hash(
    event_data: dict,
    previous_hash: Optional[str] = None,
) -> str:
    """
    Compute the appropriate hash for an audit record.
    
    If previous_hash is None (first record), uses standalone hash.
    If previous_hash is provided, uses chained hash.
    
    Args:
        event_data:    The event fields to hash.
        previous_hash: Hash of the previous record, or None.
    
    Returns:
        SHA-256 hex digest string.
    """
    if previous_hash is None:
        return hash_event(event_data)
    return chain_hash(event_data, previous_hash)


def verify_record(
    record_data: dict,
    stored_hash: str,
    previous_hash: Optional[str] = None,
) -> bool:
    """
    Verify that a single audit record has not been tampered with.
    
    Recomputes the expected hash and compares to the stored hash.
    
    Args:
        record_data:   The stored event data fields.
        stored_hash:   The hash stored in the audit record.
        previous_hash: The previous record's hash (or None for first).
    
    Returns:
        True if the record is intact, False if tampered.
    """
    expected = compute_event_hash(record_data, previous_hash)
    return expected == stored_hash


def verify_chain(records: list[dict]) -> bool:
    """
    Verify the integrity of an entire audit chain.
    
    Each record is expected to have:
        - 'data':                dict of event fields
        - 'event_hash':         stored SHA-256 hash
        - 'previous_event_hash': hash of prior record (or None)
    
    Args:
        records: List of audit record dicts in chronological order.
    
    Returns:
        True if ALL records in the chain are intact.
        False if ANY record has been tampered with.
    
    Note:
        A False result means the audit log may have been modified
        after the fact. It does NOT necessarily mean an attack occurred.
    """
    if not records:
        return True  # Empty chain is trivially valid

    for i, record in enumerate(records):
        data = record.get("data", {})
        stored_hash = record.get("event_hash", "")
        previous_hash = record.get("previous_event_hash", None)

        expected = compute_event_hash(data, previous_hash)

        if expected != stored_hash:
            return False  # Chain broken at record i

        # Also verify that previous_event_hash matches the actual prior record's hash
        if i > 0:
            prior_hash = records[i - 1].get("event_hash", "")
            if previous_hash != prior_hash:
                return False

    return True


def genesis_hash() -> str:
    """
    Return the canonical 'genesis' hash for the first audit record.
    This is the SHA-256 of the empty string — well-defined and reproducible.
    """
    return hashlib.sha256(b"").hexdigest()
