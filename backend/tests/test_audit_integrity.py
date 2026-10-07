"""
Tests for AgentGuard Audit Integrity System (SHA-256 chain)
"""
import pytest
from app.audit.integrity import (
    hash_event,
    chain_hash,
    compute_event_hash,
    verify_record,
    verify_chain,
    genesis_hash,
    INTEGRITY_DISCLAIMER,
)


# --- hash_event tests ---

def test_hash_event_is_deterministic():
    """Same input must always produce same hash."""
    data = {"agent_id": "a1", "action": "read_file", "target": ".env"}
    h1 = hash_event(data)
    h2 = hash_event(data)
    assert h1 == h2


def test_hash_event_is_sha256_length():
    """SHA-256 hex digest is always 64 characters."""
    h = hash_event({"action": "read_file"})
    assert len(h) == 64
    assert all(c in '0123456789abcdef' for c in h)


def test_hash_event_is_sensitive_to_changes():
    """Different data must produce different hashes."""
    h1 = hash_event({"action": "read_file"})
    h2 = hash_event({"action": "write_file"})
    assert h1 != h2


def test_hash_event_key_order_independent():
    """Hash must be the same regardless of dict key insertion order."""
    h1 = hash_event({"a": 1, "b": 2})
    h2 = hash_event({"b": 2, "a": 1})
    assert h1 == h2


# --- chain_hash tests ---

def test_chain_hash_differs_from_standalone():
    """A chained hash must differ from the standalone hash."""
    data = {"action": "read_file"}
    standalone = hash_event(data)
    chained = chain_hash(data, previous_hash="abc123")
    assert standalone != chained


def test_chain_hash_is_deterministic():
    """Same event + same previous_hash = same chain hash."""
    data = {"action": "read_file"}
    h1 = chain_hash(data, "prev_hash_xyz")
    h2 = chain_hash(data, "prev_hash_xyz")
    assert h1 == h2


def test_chain_hash_differs_with_different_previous():
    """Different previous_hash values must produce different chain hashes."""
    data = {"action": "read_file"}
    h1 = chain_hash(data, "hash_aaa")
    h2 = chain_hash(data, "hash_bbb")
    assert h1 != h2


# --- verify_chain tests ---

def test_verify_empty_chain():
    """Empty chain should be trivially valid."""
    assert verify_chain([]) is True


def test_verify_valid_single_record():
    """A single valid record should verify successfully."""
    data = {"id": "1", "action": "read_file", "agent": "a1"}
    h = hash_event(data)
    records = [{"data": data, "event_hash": h, "previous_event_hash": None}]
    assert verify_chain(records) is True


def test_verify_valid_two_record_chain():
    """A valid two-record chain should verify successfully."""
    e1 = {"id": "1", "action": "read_file"}
    e2 = {"id": "2", "action": "network_request"}
    h1 = hash_event(e1)
    h2 = chain_hash(e2, h1)
    records = [
        {"data": e1, "event_hash": h1, "previous_event_hash": None},
        {"data": e2, "event_hash": h2, "previous_event_hash": h1},
    ]
    assert verify_chain(records) is True


def test_verify_fails_for_tampered_first_record():
    """Tampering with the first record must break chain verification."""
    e1 = {"id": "1", "action": "read_file"}
    e2 = {"id": "2", "action": "network_request"}
    h1 = hash_event(e1)
    h2 = chain_hash(e2, h1)
    tampered_e1 = {"id": "1", "action": "delete_file"}  # tampered!
    records = [
        {"data": tampered_e1, "event_hash": h1, "previous_event_hash": None},
        {"data": e2, "event_hash": h2, "previous_event_hash": h1},
    ]
    assert verify_chain(records) is False


def test_verify_fails_for_tampered_hash():
    """Replacing a stored hash with a fake must break verification."""
    data = {"id": "1", "action": "read_file"}
    records = [
        {"data": data, "event_hash": "fake_hash_0000", "previous_event_hash": None}
    ]
    assert verify_chain(records) is False


# --- genesis hash ---

def test_genesis_hash_is_sha256_of_empty():
    """Genesis hash must be SHA-256 of empty bytes."""
    import hashlib
    expected = hashlib.sha256(b"").hexdigest()
    assert genesis_hash() == expected


# --- disclaimer ---

def test_integrity_disclaimer_exists():
    """Integrity disclaimer string must exist and mention what hashing does NOT guarantee."""
    assert INTEGRITY_DISCLAIMER
    assert "NOT" in INTEGRITY_DISCLAIMER or "not" in INTEGRITY_DISCLAIMER.lower()
