"""Security tests for the keyslot module (07-01)."""
import os
import pytest
from wireseal.security.keyslot import (
    Keyslot, KeyslotStore, _DEV_FAST_PARAMS,
    create_keyslot, unlock_keyslot, find_and_unlock,
    serialize_keyslot, deserialize_keyslot,
    serialize_store, deserialize_store,
    _SLOT_SIZE,
)
from wireseal.security.exceptions import KeyslotNotFoundError


@pytest.fixture
def master_key():
    return os.urandom(32)


@pytest.fixture
def passphrase():
    return bytearray(b"test-passphrase-secure")


def test_create_and_unlock_round_trip(master_key, passphrase):
    slot = create_keyslot("owner", passphrase, master_key, role="owner", **_DEV_FAST_PARAMS)
    recovered = unlock_keyslot(slot, passphrase, **_DEV_FAST_PARAMS)
    assert bytes(recovered) == master_key


def test_wrong_passphrase_raises(master_key, passphrase):
    slot = create_keyslot("owner", passphrase, master_key, **_DEV_FAST_PARAMS)
    with pytest.raises(KeyslotNotFoundError):
        unlock_keyslot(slot, bytearray(b"wrong-passphrase"), **_DEV_FAST_PARAMS)


def test_serialize_deserialize_144_bytes(master_key, passphrase):
    slot = create_keyslot("alice", passphrase, master_key, role="admin", **_DEV_FAST_PARAMS)
    raw = serialize_keyslot(slot)
    assert len(raw) == _SLOT_SIZE == 144
    slot2 = deserialize_keyslot(raw, role="admin")
    assert slot2.admin_id == "alice"
    recovered = unlock_keyslot(slot2, passphrase, **_DEV_FAST_PARAMS)
    assert bytes(recovered) == master_key


def test_find_and_unlock_correct_admin(master_key, passphrase):
    store = KeyslotStore()
    store.keyslots.append(create_keyslot("owner", passphrase, master_key, role="owner", **_DEV_FAST_PARAMS))
    other_pass = bytearray(b"other-pass")
    store.keyslots.append(create_keyslot("alice", other_pass, master_key, role="admin", **_DEV_FAST_PARAMS))
    recovered = find_and_unlock(store, "alice", other_pass, **_DEV_FAST_PARAMS)
    assert bytes(recovered) == master_key


def test_find_unknown_admin_raises(master_key, passphrase):
    store = KeyslotStore()
    store.keyslots.append(create_keyslot("owner", passphrase, master_key, **_DEV_FAST_PARAMS))
    with pytest.raises(KeyslotNotFoundError):
        find_and_unlock(store, "nonexistent", passphrase, **_DEV_FAST_PARAMS)


def test_serialize_store_round_trip(master_key, passphrase):
    store = KeyslotStore()
    store.keyslots.append(create_keyslot("owner", passphrase, master_key, role="owner", **_DEV_FAST_PARAMS))
    store.keyslots.append(create_keyslot("bob", bytearray(b"bob-pass"), master_key, role="admin", **_DEV_FAST_PARAMS))
    raw = serialize_store(store)
    assert len(raw) == 2 * 144
    store2 = deserialize_store(raw, roles={"owner": "owner", "bob": "admin"})
    assert len(store2.keyslots) == 2
    assert store2.keyslots[0].admin_id == "owner"
