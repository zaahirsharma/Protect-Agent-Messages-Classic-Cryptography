import hashlib
import hmac

import pytest

import secure_record as sr


def reject_without_decryption(monkeypatch, state, record, expected):
    before = state.expected_sequence
    result = None

    def forbidden_cipher(*args, **kwargs):
        pytest.fail("Rejected record reached decryption")

    with monkeypatch.context() as patch:
        patch.setattr(sr, "Cipher", forbidden_cipher)
        with pytest.raises(sr.RecordError) as error:
            result = sr.open_record(state, record)

    assert str(error.value) == expected
    assert result is None
    assert state.expected_sequence == before


def test_valid_handshake_and_bidirectional_messages(endpoints):
    gateway, node = endpoints
    assert gateway.tx.next_sequence == node.tx.next_sequence == 0
    assert gateway.rx.expected_sequence == node.rx.expected_sequence == 0

    command = sr.seal(gateway.tx, b"READ notes.txt", message_type=1)
    reply = sr.seal(node.tx, b"OK", message_type=2)

    assert sr.HEADER.unpack(command[:sr.HEADER.size])[:3] == (
        1, sr.GATEWAY_TO_NODE, 0
    )
    assert sr.HEADER.unpack(reply[:sr.HEADER.size])[:3] == (
        1, sr.NODE_TO_GATEWAY, 0
    )
    expected_tag = hmac.new(
        gateway.tx.mac_key, command[:-sr.TAG_SIZE], hashlib.sha256
    ).digest()
    assert command[-sr.TAG_SIZE:] == expected_tag

    assert sr.open_record(node.rx, command) == (1, b"READ notes.txt")
    assert sr.open_record(gateway.rx, reply) == (2, b"OK")


@pytest.mark.parametrize("offset", [
    pytest.param(0, id="version"),
    pytest.param(1, id="direction"),
    pytest.param(9, id="sequence"),
    pytest.param(10, id="message-type"),
    pytest.param(sr.HEADER.size, id="iv"),
    pytest.param(sr.HEADER.size + sr.IV_SIZE, id="ciphertext"),
    pytest.param(-1, id="tag"),
])
def test_modified_authenticated_bytes(endpoints, monkeypatch, offset):
    gateway, node = endpoints
    original = sr.seal(gateway.tx, b"READ notes.txt")
    modified = bytearray(original)
    modified[offset] ^= 1

    reject_without_decryption(
        monkeypatch, node.rx, bytes(modified), "invalid MAC"
    )
    assert sr.open_record(node.rx, original) == (1, b"READ notes.txt")


@pytest.mark.parametrize("case,expected", [
    ("short", "record too short"),
    ("truncated", "record length mismatch"),
    ("trailing", "record length mismatch"),
    ("declared_length", "record length mismatch"),
])
def test_malformed_record(endpoints, monkeypatch, case, expected):
    gateway, node = endpoints
    original = sr.seal(gateway.tx, b"READ notes.txt")

    if case == "short":
        malformed = original[:20]
    elif case == "truncated":
        malformed = original[:-1]
    elif case == "trailing":
        malformed = original + b"x"
    else:
        modified = bytearray(original)
        modified[14] ^= 1
        malformed = bytes(modified)

    reject_without_decryption(monkeypatch, node.rx, malformed, expected)
    assert sr.open_record(node.rx, original) == (1, b"READ notes.txt")


def test_replayed_record(endpoints, monkeypatch):
    gateway, node = endpoints
    record = sr.seal(gateway.tx, b"READ notes.txt")
    assert sr.open_record(node.rx, record) == (1, b"READ notes.txt")

    reject_without_decryption(
        monkeypatch, node.rx, record, "unexpected sequence"
    )
    next_record = sr.seal(gateway.tx, b"WAIT")
    assert sr.open_record(node.rx, next_record) == (1, b"WAIT")


def test_record_reflected_into_opposite_direction(endpoints, monkeypatch):
    gateway, node = endpoints
    record = sr.seal(gateway.tx, b"READ notes.txt")
    reject_without_decryption(
        monkeypatch, gateway.rx, record, "invalid MAC"
    )
    reply = sr.seal(node.tx, b"OK")
    assert sr.open_record(gateway.rx, reply) == (1, b"OK")


def test_out_of_order_record(endpoints, monkeypatch):
    gateway, node = endpoints
    first = sr.seal(gateway.tx, b"FIRST")
    second = sr.seal(gateway.tx, b"SECOND")
    reject_without_decryption(
        monkeypatch, node.rx, second, "unexpected sequence"
    )
    assert sr.open_record(node.rx, first) == (1, b"FIRST")
    assert sr.open_record(node.rx, second) == (1, b"SECOND")


@pytest.mark.parametrize("case,expected", [
    ("version", "unsupported version"),
    ("direction", "wrong direction"),
    ("sequence", "unexpected sequence"),
    ("iv", "IV does not match session and sequence"),
])
def test_authenticated_but_invalid_metadata(
    endpoints, monkeypatch, case, expected
):
    gateway, node = endpoints
    original = sr.seal(gateway.tx, b"OK")
    values = list(sr.HEADER.unpack(original[:sr.HEADER.size]))
    iv_end = sr.HEADER.size + sr.IV_SIZE
    iv = original[sr.HEADER.size:iv_end]
    ciphertext = original[iv_end:-sr.TAG_SIZE]

    if case == "version":
        values[0] = 2
    elif case == "direction":
        values[1] = sr.NODE_TO_GATEWAY
    elif case == "sequence":
        values[2] = 1
    else:
        iv = bytes([iv[0] ^ 1]) + iv[1:]

    # Simulate a buggy authenticated sender using this lab's own key.
    authenticated = sr.HEADER.pack(*values) + iv + ciphertext
    tag = hmac.new(
        gateway.tx.mac_key, authenticated, hashlib.sha256
    ).digest()
    reject_without_decryption(
        monkeypatch, node.rx, authenticated + tag, expected
    )
    assert sr.open_record(node.rx, original) == (1, b"OK")


@pytest.mark.parametrize("plaintext", [b"", b"A" * 16])
def test_supported_plaintext_boundaries(endpoints, plaintext):
    gateway, node = endpoints
    record = sr.seal(gateway.tx, plaintext)
    assert sr.open_record(node.rx, record) == (1, plaintext)


def test_oversized_plaintext_rejected_without_consuming_sequence(endpoints):
    gateway, node = endpoints
    with pytest.raises(sr.RecordError) as error:
        sr.seal(gateway.tx, b"A" * 17)
    assert str(error.value) == "plaintext exceeds 16-byte record limit"
    assert gateway.tx.next_sequence == 0
    record = sr.seal(gateway.tx, b"OK")
    assert sr.open_record(node.rx, record) == (1, b"OK")


def test_consecutive_records_have_distinct_ivs(endpoints):
    gateway, node = endpoints
    packets = [
        sr.seal(gateway.tx, plaintext)
        for plaintext in (b"ONE", b"TWO", b"THREE")
    ]
    ivs = [
        packet[sr.HEADER.size:sr.HEADER.size + sr.IV_SIZE]
        for packet in packets
    ]
    assert len(set(ivs)) == 3
    assert [
        sr.HEADER.unpack(packet[:sr.HEADER.size])[2]
        for packet in packets
    ] == [0, 1, 2]
    for packet, plaintext in zip(packets, (b"ONE", b"TWO", b"THREE")):
        assert sr.open_record(node.rx, packet) == (1, plaintext)


def test_sequence_exhaustion_fails_closed(endpoints, monkeypatch):
    gateway, node = endpoints
    # Simulate reaching the final permissible sequence.
    gateway.tx.next_sequence = sr.MAX_SEQUENCE
    node.rx.expected_sequence = sr.MAX_SEQUENCE

    final_record = sr.seal(gateway.tx, b"LAST")
    assert sr.open_record(node.rx, final_record) == (1, b"LAST")
    assert gateway.tx.next_sequence == sr.MAX_SEQUENCE + 1
    assert node.rx.expected_sequence == sr.MAX_SEQUENCE + 1

    with pytest.raises(sr.RecordError) as error:
        sr.seal(gateway.tx, b"AGAIN")
    assert str(error.value) == "sender sequence exhausted or invalid"
    assert gateway.tx.next_sequence == sr.MAX_SEQUENCE + 1

    reject_without_decryption(
        monkeypatch, node.rx, final_record,
        "receiver sequence exhausted or invalid"
    )
