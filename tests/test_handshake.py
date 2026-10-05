import hashlib
import hmac

import pytest

import handshake as hs


def finish_gateway(exchange, transcript=None, role=None,
                   signature=None, public_key=None):
    return hs.finish_handshake(
        exchange.gateway,
        exchange.transcript if transcript is None else transcript,
        hs.NODE_ROLE if role is None else role,
        exchange.node_signature if signature is None else signature,
        exchange.node_key.public_key() if public_key is None else public_key,
    )


def forbidden_derivation(*args, **kwargs):
    pytest.fail("Rejected handshake reached session-key derivation")


def test_valid_handshake_and_key_separation(identities):
    parameters, gateway_key, node_key = identities
    gateway_keys, node_keys, transcript = hs.run_handshake(
        parameters, gateway_key, node_key
    )
    assert gateway_keys == node_keys
    fields = hs.parse_transcript(transcript)
    assert [len(field) for field in fields] == [
        13, 9, 10, 7, 384, 384, 16, 16
    ]
    keys = [
        gateway_keys.g2n_enc, gateway_keys.g2n_mac,
        gateway_keys.n2g_enc, gateway_keys.n2g_mac,
    ]
    assert all(len(key) == 32 for key in keys)
    assert len(set(keys)) == 4
    assert len(gateway_keys.session_id) == 8


def test_exact_kdf_and_left_padding():
    short_secret = b"\x02"
    padded_secret = b"\x00" * 383 + short_secret
    transcript_hash = hashlib.sha256(b"local KDF test").digest()
    master = hashlib.sha256(
        b"CSCE465-KDF-v1" + padded_secret + transcript_hash
    ).digest()
    actual = hs.derive_keys(short_secret, transcript_hash)

    labels = {
        "g2n_enc": b"gateway-to-node encryption",
        "g2n_mac": b"gateway-to-node MAC",
        "n2g_enc": b"node-to-gateway encryption",
        "n2g_mac": b"node-to-gateway MAC",
    }
    for attribute, label in labels.items():
        expected = hmac.new(
            master, label + transcript_hash, hashlib.sha256
        ).digest()
        assert getattr(actual, attribute) == expected

    expected_id = hmac.new(
        master, b"session identifier" + transcript_hash, hashlib.sha256
    ).digest()[:8]
    assert actual.session_id == expected_id


@pytest.mark.parametrize("case,expected", [
    ("nonce", "invalid peer signature"),
    ("public_value", "invalid peer signature"),
    ("identity", "unexpected peer identity"),
    ("signature", "invalid peer signature"),
    ("public_key", "invalid peer signature"),
    ("reflection", "unexpected peer role"),
    ("relabeled_reflection", "invalid peer signature"),
])
def test_rejected_peer_handshake(exchange, monkeypatch, case, expected):
    transcript = exchange.transcript
    fields = hs.parse_transcript(transcript)
    role = hs.NODE_ROLE
    signature = exchange.node_signature
    public_key = exchange.node_key.public_key()

    if case == "nonce":
        fields[7] = bytes([fields[7][0] ^ 1]) + fields[7][1:]
        transcript = hs.encode_fields(fields)
    elif case == "public_value":
        fields[5] = fields[5][:-1] + bytes([fields[5][-1] ^ 1])
        transcript = hs.encode_fields(fields)
    elif case == "identity":
        fields[3] = b"unexpected-node"
        transcript = hs.encode_fields(fields)
    elif case == "signature":
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    elif case == "public_key":
        public_key = exchange.gateway_key.public_key()
    elif case == "reflection":
        role = hs.GATEWAY_ROLE
        signature = exchange.gateway_signature
    elif case == "relabeled_reflection":
        signature = exchange.gateway_signature

    result = None
    with monkeypatch.context() as patch:
        patch.setattr(hs, "derive_keys", forbidden_derivation)
        with pytest.raises(hs.HandshakeError) as error:
            result = finish_gateway(
                exchange, transcript, role, signature, public_key
            )
    assert str(error.value) == expected
    assert result is None
    assert not exchange.gateway.used
    assert exchange.gateway.private_key is not None

    # A rejected message must not prevent the original valid exchange.
    valid_keys = finish_gateway(exchange)
    assert len(valid_keys.session_id) == 8


@pytest.mark.parametrize("case,expected", [
    ("length", "malformed transcript: truncated field"),
    ("truncated", "malformed transcript: truncated field"),
    ("trailing", "malformed transcript: trailing bytes"),
    ("public_width", "DH public values must be 384 bytes"),
    ("nonce_width", "nonces must be 16 bytes"),
])
def test_malformed_transcript_rejected_before_hashing(
    exchange, monkeypatch, case, expected
):
    transcript = exchange.transcript
    if case == "length":
        transcript = b"\xff\xff\xff\xff" + transcript[4:]
    elif case == "truncated":
        transcript = transcript[:-1]
    elif case == "trailing":
        transcript += b"x"
    else:
        fields = hs.parse_transcript(transcript)
        index = 5 if case == "public_width" else 7
        fields[index] = fields[index][:-1]
        transcript = hs.encode_fields(fields)

    def forbidden_hash(*args, **kwargs):
        pytest.fail("Malformed transcript reached hashing")

    with monkeypatch.context() as patch:
        patch.setattr(hs, "sha256", forbidden_hash)
        with pytest.raises(hs.HandshakeError) as error:
            finish_gateway(exchange, transcript)
    assert str(error.value) == expected
    assert not exchange.gateway.used


@pytest.mark.parametrize("index,expected", [
    (4, "local DH value does not match this session"),
    (6, "local nonce does not match this session"),
])
def test_local_session_binding(exchange, index, expected):
    fields = hs.parse_transcript(exchange.transcript)
    fields[index] = bytes([fields[index][0] ^ 1]) + fields[index][1:]
    with pytest.raises(hs.HandshakeError) as error:
        finish_gateway(exchange, hs.encode_fields(fields))
    assert str(error.value) == expected
    assert not exchange.gateway.used


def test_consumed_handshake_cannot_be_reused(exchange):
    finish_gateway(exchange)
    assert exchange.gateway.used
    assert exchange.gateway.private_key is None
    with pytest.raises(hs.HandshakeError) as error:
        finish_gateway(exchange)
    assert str(error.value) == "handshake state already consumed"


def test_old_transcript_rejected_by_fresh_session(exchange):
    fresh_gateway = hs.new_pending(
        exchange.parameters, hs.GATEWAY_ROLE
    )
    with pytest.raises(hs.HandshakeError) as error:
        hs.finish_handshake(
            fresh_gateway, exchange.transcript, hs.NODE_ROLE,
            exchange.node_signature, exchange.node_key.public_key()
        )
    assert str(error.value) == "local DH value does not match this session"
    assert not fresh_gateway.used
