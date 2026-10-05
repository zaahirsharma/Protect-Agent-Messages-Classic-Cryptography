
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from handshake import (
    load_parameters,
    load_or_create_signing_key,
    run_handshake,
)


VERSION = 1
GATEWAY_TO_NODE = 1
NODE_TO_GATEWAY = 2
HEADER = struct.Struct(">BBQBI")
IV_SIZE = 16
TAG_SIZE = 32
OVERHEAD = HEADER.size + IV_SIZE + TAG_SIZE
MAX_PLAINTEXT = 16
MAX_SEQUENCE = (1 << 64) - 1


class RecordError(Exception):
    pass


@dataclass(repr=False)
class KeyMaterial:
    direction: int
    enc_key: bytes
    mac_key: bytes
    session_id: bytes

    def __post_init__(self):
        if self.direction not in (GATEWAY_TO_NODE, NODE_TO_GATEWAY):
            raise RecordError("invalid configured direction")
        if not isinstance(self.enc_key, bytes) or len(self.enc_key) != 32:
            raise RecordError("encryption key must be 32 bytes")
        if not isinstance(self.mac_key, bytes) or len(self.mac_key) != 32:
            raise RecordError("MAC key must be 32 bytes")
        if not isinstance(self.session_id, bytes) or len(self.session_id) != 8:
            raise RecordError("session identifier must be 8 bytes")


@dataclass(repr=False)
class SendState(KeyMaterial):
    next_sequence: int = 0


@dataclass(repr=False)
class ReceiveState(KeyMaterial):
    expected_sequence: int = 0


@dataclass(repr=False)
class Endpoint:
    tx: SendState
    rx: ReceiveState


def make_endpoints(gateway_keys, node_keys):
    if gateway_keys != node_keys:
        raise RecordError("session material mismatch")

    gateway = Endpoint(
        tx=SendState(
            GATEWAY_TO_NODE,
            gateway_keys.g2n_enc,
            gateway_keys.g2n_mac,
            gateway_keys.session_id,
        ),
        rx=ReceiveState(
            NODE_TO_GATEWAY,
            gateway_keys.n2g_enc,
            gateway_keys.n2g_mac,
            gateway_keys.session_id,
        ),
    )
    node = Endpoint(
        tx=SendState(
            NODE_TO_GATEWAY,
            node_keys.n2g_enc,
            node_keys.n2g_mac,
            node_keys.session_id,
        ),
        rx=ReceiveState(
            GATEWAY_TO_NODE,
            node_keys.g2n_enc,
            node_keys.g2n_mac,
            node_keys.session_id,
        ),
    )
    return gateway, node


def seal(state, plaintext, message_type=1):
    if not isinstance(state, SendState):
        raise RecordError("seal requires sender state")
    if not isinstance(plaintext, bytes):
        raise RecordError("plaintext must be bytes")
    if len(plaintext) > MAX_PLAINTEXT:
        raise RecordError("plaintext exceeds 16-byte record limit")
    if type(message_type) is not int or not 0 <= message_type <= 255:
        raise RecordError("invalid message type")
    if (
        type(state.next_sequence) is not int
        or not 0 <= state.next_sequence <= MAX_SEQUENCE
    ):
        raise RecordError("sender sequence exhausted or invalid")

    sequence = state.next_sequence
    header = HEADER.pack(
        VERSION, state.direction, sequence, message_type, len(plaintext)
    )
    iv = state.session_id + sequence.to_bytes(8, "big")

    # Reserve this sequence before encryption so errors cannot reuse its IV.
    # If encryption fails, abandon the session and start a fresh handshake.
    state.next_sequence += 1

    encryptor = Cipher(
        algorithms.AES(state.enc_key), modes.CTR(iv)
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    authenticated = header + iv + ciphertext
    authenticator = hmac.HMAC(state.mac_key, hashes.SHA256())
    authenticator.update(authenticated)
    tag = authenticator.finalize()
    return authenticated + tag


def open_record(state, record):
    if not isinstance(state, ReceiveState):
        raise RecordError("open_record requires receiver state")
    if not isinstance(record, bytes):
        raise RecordError("record must be bytes")
    if len(record) < OVERHEAD:
        raise RecordError("record too short")

    version, direction, sequence, message_type, length = HEADER.unpack(
        record[:HEADER.size]
    )
    if length > MAX_PLAINTEXT:
        raise RecordError("ciphertext exceeds 16-byte record limit")
    if len(record) != OVERHEAD + length:
        raise RecordError("record length mismatch")

    iv_start = HEADER.size
    ciphertext_start = iv_start + IV_SIZE
    iv = record[iv_start:ciphertext_start]
    ciphertext = record[ciphertext_start:-TAG_SIZE]
    tag = record[-TAG_SIZE:]

    # Library verification securely compares the MAC before any decryption.
    authenticator = hmac.HMAC(state.mac_key, hashes.SHA256())
    authenticator.update(record[:-TAG_SIZE])
    try:
        authenticator.verify(tag)
    except InvalidSignature as error:
        raise RecordError("invalid MAC") from error

    # Metadata is authenticated now, but must also satisfy session policy.
    if version != VERSION:
        raise RecordError("unsupported version")
    if direction != state.direction:
        raise RecordError("wrong direction")
    if (
        type(state.expected_sequence) is not int
        or not 0 <= state.expected_sequence <= MAX_SEQUENCE
    ):
        raise RecordError("receiver sequence exhausted or invalid")
    if sequence != state.expected_sequence:
        raise RecordError("unexpected sequence")

    expected_iv = state.session_id + sequence.to_bytes(8, "big")
    if iv != expected_iv:
        raise RecordError("IV does not match session and sequence")

    decryptor = Cipher(
        algorithms.AES(state.enc_key), modes.CTR(iv)
    ).decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Commit receive state only after all checks and decryption succeed.
    state.expected_sequence += 1
    return message_type, plaintext


def main():
    parameters = load_parameters()
    gateway_signing = load_or_create_signing_key("gateway-rsa.pem")
    node_signing = load_or_create_signing_key("node-rsa.pem")
    gateway_keys, node_keys, _ = run_handshake(
        parameters, gateway_signing, node_signing
    )
    gateway, node = make_endpoints(gateway_keys, node_keys)

    print("Header bytes:", HEADER.size)
    print("Maximum plaintext bytes per record:", MAX_PLAINTEXT)
    print("Initial send sequences:",
          gateway.tx.next_sequence, node.tx.next_sequence)

    def reject(label, receiver, record, expected_error):
        before = receiver.expected_sequence
        try:
            open_record(receiver, record)
        except RecordError as error:
            assert str(error) == expected_error
            assert receiver.expected_sequence == before
            print(f"REJECTED {label}: {error}")
        else:
            raise AssertionError(f"unsafe acceptance: {label}")

    first = seal(gateway.tx, b"READ notes.txt")

    modified = bytearray(first)
    modified[HEADER.size + IV_SIZE] ^= 1
    reject("modified ciphertext", node.rx, bytes(modified), "invalid MAC")

    modified = bytearray(first)
    modified[10] ^= 1  # Authenticated message_type byte.
    reject("modified header", node.rx, bytes(modified), "invalid MAC")

    reject("reflected record", gateway.rx, first, "invalid MAC")

    message_type, plaintext = open_record(node.rx, first)
    assert (message_type, plaintext) == (1, b"READ notes.txt")
    print("Accepted gateway-to-node:", plaintext.decode())

    reject("replayed record", node.rx, first, "unexpected sequence")

    reply = seal(node.tx, b"OK")
    assert open_record(gateway.rx, reply) == (1, b"OK")
    print("Accepted node-to-gateway: OK")

    second = seal(gateway.tx, b"WAIT")
    third = seal(gateway.tx, b"STATUS")
    reject("out-of-order record", node.rx, third, "unexpected sequence")
    assert open_record(node.rx, second) == (1, b"WAIT")
    assert open_record(node.rx, third) == (1, b"STATUS")
    print("PASS: rejected records did not advance receive state.")

    ivs = {
        packet[HEADER.size:HEADER.size + IV_SIZE]
        for packet in (first, second, third)
    }
    assert len(ivs) == 3
    print("PASS: distinct IVs for consecutive gateway records.")

    before = gateway.tx.next_sequence
    try:
        seal(gateway.tx, b"X" * 17)
    except RecordError as error:
        assert str(error) == "plaintext exceeds 16-byte record limit"
        assert gateway.tx.next_sequence == before
        print("REJECTED oversized plaintext:", error)
    else:
        raise AssertionError("oversized plaintext was accepted")

    print("All Task 3 demonstration checks passed.")


if __name__ == "__main__":
    main()
