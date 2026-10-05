
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa


BASE = Path(__file__).resolve().parent
PROTOCOL = b"CSCE465-HS-v2"
GROUP = b"ffdhe3072"
GATEWAY_ID = b"gateway-01"
NODE_ID = b"node-01"
GATEWAY_ROLE = b"gateway"
NODE_ROLE = b"node"
DH_WIDTH = 384


class HandshakeError(Exception):
    pass


def sha256(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def mac(key, data):
    context = hmac.HMAC(key, hashes.SHA256())
    context.update(data)
    return context.finalize()


def pss():
    return padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH,
    )


def load_parameters():
    parameters = serialization.load_pem_parameters(
        (BASE / "ffdhe3072.pem").read_bytes()
    )
    if not isinstance(parameters, dh.DHParameters):
        raise HandshakeError("group file is not DH parameters")
    numbers = parameters.parameter_numbers()
    if numbers.p.bit_length() != 3072 or numbers.g != 2:
        raise HandshakeError("unexpected DH parameters")
    # This is the trusted ffdhe3072 file verified during Task 0.
    return parameters


def load_or_create_signing_key(filename):
    directory = BASE / "local_keys"
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / filename

    if path.exists():
        key = serialization.load_pem_private_key(
            path.read_bytes(), password=None
        )
    else:
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=3072
        )
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            output.write(pem)

    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072:
        raise HandshakeError("expected a 3072-bit RSA signing key")
    path.chmod(0o600)
    return key


@dataclass(repr=False)
class PendingHandshake:
    role: bytes
    private_key: dh.DHPrivateKey | None
    nonce: bytes
    used: bool = False

    def public_bytes(self):
        if self.used or self.private_key is None:
            raise HandshakeError("handshake state already consumed")
        value = self.private_key.public_key().public_numbers().y
        return value.to_bytes(DH_WIDTH, "big")


@dataclass(frozen=True, repr=False)
class SessionKeys:
    g2n_enc: bytes
    g2n_mac: bytes
    n2g_enc: bytes
    n2g_mac: bytes
    session_id: bytes


def new_pending(parameters, role):
    if role not in (GATEWAY_ROLE, NODE_ROLE):
        raise HandshakeError("unknown local role")
    return PendingHandshake(
        role=role,
        private_key=parameters.generate_private_key(),
        nonce=os.urandom(16),
    )


def encode_fields(fields):
    return b"".join(
        len(field).to_bytes(4, "big") + field for field in fields
    )


def parse_transcript(transcript):
    fields = []
    position = 0

    for _ in range(8):
        if position + 4 > len(transcript):
            raise HandshakeError("malformed transcript: missing length")
        length = int.from_bytes(
            transcript[position:position + 4], "big"
        )
        position += 4
        end = position + length
        if end > len(transcript):
            raise HandshakeError("malformed transcript: truncated field")
        fields.append(transcript[position:end])
        position = end

    if position != len(transcript):
        raise HandshakeError("malformed transcript: trailing bytes")
    if fields[0] != PROTOCOL or fields[1] != GROUP:
        raise HandshakeError("unexpected protocol or group")
    if len(fields[4]) != DH_WIDTH or len(fields[5]) != DH_WIDTH:
        raise HandshakeError("DH public values must be 384 bytes")
    if len(fields[6]) != 16 or len(fields[7]) != 16:
        raise HandshakeError("nonces must be 16 bytes")

    return fields


def build_transcript(gateway, node):
    if gateway.role != GATEWAY_ROLE or node.role != NODE_ROLE:
        raise HandshakeError("incorrect transcript role ordering")
    return encode_fields([
        PROTOCOL,
        GROUP,
        GATEWAY_ID,
        NODE_ID,
        gateway.public_bytes(),
        node.public_bytes(),
        gateway.nonce,
        node.nonce,
    ])


def validate_local_transcript(state, transcript):
    if state.used or state.private_key is None:
        raise HandshakeError("handshake state already consumed")

    # All structural and identity checks happen before hashing.
    fields = parse_transcript(transcript)
    if fields[2] != GATEWAY_ID or fields[3] != NODE_ID:
        raise HandshakeError("unexpected peer identity")

    own_public_index = 4 if state.role == GATEWAY_ROLE else 5
    own_nonce_index = 6 if state.role == GATEWAY_ROLE else 7

    if fields[own_public_index] != state.public_bytes():
        raise HandshakeError("local DH value does not match this session")
    if fields[own_nonce_index] != state.nonce:
        raise HandshakeError("local nonce does not match this session")

    return fields


def sign_transcript(state, transcript, signing_key):
    validate_local_transcript(state, transcript)
    return signing_key.sign(
        state.role + sha256(transcript), pss(), hashes.SHA256()
    )


def derive_keys(shared_secret, transcript_hash):
    if len(shared_secret) > DH_WIDTH:
        raise HandshakeError("shared secret exceeds group width")
    z = shared_secret.rjust(DH_WIDTH, b"\x00")
    master = sha256(b"CSCE465-KDF-v1" + z + transcript_hash)

    return SessionKeys(
        g2n_enc=mac(
            master, b"gateway-to-node encryption" + transcript_hash
        ),
        g2n_mac=mac(
            master, b"gateway-to-node MAC" + transcript_hash
        ),
        n2g_enc=mac(
            master, b"node-to-gateway encryption" + transcript_hash
        ),
        n2g_mac=mac(
            master, b"node-to-gateway MAC" + transcript_hash
        ),
        session_id=mac(
            master, b"session identifier" + transcript_hash
        )[:8],
    )


def finish_handshake(
    state, transcript, peer_role, peer_signature, trusted_peer_key
):
    fields = validate_local_transcript(state, transcript)
    expected_role = (
        NODE_ROLE if state.role == GATEWAY_ROLE else GATEWAY_ROLE
    )
    if peer_role != expected_role:
        raise HandshakeError("unexpected peer role")
    if (
        not isinstance(trusted_peer_key, rsa.RSAPublicKey)
        or trusted_peer_key.key_size != 3072
    ):
        raise HandshakeError("expected a trusted 3072-bit RSA public key")

    transcript_hash = sha256(transcript)
    try:
        trusted_peer_key.verify(
            peer_signature,
            peer_role + transcript_hash,
            pss(),
            hashes.SHA256(),
        )
    except InvalidSignature as error:
        raise HandshakeError("invalid peer signature") from error

    peer_index = 5 if state.role == GATEWAY_ROLE else 4
    numbers = state.private_key.parameters().parameter_numbers()
    peer_value = int.from_bytes(fields[peer_index], "big")

    if not 2 <= peer_value <= numbers.p - 2:
        raise HandshakeError("invalid peer DH public value")

    try:
        peer_public = dh.DHPublicNumbers(
            peer_value, numbers
        ).public_key()
        shared_secret = state.private_key.exchange(peer_public)
    except ValueError as error:
        raise HandshakeError("invalid peer DH public value") from error

    keys = derive_keys(shared_secret, transcript_hash)
    state.used = True
    state.private_key = None
    return keys


def run_handshake(parameters, gateway_key, node_key):
    gateway = new_pending(parameters, GATEWAY_ROLE)
    node = new_pending(parameters, NODE_ROLE)
    transcript = build_transcript(gateway, node)
    gateway_signature = sign_transcript(gateway, transcript, gateway_key)
    node_signature = sign_transcript(node, transcript, node_key)

    gateway_keys = finish_handshake(
        gateway, transcript, NODE_ROLE,
        node_signature, node_key.public_key()
    )
    node_keys = finish_handshake(
        node, transcript, GATEWAY_ROLE,
        gateway_signature, gateway_key.public_key()
    )
    return gateway_keys, node_keys, transcript


def main():
    parameters = load_parameters()
    gateway_key = load_or_create_signing_key("gateway-rsa.pem")
    node_key = load_or_create_signing_key("node-rsa.pem")
    print("RSA signing key sizes:", gateway_key.key_size, node_key.key_size)

    gateway = new_pending(parameters, GATEWAY_ROLE)
    node = new_pending(parameters, NODE_ROLE)
    transcript = build_transcript(gateway, node)
    gateway_signature = sign_transcript(gateway, transcript, gateway_key)
    node_signature = sign_transcript(node, transcript, node_key)
    fields = parse_transcript(transcript)
    print("Transcript field lengths:", [len(field) for field in fields])
    print("Transcript SHA-256:", sha256(transcript).hex())

    def reject(
        label, candidate, role=NODE_ROLE,
        signature=node_signature, public_key=None
    ):
        if public_key is None:
            public_key = node_key.public_key()
        try:
            finish_handshake(
                gateway, candidate, role, signature, public_key
            )
        except HandshakeError as error:
            print(f"REJECTED {label}: {error}")
        else:
            raise AssertionError(f"unsafe acceptance: {label}")

    bad_fields = fields.copy()
    bad_fields[7] = bytes([fields[7][0] ^ 1]) + fields[7][1:]
    reject("changed peer nonce", encode_fields(bad_fields))

    bad_fields = fields.copy()
    bad_fields[5] = bytes([fields[5][0] ^ 1]) + fields[5][1:]
    reject("changed peer DH value", encode_fields(bad_fields))

    bad_fields = fields.copy()
    bad_fields[3] = b"unexpected-node"
    reject("unexpected identity", encode_fields(bad_fields))

    malformed = (0xffffffff).to_bytes(4, "big") + transcript[4:]
    reject("malformed length", malformed)

    bad_signature = (
        bytes([node_signature[0] ^ 1]) + node_signature[1:]
    )
    reject("invalid RSA-PSS signature", transcript, signature=bad_signature)
    reject(
        "incorrect RSA public key", transcript,
        public_key=gateway_key.public_key()
    )
    reject(
        "reflected handshake", transcript,
        role=GATEWAY_ROLE, signature=gateway_signature
    )

    gateway_keys = finish_handshake(
        gateway, transcript, NODE_ROLE,
        node_signature, node_key.public_key()
    )
    node_keys = finish_handshake(
        node, transcript, GATEWAY_ROLE,
        gateway_signature, gateway_key.public_key()
    )
    assert gateway_keys == node_keys
    separated = {
        gateway_keys.g2n_enc, gateway_keys.g2n_mac,
        gateway_keys.n2g_enc, gateway_keys.n2g_mac,
    }
    assert len(separated) == 4
    assert all(len(key) == 32 for key in separated)
    assert len(gateway_keys.session_id) == 8

    print("PASS: both parties derived identical session material.")
    print("PASS: four distinct 32-byte directional keys.")
    print("Session 1 identifier:", gateway_keys.session_id.hex())

    second_gateway, second_node, second_transcript = run_handshake(
        parameters, gateway_key, node_key
    )
    second_fields = parse_transcript(second_transcript)
    assert second_gateway == second_node
    assert all(fields[index] != second_fields[index] for index in (4, 5, 6, 7))
    assert second_gateway.session_id != gateway_keys.session_id
    print("Session 2 identifier:", second_gateway.session_id.hex())
    print("PASS: fresh DH public values and nonces in the second session.")
    print("All Task 2 demonstration checks passed.")


if __name__ == "__main__":
    main()
