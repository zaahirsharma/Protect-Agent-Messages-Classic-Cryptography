
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


ORIGINAL = b'{"action":"READ","path":"notes.txt"}'
EXPECTED = b'{"action":"WAIT","path":"notes.txt"}'


def xor_bytes(left, right):
    if len(left) != len(right):
        raise ValueError("XOR inputs must have equal lengths")
    return bytes(a ^ b for a, b in zip(left, right))


def encrypt(key, iv, plaintext):
    encryptor = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def relay(ciphertext):
    """Alter only this lab's known READ field; no key is supplied."""
    offset = ORIGINAL.index(b"READ")
    difference = xor_bytes(b"READ", b"WAIT")
    modified = bytearray(ciphertext)

    for index, mask in enumerate(difference):
        modified[offset + index] ^= mask

    return bytes(modified)


class SimulatedReceiver:
    """Logs accepted commands; never performs file or shell operations."""

    def __init__(self, key):
        self.key = key
        self.processed = []

    def receive(self, iv, ciphertext):
        decryptor = Cipher(
            algorithms.AES(self.key), modes.CTR(iv)
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        command = json.loads(plaintext)

        # Intentionally no MAC verification or replay protection.
        self.processed.append(command)
        print(
            f"Processed #{len(self.processed)}: "
            f"action={command['action']}, path={command['path']}"
        )
        return plaintext


def main():
    key = os.urandom(32)
    iv = os.urandom(16)
    ciphertext = encrypt(key, iv, ORIGINAL)

    print("DEMONSTRATION 1: ciphertext modification")
    print("Original plaintext:", ORIGINAL.decode())
    print("IV:", iv.hex())
    print("Original ciphertext:", ciphertext.hex())

    receiver = SimulatedReceiver(key)
    assert receiver.receive(iv, ciphertext) == ORIGINAL

    modified = relay(ciphertext)
    print("Modified ciphertext:", modified.hex())
    recovered = receiver.receive(iv, modified)
    print("Modified plaintext:", recovered.decode())
    assert recovered == EXPECTED

    print("\nXOR relation: C XOR C' = P XOR P'")
    plaintext_difference = xor_bytes(ORIGINAL, EXPECTED)
    ciphertext_difference = xor_bytes(ciphertext, modified)
    assert ciphertext_difference == plaintext_difference

    offset = ORIGINAL.index(b"READ")
    print("READ bytes:", b"READ".hex())
    print("WAIT bytes:", b"WAIT".hex())
    print("Plaintext XOR:", plaintext_difference[offset:offset + 4].hex())
    print("Ciphertext XOR:", ciphertext_difference[offset:offset + 4].hex())
    print("PASS: relay changed READ to WAIT without receiving the key.")

    print("\nDEMONSTRATION 2: replay")
    replay_receiver = SimulatedReceiver(key)
    first = replay_receiver.receive(iv, ciphertext)
    second = replay_receiver.receive(iv, ciphertext)

    assert first == second == ORIGINAL
    assert len(replay_receiver.processed) == 2
    print("PASS: the identical IV and ciphertext were processed twice.")
    print("\nAll Task 1 demonstration checks passed.")


if __name__ == "__main__":
    main()
