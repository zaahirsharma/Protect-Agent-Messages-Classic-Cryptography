# Homework 2: Protect Agent Messages with Classic Cryptography

This project simulates a gateway and node locally within one Python process.
It demonstrates the limitations of encryption alone, authenticated ephemeral
Diffie-Hellman key establishment, and an encrypt-then-MAC record layer.
Application commands are logged as simulated actions; they do not execute
shell commands or access the named files. Network sockets, OpenClaw, and
model-provider API credentials are not required.

## Verified environment

The supplied evidence records execution inside the course Ubuntu VM:

- Python 3.12.3
- OpenSSL 3.0.13
- cryptography 49.0.0
- pytest 9.1.1

Use the course VM with NAT networking, as required by the assignment.
OpenSSL 3.0 or newer and Python's matching venv support are needed.
The recorded VM required installation of `python3.12-venv`.

## Set up the environment

Open a terminal in the `hw2` directory and run:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If venv creation reports that ensurepip is unavailable, install the matching
venv package. For the recorded Python 3.12 Ubuntu environment:

```bash
sudo apt update
sudo apt install python3.12-venv
```

Then rerun environment creation as the normal user. Do not create the venv
with sudo. When using the original course environment instead, activate
`$HOME/csce465-agentsec/.venv/bin/activate` before entering `hw2`.

## Verify the DH parameters

The included `ffdhe3072.pem` contains public parameters generated in Task 0.
Verify it with:

```bash
openssl dhparam -in ffdhe3072.pem -text -noout
```

Expected identification: `DH Parameters: (3072 bit)` and `GROUP: ffdhe3072`.
To regenerate the parameter file if needed:

```bash
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
```

## Run the demonstrations

```bash
python baseline_ctr.py
python handshake.py
python secure_record.py
```

- `baseline_ctr.py`: AES-CTR without a MAC. A keyless simulated relay changes
  READ to WAIT, displays the XOR relation, and demonstrates replay acceptance.
- `handshake.py`: authenticates a canonical length-prefixed transcript using
  3072-bit RSA-PSS/SHA-256 signing keys, fresh ffdhe3072 values and nonces,
  identity/role checks, and the assignment's exact key derivation. It checks
  successful exchange, rejected invalid exchanges, and session freshness.
- `secure_record.py`: implements `seal()` and `open_record()` using AES-256-CTR
  and HMAC-SHA-256, directional keys, strict sequencing, and verification
  before decryption. It demonstrates successful bidirectional messages and
  rejection of tampering, reflection, replay, and out-of-order delivery.

Each demonstration should end with its corresponding passing message.
Fresh random values mean ciphertexts and session identifiers vary by run.

## Run the automated tests

```bash
python -m pytest tests/ -v --tb=short
```

The provided evidence reports 42 passing cases: 18 handshake cases and
24 record-layer cases. Execution time varies. Tests cover all six required
categories and additional malformed inputs, exact KDF padding, pending-session
binding, sequence exhaustion, and record-length limits. Negative cases assert
specific errors. Guards verify that rejected records do not reach decryption.

To save a new test log in the VM:

```bash
mkdir -p evidence
set -o pipefail
python -m pytest tests/ -v --tb=short 2>&1 | tee evidence/task4-pytest.txt
```

## Record format and limits

Wire representation: `header || iv || ciphertext || tag`.

- Header: version(1 byte), direction(1 byte), sequence(8 bytes),
  message_type(1 byte), ciphertext_length(4 bytes).
- Numeric fields use big-endian encoding. The header occupies 15 bytes.
- Version: 1. Direction: 1 for gateway-to-node, 2 for node-to-gateway.
- IV: `session_id(8 bytes) || sequence(8 bytes)`.
- Encryption: AES-256-CTR with the appropriate directional encryption key.
- Authentication: full 32-byte HMAC-SHA-256 over header, IV, and ciphertext.

Plaintext is limited to 16 bytes per record. With the prescribed IV layout
and consecutive sequence numbers, multi-block records would overlap CTR
counter values. Oversized records are rejected. Arbitrary-length messages
and fragmentation are not implemented.

Each endpoint pair belongs to one fresh session. Preserve its state throughout
that session: never reset counters or recreate endpoints with the same keys.
Counters do not wrap; exhaustion requires a new handshake. If sender encryption
fails after sequence reservation, abandon that session. This simulation is
sequential and does not implement concurrent access or persistent resumption.

## Local signing keys

On the first handshake run, course-only RSA signing keys are generated in
`local_keys/`; later runs reuse them. Both endpoints receive the expected
peer public key through trusted local setup. No certificate infrastructure
or remote key enrollment is implemented.

The key files, virtual environments, and caches are excluded from the transfer
archive and should remain excluded from the final submission. The grader can
regenerate signing keys by running the project. Include `ffdhe3072.pem`, which
contains public group parameters. Private DH values, shared secrets, and
derived traffic keys are not printed by the demonstrations.

## Project files and evidence

```text
hw2/
  baseline_ctr.py
  handshake.py
  secure_record.py
  ffdhe3072.pem
  requirements.txt
  README.md
  AI_USAGE.md
  AILogs.txt
  report.pdf
  tests/
    conftest.py
    test_handshake.py
    test_secure_record.py
  evidence/
    python-version.txt
    openssl-version.txt
    python-packages.txt
    dh-group.txt
    task1-baseline.txt
    task2-handshake.txt
    task3-records.txt
    task4-pytest.txt
```

`report.pdf` is the main graded deliverable. Include the student-reviewed
explanations, required evidence, and 500-700 word security note. Complete and
review `AI_USAGE.md`, and retain the actual prompts and responses in `AILogs.txt`.
These instructions do not establish that the final PDF has already been created.

Submit a Git repository or an archive of one containing the required files.
The directory structure above describes the intended final submission.
