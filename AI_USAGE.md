# AI Usage

## Tool/model and date

OpenAI Codex, recorded model `gpt-6.1-sol`.
Assistance occurred on October 2 and October 4, 2026.

## Purpose

Interpret the assignment; provide terminal commands; troubleshoot Python
virtual-environment setup; generate implementation code and automated tests;
explain encryption, integrity, DH authentication, replay resistance, forward
secrecy, and key separation; draft and revise the report and documentation;
and guide and verify file transfer from the course VM to the Mac.

## AI Conversation Log files

`AILogs.txt` contains actual user-prompt/final-response pairs, from the
first Homework 2 request through delivery of the README and AI documentation.
It is a condensed record: routine progress updates are omitted, and complete
file inputs/outputs and report-section bodies in their final versions are seen in the submission.
Relevant user-provided text attachments are included. Internal
reasoning and system/developer instructions are omitted. Personal Mac home
paths are redacted. The exchanges are actual, not an invented conversation.

The README rewrite, log export, AI-use description, and subsequent log
reformatting and condensation were also prepared with AI assistance. The
current formatting requests and delivery occur after the logged exchanges.

## What I used it for

AI-generated commands and adivising along the programming for `baseline_ctr.py`, `handshake.py`,
`secure_record.py`, and the tests files under `tests/`. AI also helped me revise my final report versions.I ran any implementation fixes and testing inside the VM and supplied actual terminal results.

## What I changed

I accepted all code crticism and optimzaions, but the report revisions were heavily combatted. I kept Task 0 screenshot-based, as it was simply set up, shortened Task 2, and revised Tasks 1, 3, and 4 around their report requirements. Those revisions were AI-assisted in the end. The visible VM runs used the assisted implementation and testing structure.

## How I tested it

Captured Python 3.12.3, OpenSSL 3.0.13, cryptography 49.0.0, and pytest 9.1.1
versions. Verified ffdhe3072 with 3072-bit parameters. Ran all three
demonstrations and the full pytest suite. The transferred evidence records
42 passing tests in 3.95 seconds. Tests assert specific failures and use
guards against decryption or derivation on rejected inputs. Transfer review
confirmed that decoded Base64 matched the archive and all 18 extracted files
matched their archive contents. Code syntax was checked without executing
the coursework on the Mac.

Review the replacement README and the log for accuracy before submission;
the documentation changes do not change the cryptographic implementation.

## One error, limitation, or rejected suggestion

The initial venv creation failed because the matching python3.12-venv package
was missing. It was installed, and ownership was repaired after a sudo creation
attempt. The environment was then recreated as the normal user.

The implementation has an explicit 16-byte record limit to prevent CTR counter
block overlap under the prescribed IV layout and consecutive record sequences.
It does not implement concurrency, session resumption, or guaranteed secure
memory erasure. The first transferred README was truncated; a complete
replacement was prepared. Synthetic conversations were not substituted for
the actual assistance record.
