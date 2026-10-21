# Blue — verified WOW W3 primitives

Small, transport-independent Rust library for the experimental WOW W3 v2 encrypted/signed message format.

Blue is intended to become the common cryptographic boundary used by WOW and Akula. It does not implement network transport, endpoint discovery, account enrollment, message authorization, durable inbox/outbox, or final W4 delivery receipts.

**Security status: laboratory code, not approved for production.** The W3 v2 format currently used by WOW is itself experimental. Completing this crate does not automatically approve the format or its key lifecycle.

## Boundary

- The W3 packet is capped at **16 KiB before decryption or decoding**.
- HPKE Base (RFC 9180) decrypts for the expected recipient; COSE_Sign1/Ed25519 authenticates the sender with the complete W3 v2 header as external AAD.
- `open_verified` gets sender keys from an explicitly provisioned `TrustedSenderKeys` interface, **never from the packet or TLS connection**.
- On success, it returns `VerifiedW3` with **private fields** and accessors for the original immutable ciphertext, its BLAKE3 digest, authenticated header and payload.
- Blue verification is a snapshot, **not authorization to commit**. Akula must validate its own recipient/sender permissions and the **current trust epoch under a consistent commit/revocation fence** before calling its W4 inbox. No constructor accepting arbitrary claimed verification is exposed.
- Expiry on the W3 v2 wire is an unsigned **Unix millisecond** timestamp in this library. Consumers must not pass seconds.

Transport endpoint identity (Roha/QUIC) is **not** the W3 application sender identity. Relay and QUIC acknowledgments are **not** signed W4 recipient receipts.

## Scope and dependencies

Pure Rust library: no Roha, noq, UDP, GUI, timers, SQLite or background workers. W3 sealing is included for compatibility and shared format ownership, but no key generation or registration is performed on behalf of a user (the HPKE recipient-key generation helper is an isolated primitive).

## Verification

```sh
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

The integration tests preserve the WOW W3 v2 header/domain separation and contain an independently compiled reference codec derived from [WOW main at 5f1a413](https://github.com/calex794/wow/blob/5f1a4138799f85f647760f1c49df83ca1242e213/src/crypto_identity_w3.rs); they check packets in both directions and reject modified, expired or untrusted messages. CI is one targeted job to avoid unnecessary matrix fan-out.

## Project links

- [E2E-01: Akula message to another PC](https://app.notion.com/p/40032a84beec81349bafc1ecd765dd58)
- [W3 → Akula: theory, invariants and acceptance](https://app.notion.com/p/40032a84beec816e9938e227324acbf8)
- [WOW W3 v2 source](https://github.com/calex794/wow/blob/5f1a4138799f85f647760f1c49df83ca1242e213/src/crypto_identity_w3.rs)

Next: prove the Blue API and security invariants with its CI; only then propose replacing WOW's duplicate crypto functions and connecting Akula's authenticated inbox boundary. Keep both consumers on an exact Blue revision, not a floating branch.
