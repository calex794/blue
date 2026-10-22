# Blue W3 v3 — opaque recipient invitation routing (experimental)

## Evidence and reason

The current W3 v2 public header includes sender identity in bytes 41..57
and recipient identity in bytes 17..33, as verified directly from
the pinned Blue and WOW code. End-to-end payload encryption alone does
**NOT** protect the social graph.

[Blue issue #2](https://github.com/calex794/blue/issues/2) tracks this
blocking privacy gap before LABO routing can enter Akula production.

## New experimental v3 profile (no automatic v2 upgrade/downgrade)

- The only specified public 41 bytes are: version (1), random message ID
  (16), an out-of-band privately provisioned 128-bit route token (16),
  expiry milliseconds (8). HPKE KEM encapsulation and encrypted signed
  body follow. There is **no sender ID, recipient ID, or signer key epoch**
  in this outer header. The token must be independent of public identities.
- Exact recipient identity, sender identity, current signing-key epoch and
  application payload are inside one Ed25519 COSE Sign1, sealed using
  existing X25519 HPKE + ChaCha20Poly1305 + HKDF-SHA256 crates.
- Domain-separated v3 HPKE info and full public header as AAD and COSE
  external AAD; forged header, ciphertext, identity binding or sender
  signature is rejected. Trust registry must already authorize sender
  identity/epoch. No TOFU, ACL grant, or public signers from received bytes.
- Public metadata parse is explicitly **unauthenticated** and not evidence
  of receipt or identity. Recipient must verify its separately provisioned
  route token and own HPKE key. Blue returns a private-field VerifiedW3
  only after verified HPKE/COSE and identity binding.
- Existing v2 seal/open behavior and test vectors remain unchanged. An old
  v2 parser rejects a v3 packet and vice versa; explicit compatibility
  negotiation is needed rather than a silent plaintext downgrade.

## Limitations

**NOT ANONYMITY:** identical ciphertext/message ID/route token can be
linked across relays. Route tokens need recipient-controlled issuance,
TTL overlap, storage, replay controls and rotation before real deployment.
The matching recipient mail inbox, W4 recipient-signed receipt, retry
journals and signed invitations must ALSO avoid public identities; current
W4 ACK is still openly identifying. The outer token is only private if
the separate invitation was authenticated and never derived from a public
identity. This code does not implement invitations, consent, installed
mobile transports, an Akula/Sync Core ACL gate, nor actual physical delivery.

Next: return-path private W4 receipt wrapper, strict token rotation and
encrypted invitation, test multihop delivery with pinned WOW W4 and
an independently reviewed wire-format specification.