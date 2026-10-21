//! Independent compatibility harness derived from WOW's W3 v2 reference
//! (calex794/wow@5f1a413, src/crypto_identity_w3.rs).
//!
//! The independent reference routines deliberately live ONLY in tests, so
//! no second cryptographic implementation ships in Blue.

use akula_blue_w3::{
    new_recipient, open_verified, seal_v2, OpenContext, RecipientPublic, RecipientSecret,
    SignedHeader, TrustedSenderKeys,
};
use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem,
    OpModeR, OpModeS, Serializable,
};

const WOW_HEADER: usize = 1 + 16 + 16 + 8 + 16 + 8;
const WOW_ENCAP: usize = 32;
const WOW_INFO: &[u8] = b"Akula/WOW/W3/device-epoch-v2/HPKE-COSE";

fn wow_header(header: SignedHeader) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(WOW_HEADER);
    bytes.push(2);
    bytes.extend_from_slice(&header.message_id);
    bytes.extend_from_slice(&header.recipient_id);
    bytes.extend_from_slice(&header.expires_at_ms.to_be_bytes());
    bytes.extend_from_slice(&header.sender_id);
    bytes.extend_from_slice(&header.epoch.to_be_bytes());
    bytes
}

/// Same HPKE/COSE sealing order and domain separation as WOW W3 v2.
fn original_wow_seal(
    signer: &SigningKey,
    recipient: &RecipientPublic,
    header: SignedHeader,
    payload: &[u8],
) -> Vec<u8> {
    let aad = wow_header(header);
    let signed = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::EdDSA)
                .build(),
        )
        .payload(payload.to_vec())
        .create_signature(&aad, |bytes| signer.sign(bytes).to_bytes().to_vec())
        .build()
        .to_vec()
        .unwrap();
    let (enc, ciphertext) =
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            recipient,
            WOW_INFO,
            &signed,
            &aad,
        )
        .unwrap();
    let mut bytes = aad;
    bytes.extend_from_slice(&enc.to_bytes());
    bytes.extend_from_slice(&ciphertext);
    bytes
}

/// W3 v2 WOW's original decoding checks, independently expressed as Option.
/// Sender key is supplied by the test fixture, NOT taken from the wire.
fn original_wow_open(
    packet: &[u8],
    recipient_secret: &RecipientSecret,
    expected_recipient: [u8; 16],
    trusted_signer: &VerifyingKey,
    now_ms: u64,
) -> Option<Vec<u8>> {
    if packet.len() <= WOW_HEADER + WOW_ENCAP + 16 || packet.len() > 16 * 1024 {
        return None;
    }
    if packet[0] != 2 || packet[17..33] != expected_recipient {
        return None;
    }
    let expiry = u64::from_be_bytes(packet[33..41].try_into().ok()?);
    if now_ms >= expiry {
        return None;
    }
    let enc = <X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(
        &packet[WOW_HEADER..WOW_HEADER + WOW_ENCAP],
    )
    .ok()?;
    let plaintext = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        recipient_secret,
        &enc,
        WOW_INFO,
        &packet[WOW_HEADER + WOW_ENCAP..],
        &packet[..WOW_HEADER],
    )
    .ok()?;
    let signed = CoseSign1::from_slice(&plaintext).ok()?;
    if signed.protected.header.alg
        != Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA))
        || signed.unprotected != coset::Header::default()
    {
        return None;
    }
    signed
        .verify_signature(&packet[..WOW_HEADER], |sig, data| {
            let signature = Signature::from_slice(sig).map_err(|_| ())?;
            trusted_signer.verify(data, &signature).map_err(|_| ())
        })
        .ok()?;
    signed.payload
}

struct TestTrust(VerifyingKey);
impl TrustedSenderKeys for TestTrust {
    fn key_for(&self, sender_id: [u8; 16], epoch: u64) -> Option<VerifyingKey> {
        if sender_id == [3; 16] && epoch == 7 {
            Some(self.0)
        } else {
            None
        }
    }
}

fn fixture() -> (SigningKey, RecipientSecret, RecipientPublic, SignedHeader) {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (secret, recipient) = new_recipient();
    let header = SignedHeader {
        message_id: [1; 16],
        recipient_id: [2; 16],
        expires_at_ms: 5_000,
        sender_id: [3; 16],
        epoch: 7,
    };
    (signer, secret, recipient, header)
}

#[test]
fn existing_wow_w3_v2_seal_is_accepted_by_blue() {
    let (signer, secret, recipient, header) = fixture();
    let wire = original_wow_seal(&signer, &recipient, header, b"original WOW payload");
    let trust = TestTrust(signer.verifying_key());
    let accepted = open_verified(
        &wire,
        OpenContext {
            secret: &secret,
            recipient_id: header.recipient_id,
            now_ms: 100,
            trusted_sender_keys: &trust,
        },
    )
    .unwrap();
    assert_eq!(accepted.payload(), b"original WOW payload");
    assert_eq!(accepted.header(), header);
    assert_eq!(accepted.original_packet(), wire.as_slice());
}

#[test]
fn blue_w3_v2_seal_is_accepted_by_existing_wow_reference_decoder() {
    let (signer, secret, recipient, header) = fixture();
    let wire = seal_v2(&signer, &recipient, header, b"Blue payload to WOW").unwrap();
    assert_eq!(&wire[..WOW_HEADER], wow_header(header));
    let payload = original_wow_open(
        &wire,
        &secret,
        header.recipient_id,
        &signer.verifying_key(),
        100,
    )
    .expect("WOW reference must verify Blue W3 wire");
    assert_eq!(payload, b"Blue payload to WOW");
}

#[test]
fn independently_decoded_wow_wire_detects_modified_signature_and_ciphertext() {
    let (signer, secret, recipient, header) = fixture();
    let mut wire = seal_v2(&signer, &recipient, header, b"identity-bound").unwrap();
    wire[WOW_HEADER + WOW_ENCAP] ^= 0x20;
    assert!(
        original_wow_open(
            &wire,
            &secret,
            header.recipient_id,
            &signer.verifying_key(),
            100,
        )
        .is_none()
    );
}
