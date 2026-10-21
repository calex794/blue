//! Auditable WOW W3 v2 crypto boundary, separate from any network stack.
//!
//! This is experimental wire compatibility, NOT a production messaging system.
//! Authentication here is a snapshot of the caller's independently approved
//! sender-key mapping; Akula MUST re-check authorization and revocation with
//! its durable inbox commit. No transport peer can establish W3 trust.

#![forbid(unsafe_code)]

use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    OpModeS, Serializable,
};

type X25519 = X25519HkdfSha256;

/// Matches WOW W3 v2's maximum entire packet size.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
/// Original WOW W3 identity-bound format, not a final release wire suite.
pub const W3_VERSION: u8 = 2;
const HEADER_BYTES: usize = 1 + 16 + 16 + 8 + 16 + 8;
const ENCAP_BYTES: usize = 32;
const INFO: &[u8] = b"Akula/WOW/W3/device-epoch-v2/HPKE-COSE";

/// HPKE recipient key types matching WOW W3 v2.
pub type RecipientSecret = <X25519 as Kem>::PrivateKey;
pub type RecipientPublic = <X25519 as Kem>::PublicKey;

/// Low-level recipient keypair primitive; enrollment remains Akula's job.
pub fn new_recipient() -> (RecipientSecret, RecipientPublic) {
    X25519::gen_keypair()
}

/// Authenticated W3 header. The wire encodes expiry as Unix milliseconds.
///
/// This structure is not proof of authenticity on its own; only VerifiedW3
/// may be treated as cryptographically authenticated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignedHeader {
    pub message_id: [u8; 16],
    pub recipient_id: [u8; 16],
    pub expires_at_ms: u64,
    pub sender_id: [u8; 16],
    pub epoch: u64,
}

impl SignedHeader {
    fn check(&self) -> Result<(), W3Error> {
        if self.message_id == [0; 16]
            || self.epoch == 0
            || self.epoch > i64::MAX as u64
            || self.expires_at_ms == 0
            || self.expires_at_ms > i64::MAX as u64
        {
            return Err(W3Error::InvalidDescriptor);
        }
        Ok(())
    }

    fn wire_bytes(&self) -> [u8; HEADER_BYTES] {
        let mut out = [0; HEADER_BYTES];
        out[0] = W3_VERSION;
        out[1..17].copy_from_slice(&self.message_id);
        out[17..33].copy_from_slice(&self.recipient_id);
        out[33..41].copy_from_slice(&self.expires_at_ms.to_be_bytes());
        out[41..57].copy_from_slice(&self.sender_id);
        out[57..65].copy_from_slice(&self.epoch.to_be_bytes());
        out
    }

    fn parse(packet: &[u8]) -> Result<Self, W3Error> {
        if packet.len() < HEADER_BYTES {
            return Err(W3Error::InvalidPacket);
        }
        if packet[0] != W3_VERSION {
            return Err(W3Error::UnsupportedVersion);
        }
        let mut message_id = [0; 16];
        let mut recipient_id = [0; 16];
        let mut sender_id = [0; 16];
        let mut expires_at_ms = [0; 8];
        let mut epoch = [0; 8];
        message_id.copy_from_slice(&packet[1..17]);
        recipient_id.copy_from_slice(&packet[17..33]);
        expires_at_ms.copy_from_slice(&packet[33..41]);
        sender_id.copy_from_slice(&packet[41..57]);
        epoch.copy_from_slice(&packet[57..65]);
        let header = Self {
            message_id,
            recipient_id,
            expires_at_ms: u64::from_be_bytes(expires_at_ms),
            sender_id,
            epoch: u64::from_be_bytes(epoch),
        };
        header.check()?;
        Ok(header)
    }
}

/// Explicit failure without leaking decrypted payloads or keys through errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum W3Error {
    Oversized,
    InvalidPacket,
    InvalidDescriptor,
    UnsupportedVersion,
    WrongRecipient,
    Expired,
    UntrustedSender,
    DecryptFailed,
    InvalidSignature,
}

impl std::fmt::Display for W3Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for W3Error {}

/// Must be backed by an out-of-band authorized device enrollment/revocation
/// system. NEVER return a key supplied by the received packet, QUIC peer,
/// relay, or unauthenticated network profile. No TOFU is performed here.
///
/// This check cannot act as the atomic revocation fence for a later SQLite
/// commit. Akula must independently authorize the current version at commit.
pub trait TrustedSenderKeys {
    fn key_for(&self, sender_id: [u8; 16], epoch: u64) -> Option<VerifyingKey>;
}

/// Inputs controlled by the receiving application, not by the wire.
pub struct OpenContext<'a> {
    pub secret: &'a RecipientSecret,
    pub recipient_id: [u8; 16],
    pub now_ms: u64,
    pub trusted_sender_keys: &'a dyn TrustedSenderKeys,
}

/// Cryptographically verified WOW W3 v2 packet. Unforgeable via safe public
/// constructors: fields are private and this type implements no Deserialize,
/// Default, Clone, or caller-supplied "already verified" shortcut.
///
/// IMPORTANT: Authentication is not authorization. It does not grant file
/// access, approve a device, or prove the current revocation/ACL state.
pub struct VerifiedW3<'packet> {
    header: SignedHeader,
    original_packet: &'packet [u8],
    packet_digest: [u8; 32],
    payload: Vec<u8>,
}

impl VerifiedW3<'_> {
    pub fn header(&self) -> SignedHeader {
        self.header
    }

    /// Exact original ciphertext: never re-serialize for W4 journaling.
    pub fn original_packet(&self) -> &[u8] {
        self.original_packet
    }

    /// BLAKE3 digest of the exact received ciphertext, compatible with W4.
    pub fn packet_digest(&self) -> [u8; 32] {
        self.packet_digest
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Decode WOW W3 v2 only after authenticated sender-key lookup, HPKE
/// decryption and COSE Ed25519 signature verification over the ORIGINAL
/// 65-byte header as external AAD.
///
/// The caller MUST apply current application rights and the revocation fence
/// before a durable W4 inbox commit. A verified cryptographic packet is not
/// permission to issue a recipient receipt.
pub fn open_verified<'packet>(
    packet: &'packet [u8],
    ctx: OpenContext<'_>,
) -> Result<VerifiedW3<'packet>, W3Error> {
    if packet.len() > MAX_MESSAGE_BYTES {
        return Err(W3Error::Oversized);
    }
    if packet.len() <= HEADER_BYTES + ENCAP_BYTES + 16 {
        return Err(W3Error::InvalidPacket);
    }

    let header = SignedHeader::parse(packet)?;
    if header.recipient_id != ctx.recipient_id {
        return Err(W3Error::WrongRecipient);
    }
    if ctx.now_ms >= header.expires_at_ms {
        return Err(W3Error::Expired);
    }

    let sender_key = ctx
        .trusted_sender_keys
        .key_for(header.sender_id, header.epoch)
        .ok_or(W3Error::UntrustedSender)?;
    let encapsulated =
        <X25519 as Kem>::EncappedKey::from_bytes(&packet[HEADER_BYTES..HEADER_BYTES + ENCAP_BYTES])
            .map_err(|_| W3Error::InvalidPacket)?;

    let decrypted = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519>(
        &OpModeR::Base,
        ctx.secret,
        &encapsulated,
        INFO,
        &packet[HEADER_BYTES + ENCAP_BYTES..],
        &packet[..HEADER_BYTES],
    )
    .map_err(|_| W3Error::DecryptFailed)?;

    let signed = CoseSign1::from_slice(&decrypted).map_err(|_| W3Error::InvalidSignature)?;
    if signed.protected.header.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA))
        || signed.unprotected != coset::Header::default()
    {
        return Err(W3Error::InvalidSignature);
    }
    signed
        .verify_signature(&packet[..HEADER_BYTES], |signature, bytes| {
            let signature = Signature::from_slice(signature).map_err(|_| ())?;
            sender_key.verify(bytes, &signature).map_err(|_| ())
        })
        .map_err(|_| W3Error::InvalidSignature)?;
    let payload = signed.payload.ok_or(W3Error::InvalidSignature)?;

    Ok(VerifiedW3 {
        header,
        original_packet: packet,
        packet_digest: *blake3::hash(packet).as_bytes(),
        payload,
    })
}

/// Emit the same W3 v2 wire format as the existing WOW crypto_identity_w3
/// implementation: header || HPKE(X25519, ChaCha20Poly1305, COSE Sign1).
///
/// Signing or encrypting does NOT enroll the sender or authorize a recipient.
pub fn seal_v2(
    signer: &SigningKey,
    recipient: &RecipientPublic,
    header: SignedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, W3Error> {
    header.check()?;
    if payload.len() > MAX_MESSAGE_BYTES.saturating_sub(512) {
        return Err(W3Error::Oversized);
    }

    let aad = header.wire_bytes();
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
        .map_err(|_| W3Error::InvalidPacket)?;

    let (encapsulated, ciphertext) =
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519>(
            &OpModeS::Base,
            recipient,
            INFO,
            &signed,
            &aad,
        )
        .map_err(|_| W3Error::InvalidPacket)?;

    let mut wire = Vec::with_capacity(HEADER_BYTES + ENCAP_BYTES + ciphertext.len());
    wire.extend_from_slice(&aad);
    wire.extend_from_slice(&encapsulated.to_bytes());
    wire.extend_from_slice(&ciphertext);
    if wire.len() > MAX_MESSAGE_BYTES {
        return Err(W3Error::Oversized);
    }
    Ok(wire)
}
