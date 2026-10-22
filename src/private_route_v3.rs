//! Experimental private-routing W3 v3: hide sender and recipient identities
//! inside authenticated HPKE ciphertext. The public route token must be
//! RANDOMLY provisioned by a trusted recipient invitation; NEVER derive it
//! from a public sender/recipient key. Tokens/ciphertexts are linkable, so
//! this does not make forwarding anonymous. W4 receipts remain a separate
//! privacy problem and production Akula MUST NOT activate this lab format.

use crate::{
    OpenContext, RecipientPublic, SignedHeader, VerifiedW3, W3Error, X25519, MAX_MESSAGE_BYTES,
};
use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, Deserializable, Kem, OpModeR, OpModeS,
    Serializable,
};

/// v3 public bytes: version | opaque MessageId | opaque recipient invitation
/// route token | expiration. NO sender_id, recipient_id, or key epoch.
pub const VERSION: u8 = 3;
pub const PUBLIC_HEADER_BYTES: usize = 1 + 16 + 16 + 8;
const IDENTITY_BYTES: usize = 16 + 16 + 8;
const ENCAP_BYTES: usize = 32;
const INFO: &[u8] = b"Akula/WOW/W3/v3/private-route/HPKE-COSE";

/// Parsed, **unauthenticated** routing hint. It has no access rights.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteHint {
    pub message_id: [u8; 16],
    pub token: [u8; 16],
    pub expires_at_ms: u64,
}

fn parse_header(packet: &[u8]) -> Result<RouteHint, W3Error> {
    if packet.len() < PUBLIC_HEADER_BYTES {
        return Err(W3Error::InvalidPacket);
    }
    if packet[0] != VERSION {
        return Err(W3Error::UnsupportedVersion);
    }
    let mut message_id = [0; 16];
    let mut token = [0; 16];
    message_id.copy_from_slice(&packet[1..17]);
    token.copy_from_slice(&packet[17..33]);
    let expires_at_ms = u64::from_be_bytes(
        packet[33..41].try_into().map_err(|_| W3Error::InvalidPacket)?,
    );
    if message_id == [0; 16]
        || token == [0; 16]
        || expires_at_ms == 0
        || expires_at_ms > i64::MAX as u64
    {
        return Err(W3Error::InvalidDescriptor);
    }
    Ok(RouteHint {
        message_id,
        token,
        expires_at_ms,
    })
}

/// Relay-facing parse: metadata only, NOT verified sender or recipient.
pub fn inspect_route(packet: &[u8]) -> Result<RouteHint, W3Error> {
    if packet.len() > MAX_MESSAGE_BYTES {
        return Err(W3Error::Oversized);
    }
    parse_header(packet)
}

/// Securely seal a v3 packet. The route token is an opaque 128-bit value from
/// a previously authenticated invite; it is caller supplied, not guessed.
/// The exact signed identity fields are moved INSIDE the HPKE/COSE payload.
pub fn seal_private_v3(
    signer: &SigningKey,
    recipient: &RecipientPublic,
    token: [u8; 16],
    header: SignedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, W3Error> {
    header.check()?;
    if token == [0; 16] {
        return Err(W3Error::InvalidDescriptor);
    }
    if payload.len() > MAX_MESSAGE_BYTES.saturating_sub(640) {
        return Err(W3Error::Oversized);
    }
    let mut public = [0_u8; PUBLIC_HEADER_BYTES];
    public[0] = VERSION;
    public[1..17].copy_from_slice(&header.message_id);
    public[17..33].copy_from_slice(&token);
    public[33..41].copy_from_slice(&header.expires_at_ms.to_be_bytes());

    let mut private = Vec::with_capacity(IDENTITY_BYTES + payload.len());
    private.extend_from_slice(&header.recipient_id);
    private.extend_from_slice(&header.sender_id);
    private.extend_from_slice(&header.epoch.to_be_bytes());
    private.extend_from_slice(payload);
    let signed = CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::EdDSA)
                .build(),
        )
        .payload(private)
        .create_signature(&public, |bytes| signer.sign(bytes).to_bytes().to_vec())
        .build()
        .to_vec()
        .map_err(|_| W3Error::InvalidPacket)?;

    let (encapsulated, ciphertext) =
        hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519>(
            &OpModeS::Base,
            recipient,
            INFO,
            &signed,
            &public,
        )
        .map_err(|_| W3Error::InvalidPacket)?;
    let mut out = Vec::with_capacity(PUBLIC_HEADER_BYTES + ENCAP_BYTES + ciphertext.len());
    out.extend_from_slice(&public);
    out.extend_from_slice(&encapsulated.to_bytes());
    out.extend_from_slice(&ciphertext);
    if out.len() > MAX_MESSAGE_BYTES {
        return Err(W3Error::Oversized);
    }
    Ok(out)
}

/// Authenticate v3 against a recipient-controlled token and a separately
/// enrolled sender signing key. Token knowledge alone gives NO authorization.
pub fn open_private_v3<'packet>(
    packet: &'packet [u8],
    ctx: OpenContext<'_>,
    expected_route_token: [u8; 16],
) -> Result<VerifiedW3<'packet>, W3Error> {
    if packet.len() > MAX_MESSAGE_BYTES {
        return Err(W3Error::Oversized);
    }
    if packet.len() <= PUBLIC_HEADER_BYTES + ENCAP_BYTES + 16 {
        return Err(W3Error::InvalidPacket);
    }
    let hint = parse_header(packet)?;
    if hint.token != expected_route_token {
        return Err(W3Error::WrongRecipient);
    }
    if ctx.now_ms >= hint.expires_at_ms {
        return Err(W3Error::Expired);
    }
    let encapsulated = <X25519 as Kem>::EncappedKey::from_bytes(
        &packet[PUBLIC_HEADER_BYTES..PUBLIC_HEADER_BYTES + ENCAP_BYTES],
    )
    .map_err(|_| W3Error::InvalidPacket)?;
    let decrypted = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519>(
        &OpModeR::Base,
        ctx.secret,
        &encapsulated,
        INFO,
        &packet[PUBLIC_HEADER_BYTES + ENCAP_BYTES..],
        &packet[..PUBLIC_HEADER_BYTES],
    )
    .map_err(|_| W3Error::DecryptFailed)?;

    let signed = CoseSign1::from_slice(&decrypted).map_err(|_| W3Error::InvalidSignature)?;
    if signed.protected.header.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA))
        || signed.unprotected != coset::Header::default()
    {
        return Err(W3Error::InvalidSignature);
    }
    let inner = signed.payload.as_deref().ok_or(W3Error::InvalidSignature)?;
    if inner.len() < IDENTITY_BYTES {
        return Err(W3Error::InvalidSignature);
    }
    let mut recipient_id = [0; 16];
    let mut sender_id = [0; 16];
    recipient_id.copy_from_slice(&inner[..16]);
    sender_id.copy_from_slice(&inner[16..32]);
    let epoch = u64::from_be_bytes(inner[32..40].try_into().map_err(|_| W3Error::InvalidSignature)?);
    let header = SignedHeader {
        message_id: hint.message_id,
        recipient_id,
        expires_at_ms: hint.expires_at_ms,
        sender_id,
        epoch,
    };
    header.check()?;
    if header.recipient_id != ctx.recipient_id {
        return Err(W3Error::WrongRecipient);
    }
    let sender_key = ctx
        .trusted_sender_keys
        .key_for(header.sender_id, header.epoch)
        .ok_or(W3Error::UntrustedSender)?;
    signed
        .verify_signature(&packet[..PUBLIC_HEADER_BYTES], |signature, bytes| {
            let signature = Signature::from_slice(signature).map_err(|_| ())?;
            sender_key.verify(bytes, &signature).map_err(|_| ())
        })
        .map_err(|_| W3Error::InvalidSignature)?;

    Ok(VerifiedW3 {
        header,
        original_packet: packet,
        packet_digest: *blake3::hash(packet).as_bytes(),
        payload: inner[IDENTITY_BYTES..].to_vec(),
    })
}
