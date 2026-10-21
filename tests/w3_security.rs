use akula_blue_w3::{
    new_recipient, open_verified, seal_v2, OpenContext, RecipientPublic, RecipientSecret,
    SignedHeader, TrustedSenderKeys, W3Error, MAX_MESSAGE_BYTES,
};
use ed25519_dalek::{SigningKey, VerifyingKey};

#[derive(Clone)]
struct FixedKeys {
    sender: [u8; 16],
    epoch: u64,
    approved: Option<VerifyingKey>,
}
impl TrustedSenderKeys for FixedKeys {
    fn key_for(&self, sender_id: [u8; 16], epoch: u64) -> Option<VerifyingKey> {
        if self.sender == sender_id && self.epoch == epoch {
            self.approved
        } else {
            None
        }
    }
}

fn fixture() -> (
    SigningKey,
    RecipientSecret,
    RecipientPublic,
    SignedHeader,
    FixedKeys,
) {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (secret, recipient) = new_recipient();
    let header = SignedHeader {
        message_id: [1; 16],
        recipient_id: [2; 16],
        expires_at_ms: 5_000,
        sender_id: [3; 16],
        epoch: 7,
    };
    let trust = FixedKeys {
        sender: header.sender_id,
        epoch: header.epoch,
        approved: Some(signer.verifying_key()),
    };
    (signer, secret, recipient, header, trust)
}

fn verify<'wire>(
    wire: &'wire [u8],
    secret: &RecipientSecret,
    recipient_id: [u8; 16],
    now_ms: u64,
    trust: &dyn TrustedSenderKeys,
) -> Result<akula_blue_w3::VerifiedW3<'wire>, W3Error> {
    open_verified(
        wire,
        OpenContext {
            secret,
            recipient_id,
            now_ms,
            trusted_sender_keys: trust,
        },
    )
}

#[test]
fn signed_identity_and_epoch_are_verified_before_returning_safe_type() {
    let (signer, secret, recipient, header, trust) = fixture();
    let wire = seal_v2(&signer, &recipient, header, b"hello W3").unwrap();
    let accepted = verify(&wire, &secret, header.recipient_id, 123, &trust).unwrap();
    assert_eq!(accepted.header(), header);
    assert_eq!(accepted.payload(), b"hello W3");
    assert_eq!(accepted.original_packet(), wire.as_slice());
    assert_eq!(accepted.packet_digest(), *blake3::hash(&wire).as_bytes());
    assert!(wire.len() <= MAX_MESSAGE_BYTES);
}

#[test]
fn no_trust_on_first_use_or_revoked_or_wrong_epoch() {
    let (signer, secret, recipient, header, mut trust) = fixture();
    let wire = seal_v2(&signer, &recipient, header, b"sealed").unwrap();
    trust.approved = None;
    assert_eq!(
        verify(&wire, &secret, header.recipient_id, 100, &trust).err(),
        Some(W3Error::UntrustedSender)
    );
    trust.approved = Some(signer.verifying_key());
    assert!(verify(&wire, &secret, header.recipient_id, 100, &trust).is_ok());
    trust.epoch += 1;
    assert_eq!(
        verify(&wire, &secret, header.recipient_id, 100, &trust).err(),
        Some(W3Error::UntrustedSender)
    );
}

#[test]
fn wrong_recipient_expired_and_wrong_private_key_are_rejected() {
    let (signer, secret, recipient, header, trust) = fixture();
    let wire = seal_v2(&signer, &recipient, header, b"private").unwrap();
    assert_eq!(
        verify(&wire, &secret, [4; 16], 100, &trust).err(),
        Some(W3Error::WrongRecipient)
    );
    assert_eq!(
        verify(&wire, &secret, header.recipient_id, 5_000, &trust).err(),
        Some(W3Error::Expired)
    );
    let (wrong_secret, _) = new_recipient();
    assert_eq!(
        verify(&wire, &wrong_secret, header.recipient_id, 100, &trust).err(),
        Some(W3Error::DecryptFailed)
    );
}

#[test]
fn tampering_with_signed_header_ciphertext_or_signature_is_rejected() {
    let (signer, secret, recipient, header, trust) = fixture();
    let wire = seal_v2(&signer, &recipient, header, b"private").unwrap();

    // Sender ID, message ID, recipient ID, expiry and epoch are all bound
    // to the original 65-byte header using HPKE AAD and the COSE signature.
    for index in [1usize, 20, 34, 42, 58, wire.len() - 1] {
        let mut tampered = wire.clone();
        tampered[index] ^= 1;
        assert!(
            verify(&tampered, &secret, header.recipient_id, 100, &trust).is_err(),
            "tampering byte {index} was accepted"
        );
    }

    let mallory = SigningKey::from_bytes(&[8; 32]);
    let forged = seal_v2(&mallory, &recipient, header, b"private").unwrap();
    assert_eq!(
        verify(&forged, &secret, header.recipient_id, 100, &trust).err(),
        Some(W3Error::InvalidSignature)
    );
}

#[test]
fn reject_bad_version_short_packet_and_oversize_before_decryption() {
    let (signer, secret, recipient, header, trust) = fixture();
    let mut wire = seal_v2(&signer, &recipient, header, b"x").unwrap();
    wire[0] = 1;
    assert_eq!(
        verify(&wire, &secret, header.recipient_id, 100, &trust).err(),
        Some(W3Error::UnsupportedVersion)
    );
    assert_eq!(
        verify(&[], &secret, header.recipient_id, 100, &trust).err(),
        Some(W3Error::InvalidPacket)
    );
    let too_large = vec![0_u8; MAX_MESSAGE_BYTES + 1];
    assert_eq!(
        verify(&too_large, &secret, header.recipient_id, 100, &trust).err(),
        Some(W3Error::Oversized)
    );
    assert_eq!(
        seal_v2(&signer, &recipient, header, &too_large).err(),
        Some(W3Error::Oversized)
    );
}

#[test]
fn invalid_descriptor_and_repeated_exact_wire_do_not_create_new_authority() {
    let (signer, secret, recipient, mut header, trust) = fixture();
    header.message_id = [0; 16];
    assert_eq!(
        seal_v2(&signer, &recipient, header, b"x").err(),
        Some(W3Error::InvalidDescriptor)
    );
    header.message_id = [1; 16];
    header.epoch = 0;
    assert_eq!(
        seal_v2(&signer, &recipient, header, b"x").err(),
        Some(W3Error::InvalidDescriptor)
    );
    header.epoch = 7;
    let wire = seal_v2(
        &signer,
        &recipient,
        header,
        b"dedup must be enforced by Akula",
    )
    .unwrap();
    let a = verify(&wire, &secret, header.recipient_id, 100, &trust).unwrap();
    let b = verify(&wire, &secret, header.recipient_id, 100, &trust).unwrap();
    assert_eq!(a.packet_digest(), b.packet_digest());
    assert_eq!(a.original_packet(), b.original_packet());
    // Two successful verifications do NOT imply two durable deliveries.
}
