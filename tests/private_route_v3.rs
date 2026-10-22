use akula_blue_w3::private_route_v3::{
    inspect_route, open_private_v3, seal_private_v3, PUBLIC_HEADER_BYTES, VERSION,
};
use akula_blue_w3::{
    new_recipient, open_verified, seal_v2, OpenContext, SignedHeader, TrustedSenderKeys, W3Error,
    MAX_MESSAGE_BYTES,
};
use ed25519_dalek::{SigningKey, VerifyingKey};

const ROUTE_TOKEN: [u8; 16] = [9; 16];

struct Keys {
    id: [u8; 16],
    epoch: u64,
    key: Option<VerifyingKey>,
}
impl TrustedSenderKeys for Keys {
    fn key_for(&self, sender_id: [u8; 16], epoch: u64) -> Option<VerifyingKey> {
        if sender_id == self.id && epoch == self.epoch {
            self.key
        } else {
            None
        }
    }
}
fn identity() -> SignedHeader {
    SignedHeader {
        message_id: [1; 16],
        recipient_id: [2; 16],
        expires_at_ms: 5_000,
        sender_id: [3; 16],
        epoch: 7,
    }
}

#[test]
fn external_header_contains_no_sender_recipient_or_epoch() {
    let sender = SigningKey::from_bytes(&[3; 32]);
    let (secret, recipient) = new_recipient();
    let h = identity();
    let wire = seal_private_v3(&sender, &recipient, ROUTE_TOKEN, h, b"separate recipients").unwrap();
    assert_eq!(wire[0], VERSION);
    assert!(wire.len() > PUBLIC_HEADER_BYTES + 32);
    assert_eq!(&wire[1..17], &h.message_id);
    assert_eq!(&wire[17..33], &ROUTE_TOKEN);
    assert_eq!(&wire[33..41], &h.expires_at_ms.to_be_bytes());
    // Parse the entire *defined* public header, rather than probabilistically
    // searching ciphertext for a 16-byte sequence.
    assert_ne!(&wire[17..33], &h.recipient_id);
    assert!(!wire[..PUBLIC_HEADER_BYTES]
        .windows(16)
        .any(|window| window == h.sender_id.as_slice() || window == h.recipient_id.as_slice()));
    let hint = inspect_route(&wire).unwrap();
    assert_eq!(hint.token, ROUTE_TOKEN);
    assert_eq!(hint.message_id, h.message_id);
    let keys = Keys {
        id: h.sender_id,
        epoch: h.epoch,
        key: Some(sender.verifying_key()),
    };
    let verified = open_private_v3(
        &wire,
        OpenContext {
            secret: &secret,
            recipient_id: h.recipient_id,
            now_ms: 100,
            trusted_sender_keys: &keys,
        },
        ROUTE_TOKEN,
    )
    .unwrap();
    assert_eq!(verified.header(), h);
    assert_eq!(verified.payload(), b"separate recipients");
    assert_eq!(verified.original_packet(), wire.as_slice());
    assert_eq!(verified.packet_digest(), *blake3::hash(&wire).as_bytes());
}

#[test]
fn false_token_wrong_key_wrong_id_and_epoch_fail_closed() {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (secret, public) = new_recipient();
    let header = identity();
    let wire = seal_private_v3(&signer, &public, ROUTE_TOKEN, header, b"secret").unwrap();
    let mut keys = Keys {
        id: header.sender_id,
        epoch: header.epoch,
        key: Some(signer.verifying_key()),
    };
    let open = |keys: &Keys, recipient_id: [u8; 16], token: [u8; 16]| {
        open_private_v3(
            &wire,
            OpenContext {
                secret: &secret,
                recipient_id,
                now_ms: 100,
                trusted_sender_keys: keys,
            },
            token,
        )
        .err()
    };
    assert_eq!(open(&keys, header.recipient_id, [8; 16]), Some(W3Error::WrongRecipient));
    assert_eq!(open(&keys, [5; 16], ROUTE_TOKEN), Some(W3Error::WrongRecipient));
    keys.epoch += 1;
    assert_eq!(open(&keys, header.recipient_id, ROUTE_TOKEN), Some(W3Error::UntrustedSender));
    keys.epoch -= 1;
    keys.key = None;
    assert_eq!(open(&keys, header.recipient_id, ROUTE_TOKEN), Some(W3Error::UntrustedSender));
    let (other_secret, _) = new_recipient();
    let result = open_private_v3(
        &wire,
        OpenContext {
            secret: &other_secret,
            recipient_id: header.recipient_id,
            now_ms: 100,
            trusted_sender_keys: &keys,
        },
        ROUTE_TOKEN,
    );
    assert_eq!(result.err(), Some(W3Error::DecryptFailed));
}

#[test]
fn tampering_any_public_header_field_or_ciphertext_is_detected() {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (secret, recipient) = new_recipient();
    let header = identity();
    let keys = Keys {
        id: header.sender_id,
        epoch: header.epoch,
        key: Some(signer.verifying_key()),
    };
    let wire = seal_private_v3(&signer, &recipient, ROUTE_TOKEN, header, b"genuine").unwrap();
    for offset in [1usize, 19, 34, PUBLIC_HEADER_BYTES, wire.len() - 1] {
        let mut tampered = wire.clone();
        tampered[offset] ^= 1;
        assert!(
            open_private_v3(
                &tampered,
                OpenContext {
                    secret: &secret,
                    recipient_id: header.recipient_id,
                    now_ms: 100,
                    trusted_sender_keys: &keys,
                },
                ROUTE_TOKEN,
            )
            .is_err(),
            "mutated byte {offset} was accepted"
        );
    }
    let forged = seal_private_v3(
        &SigningKey::from_bytes(&[7; 32]),
        &recipient,
        ROUTE_TOKEN,
        header,
        b"not signed by enrolled sender",
    )
    .unwrap();
    assert_eq!(
        open_private_v3(
            &forged,
            OpenContext {
                secret: &secret,
                recipient_id: header.recipient_id,
                now_ms: 100,
                trusted_sender_keys: &keys,
            },
            ROUTE_TOKEN,
        )
        .err(),
        Some(W3Error::InvalidSignature)
    );
}

#[test]
fn privacy_v3_has_no_silent_fallback_to_legacy_v2() {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (secret, public) = new_recipient();
    let header = identity();
    let keys = Keys {
        id: header.sender_id,
        epoch: header.epoch,
        key: Some(signer.verifying_key()),
    };
    let v2 = seal_v2(&signer, &public, header, b"legacy").unwrap();
    let v3 = seal_private_v3(&signer, &public, ROUTE_TOKEN, header, b"private").unwrap();
    assert_eq!(
        open_private_v3(
            &v2,
            OpenContext {
                secret: &secret,
                recipient_id: header.recipient_id,
                now_ms: 100,
                trusted_sender_keys: &keys,
            },
            ROUTE_TOKEN,
        )
        .err(),
        Some(W3Error::UnsupportedVersion)
    );
    assert_eq!(
        open_verified(
            &v3,
            OpenContext {
                secret: &secret,
                recipient_id: header.recipient_id,
                now_ms: 100,
                trusted_sender_keys: &keys,
            },
        )
        .err(),
        Some(W3Error::UnsupportedVersion)
    );
}

#[test]
fn expiry_zero_tokens_and_oversize_are_rejected() {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (secret, recipient) = new_recipient();
    let header = identity();
    assert_eq!(
        seal_private_v3(&signer, &recipient, [0; 16], header, b"empty token").err(),
        Some(W3Error::InvalidDescriptor)
    );
    let keys = Keys {
        id: header.sender_id,
        epoch: header.epoch,
        key: Some(signer.verifying_key()),
    };
    let packet = seal_private_v3(&signer, &recipient, ROUTE_TOKEN, header, b"payload").unwrap();
    assert_eq!(
        open_private_v3(
            &packet,
            OpenContext {
                secret: &secret,
                recipient_id: header.recipient_id,
                now_ms: header.expires_at_ms,
                trusted_sender_keys: &keys,
            },
            ROUTE_TOKEN,
        )
        .err(),
        Some(W3Error::Expired)
    );
    let huge = vec![3u8; MAX_MESSAGE_BYTES + 1];
    assert_eq!(inspect_route(&huge), Err(W3Error::Oversized));
    assert_eq!(
        seal_private_v3(&signer, &recipient, ROUTE_TOKEN, header, &huge).err(),
        Some(W3Error::Oversized)
    );
}
