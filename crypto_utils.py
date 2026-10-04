import base64
import os

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat
)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key_pair():

    private_key = X25519PrivateKey.generate()

    public_key = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw
    )

    return private_key, public_key


def derive_shared_key(
    private_key,
    peer_public_key_b64
):

    peer_public_bytes = base64.b64decode(
        peer_public_key_b64.encode("ascii"),
        validate=True
    )

    peer_public = X25519PublicKey.from_public_bytes(
        peer_public_bytes
    )

    shared_secret = private_key.exchange(
        peer_public
    )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-chat-application-v1"
    ).derive(shared_secret)


def encrypt_message(
    plaintext,
    aes_key
):

    nonce = os.urandom(12)

    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    return base64.b64encode(
        nonce + ciphertext
    ).decode("ascii")


def decrypt_message(
    encoded_ciphertext,
    aes_key
):

    raw = base64.b64decode(
        encoded_ciphertext.encode("ascii"),
        validate=True
    )

    if len(raw) < 13:
        raise ValueError(
            "Invalid encrypted message."
        )

    nonce = raw[:12]

    ciphertext = raw[12:]

    plaintext = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode("utf-8")