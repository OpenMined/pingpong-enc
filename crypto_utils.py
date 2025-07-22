import base64
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jwcrypto import jwk
from pydantic import BaseModel, Field, field_serializer, field_validator
import base64
from typing import Any
from syft_core import Client


class EncryptedPayload(BaseModel):
    ek: bytes = Field(..., description="Ephemeral key")
    iv: bytes = Field(..., description="Initialization vector")
    ciphertext: bytes = Field(..., description="Encrypted message")
    tag: bytes = Field(..., description="Authentication tag")
    sender: str = Field(..., description="Sender's email")
    receiver: str = Field(..., description="Receiver's email")

    # Serialize bytes fields to base64 for JSON
    @field_serializer("ek", "iv", "ciphertext", "tag")
    def serialize_bytes(self, value: bytes) -> str:
        return base64.b64encode(value).decode("utf-8")

    # Validate and deserialize base64 strings back to bytes
    @field_validator("ek", "iv", "ciphertext", "tag", mode="before")
    @classmethod
    def validate_bytes(cls, value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, str):
            try:
                return base64.b64decode(value)
            except Exception as e:
                raise ValueError(f"Invalid base64 string: {e}")
        raise ValueError(f"Expected bytes or base64 string, got {type(value)}")


def did_path(client: Client, user: str = None):
    if user is None:
        user = client.config.email
    return client.datasites / user / "public" / "did.json"


def private_key_path(client: Client):
    """Path to store private keys as JWKs securely"""
    partition = f"{client.config.server_url}::{client.config.email}"
    partitionHash = hashlib.sha256(partition.encode()).hexdigest()
    syftbox_dir = Path.home() / ".syftbox" / partitionHash[:8]
    syftbox_dir.mkdir(exist_ok=True, parents=True)
    return syftbox_dir / "pvt.jwks.json"


def load_private_keys(client: Client):
    """Load private keys from JWK storage"""
    with open(private_key_path(client), "r") as f:
        keys_data = json.load(f)

    # Reconstruct private keys from JWKs
    identity_jwk = jwk.JWK.from_json(json.dumps(keys_data["identity_key"]))
    spk_jwk = jwk.JWK.from_json(json.dumps(keys_data["signed_prekey"]))

    # Convert back to cryptography objects using correct jwcrypto API
    identity_private_key = identity_jwk.get_op_key("sign")  # Ed25519 for signing
    spk_private_key = spk_jwk.get_op_key("unwrapKey")  # X25519 for key exchange

    return identity_private_key, spk_private_key


def encrypt_message(message: str, to: str, client: Client) -> EncryptedPayload:
    """Encrypt message using X3DH protocol"""
    receiver_did_file = did_path(client, to)

    if not receiver_did_file.exists():
        raise ValueError(f"No DID document found for {to}")

    # Load receiver's DID document
    with open(receiver_did_file, "r") as f:
        receiver_did = json.load(f)

    # Extract receiver's public keys
    receiver_spk_jwk = None
    for key_agreement in receiver_did.get("keyAgreement", []):
        if key_agreement["id"].endswith("#signed-prekey"):
            receiver_spk_jwk = key_agreement["publicKeyJwk"]
            break

    if not receiver_spk_jwk:
        raise ValueError("No signed prekey found in receiver's DID")

    # Reconstruct receiver's public key
    receiver_spk_public = x25519.X25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(receiver_spk_jwk["x"] + "===")
    )

    # Load our private keys
    identity_private_key, spk_private_key = load_private_keys(client)

    # Generate ephemeral key pair
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    # Perform X3DH key agreement
    # DH1 = DH(SPK_a, SPK_b) - our signed prekey with their signed prekey
    dh1 = spk_private_key.exchange(receiver_spk_public)

    # DH2 = DH(EK_a, SPK_b) - our ephemeral key with their signed prekey
    dh2 = ephemeral_private.exchange(receiver_spk_public)

    # Derive shared secret using HKDF
    shared_key_material = dh1 + dh2
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"X3DH",
        backend=default_backend(),
    ).derive(shared_key_material)

    # Encrypt the message using AES-GCM
    iv = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(shared_key), modes.GCM(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    # Create the encrypted payload
    encrypted_payload = EncryptedPayload(
        ek=ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ),
        iv=iv,
        ciphertext=ciphertext,
        tag=encryptor.tag,
        sender=client.config.email,
        receiver=to,
    )

    print(f"🔒 Encrypted message for {to}")
    return encrypted_payload


def decrypt_message(payload: EncryptedPayload, client: Client) -> str:
    """Decrypt message using X3DH protocol"""
    # Load sender's DID document to get their public keys
    sender_did_file = did_path(client, payload.sender)

    if not sender_did_file.exists():
        raise ValueError(f"No DID document found for sender {payload.sender}")

    # Load sender's DID document
    with open(sender_did_file, "r") as f:
        sender_did = json.load(f)

    # Extract sender's signed prekey
    sender_spk_jwk = None
    for key_agreement in sender_did.get("keyAgreement", []):
        if key_agreement["id"].endswith("#signed-prekey"):
            sender_spk_jwk = key_agreement["publicKeyJwk"]
            break

    if not sender_spk_jwk:
        raise ValueError("No signed prekey found in sender's DID")

    # Reconstruct sender's public key
    sender_spk_public = x25519.X25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(sender_spk_jwk["x"] + "===")
    )

    # Reconstruct sender's ephemeral public key
    sender_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(payload.ek)

    # Load our private keys
    identity_private_key, spk_private_key = load_private_keys(client)

    # Perform X3DH key agreement (reverse of encryption)
    # DH1 = DH(SPK_b, SPK_a) - our signed prekey with their signed prekey
    dh1 = spk_private_key.exchange(sender_spk_public)

    # DH2 = DH(SPK_b, EK_a) - our signed prekey with their ephemeral key
    dh2 = spk_private_key.exchange(sender_ephemeral_public)

    # Derive shared secret using HKDF
    shared_key_material = dh1 + dh2
    shared_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"X3DH",
        backend=default_backend(),
    ).derive(shared_key_material)

    # Decrypt the message using AES-GCM
    cipher = Cipher(
        algorithms.AES(shared_key),
        modes.GCM(payload.iv, payload.tag),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(payload.ciphertext) + decryptor.finalize()

    message = decrypted_bytes.decode()
    print(f"🔓 Decrypted message from {payload.sender}")
    return message
